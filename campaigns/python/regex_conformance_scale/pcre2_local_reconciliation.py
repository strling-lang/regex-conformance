"""Reconcile exact PCRE2 captures into local, independently verifiable evidence."""

from base64 import b64decode, b64encode
from collections import Counter
from hashlib import sha256
from pathlib import Path

from regex_conformance_schema.applicability import _content_id
from regex_conformance_schema.execution_provenance import (
    COUNT_DERIVATION_METHOD, RETRY_REASON_BY_OUTCOME, attempt_set_sha256, lineage_set_sha256, result_signature,
)
from regex_conformance_schema.execution_provenance_v3 import (
    ATTEMPT_VERSION, LINEAGE_VERSION, NATIVE_EVIDENCE_VERSION, OBSERVATION_VERSION,
    observation_content_id, parse_native_frame, receipt_binding, successor_policy, validate_lineage_set,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.pcre2_production_adjudication import production_trace_reference, request_semantics

from .evidence_pack_v3 import RetainedBlock, build_evidence_pack, decode_evidence_pack
from .pcre2_execution_gate import Pcre2ExecutionGate, Pcre2ExecutionGateError, _read_journal, _validate_closed
from .pcre2_native_dispatch import _frame_pairs, _validate_native_exchange


def _sha(value: bytes) -> str:
    return sha256(value).hexdigest()


def _ref(path: str, raw: bytes, category: str) -> dict:
    return {"relative_path": path, "size_bytes": len(raw), "sha256": _sha(raw), "category": category}


def _outcome(response: dict) -> tuple[str, dict]:
    observation = response["observation"]
    if observation["compile_status"] == "rejected":
        return "compile-rejection", observation
    if observation["execution_status"] == "rejected":
        return "target-error", observation
    if observation["operation"]["name"] == "compile":
        return "compile-acceptance", observation
    return observation["match_state"], observation


def _context(root: Path, proposal: dict, session: dict, row: dict) -> dict:
    stable_fields = (
        "adapter_release_id", "adapter_release_manifest_id", "applicability_coordinate_id", "campaign_manifest_id",
        "control_plane_revision_sha256", "environment_fingerprint_id", "harness_revision_sha256", "profile_revision_id",
        "protocol_revision_id", "target_release_revision_id", "vector_revision_id",
    )
    return {
        **{field: row[field] for field in stable_fields},
        "campaign_id": session["campaign_id"], "environment_realization_id": session["environment_realization_id"],
        "execution_policy_revision_sha256": proposal["execution_policy_revision_sha256"],
        "execution_shard_id": _content_id(root, "shard", "bounded-campaign-shard-v1", {
            "campaign_manifest_id": proposal["campaign_manifest_id"],
        }),
        "partition_id": None,
        "work_unit_id": _content_id(root, "shard", "bounded-campaign-work-unit-v1", {
            "logical_execution_id": row["logical_execution_id"],
        }),
    }


def _record_capture(root: Path, journal: Path, index: int, row: dict, proposal: dict, session: dict, policy: dict) -> tuple[dict, dict | None]:
    logical_id = row["logical_execution_id"]
    _validate_closed(journal, index, logical_id, session["execution_admission_sha256"])
    reserved = _read_journal(journal / f"{index:02d}.reserved")
    capture_name = f"{index:02d}.closed"
    capture = _read_journal(journal / capture_name)
    process = capture["process"]
    physical_id = reserved["physical_run_id"]
    request_frame = capture["native_request_frame"]
    request = parse_native_frame(request_frame, root / "schemas/json/adapter-request.schema.json", capture_name)
    if (
        capture["schema_version"] != "pcre2-physical-capture.v1" or capture["logical_execution_id"] != logical_id
        or _sha(canonical_bytes(request)) != reserved["request_sha256"]
        or _sha(canonical_bytes(request_semantics(request))) != row["request_semantic_sha256"]
        or request["correlation_id"] != physical_id.rsplit(":", 1)[1]
        or request["trace_reference"] != production_trace_reference(physical_id)
        or reserved["environment_realization_id"] != session["environment_realization_id"]
    ):
        raise Pcre2ExecutionGateError("capture differs from the reserved request or realized scope")
    stdout = b64decode(capture["native_stdout"], validate=True)
    stderr = b64decode(capture["native_stderr"], validate=True)
    budget = row["resource_budget"]
    for name, payload in (("stdout", stdout), ("stderr", stderr)):
        total = process[f"{name}_total_bytes"]
        if len(payload) > min(total, budget[f"{name}_bytes"]) or (
            len(payload) == total and _sha(payload) != process[f"{name}_sha256"]
        ):
            raise Pcre2ExecutionGateError("raw process bytes do not match their supervisor commitment")
    complete = capture["disposition"] == "complete-native-response"
    outcome, semantic = "inconclusive-attribution", None
    native_response = None
    if complete:
        if (
            process["exit_code"] != 0 or process["outcome"] != "completed"
            or process["wall_time_ms"] > budget["wall_time_ms"]
            or len(stdout) != process["stdout_total_bytes"] or len(stderr) != process["stderr_total_bytes"]
        ):
            raise Pcre2ExecutionGateError("terminal response must have a complete successful supervisor capture")
        facts = {
            item["name"]: item["value"] for item in proposal["worker"]["scope"]["runtime_identity"]["facts"]
            if item["name"] in {"engine-version", "runtime-kind", "library-sha256"}
        }
        offer = parse_native_frame(
            capture["native_offer_frame"], root / "schemas/json/adapter-handshake.schema.json", capture_name,
        )
        if offer.get("message_type") != "handshake-offer":
            raise Pcre2ExecutionGateError("retained native offer frame has the wrong message type")
        _validate_native_exchange(root, stdout, offer, request, facts)
        _, native = _frame_pairs(stdout)
        native_response = b64encode(native).decode("ascii")
        response = parse_native_frame(native_response, root / "schemas/json/adapter-response.schema.json", capture_name)
        outcome, semantic = _outcome(response)
    obs_id = capture["observation_id"] if complete else None
    capture_ref = _ref(capture_name, canonical_bytes(capture) + b"\n", "raw-physical-capture")
    attribution = {
        "attribution_layer": "target" if complete else "supervisor",
        "reason_code": "complete-native-response" if complete else outcome,
        "target_attributable": complete, "evidence_reference": capture_ref,
    }
    attempt = {
        "schema_version": ATTEMPT_VERSION, "logical_execution_id": logical_id, "physical_run_id": physical_id,
        "attempt_ordinal": 1, "attempt_purpose": "initial", "predecessor_physical_run_id": None,
        "started_at": capture["start_time"], "ended_at": capture["end_time"],
        "execution_context": _context(root, proposal, session, row),
        "checkpoint_context": {
            "controller_session_id": session["campaign_id"], "start_state": "running", "recovery_action": "start",
            "predecessor_checkpoint_sha256": None, "start_checkpoint_sha256": _sha(canonical_bytes(reserved)),
        },
        "expected_intermittence": {"declared": False, "source_reference": None},
        "physical_telemetry_references": [capture_ref], "resource_budget": budget,
        "repeat": None, "retry": None, "reset": {"evidence_references": [], "reason_code": "initial-state", "scope": "none"},
        "terminality": {
            "disposition": "terminal-scientific-observation" if complete else "inconclusive-attempt",
            "outcome_class": outcome, "semantic_result": semantic, "observation_complete": complete,
            "protocol_status": {"state": "valid" if complete else "missing",
                                "last_checkpoint": "target-response-complete" if complete else "target-not-started"},
            "protocol_valid": complete, "fault_attribution": attribution, "produced_observation_id": obs_id,
            "target_process_status": {"exit_code": process["exit_code"], "resource_limit": None, "signal": None,
                                      "timeout_source": None, "target_started": complete},
            "scientific_result_signature": result_signature(outcome, semantic) if complete else None,
        },
        "native_evidence_sha256": None,
    }
    receipt, observations, groups = None, [], []
    if complete:
        receipt = {
            "schema_version": NATIVE_EVIDENCE_VERSION, "attempt_binding_sha256": receipt_binding(attempt),
            "request_frame": request_frame, "response_frame": native_response,
        }
        attempt["native_evidence_sha256"] = _sha(canonical_bytes(receipt))
        attribution["evidence_reference"] = _ref(f"native/{physical_id.rsplit(':', 1)[1]}.json",
                                                canonical_bytes(receipt), "native-execution-receipt")
        observation = {
            "schema_version": OBSERVATION_VERSION, "logical_execution_id": logical_id, "terminal_attempt_id": physical_id,
            "observation_id": obs_id, "observation_complete": True, "campaign_manifest_id": proposal["campaign_manifest_id"],
            "attempt_set_reference": {"attempt_set_sha256": attempt_set_sha256([physical_id]), "attempts_total": 1},
            "fault_attribution": attribution, "outcome_class": outcome, "protocol_valid": True,
            "semantic_result": semantic, "result_signature": attempt["terminality"]["scientific_result_signature"],
            "physical_telemetry_references": [capture_ref], "derivation_revision_ids": [],
        }
        observation["observation_content_id"] = observation_content_id(root, observation)
        observations.append(observation)
        groups.append({"observation_count": 1, "observation_ids": [obs_id], "sha256": observation["result_signature"]["sha256"]})
    retry_rule = next((rule for rule in policy["retry_rules"] if rule["reason_code"] == RETRY_REASON_BY_OUTCOME.get(outcome)), None)
    disposition = {
        "schema_version": "logical-execution-disposition.v1", "logical_execution_id": logical_id,
        "status": "satisfied" if complete else "unresolved",
        "attempt_set_sha256": attempt_set_sha256([physical_id]), "attempts_total": 1, "last_attempt_id": physical_id,
        "distinct_terminal_result_signature_count": len(groups), "inconclusive_attempt_count": int(not complete),
        "terminal_attempt_count": int(complete), "terminal_result_signatures": groups,
        "observation_ids": [obs_id] if complete else [], "recovered_attempt_count": 0,
        "repeat_measurement_attempt_count": 0, "retry_attempt_count": 0, "retry_budget_exhausted": False,
        "satisfaction_attempt_id": physical_id if complete else None, "satisfaction_observation_id": obs_id,
        "unresolved_reason": None if complete else ("retry-not-attempted" if retry_rule["retry_permitted"] else "nonretryable-inconclusive"),
    }
    return {"logical_execution_id": logical_id, "attempts": [attempt], "observations": observations, "disposition": disposition}, receipt


def reconcile_local(root: Path, journal: Path, gate: Pcre2ExecutionGate):
    """Verify captured lineage and retain a canonical pack only for the complete pilot."""
    proposal = loads_strict(gate.proposal_bytes.decode("utf-8"))
    policy = successor_policy(root)
    session = _read_journal(journal / "dispatch-session.json")
    if (
        session.get("campaign_manifest_id") != proposal["campaign_manifest_id"]
        or session.get("execution_admission_sha256") != gate.admission_sha256
        or session.get("environment_realization_id") != gate.environment_realization_id
    ):
        raise Pcre2ExecutionGateError("dispatch session differs from the separate verified admission")
    entries, receipts, pending = [], {}, []
    timeline = {}
    count = Counter()
    names = {path.name for path in journal.iterdir() if path.suffix in {".reserved", ".closed"}}
    stopped = False
    for index, row in enumerate(proposal["logical_assignments"]):
        reserved_path = journal / f"{index:02d}.reserved"
        closed_path = journal / f"{index:02d}.closed"
        if reserved_path.name not in names:
            if closed_path.name in names:
                raise Pcre2ExecutionGateError("capture has no prior reservation")
            stopped = True
            continue
        if stopped:
            raise Pcre2ExecutionGateError("journal contains a reservation after an incomplete prefix")
        names.remove(reserved_path.name)
        timeline[reserved_path.name] = _read_journal(reserved_path)
        if closed_path.name not in names:
            pending.append(row["logical_execution_id"])
            stopped = True
            continue
        names.remove(closed_path.name)
        entry, receipt = _record_capture(root, journal, index, row, proposal, session, policy)
        timeline[closed_path.name] = _read_journal(closed_path)
        entries.append(entry)
        attempt = entry["attempts"][0]
        if receipt is not None:
            receipts[attempt["physical_run_id"]] = receipt
        else:
            stopped = True
        count.update({
            "logical_execution_count": 1, "physical_attempt_count": 1, "terminal_observation_count": len(entry["observations"]),
            "terminal_attempt_count": len(entry["observations"]), "inconclusive_attempt_count": int(not entry["observations"]),
        })
    if names:
        raise Pcre2ExecutionGateError("journal contains a physical record outside the approved population")
    lineage = None
    pack = None
    if entries:
        catalog = load_strict(root / "registries/provenance/generated-assertion-derivations.v1.json")
        method = next(row for row in catalog["derivations"] if row["method_key"] == COUNT_DERIVATION_METHOD)
        lineage = {
            "schema_version": LINEAGE_VERSION, "campaign_manifest_id": proposal["campaign_manifest_id"],
            "execution_policy_revision_sha256": policy["policy_revision_sha256"],
            "count_derivation_revision_id": method["derivation_revision_id"],
            "counts": {key: count[key] for key in policy["reporting_populations"]},
            "lineages": sorted(entries, key=lambda row: row["logical_execution_id"]),
        }
        lineage["lineage_set_sha256"] = lineage_set_sha256(lineage)
        validate_lineage_set(root, lineage, native_evidence=receipts)
        if count["terminal_observation_count"] == len(proposal["logical_assignments"]):
            blocks = [
                RetainedBlock("physical_attempt_facts", "execution-lineage-set-v2", 0, lineage),
                RetainedBlock("diagnostics", "native-execution-evidence-v1", 0, receipts),
                RetainedBlock("diagnostics", "raw-physical-capture-journal", 0, timeline),
                RetainedBlock("profile_environment_release_provenance", "dispatch-session", 0, session),
            ]
            pack = build_evidence_pack(
                blocks, campaign_manifest_sha256=proposal["campaign_manifest_id"].rsplit(":", 1)[1],
                counts={"logical_executions": len(entries), "observations": count["terminal_observation_count"],
                        "physical_attempts": count["physical_attempt_count"]},
                canonical_input_derivation="pcre2-admitted-execution-lineage-v2",
            )
            raw_size = sum(path.stat().st_size for path in journal.iterdir() if path.is_file())
            if raw_size + pack.retained_bytes > proposal["execution_caps"]["local_evidence_bytes"] or (
                {block.role: block.value for block in decode_evidence_pack(pack.manifest, pack.objects)}
                != {block.role: block.value for block in blocks}
            ):
                raise Pcre2ExecutionGateError("local pack failed exact recovery or capacity admission")
    report = {"lineage": lineage, "native_receipts": receipts, "uncertain_dispatch_logical_ids": pending}
    return report, pack
