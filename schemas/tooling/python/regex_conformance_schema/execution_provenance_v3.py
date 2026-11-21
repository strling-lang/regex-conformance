"""Versioned native execution lineage. The digest-bound historical verifier remains immutable."""

from base64 import b64decode
from binascii import Error as Base64Error
from collections import Counter, defaultdict
from collections.abc import Mapping
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import Any

from . import execution_provenance as legacy
from .errors import fail
from .execution_provenance import (
    COUNT_DERIVATION_METHOD, IDENTITY_PROFILE_PATH, NAMESPACE_PATH, RETRY_REASON_BY_OUTCOME,
    SCHEMA_FAMILY_ID, TERMINAL_PROCESS_OUTCOMES, _instant, _validate_artifact_reference,
    attempt_set_sha256, lineage_set_sha256, policy_revision, result_signature,
)
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict, loads_strict
from .profile import IdentityProfile
from .schema import validate_instance


AMENDMENT_PATH = Path("registries/provenance/execution-provenance-policy-amendment.v1.json")
LINEAGE_VERSION = "execution-lineage-set.v2"
ATTEMPT_VERSION = "physical-attempt-evidence.v3"
OBSERVATION_VERSION = "terminal-observation-content.v3"
NATIVE_EVIDENCE_VERSION = "native-execution-evidence.v1"
NATIVE_EVIDENCE_SCHEMA = Path("schemas/json/native-execution-evidence.schema.json")
NATIVE_OUTCOMES = legacy.TERMINAL_RESPONSE_OUTCOMES | {"compile-acceptance"}
SCHEMA_PATHS = {
    "attempt": Path("schemas/json/physical-attempt-evidence-v3.schema.json"),
    "observation": Path("schemas/json/terminal-observation-content-v3.schema.json"),
    "disposition": legacy.SCHEMA_PATHS["disposition"],
    "lineage_set": Path("schemas/json/execution-lineage-set-v2.schema.json"),
}
COMPILE = {"name": "compile", "version": "1.0.0"}
COMPILE_FIELDS = {
    "operation": COMPILE, "compile_status": "accepted", "execution_status": "not-requested",
    "match_state": "not-applicable", "native_error": None,
}


def _digest(record: Any) -> str:
    return sha256(canonical_bytes(record)).hexdigest()


def successor_policy(root: Path) -> dict:
    amendment = load_strict(root / AMENDMENT_PATH)
    predecessor = load_strict(root / legacy.POLICY_PATH)
    legacy.validate_policy(root, predecessor)
    expected = {
        "schema_version": "execution-provenance-policy-amendment.v1",
        "scope": "prospective-native-execution-lineage",
        "lineage_schema_version": LINEAGE_VERSION,
        "attempt_schema_version": ATTEMPT_VERSION,
        "observation_schema_version": OBSERVATION_VERSION,
        "native_receipt_schema_version": NATIVE_EVIDENCE_VERSION,
        "legacy_execution_policy_revision_sha256": predecessor["policy_revision_sha256"],
        "native_terminal_response_outcomes": sorted(NATIVE_OUTCOMES),
        "target_process_terminal_outcomes": sorted(TERMINAL_PROCESS_OUTCOMES),
        "compile_acceptance": COMPILE_FIELDS,
    }
    if any(amendment.get(key) != value for key, value in expected.items()) or (
        amendment.get("policy_revision_sha256") != policy_revision(amendment)
    ):
        fail("execution-policy-amendment-mismatch", "successor policy differs from its governed scope or digest")
    bound_paths = {
        legacy.POLICY_PATH, Path("schemas/tooling/python/regex_conformance_schema/execution_provenance.py"),
        *legacy.SCHEMA_PATHS.values(), *SCHEMA_PATHS.values(),
        Path("schemas/json/adapter-request.schema.json"), Path("schemas/json/adapter-response.schema.json"),
        NATIVE_EVIDENCE_SCHEMA,
    } - {legacy.SCHEMA_PATHS["policy"]}
    contracts = amendment["contracts_sha256"]
    if set(contracts) != {path.as_posix() for path in bound_paths}:
        fail("execution-policy-contract-set", "successor policy must identify each exact contract")
    for path, expected_digest in contracts.items():
        if sha256((root / path).read_bytes()).hexdigest() != expected_digest:
            fail("execution-policy-contract-digest", f"bound contract differs: {path}")
    return {**predecessor, "policy_revision_sha256": amendment["policy_revision_sha256"]}


def observation_content_id(root: Path, record: dict) -> str:
    version = record.get("schema_version")
    if version == "terminal-observation-content.v2":
        return legacy.observation_content_id(root, record)
    if version != OBSERVATION_VERSION:
        fail("unsupported-terminal-observation-version", "observation identity requires an exact registered version")
    body = {key: val for key, val in record.items() if key != "observation_content_id"}
    identity = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / IDENTITY_PROFILE_PATH)),
        namespace="observation-content",
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": "terminal-observation-content-v3", "content_sha256": _digest(body)},
    )
    return str(identity["content_id"])


def _validate_terminality(attempt: dict, path: str) -> None:
    terminality = attempt["terminality"]
    if terminality["outcome_class"] != "compile-acceptance":
        legacy._validate_terminality(attempt, path)
        return
    attribution = terminality["fault_attribution"]
    process = terminality["target_process_status"]
    if not (
        attribution["target_attributable"] and attribution["attribution_layer"] == "target"
        and attribution["evidence_reference"] is not None
        and process == {"target_started": True, "exit_code": 0, "signal": None, "timeout_source": None, "resource_limit": None}
    ):
        fail("native-compile-not-attributed", "successful native compile requires a started, successful and evidenced target response", path)
    for reference in [attribution["evidence_reference"], *attempt["physical_telemetry_references"]]:
        _validate_artifact_reference(reference, path)
    intermittence = attempt["expected_intermittence"]["source_reference"]
    if intermittence is not None:
        _validate_artifact_reference(intermittence, path)
    if terminality["scientific_result_signature"] != result_signature("compile-acceptance", terminality["semantic_result"]):
        fail("result-signature-mismatch", "native compilation signature differs", path)


def receipt_binding(attempt: dict) -> str:
    body = {key: val for key, val in attempt.items() if key != "native_evidence_sha256"}
    terminality = body["terminality"]
    attribution = {key: val for key, val in terminality["fault_attribution"].items() if key != "evidence_reference"}
    body["terminality"] = {**terminality, "fault_attribution": attribution}
    return _digest(body)


def parse_native_frame(encoded: str, schema_path: Path, path: str) -> dict:
    if not isinstance(encoded, str) or len(encoded) > 1_398_108:
        fail("native-evidence-incomplete-frame", "native frame is missing or exceeds the receipt limit", path)
    try:
        raw = b64decode(encoded, validate=True)
        if len(raw) <= 4 or len(raw) - 4 != int.from_bytes(raw[:4], "big"):
            fail("native-evidence-incomplete-frame", "uint32 frame length differs from retained bytes", path)
        frame = loads_strict(raw[4:].decode("utf-8"))
    except (UnicodeError, Base64Error) as error:
        fail("native-evidence-invalid-encoding", str(error), path)
    validate_instance(frame, load_strict(schema_path), source=path)
    return frame


def _validate_attempt_native_evidence(root: Path, attempt: dict, receipt: dict | None, path: str) -> None:
    terminality = attempt["terminality"]
    outcome = terminality["outcome_class"]
    receipt_digest = attempt["native_evidence_sha256"]
    if outcome not in NATIVE_OUTCOMES:
        if receipt is not None or receipt_digest is not None:
            fail("unexpected-native-response-evidence", "only complete target responses use a native response receipt", path)
        return
    if receipt is None or _digest(receipt) != receipt_digest:
        fail("native-evidence-digest-mismatch", "terminal response requires its exact retained native receipt", path)
    validate_instance(receipt, load_strict(root / NATIVE_EVIDENCE_SCHEMA), source=path)
    reference = terminality["fault_attribution"]["evidence_reference"]
    if reference is None or reference["sha256"] != receipt_digest:
        fail("native-evidence-attribution-mismatch", "target attribution must reference this native receipt", path)
    if receipt["attempt_binding_sha256"] != receipt_binding(attempt):
        fail("native-evidence-attempt-mismatch", "worker receipt differs from the physical attempt and its immutable context", path)
    request = parse_native_frame(receipt["request_frame"], root / "schemas/json/adapter-request.schema.json", path)
    response = parse_native_frame(receipt["response_frame"], root / "schemas/json/adapter-response.schema.json", path)
    if any(request[key] != response[key] for key in (
        "adapter_release_manifest_id", "correlation_id", "profile_id", "target_release_id", "trace_reference",
    )) or request["adapter_release_manifest_id"] != attempt["execution_context"]["adapter_release_manifest_id"]:
        fail("native-evidence-request-response-mismatch", "request, complete native response and execution context disagree", path)
    observed = response["observation"]
    if outcome == "unsupported":
        if response["status"] != "unsupported" or terminality["semantic_result"] != response["failure"]:
            fail("native-evidence-result-mismatch", "unsupported requires the complete native unsupported result", path)
        return
    if response["status"] != "completed" or observed != terminality["semantic_result"] or observed["operation"] != request["operation"]:
        fail("native-evidence-result-mismatch", "terminal result must preserve the complete native result for the requested operation", path)
    if any(absence["reason"] == "truncated" for absence in observed["absences"]):
        fail("native-evidence-truncated", "a truncated response cannot establish a target terminal result", path)
    compile_status, execution_status, match_state, native_error = (
        observed["compile_status"], observed["execution_status"], observed["match_state"], observed["native_error"],
    )
    if outcome == "compile-acceptance":
        consistent = (
            request["operation"] == COMPILE
            and all(observed[key] == value for key, value in COMPILE_FIELDS.items())
            and observed["matches"] == [] and observed["cursor"] is None
            and observed["outputs"] == {"kind": "none", "values": []}
        )
    elif outcome == "compile-rejection":
        consistent = (compile_status, execution_status, match_state) == ("rejected", "not-requested", "not-applicable") and native_error is not None
    elif outcome in {"match", "no-match"}:
        consistent = request["operation"] != COMPILE and (
            compile_status, execution_status, match_state, native_error
        ) == ("accepted", "completed", outcome, None)
    else:
        consistent = execution_status == "rejected" and native_error is not None
    if not consistent:
        fail("native-evidence-outcome-mismatch", "scientific outcome contradicts native compile or execution status", path)


# The historical validator is a byte-bound implementation. These successor checks
# retain its reconciliation rules on the original records, with v3 schema, response
# and identity verification added before any count receives credit.
def _validate_attempt_sequence(
    root: Path,
    attempts: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    disposition: dict[str, Any],
    policy: dict[str, Any],
    path: str,
    native_evidence: Mapping[str, dict],
) -> None:
    registry = NamespaceRegistry.load(root / NAMESPACE_PATH)
    retry_rules = {rule["reason_code"]: rule for rule in policy["retry_rules"]}
    repeat_rules = {rule["reason_code"]: rule for rule in policy["repeat_rules"]}
    observation_by_attempt = {item["terminal_attempt_id"]: item for item in observations}
    observation_by_id = {item["observation_id"]: item for item in observations}
    logical_id = disposition["logical_execution_id"]
    terminal_attempts: list[dict[str, Any]] = []
    repeat_counts: Counter[str] = Counter()

    if [item["attempt_ordinal"] for item in attempts] != list(range(1, len(attempts) + 1)):
        fail("noncontiguous-attempt-ordinals", "attempt ordinals must be unique and contiguous", path)

    stable_context: dict[str, Any] | None = None
    for index, attempt in enumerate(attempts):
        attempt_path = f"{path}.attempts[{index}]"
        validate_instance(attempt, load_strict(root / SCHEMA_PATHS["attempt"]), source=attempt_path)
        registry.validate(attempt["physical_run_id"])
        registry.validate(attempt["logical_execution_id"])
        if attempt["logical_execution_id"] != logical_id:
            fail("attempt-logical-mismatch", "attempt belongs to another logical execution", attempt_path)
        start = _instant(attempt["started_at"], f"{attempt_path}.started_at")
        end = _instant(attempt["ended_at"], f"{attempt_path}.ended_at")
        if end < start:
            fail("attempt-time-reversal", "attempt ends before it starts", attempt_path)
        expected_predecessor = None if index == 0 else attempts[index - 1]["physical_run_id"]
        if attempt["predecessor_physical_run_id"] != expected_predecessor:
            fail("invalid-attempt-predecessor", "predecessor must be the immediately preceding attempt", attempt_path)
        context = attempt["execution_context"]
        if context["execution_policy_revision_sha256"] != policy["policy_revision_sha256"]:
            fail("attempt-policy-mismatch", "attempt binds another execution policy", attempt_path)
        if stable_context is None:
            stable_context = deepcopy(context)
        else:
            for key, value in stable_context.items():
                if key in {"environment_realization_id", "environment_fingerprint_id"}:
                    continue
                if context[key] != value:
                    fail("logical-context-drift", f"{key} changed within one logical execution", attempt_path)
        reset = attempt["reset"]
        for ref_index, reference in enumerate(reset["evidence_references"]):
            _validate_artifact_reference(reference, f"{attempt_path}.reset.evidence_references[{ref_index}]")
        _validate_terminality(attempt, attempt_path)
        _validate_attempt_native_evidence(root, attempt, native_evidence.get(attempt["physical_run_id"]), attempt_path)
        if attempt["terminality"]["disposition"] == "terminal-scientific-observation":
            terminal_attempts.append(attempt)
            observation = observation_by_attempt.get(attempt["physical_run_id"])
            if observation is None:
                fail("missing-terminal-observation", "terminal attempt has no observation", attempt_path)
            if observation["observation_id"] != attempt["terminality"]["produced_observation_id"]:
                fail("attempt-observation-mismatch", "attempt names another observation", attempt_path)

        retry = attempt["retry"]
        repeat = attempt["repeat"]
        if index == 0:
            if attempt["attempt_purpose"] != "initial" or retry is not None or repeat is not None:
                fail("invalid-initial-attempt", "the first attempt must be an unaffiliated initial attempt", attempt_path)
            if reset["reason_code"] != "initial-state":
                fail("invalid-initial-reset", "the initial attempt must declare its initial-state reset reason", attempt_path)
        elif (retry is None) == (repeat is None):
            fail("unexplained-subsequent-attempt", "every later attempt requires exactly one retry or repeat authorization", attempt_path)
        if retry is not None:
            if index == 0 or attempts[index - 1]["terminality"]["disposition"] != "inconclusive-attempt":
                fail("retry-laundering", "retry must follow an inconclusive attempt", attempt_path)
            predecessor = attempts[index - 1]
            expected_reason = RETRY_REASON_BY_OUTCOME[predecessor["terminality"]["outcome_class"]]
            if retry["reason_code"] != expected_reason:
                fail("retry-cause-mismatch", "retry reason differs from predecessor outcome", attempt_path)
            rule = retry_rules[retry["reason_code"]]
            if not rule["retry_permitted"] or retry["authorization_kind"] not in rule["authorization_kinds"]:
                fail("unauthorized-retry", "retry is not authorized by its bound policy", attempt_path)
            if retry["policy_rule"] != retry["reason_code"] or retry["policy_revision_sha256"] != policy["policy_revision_sha256"]:
                fail("retry-policy-mismatch", "retry does not bind the governing rule revision", attempt_path)
            if reset["scope"] != rule["required_reset_scope"]:
                fail("retry-reset-mismatch", "retry reset scope differs from policy", attempt_path)
            if reset["reason_code"] != retry["reason_code"]:
                fail("retry-reset-reason-mismatch", "retry reset reason differs from retry causality", attempt_path)
            if attempt["attempt_ordinal"] > rule["maximum_attempts"]:
                fail("retry-budget-exceeded", "attempt exceeds retry policy maximum", attempt_path)
            prior_environment = predecessor["execution_context"]["environment_realization_id"]
            current_environment = context["environment_realization_id"]
            requirement = rule["environment_realization_requirement"]
            if requirement == "same":
                for key in ("environment_realization_id", "environment_fingerprint_id"):
                    if context[key] != predecessor["execution_context"][key]:
                        fail("retry-environment-drift", "retry requires the same environment realization", attempt_path)
            if requirement == "new-allowed" and reset["scope"] == "environment-realization" and current_environment == prior_environment:
                fail("retry-environment-not-replaced", "environment reset requires a new realization", attempt_path)
        elif repeat is not None:
            if index == 0 or attempts[index - 1]["terminality"]["disposition"] != "terminal-scientific-observation":
                fail("invalid-repeat-predecessor", "repeat measurement must follow terminal evidence", attempt_path)
            rule = repeat_rules[repeat["reason_code"]]
            if repeat["authorization_kind"] not in rule["authorization_kinds"] or reset["scope"] != rule["required_reset_scope"]:
                fail("unauthorized-repeat", "repeat does not satisfy its bound rule", attempt_path)
            if repeat["policy_rule"] != repeat["reason_code"] or repeat["policy_revision_sha256"] != policy["policy_revision_sha256"]:
                fail("repeat-policy-mismatch", "repeat names an unknown policy rule", attempt_path)
            if reset["reason_code"] != repeat["reason_code"]:
                fail("repeat-reset-reason-mismatch", "repeat reset reason differs from repeat causality", attempt_path)
            predecessor = attempts[index - 1]
            if rule["environment_realization_requirement"] == "same":
                for key in ("environment_realization_id", "environment_fingerprint_id"):
                    if context[key] != predecessor["execution_context"][key]:
                        fail("repeat-environment-drift", "repeat comparison requires the same environment realization", attempt_path)
            repeat_counts[repeat["reason_code"]] += 1
            if repeat_counts[repeat["reason_code"]] > rule["maximum_additional_attempts"]:
                fail("repeat-budget-exceeded", "repeat exceeds policy maximum", attempt_path)
            predecessor_observation = observation_by_attempt.get(attempts[index - 1]["physical_run_id"])
            if predecessor_observation is None or repeat["terminal_predecessor_observation_id"] != predecessor_observation["observation_id"]:
                fail("repeat-observation-mismatch", "repeat does not bind predecessor terminal evidence", attempt_path)

        checkpoint = attempt["checkpoint_context"]
        if index == 0:
            if checkpoint["recovery_action"] != "start" or checkpoint["predecessor_checkpoint_sha256"] is not None:
                fail("invalid-initial-checkpoint", "initial attempt must begin a checkpoint chain", attempt_path)
        else:
            previous_checkpoint = attempts[index - 1]["checkpoint_context"]["start_checkpoint_sha256"]
            if checkpoint["predecessor_checkpoint_sha256"] != previous_checkpoint:
                fail("checkpoint-attempt-contradiction", "attempt and checkpoint predecessor chains differ", attempt_path)
            expected_action = "retry" if retry is not None else "repeat"
            if checkpoint["recovery_action"] != expected_action:
                fail("checkpoint-action-mismatch", "checkpoint action differs from attempt purpose", attempt_path)

    if len(observation_by_attempt) != len(observations) or len(observation_by_id) != len(observations):
        fail("duplicate-observation-owner", "observations require unique IDs and terminal attempts", path)
    physical_ids = [item["physical_run_id"] for item in attempts]
    expected_observation_order = [
        item["terminality"]["produced_observation_id"] for item in attempts
        if item["terminality"]["disposition"] == "terminal-scientific-observation"
    ]
    if [item["observation_id"] for item in observations] != expected_observation_order:
        fail("unordered-terminal-observations", "observations must follow producing-attempt order", path)
    for observation_index, observation in enumerate(observations):
        observation_path = f"{path}.observations[{observation_index}]"
        validate_instance(observation, load_strict(root / SCHEMA_PATHS["observation"]), source=observation_path)
        registry.validate(observation["observation_id"])
        registry.validate(observation["observation_content_id"])
        attempt = next((item for item in attempts if item["physical_run_id"] == observation["terminal_attempt_id"]), None)
        if attempt is None or attempt["logical_execution_id"] != observation["logical_execution_id"]:
            fail("dangling-terminal-attempt", "observation names no attempt in its logical lineage", observation_path)
        if observation["campaign_manifest_id"] != attempt["execution_context"]["campaign_manifest_id"]:
            fail("observation-campaign-mismatch", "observation and attempt bind different campaigns", observation_path)
        ordinal = attempt["attempt_ordinal"]
        if observation["attempt_set_reference"] != {
            "attempt_set_sha256": attempt_set_sha256(physical_ids[:ordinal]),
            "attempts_total": ordinal,
        }:
            fail("observation-attempt-set-mismatch", "observation attempt set is not its committed prefix", observation_path)
        terminality = attempt["terminality"]
        for key in ("fault_attribution", "outcome_class", "semantic_result"):
            if observation[key] != terminality[key]:
                fail("observation-attempt-content-mismatch", f"observation {key} differs from attempt", observation_path)
        if observation["protocol_valid"] != terminality["protocol_valid"] or observation["result_signature"] != terminality["scientific_result_signature"]:
            fail("observation-attempt-status-mismatch", "observation status differs from attempt", observation_path)
        if observation["physical_telemetry_references"] != attempt["physical_telemetry_references"]:
            fail("telemetry-provenance-mismatch", "observation must reference, not absorb, attempt telemetry", observation_path)
        if observation["observation_content_id"] != observation_content_id(root, observation):
            fail("observation-content-id-mismatch", "observation content identity differs", observation_path)

    first_terminal = terminal_attempts[0] if terminal_attempts else None
    expected_satisfaction_attempt = None if first_terminal is None else first_terminal["physical_run_id"]
    expected_satisfaction_observation = None if first_terminal is None else first_terminal["terminality"]["produced_observation_id"]
    if disposition["satisfaction_attempt_id"] != expected_satisfaction_attempt or disposition["satisfaction_observation_id"] != expected_satisfaction_observation:
        fail("terminal-evidence-laundering", "logical satisfaction must remain bound to first terminal evidence", path)

    grouped: dict[str, list[str]] = defaultdict(list)
    for observation in observations:
        grouped[observation["result_signature"]["sha256"]].append(observation["observation_id"])
    expected_groups = [
        {"observation_count": len(ids), "observation_ids": sorted(ids), "sha256": signature}
        for signature, ids in sorted(grouped.items())
    ]
    expected_counts = {
        "attempt_set_sha256": attempt_set_sha256(physical_ids),
        "attempts_total": len(attempts),
        "distinct_terminal_result_signature_count": len(grouped),
        "inconclusive_attempt_count": sum(item["terminality"]["disposition"] == "inconclusive-attempt" for item in attempts),
        "last_attempt_id": physical_ids[-1],
        "logical_execution_id": logical_id,
        "observation_ids": sorted(item["observation_id"] for item in observations),
        "recovered_attempt_count": sum(item["attempt_purpose"] in {"recovery-retry", "recovery-validation"} for item in attempts),
        "repeat_measurement_attempt_count": sum(item["repeat"] is not None for item in attempts),
        "retry_attempt_count": sum(item["retry"] is not None for item in attempts),
        "satisfaction_attempt_id": expected_satisfaction_attempt,
        "satisfaction_observation_id": expected_satisfaction_observation,
        "schema_version": "logical-execution-disposition.v1",
        "status": "satisfied" if first_terminal else "unresolved",
        "terminal_attempt_count": len(terminal_attempts),
        "terminal_result_signatures": expected_groups,
    }
    for key, value in expected_counts.items():
        if disposition[key] != value:
            fail("logical-disposition-mismatch", f"{key} does not reconcile with attempt history", path)
    if first_terminal:
        if disposition["retry_budget_exhausted"] or disposition["unresolved_reason"] is not None:
            fail("invalid-satisfied-disposition", "satisfied lineage cannot be unresolved", path)
    else:
        last = attempts[-1]
        reason = RETRY_REASON_BY_OUTCOME[last["terminality"]["outcome_class"]]
        rule = retry_rules[reason]
        exhausted = rule["retry_permitted"] and len(attempts) >= rule["maximum_attempts"]
        expected_reason = "retry-budget-exhausted" if exhausted else (
            "nonretryable-inconclusive" if not rule["retry_permitted"] else "retry-not-attempted"
        )
        if disposition["retry_budget_exhausted"] != exhausted or disposition["unresolved_reason"] != expected_reason:
            fail("invalid-unresolved-disposition", "unresolved reason does not follow retry policy", path)


def _validate_successor_lineage_set(
    root: Path, record: dict[str, Any], native_evidence: Mapping[str, dict],
) -> dict[str, int]:
    active_policy = successor_policy(root)
    validate_instance(record, load_strict(root / SCHEMA_PATHS["lineage_set"]), source=SCHEMA_PATHS["lineage_set"].as_posix())
    if record["execution_policy_revision_sha256"] != active_policy["policy_revision_sha256"]:
        fail("lineage-policy-mismatch", "lineage set binds another execution policy")
    if record["lineage_set_sha256"] != lineage_set_sha256(record):
        fail("lineage-set-digest-mismatch", "lineage set digest differs")
    derivation_catalog = load_strict(root / "registries/provenance/generated-assertion-derivations.v1.json")
    count_derivation = next(
        (item for item in derivation_catalog["derivations"] if item["method_key"] == COUNT_DERIVATION_METHOD),
        None,
    )
    if count_derivation is None or record["count_derivation_revision_id"] != count_derivation["derivation_revision_id"]:
        fail("lineage-count-derivation-mismatch", "lineage counts do not bind the shared reconciliation calculation")
    if count_derivation["derivation_class"] != "calculation" or count_derivation["independent_evidence"]:
        fail("lineage-count-evidence-overclaim", "lineage counts must remain non-independent calculations")
    logical_ids = [item["logical_execution_id"] for item in record["lineages"]]
    if logical_ids != sorted(logical_ids) or len(logical_ids) != len(set(logical_ids)):
        fail("invalid-logical-lineage-order", "logical lineages must be unique and sorted")
    all_attempt_ids: list[str] = []
    all_observation_ids: list[str] = []
    all_content_ids: list[str] = []
    actual_counts = Counter({"logical_execution_count": len(record["lineages"])})
    for index, lineage in enumerate(record["lineages"]):
        path = f"$.lineages[{index}]"
        disposition = lineage["disposition"]
        validate_instance(disposition, load_strict(root / SCHEMA_PATHS["disposition"]), source=path)
        if lineage["logical_execution_id"] != disposition["logical_execution_id"]:
            fail("lineage-disposition-mismatch", "lineage and disposition IDs differ", path)
        for attempt in lineage["attempts"]:
            if attempt["execution_context"]["campaign_manifest_id"] != record["campaign_manifest_id"]:
                fail("attempt-campaign-mismatch", "attempt binds another campaign", path)
        _validate_attempt_sequence(root, lineage["attempts"], lineage["observations"], disposition, active_policy, path, native_evidence)
        all_attempt_ids.extend(item["physical_run_id"] for item in lineage["attempts"])
        all_observation_ids.extend(item["observation_id"] for item in lineage["observations"])
        all_content_ids.extend(item["observation_content_id"] for item in lineage["observations"])
        actual_counts.update(
            physical_attempt_count=len(lineage["attempts"]),
            inconclusive_attempt_count=disposition["inconclusive_attempt_count"],
            recovered_attempt_count=disposition["recovered_attempt_count"],
            repeat_measurement_attempt_count=disposition["repeat_measurement_attempt_count"],
            retry_attempt_count=disposition["retry_attempt_count"],
            terminal_attempt_count=disposition["terminal_attempt_count"],
            terminal_observation_count=len(lineage["observations"]),
        )
    for label, values in (
        ("physical attempt", all_attempt_ids),
        ("observation", all_observation_ids),
        ("observation content", all_content_ids),
    ):
        if len(values) != len(set(values)):
            fail("reused-immutable-identity", f"duplicate {label} identity in lineage set")
    expected_counts = {key: actual_counts[key] for key in active_policy["reporting_populations"]}
    if record["counts"] != expected_counts:
        fail("lineage-population-count-mismatch", "population-explicit counts do not reconcile")
    expected_native_ids = {
        item["physical_run_id"] for lineage in record["lineages"] for item in lineage["attempts"]
        if item["native_evidence_sha256"] is not None
    }
    if set(native_evidence) != expected_native_ids:
        fail("native-evidence-population-mismatch", "receipts must exactly cover the bound physical attempts")
    return expected_counts



def validate_lineage_set(
    root: Path, record: dict, *, native_evidence: Mapping[str, dict] | None = None,
) -> dict[str, int]:
    version = record.get("schema_version")
    if version == "execution-lineage-set.v1" and native_evidence is None:
        return legacy.validate_lineage_set(root, record)
    if version == LINEAGE_VERSION and native_evidence is not None:
        return _validate_successor_lineage_set(root, record, native_evidence)
    fail("unsupported-execution-lineage-route", "lineage requires its exact schema version and evidence set")
