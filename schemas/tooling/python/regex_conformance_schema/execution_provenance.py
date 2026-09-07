"""Prospective physical-attempt, terminal-observation, and retry lineage contract."""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from datetime import datetime
import hashlib
import os
from pathlib import Path
from typing import Any

from .errors import fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .profile import IdentityProfile
from .schema import validate_instance


POLICY_PATH = Path("registries/provenance/execution-provenance-policy.v1.json")
FIXTURE_PATH = Path("tests/fixtures/provenance/execution-lineages.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v2.json")
IDENTITY_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:019ffbeb-56fb-7745-8720-61ac3f7877d6"
COUNT_DERIVATION_METHOD = "reconciliation-aggregation"

SCHEMA_PATHS = {
    "policy": Path("schemas/json/execution-provenance-policy.schema.json"),
    "attempt": Path("schemas/json/physical-attempt-evidence-v2.schema.json"),
    "observation": Path("schemas/json/terminal-observation-content-v2.schema.json"),
    "disposition": Path("schemas/json/logical-execution-disposition.schema.json"),
    "lineage_set": Path("schemas/json/execution-lineage-set.schema.json"),
}

TERMINAL_RESPONSE_OUTCOMES = {
    "compile-rejection",
    "match",
    "no-match",
    "target-error",
    "unsupported",
}
TERMINAL_PROCESS_OUTCOMES = {
    "target-crash",
    "target-resource-limit",
    "target-timeout",
}
RETRY_REASON_BY_OUTCOME = {
    "adapter-process-failure": "adapter-process-failure",
    "environment-realization-failure": "environment-realization-failure",
    "inconclusive-attribution": "inconclusive-attribution",
    "interrupted-uncommitted": "interrupted-target-invocation",
    "lost-unattributed-response": "lost-unattributed-response",
    "malformed-adapter-response": "malformed-adapter-response",
    "network-failure": "network-before-target",
    "storage-publication-failure": "storage-publication-failure",
    "supervisor-failure": "worker-supervisor-failure",
}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def policy_revision(policy: dict[str, Any]) -> str:
    return _sha({key: value for key, value in policy.items() if key != "policy_revision_sha256"})


def result_signature(outcome_class: str, semantic_result: dict[str, Any]) -> dict[str, str]:
    return {
        "algorithm": "rfc8785-sha256-v1",
        "basis": "outcome-class-and-semantic-result",
        "sha256": _sha({"outcome_class": outcome_class, "semantic_result": semantic_result}),
    }


def attempt_set_sha256(physical_run_ids: list[str]) -> str:
    return _sha(physical_run_ids)


def lineage_set_sha256(record: dict[str, Any]) -> str:
    return _sha({key: value for key, value in record.items() if key != "lineage_set_sha256"})


def observation_content_id(root: Path, record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "observation_content_id"}
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / IDENTITY_PROFILE_PATH)),
        namespace="observation-content",
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": "terminal-observation-content-v2", "content_sha256": _sha(body)},
    )
    return str(result["content_id"])


def _instant(value: str, path: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        fail("invalid-attempt-time", str(error), path)
    if parsed.tzinfo is None:
        fail("unqualified-attempt-time", "attempt timestamps require an offset", path)
    return parsed


def _validate_artifact_reference(reference: dict[str, Any], path: str) -> None:
    relative = reference["relative_path"]
    if "\\" in relative or relative.startswith("/") or ".." in relative.split("/"):
        fail("unsafe-evidence-reference", "evidence references require a repository-neutral relative path", path)


def validate_policy(root: Path, policy: dict[str, Any]) -> dict[str, int]:
    validate_instance(policy, load_strict(root / SCHEMA_PATHS["policy"]), source=POLICY_PATH.as_posix())
    if policy["policy_revision_sha256"] != policy_revision(policy):
        fail("execution-policy-digest-mismatch", "execution provenance policy digest differs")
    historical_paths = [item["schema_path"] for item in policy["compatibility"]["historical_contracts"]]
    if historical_paths != sorted(historical_paths) or len(historical_paths) != len(set(historical_paths)):
        fail("invalid-historical-contract-order", "historical contracts must be unique and sorted")
    for contract in policy["compatibility"]["historical_contracts"]:
        source = root / contract["schema_path"]
        if hashlib.sha256(source.read_bytes()).hexdigest() != contract["schema_sha256"]:
            fail("historical-schema-mutation", f"historical contract changed: {contract['schema_path']}")
        schema = load_strict(source)
        if schema["properties"]["schema_version"]["const"] != contract["schema_version"]:
            fail("historical-schema-version-mismatch", f"historical version differs: {contract['schema_path']}")
    retry_reasons = [rule["reason_code"] for rule in policy["retry_rules"]]
    repeat_reasons = [rule["reason_code"] for rule in policy["repeat_rules"]]
    if retry_reasons != sorted(retry_reasons) or len(retry_reasons) != len(set(retry_reasons)):
        fail("invalid-retry-rule-order", "retry rules must be unique and sorted")
    if repeat_reasons != sorted(repeat_reasons) or len(repeat_reasons) != len(set(repeat_reasons)):
        fail("invalid-repeat-rule-order", "repeat rules must be unique and sorted")
    if set(retry_reasons) != set(RETRY_REASON_BY_OUTCOME.values()):
        fail("incomplete-retry-policy", "every inconclusive outcome requires exactly one disposition rule")
    return {
        "historical_execution_contracts": len(historical_paths),
        "retry_rules": len(retry_reasons),
        "repeat_rules": len(repeat_reasons),
    }


def _validate_terminality(attempt: dict[str, Any], path: str) -> None:
    terminality = attempt["terminality"]
    disposition = terminality["disposition"]
    outcome = terminality["outcome_class"]
    attribution = terminality["fault_attribution"]
    protocol = terminality["protocol_status"]
    process = terminality["target_process_status"]
    evidence = attribution["evidence_reference"]
    if evidence is not None:
        _validate_artifact_reference(evidence, f"{path}.terminality.fault_attribution.evidence_reference")
    for index, reference in enumerate(attempt["physical_telemetry_references"]):
        _validate_artifact_reference(reference, f"{path}.physical_telemetry_references[{index}]")
    intermittence_source = attempt["expected_intermittence"]["source_reference"]
    if intermittence_source is not None:
        _validate_artifact_reference(intermittence_source, f"{path}.expected_intermittence.source_reference")
    if disposition == "inconclusive-attempt":
        if outcome not in RETRY_REASON_BY_OUTCOME:
            fail("invalid-inconclusive-outcome", "inconclusive attempt uses a terminal outcome class", path)
        if attribution["target_attributable"]:
            fail("inconclusive-target-attribution", "inconclusive attempts cannot claim target behavior", path)
        return
    if outcome in RETRY_REASON_BY_OUTCOME:
        fail("invalid-terminal-outcome", "terminal attempt uses an inconclusive outcome class", path)
    if not attribution["target_attributable"] or attribution["attribution_layer"] != "target":
        fail("non-target-terminal-observation", "terminal scientific evidence must be target-attributable", path)
    expected = result_signature(outcome, terminality["semantic_result"])
    if terminality["scientific_result_signature"] != expected:
        fail("result-signature-mismatch", "terminal result signature differs", path)
    if outcome in TERMINAL_RESPONSE_OUTCOMES:
        if (
            not terminality["protocol_valid"]
            or not process["target_started"]
            or protocol != {
                "last_checkpoint": "target-response-complete",
                "state": "valid",
            }
        ):
            fail("invalid-terminal-response", "response outcomes require a complete valid target response", path)
    elif outcome in TERMINAL_PROCESS_OUTCOMES:
        if (
            terminality["protocol_valid"]
            or protocol["state"] != "missing"
            or protocol["last_checkpoint"] != "target-invocation-started"
            or not process["target_started"]
            or evidence is None
        ):
            fail(
                "unattributed-process-symptom",
                "crash, timeout, and resource outcomes require bounded target-layer attribution",
                path,
            )
    else:
        fail("unknown-terminal-outcome", f"unsupported terminal outcome {outcome!r}", path)


def _validate_attempt_sequence(
    root: Path,
    attempts: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    disposition: dict[str, Any],
    policy: dict[str, Any],
    path: str,
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


def validate_lineage_set(root: Path, record: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, int]:
    active_policy = policy or load_strict(root / POLICY_PATH)
    validate_policy(root, active_policy)
    validate_instance(record, load_strict(root / SCHEMA_PATHS["lineage_set"]), source=FIXTURE_PATH.as_posix())
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
        _validate_attempt_sequence(root, lineage["attempts"], lineage["observations"], disposition, active_policy, path)
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
    return expected_counts


def _h(namespace: str, number: int) -> str:
    return f"rcid:v1:{namespace}:h:jcs-sha256-v1:{number:064x}"


def _u(namespace: str, number: int) -> str:
    return f"rcid:v1:{namespace}:u7:019ffdee-0000-7000-8000-{number:012x}"


def _reference(category: str, number: int) -> dict[str, Any]:
    digest = f"{number:064x}"
    return {"category": category, "relative_path": f"{category}/sha256/{digest}.json", "sha256": digest, "size_bytes": 1}


def _context(policy_sha: str, logical_number: int, environment_number: int = 1) -> dict[str, Any]:
    return {
        "adapter_release_id": _u("adapter-release", 1),
        "adapter_release_manifest_id": _h("adapter-release-manifest", 1),
        "applicability_coordinate_id": _h("applicability-coordinate", logical_number),
        "campaign_id": _u("campaign", 1),
        "campaign_manifest_id": _h("campaign-manifest", 1),
        "control_plane_revision_sha256": f"{2:064x}",
        "environment_fingerprint_id": _h("environment-fingerprint", environment_number),
        "environment_realization_id": _u("environment-realization", environment_number),
        "execution_policy_revision_sha256": policy_sha,
        "execution_shard_id": _h("shard", logical_number),
        "harness_revision_sha256": f"{3:064x}",
        "partition_id": None,
        "profile_revision_id": _h("profile-revision", 1),
        "protocol_revision_id": _h("adapter-protocol-revision", 1),
        "target_release_revision_id": _h("release-revision", 1),
        "vector_revision_id": _h("vector-revision", logical_number),
        "work_unit_id": _h("shard", logical_number + 100),
    }


def _attempt(
    policy_sha: str,
    logical_number: int,
    global_number: int,
    ordinal: int,
    *,
    outcome: str,
    terminal: bool,
    purpose: str = "initial",
    predecessor: str | None = None,
    retry_reason: str | None = None,
    repeat_reason: str | None = None,
    predecessor_observation: str | None = None,
    semantic_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    physical_id = _u("physical-run", global_number)
    observation_id = _u("observation", global_number) if terminal else None
    reset_by_reason = {
        "interrupted-target-invocation": "target-process",
        "malformed-adapter-response": "adapter-process",
        "qualification-repeat": "target-process",
    }
    reset_scope = reset_by_reason.get(retry_reason or repeat_reason or "", "none")
    response_terminal = outcome in TERMINAL_RESPONSE_OUTCOMES
    process_terminal = outcome in TERMINAL_PROCESS_OUTCOMES
    target_started = terminal or outcome in {"interrupted-uncommitted", "malformed-adapter-response"}
    attribution_layer = "target" if terminal else ("protocol" if outcome == "malformed-adapter-response" else "supervisor")
    evidence_required = process_terminal or not terminal
    result = semantic_result if terminal else None
    signature = result_signature(outcome, result) if result is not None else None
    retry = None
    repeat = None
    if retry_reason is not None:
        retry = {
            "authorization_kind": "automatic",
            "policy_rule": retry_reason,
            "policy_revision_sha256": policy_sha,
            "reason_code": retry_reason,
        }
    if repeat_reason is not None:
        repeat = {
            "authorization_kind": "qualification-specific",
            "policy_rule": repeat_reason,
            "policy_revision_sha256": policy_sha,
            "reason_code": repeat_reason,
            "terminal_predecessor_observation_id": predecessor_observation,
        }
    checkpoint_sha = f"{1000 + global_number:064x}"
    evidence_reference = _reference("fault-attribution", global_number) if evidence_required else None
    return {
        "attempt_ordinal": ordinal,
        "attempt_purpose": purpose,
        "checkpoint_context": {
            "controller_session_id": f"reference-session-{logical_number}",
            "predecessor_checkpoint_sha256": None if ordinal == 1 else f"{1000 + global_number - 1:064x}",
            "recovery_action": "start" if ordinal == 1 else ("retry" if retry else "repeat"),
            "start_checkpoint_sha256": checkpoint_sha,
            "start_state": "running",
        },
        "ended_at": f"2026-09-06T12:{global_number:02d}:01Z",
        "execution_context": _context(policy_sha, logical_number),
        "expected_intermittence": {
            "declared": repeat_reason == "qualification-repeat",
            "source_reference": _reference("repeat-authorization", global_number) if repeat_reason == "qualification-repeat" else None,
        },
        "logical_execution_id": _h("logical-execution", logical_number),
        "physical_run_id": physical_id,
        "physical_telemetry_references": [_reference("physical-telemetry", global_number)],
        "predecessor_physical_run_id": predecessor,
        "repeat": repeat,
        "reset": {
            "evidence_references": [] if reset_scope == "none" else [_reference("reset-evidence", global_number)],
            "reason_code": "initial-state" if ordinal == 1 else (retry_reason or repeat_reason),
            "scope": reset_scope,
        },
        "resource_budget": {
            "cpu_time_ms": 500,
            "memory_bytes": 67108864,
            "process_count": 4,
            "stderr_bytes": 65536,
            "stdout_bytes": 65536,
            "wall_time_ms": 1000,
        },
        "retry": retry,
        "schema_version": "physical-attempt-evidence.v2",
        "started_at": f"2026-09-06T12:{global_number:02d}:00Z",
        "terminality": {
            "disposition": "terminal-scientific-observation" if terminal else "inconclusive-attempt",
            "fault_attribution": {
                "attribution_layer": attribution_layer,
                "evidence_reference": evidence_reference,
                "reason_code": "bounded-target-evidence" if terminal else outcome,
                "target_attributable": terminal,
            },
            "observation_complete": terminal,
            "outcome_class": outcome,
            "produced_observation_id": observation_id,
            "protocol_status": {
                "last_checkpoint": "target-response-complete" if response_terminal else ("target-invocation-started" if target_started else "target-not-started"),
                "state": "valid" if response_terminal else ("malformed" if outcome == "malformed-adapter-response" else "missing"),
            },
            "protocol_valid": response_terminal,
            "scientific_result_signature": signature,
            "semantic_result": result,
            "target_process_status": {
                "exit_code": 0 if response_terminal else None,
                "resource_limit": "memory" if outcome == "target-resource-limit" else None,
                "signal": "SIGSEGV" if outcome == "target-crash" else None,
                "target_started": target_started,
                "timeout_source": "target-boundary" if outcome == "target-timeout" else None,
            },
        },
    }


def _observation(root: Path, attempts: list[dict[str, Any]], attempt: dict[str, Any]) -> dict[str, Any]:
    terminality = attempt["terminality"]
    prefix = [item["physical_run_id"] for item in attempts[: attempt["attempt_ordinal"]]]
    record = {
        "attempt_set_reference": {"attempt_set_sha256": attempt_set_sha256(prefix), "attempts_total": len(prefix)},
        "campaign_manifest_id": attempt["execution_context"]["campaign_manifest_id"],
        "derivation_revision_ids": [],
        "fault_attribution": terminality["fault_attribution"],
        "logical_execution_id": attempt["logical_execution_id"],
        "observation_complete": True,
        "observation_content_id": "",
        "observation_id": terminality["produced_observation_id"],
        "outcome_class": terminality["outcome_class"],
        "physical_telemetry_references": attempt["physical_telemetry_references"],
        "protocol_valid": terminality["protocol_valid"],
        "result_signature": terminality["scientific_result_signature"],
        "schema_version": "terminal-observation-content.v2",
        "semantic_result": terminality["semantic_result"],
        "terminal_attempt_id": attempt["physical_run_id"],
    }
    record["observation_content_id"] = observation_content_id(root, record)
    return record


def _lineage(root: Path, attempts: list[dict[str, Any]], *, exhausted: bool = False) -> dict[str, Any]:
    observations = [_observation(root, attempts, attempt) for attempt in attempts if attempt["terminality"]["disposition"] == "terminal-scientific-observation"]
    terminal_attempts = [attempt for attempt in attempts if attempt["terminality"]["disposition"] == "terminal-scientific-observation"]
    grouped: dict[str, list[str]] = defaultdict(list)
    for observation in observations:
        grouped[observation["result_signature"]["sha256"]].append(observation["observation_id"])
    first_terminal = terminal_attempts[0] if terminal_attempts else None
    disposition = {
        "attempt_set_sha256": attempt_set_sha256([item["physical_run_id"] for item in attempts]),
        "attempts_total": len(attempts),
        "distinct_terminal_result_signature_count": len(grouped),
        "inconclusive_attempt_count": len(attempts) - len(terminal_attempts),
        "last_attempt_id": attempts[-1]["physical_run_id"],
        "logical_execution_id": attempts[0]["logical_execution_id"],
        "observation_ids": sorted(item["observation_id"] for item in observations),
        "recovered_attempt_count": sum(item["attempt_purpose"] in {"recovery-retry", "recovery-validation"} for item in attempts),
        "repeat_measurement_attempt_count": sum(item["repeat"] is not None for item in attempts),
        "retry_attempt_count": sum(item["retry"] is not None for item in attempts),
        "retry_budget_exhausted": exhausted,
        "satisfaction_attempt_id": None if first_terminal is None else first_terminal["physical_run_id"],
        "satisfaction_observation_id": None if first_terminal is None else first_terminal["terminality"]["produced_observation_id"],
        "schema_version": "logical-execution-disposition.v1",
        "status": "satisfied" if first_terminal else "unresolved",
        "terminal_attempt_count": len(terminal_attempts),
        "terminal_result_signatures": [
            {"observation_count": len(ids), "observation_ids": sorted(ids), "sha256": signature}
            for signature, ids in sorted(grouped.items())
        ],
        "unresolved_reason": None if first_terminal else ("retry-budget-exhausted" if exhausted else "retry-not-attempted"),
    }
    return {
        "attempts": attempts,
        "disposition": disposition,
        "logical_execution_id": attempts[0]["logical_execution_id"],
        "observations": observations,
    }


def build_reference_fixture(root: Path, policy: dict[str, Any]) -> dict[str, Any]:
    revision = policy["policy_revision_sha256"]
    ordinary = [_attempt(revision, 1, 1, 1, outcome="match", terminal=True, semantic_result={"match": True, "spans": [[0, 1]]})]
    interrupted_first = _attempt(revision, 2, 2, 1, outcome="interrupted-uncommitted", terminal=False)
    recovery = [
        interrupted_first,
        _attempt(
            revision,
            2,
            3,
            2,
            outcome="compile-rejection",
            terminal=True,
            purpose="recovery-retry",
            predecessor=interrupted_first["physical_run_id"],
            retry_reason="interrupted-target-invocation",
            semantic_result={"compile_status": "rejected", "error_code": "E_PATTERN"},
        ),
    ]
    crash = [_attempt(revision, 3, 4, 1, outcome="target-crash", terminal=True, semantic_result={"signal": "SIGSEGV"})]
    malformed_first = _attempt(revision, 4, 5, 1, outcome="malformed-adapter-response", terminal=False)
    exhausted = [
        malformed_first,
        _attempt(
            revision,
            4,
            6,
            2,
            outcome="malformed-adapter-response",
            terminal=False,
            purpose="automatic-retry",
            predecessor=malformed_first["physical_run_id"],
            retry_reason="malformed-adapter-response",
        ),
    ]
    first_terminal = _attempt(revision, 5, 7, 1, outcome="no-match", terminal=True, semantic_result={"match": False})
    repeated = [
        first_terminal,
        _attempt(
            revision,
            5,
            8,
            2,
            outcome="match",
            terminal=True,
            purpose="qualification-repeat",
            predecessor=first_terminal["physical_run_id"],
            repeat_reason="qualification-repeat",
            predecessor_observation=first_terminal["terminality"]["produced_observation_id"],
            semantic_result={"match": True, "spans": [[0, 1]]},
        ),
    ]
    lineages = [
        _lineage(root, ordinary),
        _lineage(root, recovery),
        _lineage(root, crash),
        _lineage(root, exhausted, exhausted=True),
        _lineage(root, repeated),
    ]
    lineages.sort(key=lambda item: item["logical_execution_id"])
    counts = Counter({"logical_execution_count": len(lineages)})
    for lineage in lineages:
        disposition = lineage["disposition"]
        counts.update(
            physical_attempt_count=len(lineage["attempts"]),
            inconclusive_attempt_count=disposition["inconclusive_attempt_count"],
            recovered_attempt_count=disposition["recovered_attempt_count"],
            repeat_measurement_attempt_count=disposition["repeat_measurement_attempt_count"],
            retry_attempt_count=disposition["retry_attempt_count"],
            terminal_attempt_count=disposition["terminal_attempt_count"],
            terminal_observation_count=len(lineage["observations"]),
        )
    record = {
        "campaign_manifest_id": _h("campaign-manifest", 1),
        "count_derivation_revision_id": next(
            item["derivation_revision_id"]
            for item in load_strict(root / "registries/provenance/generated-assertion-derivations.v1.json")["derivations"]
            if item["method_key"] == COUNT_DERIVATION_METHOD
        ),
        "counts": {key: counts[key] for key in policy["reporting_populations"]},
        "execution_policy_revision_sha256": revision,
        "lineage_set_sha256": "",
        "lineages": lineages,
        "schema_version": "execution-lineage-set.v1",
    }
    record["lineage_set_sha256"] = lineage_set_sha256(record)
    return record


def verify_repository_execution_provenance(root: Path) -> dict[str, int]:
    policy = load_strict(root / POLICY_PATH)
    result = validate_policy(root, policy)
    fixture = load_strict(root / FIXTURE_PATH)
    expected = build_reference_fixture(root, policy)
    if canonical_bytes(fixture) != canonical_bytes(expected):
        fail("execution-lineage-fixture-drift", "tracked reference lineage differs from deterministic rebuild")
    counts = validate_lineage_set(root, fixture, policy)
    return {**result, **counts}


def materialize_repository_execution_provenance(root: Path) -> dict[str, int]:
    policy = load_strict(root / POLICY_PATH)
    policy["policy_revision_sha256"] = policy_revision(policy)
    fixture = build_reference_fixture(root, policy)
    if canonical_bytes(fixture) != canonical_bytes(build_reference_fixture(root, policy)):
        fail("nondeterministic-lineage-generation", "reference lineage generation changed between runs")
    for relative, value in ((POLICY_PATH, policy), (FIXTURE_PATH, fixture)):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(dump_pretty(value), encoding="utf-8", newline="\n")
        os.replace(temporary, path)
        if load_strict(path) != value:
            fail("lineage-write-verification-failed", f"read-after-write differs for {relative.as_posix()}")
    return verify_repository_execution_provenance(root)
