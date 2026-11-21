"""Bind PCRE2 oracle comparisons to qualified predicates and admitted terminal evidence."""

from __future__ import annotations

from pathlib import Path

from .adjudication import compare_expected_outcome
from .errors import fail
from .execution_provenance import validate_lineage_set
from .production_campaign_design import PCRE2_OPERATIONS
from .production_oracle import digest


FIELD_VALUES = {"compile_status": frozenset({"accepted", "rejected"}), "match_state": frozenset({"match", "no-match"})}


def _pin(record: dict, field: str, expected: str, code: str) -> None:
    if record.get(field) != expected or digest({k: v for k, v in record.items() if k != field}) != expected:
        fail(code, "artifact digest differs from the independently pinned value")


def compile_comparison_plan(
    handoff: dict, applicability: dict, preflight: dict, *,
    handoff_digest: str, applicability_digest: str, preflight_digest: str,
) -> dict:
    _pin(handoff, "handoff_digest_sha256", handoff_digest, "pcre2-comparison-handoff")
    _pin(applicability, "report_digest_sha256", applicability_digest, "pcre2-comparison-applicability")
    _pin(preflight, "preflight_digest_sha256", preflight_digest, "pcre2-comparison-preflight")
    if (
        applicability["handoff_digest_sha256"] != handoff_digest
        or applicability["manifest_digest_sha256"] != preflight["candidate_manifest_sha256"]
        or applicability["profile_scope"]["release_id"] != handoff["target_release_id"]
    ):
        fail("pcre2-comparison-scope", "verified inputs refer to different profile or candidate populations")
    determinations = {row["coordinate"]["vector_revision_id"]: row for row in applicability["rows"]}
    requests = {row["vector_revision_id"]: row for row in preflight["request_previews"]}
    if len(determinations) != 16 or len(applicability["rows"]) != 16 or len(requests) != 16 or len(preflight["request_previews"]) != 16 or determinations.keys() != requests.keys():
        fail("pcre2-comparison-population", "expected exactly 16 matching applicability and transport rows")
    comparisons = []
    for bound in handoff["comparisons"]:
        coordinate = bound["coordinate"]
        vector = coordinate["vector_revision_id"]
        determination = determinations[vector]
        evaluation = determination["applicability"]
        request = requests[vector]
        operation = PCRE2_OPERATIONS[coordinate["operation_id"]]
        field = "compile_status" if operation == "compile" else "match_state"
        expected = bound["comparison_input"]
        controls = bound["control_vector_revision_ids"]
        if expected["result_type"] == "conventional" and bound["oracle_class"] == "O6":
            if set(expected["value"]) != {field} or expected["value"][field] not in FIELD_VALUES[field] or controls:
                fail("pcre2-comparison-expected-field", "documentation expectation is outside the exact operation field", vector)
            rule = {"kind": "equals", "expected": expected["value"][field]}
        elif expected["result_type"] == "relation" and bound["oracle_class"] == "O4":
            relation = expected["value"]
            if (relation["relation"], relation["field"], set(relation["terminal_values"])) != (
                "distinct-observation-field", field, FIELD_VALUES[field],
            ) or not controls or relation["control_vector_revision_ids"] != controls:
                fail("pcre2-comparison-expected-field", "unsupported relational comparison", vector)
            rule = {"kind": "distinct-from-controls", "controls": controls}
        else:
            fail("pcre2-comparison-oracle-class", "unsupported expectation role for this governed scope", vector)
        if (
            determination["coordinate"] != coordinate or determination["oracle_binding_id"] != bound["oracle_binding_id"]
            or evaluation["profile"]["profile_revision_id"] != applicability["profile_revision_id"]
            or request["semantic_requirement_id"] != coordinate["semantic_requirement_id"]
            or request["request_preview"]["operation"]["name"] != operation
            or request["request_preview"]["adapter_release_manifest_id"] != applicability["profile_scope"]["adapter_manifest_id"]
            or request["request_preview"]["target_release_id"] != handoff["target_release_id"]
        ):
            fail("pcre2-comparison-coordinate", "oracle, transport and evaluated applicability differ", vector)
        comparisons.append({
            "coordinate": coordinate, "applicability_evaluation_id": evaluation["evaluation_id"],
            "applicability_state": evaluation["result"], "oracle_class": bound["oracle_class"],
            "oracle_ref": bound["oracle_ref"], "oracle_binding_id": bound["oracle_binding_id"],
            "terminal_lineage_open_requirement": "native-compile-acceptance" if field == "compile_status" else None,
            "request_preview_sha256": digest(request["request_preview"]), "observation_field": field, "comparison": rule,
        })
    if len(comparisons) != 16 or {row["coordinate"]["vector_revision_id"] for row in comparisons} != determinations.keys():
        fail("pcre2-comparison-population", "adjudication requires one comparison per exact coordinate")
    body = {
        "schema_version": "pcre2-production-comparison-plan.v1", "classification": "comparison-plan-only",
        "source_digests": {"handoff": handoff_digest, "applicability": applicability_digest, "preflight": preflight_digest},
        "profile_revision_id": applicability["profile_revision_id"],
        "environment_fingerprint_id": applicability["profile_scope"]["environment_fingerprint_id"],
        "adapter_manifest_id": applicability["profile_scope"]["adapter_manifest_id"],
        "comparisons": sorted(comparisons, key=lambda row: row["coordinate"]["vector_revision_id"]),
        "execution_authorized": False, "production_credit": 0,
    }
    return {**body, "plan_digest_sha256": digest(body)}


def _compare(field: str, expected: str, actual: str, *, distinct: bool = False) -> str:
    def project(value: str) -> dict:
        return {"outcome_class": field, "semantic_result": {field: value}}

    model = {"kind": "relation", "operator": "not-equals", "value": project(expected)} if distinct else {
        "kind": "exact", "value": project(expected),
    }
    return compare_expected_outcome(model, project(actual))[0]


def compare_production_lineage(
    root: Path, plan: dict, lineage: dict, admission: dict, *, expected_plan_digest: str, expected_admission_digest: str,
) -> dict:
    """Compare approved, integrity-verified evidence without issuing canonical claims."""
    _pin(plan, "plan_digest_sha256", expected_plan_digest, "pcre2-comparison-plan-digest")
    _pin(admission, "admission_digest_sha256", expected_admission_digest, "pcre2-comparison-admission-digest")
    if (
        admission.get("classification") != "authorized-production-evidence-admission"
        or admission.get("comparison_plan_digest_sha256") != expected_plan_digest
        or admission.get("campaign_manifest_id") != lineage["campaign_manifest_id"]
        or admission.get("lineage_set_sha256") != lineage["lineage_set_sha256"]
    ):
        fail("pcre2-comparison-unapproved-lineage", "only the pinned exact production admission can supply observations")
    by_vector = {row["coordinate"]["vector_revision_id"]: row for row in plan["comparisons"]}
    assignments = {row["vector_revision_id"]: row for row in admission["logical_assignments"]}
    if (
        assignments.keys() != by_vector.keys() or len(assignments) != len(admission["logical_assignments"])
        or len({row["logical_execution_id"] for row in assignments.values()}) != len(assignments)
        or any(row["request_preview_sha256"] != by_vector[key]["request_preview_sha256"] for key, row in assignments.items())
    ):
        fail("pcre2-comparison-admission-scope", "the authorized logical assignments must cover this exact plan")
    validate_lineage_set(root, lineage)
    selected_ids = set(admission["admitted_observation_content_ids"])
    if len(selected_ids) != len(admission["admitted_observation_content_ids"]):
        fail("pcre2-comparison-duplicate-admission", "observation admission lists repeated content identities")
    accepted = {}
    realizations = {}
    for entry in lineage["lineages"]:
        attempts = {attempt["physical_run_id"]: attempt for attempt in entry["attempts"]}
        for observation in entry["observations"]:
            identifier = observation["observation_content_id"]
            if identifier not in selected_ids:
                continue
            attempt = attempts[observation["terminal_attempt_id"]]
            context = attempt["execution_context"]
            vector = context["vector_revision_id"]
            row = by_vector.get(vector)
            if (
                row is None or row["applicability_state"] != "applicable"
                or entry["logical_execution_id"] != assignments[vector]["logical_execution_id"]
                or context["applicability_coordinate_id"] != assignments[vector]["applicability_coordinate_id"]
                or context["target_release_revision_id"] != assignments[vector]["target_release_revision_id"]
                or context["profile_revision_id"] != plan["profile_revision_id"]
                or context["environment_fingerprint_id"] != plan["environment_fingerprint_id"]
                or context["adapter_release_manifest_id"] != plan["adapter_manifest_id"]
                or attempt["attempt_purpose"] in {"qualification-repeat", "recovery-validation"}
                or not observation["protocol_valid"]
            ):
                fail("pcre2-comparison-observation-scope", "admitted evidence does not match the exact realized coordinate", identifier)
            field = row["observation_field"]
            value = observation["semantic_result"].get(field)
            outcome = observation["outcome_class"]
            # The v2 lineage has a native compile rejection class, but lacks a compile acceptance class.
            comparable = (field == "match_state" and value == outcome and value in FIELD_VALUES[field]) or (
                field == "compile_status" and value == "rejected" and outcome == "compile-rejection"
            )
            accepted.setdefault(vector, {})[identifier] = value if comparable else None
            realizations.setdefault(vector, set()).add(context["environment_realization_id"])
    if selected_ids != {item for values in accepted.values() for item in values}:
        fail("pcre2-comparison-observation-omission", "admitted observation references are missing from the exact lineage")
    rows = []
    for vector, row in sorted(by_vector.items()):
        rule = row["comparison"]
        controls = rule.get("controls", [])
        participants = {key: accepted.get(key, {}) for key in [vector, *controls]}
        values = {key: {value for value in obs.values() if value is not None} for key, obs in participants.items()}
        if any(len(found) > 1 for found in values.values()):
            state = "conflicting-evidence"
        elif any(not obs for obs in participants.values()):
            state = "unobserved"
        elif (any(not found for found in values.values()) or any(None in obs.values() for obs in participants.values())
              or controls and len(set.union(*(realizations[key] for key in participants))) != 1):
            state = "not-comparable"
        else:
            actual = next(iter(values[vector]))
            expected = [next(iter(values[control])) for control in controls] if controls else [rule["expected"]]
            state = "agreement" if all(_compare(row["observation_field"], value, actual, distinct=bool(controls)) == "agreement" for value in expected) else "disagreement"
        rows.append({"vector_revision_id": vector, "state": state, "oracle_binding_id": row["oracle_binding_id"], "oracle_class": row["oracle_class"],
                     "observation_content_ids": {key: sorted(obs) for key, obs in participants.items()}})
    body = {"classification": "production-comparison-trace", "plan_digest_sha256": expected_plan_digest,
            "admission_digest_sha256": expected_admission_digest, "rows": rows, "issued_claims": 0, "production_credit": 0}
    return {**body, "trace_digest_sha256": digest(body)}
