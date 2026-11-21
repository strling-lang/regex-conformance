"""Bind PCRE2 oracle comparisons to qualified predicates and admitted terminal evidence."""

from __future__ import annotations

from pathlib import Path

from .adjudication import compare_expected_outcome
from .errors import fail
from .execution_provenance_v3 import LINEAGE_VERSION, parse_native_frame, successor_policy, validate_lineage_set
from .production_campaign_design import PCRE2_OPERATIONS
from .production_oracle import digest


FIELD_VALUES = {"compile_status": frozenset({"accepted", "rejected"}), "match_state": frozenset({"match", "no-match"})}


def _pin(record: dict, field: str, expected: str, code: str) -> None:
    if record.get(field) != expected or digest({k: v for k, v in record.items() if k != field}) != expected:
        fail(code, "artifact digest differs from the independently pinned value")


def compile_comparison_plan(
    handoff: dict, applicability: dict, preflight: dict, *,
    handoff_digest: str, applicability_digest: str, preflight_digest: str, successor_root: Path | None = None,
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
    if successor_root is not None:
        body["schema_version"] = "pcre2-production-comparison-plan.v2"
        body["execution_lineage_version"] = LINEAGE_VERSION
        body["execution_policy_revision_sha256"] = successor_policy(successor_root)["policy_revision_sha256"]
        body["runtime_facts"] = {
            item["name"]: item["value"] for item in applicability["profile_scope"]["runtime_identity"]["facts"]
        }
        by_vector = {row["coordinate"]["vector_revision_id"]: row for row in comparisons}
        for vector, row in by_vector.items():
            if row["applicability_state"] != "applicable":
                fail("pcre2-comparison-inapplicable", "successor scope requires an applicable coordinate", vector)
            del row["terminal_lineage_open_requirement"]
            preview = requests[vector]["request_preview"]
            row["request_semantic_sha256"] = digest(request_semantics(preview))
            row["operation"] = preview["operation"]
            row["request_profile_id"] = preview["profile_id"]
            row["request_release_id"] = preview["target_release_id"]
            for control_id in row["comparison"].get("controls", []):
                control = by_vector.get(control_id)
                if (
                    vector == control_id or control is None
                    or control["observation_field"] != row["observation_field"]
                    or vector not in control["comparison"].get("controls", [])
                ):
                    fail("pcre2-comparison-missing-reciprocal-control", "O4 requires its exact reciprocal control", vector)
        if (
            sum(row["operation"]["name"] == "compile" for row in comparisons),
            sum(row["oracle_class"] == "O4" for row in comparisons),
        ) != (4, 10):
            fail("pcre2-comparison-partition", "this release scope requires four compile rows and ten O4 bindings")
    return {**body, "plan_digest_sha256": digest(body)}


def request_semantics(request: dict) -> dict:
    return {key: val for key, val in request.items() if key not in {"correlation_id", "trace_reference"}}


def production_trace_reference(physical_run_id: str) -> str:
    return f"pcre2-production:{physical_run_id}"


def _validate_successor_attempt(
    root: Path, plan: dict, assignments: dict, realization: str, attempt: dict, receipt: dict | None,
) -> None:
    identifier = attempt["physical_run_id"]
    logical_id = attempt["logical_execution_id"]
    assignment = assignments.get(logical_id)
    context = attempt["execution_context"]
    if assignment is None or any(context[key] != assignment[key] for key in (
        "campaign_manifest_id", "vector_revision_id", "applicability_coordinate_id",
        "target_release_revision_id", "profile_revision_id", "environment_fingerprint_id",
        "adapter_release_manifest_id", "adapter_release_id",
        "protocol_revision_id", "harness_revision_sha256", "control_plane_revision_sha256",
    )) or context["environment_realization_id"] != realization or attempt["attempt_purpose"] in {
        "qualification-repeat", "recovery-validation",
    }:
        fail("pcre2-comparison-observation-scope", "physical attempt differs from the exact approved assignment", identifier)
    if any(value is None or value > assignment["resource_budget"][key] for key, value in attempt["resource_budget"].items()):
        fail("pcre2-comparison-resource-scope", "physical attempt exceeds its approved resource budget", identifier)
    if receipt is None:
        return
    request = parse_native_frame(receipt["request_frame"], root / "schemas/json/adapter-request.schema.json", identifier)
    response = parse_native_frame(receipt["response_frame"], root / "schemas/json/adapter-response.schema.json", identifier)
    if (
        request["trace_reference"] != production_trace_reference(identifier)
        or request["correlation_id"] != identifier.rsplit(":", 1)[1]
        or digest(request_semantics(request)) != assignment["request_semantic_sha256"]
    ):
        fail("pcre2-comparison-native-request-scope", "exact native request does not belong to this production attempt and reviewed stimulus", identifier)
    if response["status"] == "completed":
        native_facts = response["observation"]["runtime_identity"]["facts"]
        facts = {fact["name"]: fact["value"] for fact in native_facts}
        if len(facts) != len(native_facts) or any(plan["runtime_facts"].get(key) != val for key, val in facts.items()) or (
            not {"engine-version", "library-sha256", "runtime-kind"} <= facts.keys()
        ):
            fail("pcre2-comparison-native-runtime-scope", "response differs from the qualified native runtime", identifier)


def _compare(field: str, expected: str, actual: str, *, distinct: bool = False) -> str:
    def project(value: str) -> dict:
        return {"outcome_class": field, "semantic_result": {field: value}}

    model = {"kind": "relation", "operator": "not-equals", "value": project(expected)} if distinct else {
        "kind": "exact", "value": project(expected),
    }
    return compare_expected_outcome(model, project(actual))[0]


def compare_production_lineage(
    root: Path, plan: dict, lineage: dict, admission: dict, *, expected_plan_digest: str, expected_admission_digest: str,
    native_evidence: dict | None = None, proposal: dict | None = None, expected_proposal_digest: str | None = None,
) -> dict:
    """Compare approved, integrity-verified evidence without issuing canonical claims."""
    _pin(plan, "plan_digest_sha256", expected_plan_digest, "pcre2-comparison-plan-digest")
    _pin(admission, "admission_digest_sha256", expected_admission_digest, "pcre2-comparison-admission-digest")
    if plan.get("schema_version") not in {"pcre2-production-comparison-plan.v1", "pcre2-production-comparison-plan.v2"}:
        fail("pcre2-comparison-plan-version", "an exact versioned comparison plan is required")
    successor = plan.get("schema_version") == "pcre2-production-comparison-plan.v2"
    if successor:
        if proposal is None or expected_proposal_digest is None or native_evidence is None:
            fail("pcre2-comparison-missing-successor-admission", "successor comparisons require independent proposal, admission and native evidence pins")
        _pin(proposal, "proposal_digest_sha256", expected_proposal_digest, "pcre2-comparison-proposal-digest")
        if (
            admission.get("schema_version") != "pcre2-production-evidence-admission.v2"
            or admission.get("proposal_digest_sha256") != expected_proposal_digest
            or proposal.get("comparison_plan_digest_sha256") != expected_plan_digest
            or proposal.get("campaign_manifest_id") != lineage["campaign_manifest_id"]
            or proposal.get("logical_assignments") != admission.get("logical_assignments")
            or lineage.get("schema_version") != LINEAGE_VERSION
            or lineage.get("execution_policy_revision_sha256") != plan.get("execution_policy_revision_sha256")
        ):
            fail("pcre2-comparison-successor-admission", "proposal, lineage and authorized production admission must bind the same scope")
    elif native_evidence is not None or lineage.get("schema_version") != "execution-lineage-set.v1":
        fail("pcre2-comparison-lineage-version", "historical plans have no successor fallback")
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
    validate_lineage_set(root, lineage, native_evidence=native_evidence)
    if successor:
        by_logical_id = {row["logical_execution_id"]: row for row in assignments.values()}
        if admission.get("native_evidence_set_sha256") != digest(native_evidence):
            fail("pcre2-comparison-native-set-digest", "receipt set differs from independently admitted evidence")
        caps = proposal["execution_caps"]
        if lineage["counts"]["physical_attempt_count"] > caps["physical_attempts"] or any(
            lineage["counts"][key] > caps[cap] for key, cap in (
                ("retry_attempt_count", "automatic_retries"),
                ("repeat_measurement_attempt_count", "automatic_repeats"),
            )
        ):
            fail("pcre2-comparison-physical-budget", "lineage exceeds the exact proposal attempt or retry budget")
        for entry in lineage["lineages"]:
            for attempt in entry["attempts"]:
                _validate_successor_attempt(
                    root, plan, by_logical_id, admission.get("environment_realization_id"),
                    attempt, native_evidence.get(attempt["physical_run_id"]),
                )
    selected_ids = set(admission["admitted_observation_content_ids"])
    if len(selected_ids) != len(admission["admitted_observation_content_ids"]):
        fail("pcre2-comparison-duplicate-admission", "observation admission lists repeated content identities")
    accepted = {}
    realizations = {}
    for entry in lineage["lineages"]:
        attempts = {attempt["physical_run_id"]: attempt for attempt in entry["attempts"]}
        terminal_ids = {obs["observation_content_id"] for obs in entry["observations"]}
        if successor and selected_ids & terminal_ids and not terminal_ids <= selected_ids:
            fail("pcre2-comparison-partial-terminal-admission", "a comparison cannot omit competing terminal results", entry["logical_execution_id"])
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
            comparable = (field == "match_state" and value == outcome and value in FIELD_VALUES[field]) or (
                field == "compile_status" and value == "rejected" and outcome == "compile-rejection"
            ) or (
                successor and field == "compile_status" and value == "accepted" and outcome == "compile-acceptance"
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
