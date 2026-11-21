"""Reconcile the planned PCRE2 capability and comparison inputs by coordinate."""

from __future__ import annotations

from pathlib import Path

from .errors import fail
from .pcre2_qualification import build_plan
from .production_oracle import digest, load_pinned_contract, resolve_coordinate


def build_handoff(root: Path, review: dict, *, expected_review_digest: str) -> dict:
    """Produce a scoped comparison inventory without issuing claims or work."""
    body = {key: value for key, value in review.items() if key != "report_digest_sha256"}
    if digest(body) != expected_review_digest or review["report_digest_sha256"] != expected_review_digest:
        fail("pcre2-handoff-review-digest", "oracle review differs from its pinned body digest")
    plan = build_plan(root)
    scope = review["scope"]
    recipe_artifacts = {
        item["name"]: {field: item[field] for field in ("sha256", "size_bytes")}
        for item in plan["source_artifacts"]
    }
    archived = review["archived_release"]
    if (
        scope["profile_id"] != plan["profile_id"] or scope["target_release_id"] != plan["target_release_id"]
        or scope["environment_recipe_revision_id"] != plan["recipe_revision_id"]
        or scope["adapter_manifest_id"] != plan["adapter_manifest_id"]
        or review["source"] is None or review["source"]["sha256"] != plan["source_document"]["sha256"]
        or archived is None or archived["recipe_revision_id"] != plan["recipe_revision_id"]
        or archived["verified_bytes"] != recipe_artifacts
    ):
        fail("pcre2-handoff-profile-scope", "qualification and oracle review refer to different source or runtime scopes")

    rows = {row["coordinate"]["vector_revision_id"]: row for row in review["resolution_rows"]}
    admission_rows = review["admission_review"]["blocked_coordinates"]
    admissions = {row["vector_revision_id"]: row for row in admission_rows}
    if len(rows) != 16 or len(review["resolution_rows"]) != 16 or len(admission_rows) != 16 or rows.keys() != admissions.keys():
        fail("pcre2-handoff-population", "oracle and applicability rows must cover the exact 16 distinct candidates")
    contract = load_pinned_contract(root)
    planned = {(row["field"], row["scientific_id"]): row for row in plan["capability_assertions"]}
    required = set()
    comparisons = []
    for key, row in sorted(rows.items()):
        coordinate = row["coordinate"]
        admission = admissions[key]
        check = resolve_coordinate(root, contract, coordinate, row["oracle_records"], frozen_at=scope["frozen_at"])
        if (
            any(row[name] != value for name, value in check.items())
            or coordinate["profile_id"] != scope["profile_id"] or coordinate["target_release_id"] != scope["target_release_id"]
            or coordinate["campaign_definition_revision_id"] != review["candidate_campaign_revision_id"]
            or admission["semantic_requirement_id"] != coordinate["semantic_requirement_id"]
            or check["resolution_state"] != "oracle-established" or len(check["oracle_records"]) != 1
            or admission["oracle_binding_id"] != check["binding"]["binding_id"]
            or admission["execution_eligible"] or admission["applicability"]["result"] != "unresolved"
        ):
            fail("pcre2-handoff-coordinate", "oracle, plan and applicability do not bind the same unadmitted coordinate", key)
        unresolved = {(item["field"], item["target"]) for item in admission["applicability"]["unresolved_dependencies"]}
        if not unresolved or not unresolved <= planned.keys():
            fail("pcre2-handoff-capability", "qualification plan leaves an uncovered applicability dependency", key)
        required.update(unresolved)

        (record,) = check["oracle_records"]
        expectation = record["expected_result"]
        controls = []
        if expectation["result_type"] == "relation":
            relation = expectation["value"]
            controls = relation["control_vector_revision_ids"]
            if not controls or len(controls) != len(set(controls)) or key in controls or not set(controls) <= rows.keys():
                fail("pcre2-handoff-control-population", "relation controls must be distinct reviewed vectors", key)
            for control in controls:
                other = rows[control]
                (control_oracle,) = other["oracle_records"]
                counterpart = control_oracle["expected_result"]
                if (
                    other["coordinate"]["operation_id"] != coordinate["operation_id"]
                    or counterpart["result_type"] != "relation"
                    or counterpart["value"]["field"] != relation["field"]
                    or counterpart["value"]["terminal_values"] != relation["terminal_values"]
                    or key not in counterpart["value"]["control_vector_revision_ids"]
                ):
                    fail("pcre2-handoff-control-scope", "relation controls must reciprocate the exact same observation field and operation", control)
        comparisons.append({
            "coordinate": coordinate, "oracle_ref": check["binding"]["oracle_refs"][0],
            "oracle_binding_id": check["binding"]["binding_id"], "oracle_class": record["oracle_class"],
            "comparison_input": expectation, "control_vector_revision_ids": controls,
            "applicability_evaluation_id": admission["applicability"]["evaluation_id"],
            "required_qualification_assertions": [planned[item] for item in sorted(unresolved)],
            "missing_inputs": ["governed-realized-profile-and-applicability", "exact-production-assignment",
                               "admissible-terminal-evidence", "production-adjudication-binding"],
            "execution_eligible": False, "claim_eligible": False,
        })
    if required != planned.keys():
        fail("pcre2-handoff-qualification-population", "planned capability assertions differ from the unresolved applicability union")
    handoff = {
        "schema_version": "pcre2-production-adjudication-handoff.v1", "classification": "design-only",
        "source_review_digest_sha256": expected_review_digest, "qualification_plan_digest_sha256": plan["plan_digest_sha256"],
        "campaign_definition_revision_id": review["candidate_campaign_revision_id"],
        "profile_id": scope["profile_id"], "target_release_id": scope["target_release_id"],
        "comparisons": comparisons, "required_capability_assertions": len(required),
        "production_logical_executions": 0, "issued_claims": 0,
    }
    return {**handoff, "handoff_digest_sha256": digest(handoff)}
