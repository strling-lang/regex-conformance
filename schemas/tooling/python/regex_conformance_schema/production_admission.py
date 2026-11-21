"""Evaluate candidate applicability on bounded, provenance-checked capability inputs."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from . import applicability
from .errors import fail
from .jsonio import load_strict
from .production_campaign_design import ADAPTER_PATH, PCRE2_OPERATIONS, PROFILE_PATH, RECIPE_PATH
from .production_oracle import load_pinned_contract


ENVIRONMENT_REPORT = Path("reports/vertical-slice/minimal-environment-certification.json")
ADAPTER_REPORT = Path("reports/vertical-slice/minimal-adapter-certification.json")


def build_admission_review(root: Path, inputs, manifest: dict, design: dict, oracle_report: dict) -> dict:
    """Project certified adapter declarations without treating old runs as current execution."""
    contract = load_pinned_contract(root, applicability.CONTRACT_PATH, applicability.AUTHORITY_PATH)
    profile = next(row for row in load_strict(root / PROFILE_PATH)["profiles"] if row["selection_key"] == "pcre2-ordinary")
    recipe = load_strict(root / RECIPE_PATH)
    adapter = load_strict(root / ADAPTER_PATH)
    environment_record, adapter_record = [
        next(row for row in load_strict(root / path)["results"] if row["selection_key"] == "pcre2-ordinary")
        for path in (ENVIRONMENT_REPORT, ADAPTER_REPORT)
    ]
    for row in (environment_record, adapter_record):
        if (
            row["target_profile_id"] != design["proposed_profile_id"]
            or row["target_release_id"] != design["proposed_release_id"]
            or row["recipe_revision_id"] != design["proposed_environment_recipe_revision_id"]
        ):
            fail("production-profile-coordinate", "historical qualification does not bind the proposed graph")
    if (
        environment_record["environment_fingerprint_id"] != adapter_record["environment_fingerprint_id"]
        or environment_record["verification_digest"] != adapter_record["environment_verification_digest"]
        or adapter_record["adapter_release_manifest_id"] != adapter["adapter_release_manifest_id"]
        or adapter_record["adapter_source_digest"] != adapter["identity"]["source_digest"]
    ):
        fail("production-profile-qualification", "environment and adapter qualification provenance do not reconcile")
    historical = {
        "profile_graph": profile,
        "recipe_revision_id": recipe["recipe_revision_id"],
        "historical_environment_fingerprint_id": environment_record["environment_fingerprint_id"],
        "historical_environment_verification_sha256": environment_record["verification_digest"],
        "adapter_manifest_id": adapter["adapter_release_manifest_id"],
        "adapter_source_sha256": adapter_record["adapter_source_digest"],
        "qualification_report_sha256": {
            path.as_posix(): sha256((root / path).read_bytes()).hexdigest() for path in (ENVIRONMENT_REPORT, ADAPTER_REPORT)
        },
    }
    historical_revision = applicability._content_id(root, "profile-revision", "historical-pcre2-capability-scope-v1", historical)
    spec = next(row for row in contract["field_registry"] if row["field"] == "profile.operation_scientific_ids")
    capabilities = set(adapter["identity"]["capabilities"])
    facts = [
        applicability._finalize_fact(root, {
            "fact_revision_id": applicability._content_id(root, "applicability-rule-set", "certified-adapter-operation-projection-v1", {
                "adapter_manifest_id": adapter["adapter_release_manifest_id"], "operation_id": operation,
            }),
            "field_id": spec["field_id"], "field": spec["field"], "assertion": "member-present",
            "value_type": spec["member_type"], "value": operation,
            "authority_class": "certified-adapter-capability", "authority_state": "admissible",
            "source": {
                "artifact_id": adapter["adapter_release_manifest_id"], "revision_id": adapter["adapter_release_manifest_id"],
                "digest_sha256": design["adapter_manifest_sha256"], "locator": f"{ADAPTER_PATH.as_posix()}#/identity/capabilities/{name}",
            },
            "dependencies": [{"dependency_id": adapter["adapter_release_manifest_id"], "kind": "certified-adapter"}],
        })
        for operation, name in sorted(PCRE2_OPERATIONS.items()) if f"operation-{name}" in capabilities
    ]
    snapshot = applicability._finalize(
        root,
        {
            "schema_version": "profile-capability-fact-snapshot.v1",
            "classification": "frozen-profile-capability-authority", "profile_id": profile["profile_id"],
            "profile_revision_id": historical_revision, "world_assumption": "open", "field_closure_rules": [], "facts": facts,
        },
        namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1",
        id_field="snapshot_id", digest_field="snapshot_digest_sha256",
    )
    stimuli = {row["vector_revision_id"]: row["stimulus"] for row in manifest["vectors"]}
    rows = []
    for oracle in oracle_report["resolution_rows"]:
        coordinate = oracle["coordinate"]
        identifier = coordinate["vector_revision_id"]
        requirement = inputs.requirements[coordinate["semantic_requirement_id"]]
        predicate = stimuli[identifier]["applicability_preconditions"]
        definition = {"predicate_id": applicability._predicate_id(root, predicate), "predicate": predicate}
        result = applicability.evaluate(root, contract, requirement, {
            "requirement_scientific_id": requirement["scientific_id"],
            "feature_scientific_id": requirement["feature_scientific_id"],
            "operation_scientific_ids": requirement["required_operation_scientific_ids"],
            "predicate_id": definition["predicate_id"],
        }, definition, snapshot)
        blockers = ["current-profile-realization-unverified", "exact-campaign-authorization-absent"]
        if result["result"] != "applicable":
            blockers.append("applicability-" + result["result"])
        if oracle["resolution_state"] != "oracle-established":
            blockers.append(oracle["resolution_state"])
        rows.append({
            "vector_revision_id": identifier, "semantic_requirement_id": requirement["scientific_id"],
            "oracle_resolution": oracle["resolution_state"],
            "oracle_binding_id": oracle["binding"]["binding_id"] if oracle["binding"] is not None else None,
            "applicability": result, "execution_eligible": False, "blockers": blockers,
        })
    return {
        "historical_qualification": historical, "historical_capability_snapshot": snapshot,
        "current_production_profile_revision_id": None, "runnable_revision_ids": [],
        "blocked_coordinates": rows,
    }
