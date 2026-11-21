"""Compile the exact offline PCRE2 assignment for a separate execution decision."""

import re
from pathlib import Path

from .applicability import _content_id
from .errors import fail
from .execution_provenance_v3 import SCHEMA_PATHS, successor_policy
from .jsonio import load_strict
from .pcre2_production_adjudication import _pin, request_semantics
from .pcre2_qualification import build_plan
from .production_campaign_design import ADAPTER_PATH, PROFILE_PATH
from .production_oracle import digest


def compile_proposal(
    root: Path, plan: dict, applicability: dict, preflight: dict, *,
    source_sha: str, envelope_sha: str, certification_root: str,
) -> dict:
    if not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (source_sha, envelope_sha)) or (
        source_sha == envelope_sha or not re.fullmatch(r"[0-9a-f]{64}", certification_root)
    ):
        fail("pcre2-proposal-source-identity", "proposal needs exact source, envelope and certificate root")
    _pin(plan, "plan_digest_sha256", plan["plan_digest_sha256"], "pcre2-proposal-plan")
    _pin(applicability, "report_digest_sha256", plan["source_digests"]["applicability"], "pcre2-proposal-applicability")
    _pin(preflight, "preflight_digest_sha256", plan["source_digests"]["preflight"], "pcre2-proposal-preflight")
    qualification = build_plan(root)
    scope = applicability["profile_scope"]
    adapter = load_strict(root / ADAPTER_PATH)
    policy = successor_policy(root)
    if (
        plan["schema_version"] != "pcre2-production-comparison-plan.v2"
        or plan["execution_policy_revision_sha256"] != policy["policy_revision_sha256"]
        or plan["adapter_manifest_id"] != adapter["adapter_release_manifest_id"]
        or scope["environment_fingerprint_id"] != plan["environment_fingerprint_id"]
        or scope["qualification_sha256"] is None
    ):
        fail("pcre2-proposal-contract", "proposal requires successor policy and the exact scoped qualification")
    release = next(row for row in load_strict(root / PROFILE_PATH)["releases"] if row["release_id"] == scope["release_id"])
    release_identity = {"registered_release": release, "verified_source_artifacts": qualification["source_artifacts"]}
    release_revision = _content_id(root, "release-revision", "qualified-pcre2-release-v1", release_identity)
    transport = {row["vector_revision_id"]: row["request_preview"] for row in preflight["request_previews"]}
    assignments = []
    for row in plan["comparisons"]:
        coord = row["coordinate"]
        vector = coord["vector_revision_id"]
        preview = transport[vector]
        if digest(preview) != row["request_preview_sha256"] or (
            digest(request_semantics(preview)) != row["request_semantic_sha256"]
        ):
            fail("pcre2-proposal-transport", "assignment preview differs from the reviewed request", vector)
        limits = preview["limits"]
        assignments.append({
            "vector_revision_id": vector, "semantic_requirement_id": coord["semantic_requirement_id"],
            "operation_id": coord["operation_id"], "operation": row["operation"],
            "stimulus_sha256": coord["stimulus_sha256"], "applicability_coordinate_id": row["applicability_evaluation_id"],
            "profile_revision_id": plan["profile_revision_id"],
            "environment_fingerprint_id": plan["environment_fingerprint_id"],
            "adapter_release_manifest_id": plan["adapter_manifest_id"],
            "adapter_release_id": adapter["identity"]["adapter_release"],
            "protocol_revision_id": adapter["identity"]["protocol_revision"],
            "target_release_id": scope["release_id"], "target_release_revision_id": release_revision,
            "harness_revision_sha256": digest({"source": source_sha, "adapter_source": adapter["identity"]["source_digest"]}),
            "control_plane_revision_sha256": digest({"source": source_sha, "policy": policy["policy_revision_sha256"]}),
            "request_preview_sha256": row["request_preview_sha256"],
            "request_semantic_sha256": row["request_semantic_sha256"], "request_preview": preview,
            "oracle_class": row["oracle_class"], "oracle_binding_id": row["oracle_binding_id"],
            "oracle_ref": row["oracle_ref"], "comparison": row["comparison"],
            "resource_budget": {
                "wall_time_ms": limits["wall_time_ms"], "cpu_time_ms": limits["wall_time_ms"],
                "memory_bytes": 268_435_456, "process_count": 1,
                "stdout_bytes": 65_536, "stderr_bytes": limits["maximum_diagnostic_bytes"],
            },
        })
    if len(assignments) != 16 or len({row["vector_revision_id"] for row in assignments}) != 16:
        fail("pcre2-proposal-population", "assignment must cover all 16 distinct coordinates")
    manifest_body = {
        "schema_version": "pcre2-production-campaign-proposal.v1",
        "classification": "offline-proposal-not-execution-authority",
        "source_sha": source_sha, "protected_envelope_sha": envelope_sha, "local_certification_root": certification_root,
        "comparison_plan_digest_sha256": plan["plan_digest_sha256"],
        "execution_policy_revision_sha256": policy["policy_revision_sha256"],
        "assignment_population_sha256": digest(assignments), "release_identity": release_identity,
        "worker": {
            "trust_class": "trusted_executioner", "os": "Ubuntu 24.04", "architecture": "x86-64",
            "qualification_sha256": scope["qualification_sha256"], "scope": scope,
            "pinned_publisher_fingerprint": qualification["publisher_fingerprint"],
            "environment_resource_limits": qualification["resource_limits"],
            "production_realizations": 1, "process_tree_containment": True, "network_during_execution": False,
        },
        "execution_caps": {
            "logical_executions": 16, "physical_attempts": 16, "automatic_retries": 0, "automatic_repeats": 0,
            "concurrency": 1, "target_wall_time_total_ms": sum(row["resource_budget"]["wall_time_ms"] for row in assignments),
            "local_evidence_bytes": 16_777_216, "remote_writes": 0,
        },
        "recovery": {
            "terminal_attempts": "verify and reuse committed evidence only",
            "inconclusive_attempts": "preserve physical evidence and stop processing the affected coordinate",
            "retry_or_repeat": "requires a separately admitted amendment under the bound lineage policy",
        },
        "evidence": {
            "pack_version": "evidence-pack.v3", "lineage_schema": SCHEMA_PATHS["lineage_set"].as_posix(),
            "attempt_schema": SCHEMA_PATHS["attempt"].as_posix(), "observation_schema": SCHEMA_PATHS["observation"].as_posix(),
            "retain": ["native-request-and-response-frames", "attempt-context-and-telemetry", "lineage-and-counts",
                       "oracle-and-applicability-references", "inconclusive-attempts", "terminal-observation-content"],
            "release_storage_soft_stop_bytes": 8_000_000_000, "release_storage_hard_cap_bytes": 10_000_000_000,
            "admission": "independently pin exact production authority, realized environment, lineage, and complete receipt set",
        },
        "execution_authorized": False, "production_credit": 0,
    }
    campaign_id = _content_id(root, "campaign-manifest", "pcre2-production-campaign-proposal-v1", manifest_body)
    rows = []
    for row in assignments:
        body = {"campaign_manifest_id": campaign_id, **row}
        rows.append({**body, "logical_execution_id": _content_id(root, "logical-execution", "pcre2-production-logical-v1", body)})
    proposal = {**manifest_body, "campaign_manifest_id": campaign_id, "logical_assignments": rows}
    return {**proposal, "proposal_digest_sha256": digest(proposal)}
