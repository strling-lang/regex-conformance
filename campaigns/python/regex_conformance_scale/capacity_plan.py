"""Deterministic capacity, cost, and publication plan for a future 1M campaign."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785


class MillionScaleCapacityPlanError(ValueError):
    """Raised when a capacity plan does not reconcile with its measured basis."""


_SOURCE_PATHS = (
    "campaigns/compiled/100k-qualification.v1.json",
    "reports/scale/100k-execution.json",
    "reports/scale/100k-warehouse-reconciliation.json",
    "reports/scale/cache-disk-pressure-qualification.json",
    "campaigns/python/regex_conformance_scale/capacity_plan.py",
    "schemas/json/million-scale-capacity-plan.schema.json",
    "tools/campaigns/compile_million_scale_capacity_plan.py",
)


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise MillionScaleCapacityPlanError(f"{path} is not a JSON object")
    return value


def _source_bindings(root: Path) -> list[dict[str, str]]:
    return [
        {"path": path, "sha256": _digest((root / path).read_bytes())}
        for path in _SOURCE_PATHS
    ]


def _assert_p19_basis(root: Path) -> None:
    execution = _load(root / "reports/scale/100k-execution.json")
    expected_execution = {
        "accepted_observation_count": 100_000,
        "attempt_count": 100_500,
        "infrastructure_failure_attempt_count": 500,
        "interruption_count": 3,
        "logical_execution_count": 100_000,
        "reconciliation": "exact",
        "result_shard_count": 402,
        "trust_class": "trusted_executioner",
    }
    for key, value in expected_execution.items():
        if execution.get(key) != value:
            raise MillionScaleCapacityPlanError(
                f"P19 execution basis {key!r} changed from {value!r}"
            )

    warehouse = _load(root / "reports/scale/100k-warehouse-reconciliation.json")
    counts = warehouse.get("reconciliation", {}).get("counts")
    if counts != {
        "campaigns": 1,
        "interruptions": 3,
        "logical_executions": 100_000,
        "physical_attempts": 100_500,
        "result_segments": 404,
        "selected_observations": 100_000,
        "shards": 402,
    }:
        raise MillionScaleCapacityPlanError("P19 warehouse counts changed")
    invariants = warehouse.get("reconciliation", {}).get("invariants", {})
    if not invariants or not all(invariants.values()):
        raise MillionScaleCapacityPlanError("P19 warehouse basis is not fully reconciled")

    cache = _load(root / "reports/scale/cache-disk-pressure-qualification.json")
    if cache.get("summary", {}).get("qualification_outcome") != "passed":
        raise MillionScaleCapacityPlanError("P19 cache qualification is not passed")


def build_million_scale_capacity_plan(root: Path) -> dict[str, Any]:
    """Build the deterministic P20-T01 planning report from tracked P19 evidence."""

    _assert_p19_basis(root)
    profiles = [
        {
            "logical_execution_count": 230_780,
            "result_shard_count": 924,
            "selection_key": "mysql-regex",
        },
        {
            "logical_execution_count": 115_380,
            "result_shard_count": 462,
            "selection_key": "pcre2-dfa",
        },
        {
            "logical_execution_count": 192_310,
            "result_shard_count": 770,
            "selection_key": "pcre2-ordinary",
        },
        {
            "logical_execution_count": 461_530,
            "result_shard_count": 1_847,
            "selection_key": "python-re",
        },
    ]
    body: dict[str, Any] = {
        "acceptance_gates": {
            "p20_t02_must_remain_planned": True,
            "program_owner_configuration_confirmation_required": True,
            "publication_integration_must_be_implemented_and_verified": True,
            "research_and_operator_handoff_required": True,
            "stop_before_execution": True,
        },
        "classification": {
            "canonical_authority": False,
            "credentials_established": False,
            "docker_authorized": False,
            "external_evidence_mutated": False,
            "million_scale_execution_authorized": False,
            "normative_authority": False,
            "planning_only": True,
            "production_publication_performed": False,
            "semantic_authority": False,
        },
        "cost_envelope": {
            "billing_assumptions": {
                "class_a_usd_per_million_requests": "4.50",
                "class_b_usd_per_million_requests": "0.36",
                "free_tier_credit_assumed": False,
                "standard_storage_usd_per_gb_month": "0.015",
            },
            "hard_monthly_upper_micro_usd": {
                "class_a_operations": 45_000,
                "class_b_operations": 3_600,
                "first_month_total": 198_600,
                "storage": 150_000,
            },
            "planned_monthly_micro_usd": {
                "class_a_operations": 36_131,
                "class_b_operations": 2_891,
                "first_month_total_with_conservative_storage": 141_065,
                "storage_at_conservative_bytes": 102_043,
                "storage_at_expected_bytes": 58_029,
            },
            "storage_billing_unit": "decimal-gb-month",
        },
        "execution_capacity": {
            "compute": {
                "default_local_worker_concurrency": 4,
                "hard_worker_concurrency_ceiling": 8,
                "host_logical_cpu_reserve": 4,
                "telemetry_required_before_increase": True,
            },
            "deployment_split": {
                "hosted_execution_is_optional": True,
                "hosted_logical_execution_count": 200_000,
                "hosted_maximum_concurrency": 2,
                "local_logical_execution_count": 800_000,
                "protected_revision_only": True,
            },
            "disk": {
                "admission_store_capacity_bytes": 138_000_000_000,
                "analytical_cache_hard_bytes": 10_000_000_000,
                "build_execution_scratch_hard_bytes": 12_000_000_000,
                "environment_cache_hard_bytes": 70_000_000_000,
                "environment_cache_soft_bytes": 60_000_000_000,
                "protected_free_space_floor_bytes": 40_000_000_000,
                "protected_spool_hard_bytes": 6_000_000_000,
                "protected_spool_soft_bytes": 4_000_000_000,
            },
            "memory": {
                "campaign_working_set_upper_bytes": 34_359_738_368,
                "controller_and_provider_upper_bytes": 8_589_934_592,
                "minimum_available_bytes": 42_949_672_960,
                "protected_reserve_bytes": 8_589_934_592,
                "worker_upper_bytes": 6_442_450_944,
            },
            "runtime": {
                "calendar_linear_extrapolation_hours": "130.300",
                "expected_elapsed_hours_maximum": 72,
                "expected_elapsed_hours_minimum": 48,
                "hard_pause_and_replan_hours": 168,
                "measured_active_linear_extrapolation_hours": "101.521",
                "proposed_range_is_assumption": True,
            },
        },
        "p19_measured_basis": {
            "artifact_bytes": {
                "evidence": 317_157_279,
                "logical_segments": 69_698_118,
                "total_campaign_root": 387_483_004,
                "warehouse": 225_497_088,
            },
            "attempts": {
                "infrastructure_failure_attempts": 500,
                "logical_executions_with_one_attempt": 99_500,
                "logical_executions_with_two_attempts": 500,
                "physical_attempts": 100_500,
            },
            "elapsed": {
                "active_session_seconds": "36547.529",
                "calendar_seconds": "46908.031",
                "commit_window_seconds": "33043.717",
                "result_segment_elapsed_seconds": "16622.049",
            },
            "identities": {
                "campaign_manifest_id": "rcid:v1:campaign-manifest:h:jcs-sha256-v1:3a2df1d804fa11b7c6e30af6995bb88a5574ca8c89d5a32a9436a4590fbcc9a8",
                "evidence_manifest_id": "rcid:v1:evidence-manifest:h:jcs-sha256-v1:1572476aa1b968530356d3a310ab78eb267a3d775e3f10d760ab76e600b7cb34",
                "evidence_manifest_sha256": "a2d8d1c460d7822bc2212df41d41842e02202961caad7bc17ca1b68204ae07fa",
                "warehouse_reconciliation_digest": "fd7579971e05169953b98e2ff7606583cbb9960235b29cb82287204b089640cc",
            },
            "object_counts": {
                "attempt_only_segments": 2,
                "logical_segments": 402,
                "result_segments": 402,
                "scale_result_segment_files": 404,
            },
            "throughput_logical_executions_per_second": {
                "active_session": "2.736",
                "calendar": "2.132",
                "commit_window": "3.026",
                "target_segment_worker_equivalent": "6.016",
            },
        },
        "publication_plan": {
            "configuration_contract": {
                "account_token_type": "account-api-token",
                "bucket_access": "object-read-write-specific-bucket",
                "bucket_private": True,
                "github_repository_secrets": [
                    "STRLING_R2_ACCESS_KEY_ID",
                    "STRLING_R2_SECRET_ACCESS_KEY",
                ],
                "github_repository_variables": [
                    "STRLING_R2_ACCOUNT_ID",
                    "STRLING_R2_BUCKET_NAME",
                    "STRLING_R2_ENDPOINT",
                    "STRLING_R2_REGION",
                ],
                "local_secret_injection": "os-credential-store-to-process-environment",
                "public_access_enabled": False,
                "region": "auto",
                "secret_values_permitted_in_repository": False,
            },
            "integrity_and_recovery": {
                "conditional_put_if_none_match": "*",
                "content_addressed_object_keys": True,
                "durable_local_publication_journal": True,
                "etag_is_scientific_identity": False,
                "final_manifest_published_last": True,
                "get_and_sha256_verify_each_new_object": True,
                "list_required_in_normal_path": False,
                "no_duplicate_logical_credit": True,
                "resume_from_verified_receipts": True,
            },
            "object_budget": {
                "control_objects": 3,
                "expected_attempt_only_segments": 20,
                "expected_total_objects": 8_029,
                "hard_attempt_only_segment_ceiling": 200,
                "hard_total_object_ceiling": 8_209,
                "logical_segment_objects": 4_003,
                "result_segment_objects": 4_003,
            },
            "provider": {
                "api": "s3-compatible",
                "name": "cloudflare-r2",
                "standard_storage_class": "STANDARD",
            },
            "request_budget": {
                "class_a_expected": 8_029,
                "class_a_hard_ceiling": 10_000,
                "class_b_expected": 8_029,
                "class_b_hard_ceiling": 10_000,
                "normal_list_requests": 0,
                "repeated_full_bucket_scans_permitted": False,
            },
            "storage_budget": {
                "compression_credit_assumed": False,
                "conservative_remote_bytes": 6_802_830_955,
                "expected_local_evidence_logical_warehouse_bytes": 6_123_524_850,
                "expected_remote_bytes": 3_868_553_970,
                "hard_remote_bytes": 10_000_000_000,
                "soft_stop_remote_bytes": 8_000_000_000,
                "warehouse_publication_permitted": False,
            },
            "upload_strategy": {
                "content_md5_on_put": True,
                "maximum_measured_result_object_bytes": 873_889,
                "multipart_threshold_bytes": 104_857_600,
                "pause_before_unplanned_multipart": True,
                "single_part_put": True,
            },
        },
        "research_sources": [
            {
                "claim": "S3 endpoint, region auto, conditional operations, checksums and Standard storage support",
                "retrieved_on": "2026-08-15",
                "title": "Cloudflare R2 S3 API compatibility",
                "url": "https://developers.cloudflare.com/r2/api/s3/api/",
            },
            {
                "claim": "bucket-scoped Object Read and Write account credentials",
                "retrieved_on": "2026-08-15",
                "title": "Cloudflare R2 API tokens",
                "url": "https://developers.cloudflare.com/r2/api/tokens/",
            },
            {
                "claim": "strong read-after-write and listing consistency",
                "retrieved_on": "2026-08-15",
                "title": "Cloudflare R2 consistency model",
                "url": "https://developers.cloudflare.com/r2/reference/consistency/",
            },
            {
                "claim": "single-part and multipart size thresholds",
                "retrieved_on": "2026-08-15",
                "title": "Cloudflare R2 upload objects",
                "url": "https://developers.cloudflare.com/r2/objects/upload-objects/",
            },
            {
                "claim": "Standard storage and request pricing",
                "retrieved_on": "2026-08-15",
                "title": "Cloudflare R2 pricing",
                "url": "https://developers.cloudflare.com/r2/pricing/",
            },
            {
                "claim": "encrypted GitHub Actions secrets and explicit workflow mapping",
                "retrieved_on": "2026-08-15",
                "title": "GitHub Actions secrets",
                "url": "https://docs.github.com/en/actions/concepts/security/secrets",
            },
            {
                "claim": "non-sensitive GitHub Actions configuration variables",
                "retrieved_on": "2026-08-15",
                "title": "GitHub Actions variables",
                "url": "https://docs.github.com/en/actions/concepts/workflows-and-actions/variables",
            },
        ],
        "schema_version": "million-scale-capacity-plan.v1",
        "source_bindings": _source_bindings(root),
        "workload_plan": {
            "attempt_policy": {
                "expected_physical_attempts": 1_005_000,
                "hard_pause_physical_attempts": 1_050_000,
                "maximum_attempts_per_logical_execution": 3,
                "planning_upper_physical_attempts": 1_020_000,
            },
            "logical_execution_count": 1_000_000,
            "maximum_result_shard_size": 250,
            "profiles": profiles,
            "result_shard_count": 4_003,
        },
    }
    body["plan_digest_sha256"] = _digest(rfc8785.dumps(body))
    return body


def verify_million_scale_capacity_plan(root: Path, report: dict[str, Any]) -> None:
    """Fail closed unless the report is internally exact and source-bound."""

    digest_input = deepcopy(report)
    claimed_digest = digest_input.pop("plan_digest_sha256", None)
    if claimed_digest != _digest(rfc8785.dumps(digest_input)):
        raise MillionScaleCapacityPlanError("capacity plan digest differs")
    if report != build_million_scale_capacity_plan(root):
        raise MillionScaleCapacityPlanError("capacity plan differs from deterministic rebuild")

    workload = report["workload_plan"]
    profiles = workload["profiles"]
    if sum(item["logical_execution_count"] for item in profiles) != 1_000_000:
        raise MillionScaleCapacityPlanError("profile denominator is not 1,000,000")
    if sum(item["result_shard_count"] for item in profiles) != 4_003:
        raise MillionScaleCapacityPlanError("profile shards do not total 4,003")
    if any(
        (item["logical_execution_count"] + 249) // 250
        != item["result_shard_count"]
        for item in profiles
    ):
        raise MillionScaleCapacityPlanError("profile shard count exceeds size contract")

    publication = report["publication_plan"]
    storage = publication["storage_budget"]
    if not (
        storage["expected_remote_bytes"]
        < storage["conservative_remote_bytes"]
        < storage["soft_stop_remote_bytes"]
        < storage["hard_remote_bytes"]
        == 10_000_000_000
    ):
        raise MillionScaleCapacityPlanError("remote storage guardrails are not ordered")
    attempts = workload["attempt_policy"]
    if not (
        1_000_000
        <= attempts["expected_physical_attempts"]
        <= attempts["planning_upper_physical_attempts"]
        <= attempts["hard_pause_physical_attempts"]
    ):
        raise MillionScaleCapacityPlanError("physical attempt ceilings are not ordered")
    if publication["request_budget"]["normal_list_requests"] != 0:
        raise MillionScaleCapacityPlanError("normal publication must not list the bucket")
    if report["classification"]["million_scale_execution_authorized"]:
        raise MillionScaleCapacityPlanError("planning report cannot authorize execution")
