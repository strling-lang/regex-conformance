"""Independent offline reconciliation of safe million-scale campaign artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance

from .million_compiler import build_partition_plans, compile_million_scale_plan


CANARY_BYTES = 461
SOFT_STOP_BYTES = 8_000_000_000
HARD_CAP_BYTES = 10_000_000_000
PARTITION_COUNT = 64


class MillionReconciliationError(RuntimeError):
    """Safe campaign artifacts do not prove the expected terminal state."""


def _read_canonical_object(path: Path) -> dict[str, Any]:
    unresolved = path.absolute()
    try:
        resolved = unresolved.resolve(strict=True)
    except OSError as error:
        raise MillionReconciliationError(f"required artifact is absent: {path}") from error
    if unresolved != resolved or unresolved.is_symlink() or not resolved.is_file():
        raise MillionReconciliationError(f"artifact must be a direct regular file: {path}")
    encoded = resolved.read_bytes()
    try:
        value = loads_strict(encoded.decode("utf-8"))
    except (ConformanceDataError, UnicodeError, ValueError) as error:
        raise MillionReconciliationError(f"artifact is not strict UTF-8 JSON: {path}") from error
    if not isinstance(value, dict) or canonical_bytes(value) + b"\n" != encoded:
        raise MillionReconciliationError(f"artifact is not a canonical JSON object: {path}")
    return value


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _manifest_key(digest: str) -> str:
    return f"regex-conformance/evidence-pack-v2/manifests/sha256/{digest}.json"


def verify_million_final_artifacts(
    repository_root: Path,
    report_path: Path,
    receipts_root: Path,
) -> dict[str, Any]:
    """Verify a safe final report and all partition artifact handoffs offline."""

    repository = repository_root.resolve(strict=True)
    report = _read_canonical_object(report_path)
    report_schema = load_strict(
        repository / "schemas/json/million-scale-execution-report.schema.json"
    )
    receipt_schema = load_strict(
        repository
        / "schemas/json/million-scale-partition-publication-receipt.schema.json"
    )
    execution_schema = load_strict(
        repository / "schemas/json/million-scale-partition-execution-report.schema.json"
    )
    validate_instance(report, report_schema, source=str(report_path))

    compiled = compile_million_scale_plan(repository)
    master = compiled.plan
    partitions = build_partition_plans(repository, compiled)
    if len(partitions) != PARTITION_COUNT:
        raise MillionReconciliationError("deterministic plan does not contain 64 partitions")
    if report["campaign_manifest_id"] != master["campaign_manifest_id"]:
        raise MillionReconciliationError("final report targets a different campaign manifest")

    unresolved_root = receipts_root.absolute()
    root = unresolved_root.resolve(strict=True)
    if unresolved_root != root or unresolved_root.is_symlink() or not root.is_dir():
        raise MillionReconciliationError("receipt artifact root must be a direct directory")
    receipt_paths = sorted(root.rglob("partition-receipt.json"))
    execution_paths = sorted(root.rglob("execution-report.json"))
    if len(receipt_paths) != PARTITION_COUNT:
        raise MillionReconciliationError("safe artifact set must contain exactly 64 receipts")
    if len(execution_paths) != PARTITION_COUNT:
        raise MillionReconciliationError(
            "safe artifact set must contain exactly 64 execution reports"
        )

    receipts: list[dict[str, Any]] = []
    executions: list[dict[str, Any]] = []
    for receipt_path in receipt_paths:
        try:
            receipt_path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as error:
            raise MillionReconciliationError("partition receipt escapes the artifact root") from error
        receipt = _read_canonical_object(receipt_path)
        execution_path = receipt_path.with_name("execution-report.json")
        execution = _read_canonical_object(execution_path)
        validate_instance(receipt, receipt_schema, source=str(receipt_path))
        validate_instance(execution, execution_schema, source=str(execution_path))
        receipts.append(receipt)
        executions.append(execution)

    receipts.sort(key=lambda item: item["partition_index"])
    executions.sort(key=lambda item: item["partition_index"])
    expected_indexes = list(range(PARTITION_COUNT))
    if [item["partition_index"] for item in receipts] != expected_indexes:
        raise MillionReconciliationError("receipt partition indexes are not exactly 0 through 63")
    if [item["partition_index"] for item in executions] != expected_indexes:
        raise MillionReconciliationError("execution-report partition indexes are not exactly 0 through 63")

    for partition, receipt, execution in zip(
        partitions, receipts, executions, strict=True
    ):
        logical_count = partition["denominator"]["included_count"]
        expected = {
            "campaign_manifest_id": partition["campaign_manifest_id"],
            "parent_campaign_manifest_id": master["campaign_manifest_id"],
            "partition_count": PARTITION_COUNT,
            "partition_index": partition["partition_index"],
        }
        for field, value in expected.items():
            if receipt[field] != value or execution[field] != value:
                raise MillionReconciliationError(
                    f"partition {partition['partition_index']} {field} differs from the plan"
                )
        if receipt["logical_execution_count"] != logical_count:
            raise MillionReconciliationError("receipt logical denominator differs from its partition")
        if execution["logical_execution_count"] != logical_count:
            raise MillionReconciliationError("execution logical denominator differs from its partition")
        if execution["accepted_observation_count"] != logical_count:
            raise MillionReconciliationError("partition has a missing or duplicate credited observation")
        if receipt["attempt_count"] != receipt["physical_attempt_count"]:
            raise MillionReconciliationError("receipt attempt aliases disagree")
        if (
            receipt["created_objects"] + receipt["recovered_existing_objects"]
            != receipt["object_count"]
        ):
            raise MillionReconciliationError("partition publisher object accounting differs")
        if receipt["attempt_count"] != execution["attempt_count"]:
            raise MillionReconciliationError("receipt and execution physical attempts disagree")
        if (
            execution["attempt_count"] - logical_count
            != execution["infrastructure_failure_attempt_count"]
        ):
            raise MillionReconciliationError("infrastructure attempts are not strictly non-crediting")
        if execution["result_shard_count"] != len(partition["shards"]):
            raise MillionReconciliationError("partition result-shard count differs from its plan")
        if execution["evidence_manifest_reference"]["sha256"] != receipt[
            "evidence_manifest_sha256"
        ]:
            raise MillionReconciliationError("execution evidence identity differs from its receipt")
        if receipt["manifest_key"] != _manifest_key(receipt["manifest_sha256"]):
            raise MillionReconciliationError("pack manifest key is not its content identity")
        if execution["interruption_count"] != len(partition["planned_interruptions"]):
            raise MillionReconciliationError("observed interruption count differs from the plan")
        if execution["session_summary"]["forced_interruption"] != len(
            partition["planned_interruptions"]
        ):
            raise MillionReconciliationError("session recovery does not close every interruption")

    logical_count = sum(item["logical_execution_count"] for item in receipts)
    attempt_count = sum(item["attempt_count"] for item in receipts)
    infrastructure_attempts = sum(
        item["infrastructure_failure_attempt_count"] for item in executions
    )
    result_shards = sum(item["result_shard_count"] for item in executions)
    interruption_count = sum(item["interruption_count"] for item in executions)
    if logical_count != master["denominator"]["included_count"]:
        raise MillionReconciliationError("global logical denominator differs from the plan")
    if attempt_count - logical_count != infrastructure_attempts:
        raise MillionReconciliationError("global retry accounting does not reconcile")
    expected_report_counts = {
        "accepted_observation_count": logical_count,
        "attempt_count": attempt_count,
        "infrastructure_failure_attempt_count": infrastructure_attempts,
        "logical_execution_count": logical_count,
        "pack_manifest_count": PARTITION_COUNT,
        "partition_count": PARTITION_COUNT,
        "result_shard_count": result_shards,
    }
    for field, value in expected_report_counts.items():
        if report[field] != value:
            raise MillionReconciliationError(f"final report {field} does not reconcile")

    receipt_bytes = sum(len(canonical_bytes(item) + b"\n") for item in receipts)
    pre_aggregate_upper_bound = (
        CANARY_BYTES + sum(item["retained_bytes"] for item in receipts) + receipt_bytes
    )
    aggregate_size = (
        report["capacity"]["projected_upper_bound_bytes"] - pre_aggregate_upper_bound
    )
    pre_aggregate_unique_bytes = (
        report["capacity"]["unique_campaign_bytes"] - aggregate_size
    )
    if aggregate_size <= 0 or pre_aggregate_unique_bytes <= 0:
        raise MillionReconciliationError("aggregate retained-byte accounting is impossible")
    aggregate_body = {
        "accepted_observation_count": logical_count,
        "attempt_count": attempt_count,
        "campaign_manifest_id": master["campaign_manifest_id"],
        "capacity": {
            "canary_bytes": CANARY_BYTES,
            "hard_cap_bytes": HARD_CAP_BYTES,
            "projected_upper_bound_bytes": pre_aggregate_upper_bound,
            "soft_stop_bytes": SOFT_STOP_BYTES,
            "unique_campaign_bytes": pre_aggregate_unique_bytes,
        },
        "infrastructure_failure_attempt_count": infrastructure_attempts,
        "logical_execution_count": logical_count,
        "normal_list_requests": 0,
        "partition_receipts": receipts,
        "result_shard_count": result_shards,
        "schema_version": "million-scale-evidence-pack-aggregate-manifest.v1",
    }
    aggregate_bytes = canonical_bytes(aggregate_body) + b"\n"
    aggregate_digest = _digest(aggregate_bytes)
    if len(aggregate_bytes) != aggregate_size:
        raise MillionReconciliationError("aggregate manifest byte count does not reconcile")
    if report["aggregate_manifest_sha256"] != aggregate_digest:
        raise MillionReconciliationError("aggregate manifest digest does not reconstruct")
    if report["aggregate_manifest_key"] != _manifest_key(aggregate_digest):
        raise MillionReconciliationError("aggregate manifest key is not its content identity")
    if report["capacity"]["projected_upper_bound_bytes"] >= SOFT_STOP_BYTES:
        raise MillionReconciliationError("retained evidence reaches the operational soft stop")
    if report["capacity"]["projected_upper_bound_bytes"] > HARD_CAP_BYTES:
        raise MillionReconciliationError("retained evidence exceeds the absolute hard cap")

    unique_pack_objects = report["object_count"] - PARTITION_COUNT * 2 - 1
    if unique_pack_objects < 1:
        raise MillionReconciliationError("object accounting cannot contain the published pack set")
    aggregate_class_a = (
        report["class_a_requests"]
        - sum(item["class_a_requests"] for item in receipts)
        - PARTITION_COUNT
    )
    class_b_verification = PARTITION_COUNT * 2 + unique_pack_objects
    aggregate_class_b = (
        report["class_b_requests"]
        - sum(item["class_b_requests"] for item in receipts)
        - PARTITION_COUNT * 2
        - class_b_verification
    )
    if aggregate_class_a not in {1, 2} or aggregate_class_b not in {1, 2}:
        raise MillionReconciliationError("publisher request accounting does not reconcile")

    return {
        "aggregate_manifest_key": report["aggregate_manifest_key"],
        "aggregate_manifest_sha256": aggregate_digest,
        "campaign_manifest_id": master["campaign_manifest_id"],
        "class_a_requests": report["class_a_requests"],
        "class_b_requests": report["class_b_requests"],
        "infrastructure_failure_attempt_count": infrastructure_attempts,
        "interruption_count": interruption_count,
        "logical_execution_count": logical_count,
        "object_count": report["object_count"],
        "physical_attempt_count": attempt_count,
        "projected_upper_bound_bytes": report["capacity"][
            "projected_upper_bound_bytes"
        ],
        "result_shard_count": result_shards,
        "schema_version": "million-safe-artifact-reconciliation.v1",
        "verification": {
            "aggregate_manifest_reconstructed": True,
            "all_planned_interruptions_match": True,
            "capacity_admitted": True,
            "deterministic_partition_plan_matches": True,
            "infrastructure_attempts_non_crediting": True,
            "no_duplicate_logical_completion": True,
            "partition_indexes_exact": True,
            "publisher_requests_reconcile": True,
        },
    }
