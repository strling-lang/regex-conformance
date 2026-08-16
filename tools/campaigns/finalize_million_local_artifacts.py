#!/usr/bin/env python3
"""Reconcile all locally staged million-scale Evidence Pack v2 artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns/python",
    ROOT / "matrix/python",
    ROOT / "scheduler/python",
    ROOT / "schemas/tooling/python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.evidence_pack_v2 import verify_pack_structure
from regex_conformance_scale.local_artifacts import (
    descriptors_sha256,
    read_staged_object,
)
from regex_conformance_scale.million_compiler import (
    build_partition_plans,
    compile_million_scale_plan,
)
from regex_conformance_scale.r2_publication import PublicationItem
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance


PARTITION_COUNT = 64
CANARY_BYTES = 461
PUBLICATION_CONTROL_RESERVE_BYTES = 1_000_000
SOFT_STOP_BYTES = 8_000_000_000
HARD_CAP_BYTES = 10_000_000_000


def _read_canonical(path: Path) -> tuple[dict[str, object], bytes]:
    unresolved = path.expanduser().absolute()
    resolved = unresolved.resolve(strict=True)
    details = resolved.stat()
    if (
        unresolved != resolved
        or unresolved.is_symlink()
        or not stat.S_ISREG(details.st_mode)
        or getattr(details, "st_nlink", 1) != 1
    ):
        raise RuntimeError(f"artifact must be a direct regular file: {path}")
    encoded = resolved.read_bytes()
    try:
        value = loads_strict(encoded.decode("utf-8"))
    except (ConformanceDataError, UnicodeError) as error:
        raise RuntimeError(f"artifact is not strict JSON: {path}") from error
    if not isinstance(value, dict) or canonical_bytes(value) + b"\n" != encoded:
        raise RuntimeError(f"artifact is not canonical JSON: {path}")
    return value, encoded


def _write_atomic(path: Path, value: dict[str, object]) -> None:
    destination = path.expanduser().resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(value) + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("local readiness report read-back differs")


def _manifest(value: bytes, expected_sha256: str) -> dict[str, object]:
    if hashlib.sha256(value).hexdigest() != expected_sha256:
        raise RuntimeError("staged pack manifest identity differs")
    try:
        result = loads_strict(value.decode("utf-8"))
    except (ConformanceDataError, UnicodeError) as error:
        raise RuntimeError("staged pack manifest is not strict JSON") from error
    if not isinstance(result, dict) or canonical_bytes(result) + b"\n" != value:
        raise RuntimeError("staged pack manifest is not canonical JSON")
    validate_instance(
        result,
        load_strict(ROOT / "schemas/json/evidence-pack-v2-manifest.schema.json"),
        source="staged Evidence Pack v2 manifest",
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preparations-root", type=Path, required=True)
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()

    preparation_paths = sorted(
        arguments.preparations_root.expanduser().resolve(strict=True).rglob(
            "partition-preparation.json"
        )
    )
    if len(preparation_paths) != PARTITION_COUNT:
        raise RuntimeError("local reconciliation requires exactly 64 preparations")
    preparation_schema = load_strict(
        ROOT / "schemas/json/million-scale-partition-local-preparation.schema.json"
    )
    execution_schema = load_strict(
        ROOT / "schemas/json/million-scale-partition-execution-report.schema.json"
    )
    preparations: list[dict[str, object]] = []
    executions: list[dict[str, object]] = []
    for path in preparation_paths:
        preparation, _ = _read_canonical(path)
        execution, execution_bytes = _read_canonical(path.with_name("execution-report.json"))
        validate_instance(preparation, preparation_schema, source=str(path))
        validate_instance(execution, execution_schema, source=str(path.with_name("execution-report.json")))
        if hashlib.sha256(execution_bytes).hexdigest() != preparation["execution_report_sha256"]:
            raise RuntimeError("prepared execution report identity differs")
        preparations.append(preparation)
        executions.append(execution)
    preparations.sort(key=lambda item: item["partition_index"])
    executions.sort(key=lambda item: item["partition_index"])
    expected_indexes = list(range(PARTITION_COUNT))
    if [item["partition_index"] for item in preparations] != expected_indexes:
        raise RuntimeError("local preparation indexes are not exactly 0 through 63")
    if [item["partition_index"] for item in executions] != expected_indexes:
        raise RuntimeError("local execution indexes are not exactly 0 through 63")

    compiled = compile_million_scale_plan(ROOT)
    master = compiled.plan
    partitions = build_partition_plans(ROOT, compiled)
    unique_objects: dict[str, bytes] = {}
    for partition, preparation, execution in zip(
        partitions, preparations, executions, strict=True
    ):
        expected = {
            "campaign_manifest_id": partition["campaign_manifest_id"],
            "parent_campaign_manifest_id": master["campaign_manifest_id"],
            "partition_count": PARTITION_COUNT,
            "partition_index": partition["partition_index"],
        }
        if any(
            preparation[key] != value or execution[key] != value
            for key, value in expected.items()
        ):
            raise RuntimeError("local partition identity differs from the plan")
        logical = partition["denominator"]["included_count"]
        if (
            preparation["logical_execution_count"] != logical
            or execution["logical_execution_count"] != logical
            or execution["accepted_observation_count"] != logical
            or preparation["attempt_count"] != execution["attempt_count"]
            or preparation["physical_attempt_count"] != execution["attempt_count"]
            or execution["attempt_count"] - logical
            != execution["infrastructure_failure_attempt_count"]
            or preparation["infrastructure_failure_attempt_count"]
            != execution["infrastructure_failure_attempt_count"]
            or execution["result_shard_count"] != len(partition["shards"])
            or execution["interruption_count"] != len(partition["planned_interruptions"])
            or execution["session_summary"]["forced_interruption"]
            != len(partition["planned_interruptions"])
            or execution["evidence_manifest_reference"]["sha256"]
            != preparation["evidence_manifest_sha256"]
        ):
            raise RuntimeError("local partition execution counts do not reconcile")

        manifest_bytes = read_staged_object(
            arguments.staging_root, preparation["manifest_key"]
        )
        manifest = _manifest(manifest_bytes, preparation["manifest_sha256"])
        if manifest["pack_digest_sha256"] != preparation["pack_digest_sha256"]:
            raise RuntimeError("local pack digest differs from its preparation")
        object_map: dict[str, bytes] = {}
        items: list[PublicationItem] = []
        for descriptor in manifest["objects"]:
            data = read_staged_object(arguments.staging_root, descriptor["key"])
            if (
                len(data) != descriptor["stored_size_bytes"]
                or hashlib.sha256(data).hexdigest() != descriptor["stored_sha256"]
            ):
                raise RuntimeError("staged pack object identity differs")
            previous = unique_objects.setdefault(descriptor["key"], data)
            if previous != data:
                raise RuntimeError("content-addressed object conflicts across partitions")
            object_map[descriptor["stored_sha256"]] = data
            items.append(
                PublicationItem(
                    key=descriptor["key"],
                    data=data,
                    evidence_class=descriptor["evidence_class"],
                )
            )
        previous_manifest = unique_objects.setdefault(preparation["manifest_key"], manifest_bytes)
        if previous_manifest != manifest_bytes:
            raise RuntimeError("pack manifest conflicts across partitions")
        items.append(
            PublicationItem(
                key=preparation["manifest_key"],
                data=manifest_bytes,
                evidence_class="manifests_integrity",
                manifest=True,
            )
        )
        if (
            len(items) != preparation["object_count"]
            or sum(len(item.data) for item in items) != preparation["retained_bytes"]
            or descriptors_sha256(items) != preparation["object_descriptors_sha256"]
        ):
            raise RuntimeError("local preparation object accounting differs")
        verify_pack_structure(manifest, object_map)

    logical_count = sum(item["logical_execution_count"] for item in executions)
    attempt_count = sum(item["attempt_count"] for item in executions)
    infrastructure_count = sum(
        item["infrastructure_failure_attempt_count"] for item in executions
    )
    interruption_count = sum(item["interruption_count"] for item in executions)
    result_shards = sum(item["result_shard_count"] for item in executions)
    sum_pack_bytes = sum(item["retained_bytes"] for item in preparations)
    unique_bytes = sum(len(data) for data in unique_objects.values())
    projected = CANARY_BYTES + sum_pack_bytes + PUBLICATION_CONTROL_RESERVE_BYTES
    if (
        logical_count != 1_000_000
        or attempt_count - logical_count != infrastructure_count
        or interruption_count != 192
        or result_shards != 4_003
        or projected >= SOFT_STOP_BYTES
        or projected > HARD_CAP_BYTES
    ):
        raise RuntimeError("local million-scale readiness admission failed")
    report = {
        "accepted_observation_count": logical_count,
        "attempt_count": attempt_count,
        "campaign_manifest_id": master["campaign_manifest_id"],
        "capacity": {
            "canary_bytes": CANARY_BYTES,
            "hard_cap_bytes": HARD_CAP_BYTES,
            "local_unique_content_bytes": unique_bytes,
            "projected_remote_upper_bound_bytes": projected,
            "publication_control_reserve_bytes": PUBLICATION_CONTROL_RESERVE_BYTES,
            "soft_stop_bytes": SOFT_STOP_BYTES,
            "sum_of_partition_pack_bytes": sum_pack_bytes,
        },
        "cloud_publication_performed": False,
        "cloud_requests": {"class_a": 0, "class_b": 0, "list": 0},
        "content_addressed_object_count": len(unique_objects),
        "deferred_cloud_control_objects": {
            "aggregate_manifest": 1,
            "partition_coordinate_receipts": PARTITION_COUNT,
        },
        "infrastructure_failure_attempt_count": infrastructure_count,
        "interruption_count": interruption_count,
        "logical_execution_count": logical_count,
        "pack_manifest_count": PARTITION_COUNT,
        "partition_count": PARTITION_COUNT,
        "ready_for_cloudflare_integrity_check": True,
        "result_shard_count": result_shards,
        "schema_version": "million-scale-local-readiness-report.v1",
        "verification": {
            "all_planned_interruptions_match": True,
            "capacity_admitted": True,
            "deterministic_partition_plan_matches": True,
            "exact_source_reconstruction": all(
                item["verification"]["exact_reconstruction"] for item in preparations
            ),
            "infrastructure_attempts_non_crediting": True,
            "no_duplicate_logical_completion": True,
            "pack_structures": PARTITION_COUNT,
            "partition_indexes_exact": True,
            "staged_object_identities": True,
        },
    }
    validate_instance(
        report,
        load_strict(
            ROOT / "schemas/json/million-scale-local-readiness-report.schema.json"
        ),
        source="million-scale local readiness report",
    )
    _write_atomic(arguments.report, report)
    sys.stdout.buffer.write(canonical_bytes(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
