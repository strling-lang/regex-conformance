#!/usr/bin/env python3
"""Certify one completed partition and stage its exact pack bytes locally."""

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

from regex_conformance_scale.evidence_pack_v2 import build_evidence_pack, certify_pack
from regex_conformance_scale.factorized_evidence import (
    build_semantic_corpus,
    discover_scale_corpus,
)
from regex_conformance_scale.local_artifacts import stage_publication_items
from regex_conformance_scale.million_compiler import verify_partition_plan
from regex_conformance_scale.r2_publication import publication_items_from_evidence_pack
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance


PARTITION_SOFT_STOP_BYTES = 8_000_000


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
        raise RuntimeError("partition execution report must be a direct regular file")
    encoded = resolved.read_bytes()
    try:
        value = loads_strict(encoded.decode("utf-8"))
    except (ConformanceDataError, UnicodeError) as error:
        raise RuntimeError("partition execution report is not strict JSON") from error
    if not isinstance(value, dict) or canonical_bytes(value) + b"\n" != encoded:
        raise RuntimeError("partition execution report is not canonical JSON")
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
        raise RuntimeError("local partition preparation read-back differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--master-plan",
        type=Path,
        default=ROOT / "campaigns/million/compiled/million-qualification.v1.json",
    )
    parser.add_argument("--partition-plan", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--execution-report", type=Path, required=True)
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--preparation-record", type=Path, required=True)
    arguments = parser.parse_args()

    master = load_strict(arguments.master_plan)
    partition = load_strict(arguments.partition_plan)
    verify_partition_plan(ROOT, master, partition)
    execution, execution_bytes = _read_canonical(arguments.execution_report)
    validate_instance(
        execution,
        load_strict(
            ROOT / "schemas/json/million-scale-partition-execution-report.schema.json"
        ),
        source=str(arguments.execution_report),
    )
    expected = {
        "campaign_manifest_id": partition["campaign_manifest_id"],
        "parent_campaign_manifest_id": partition["parent_campaign_manifest_id"],
        "partition_count": partition["partition_count"],
        "partition_index": partition["partition_index"],
        "logical_execution_count": partition["denominator"]["included_count"],
    }
    if any(execution.get(key) != value for key, value in expected.items()):
        raise RuntimeError("partition execution report differs from the exact plan")

    source = discover_scale_corpus(arguments.campaign_root)
    semantic = build_semantic_corpus(ROOT, source, plan=partition)
    pack = build_evidence_pack(ROOT, source, semantic)
    repeated = build_evidence_pack(ROOT, source, semantic)
    if pack.manifest_bytes != repeated.manifest_bytes or pack.object_map() != repeated.object_map():
        raise RuntimeError("partition Evidence Pack v2 is not deterministic")
    certification = certify_pack(ROOT, source, semantic, pack)
    if pack.retained_bytes >= PARTITION_SOFT_STOP_BYTES:
        raise RuntimeError("partition pack reaches its closed capacity allocation")
    items = publication_items_from_evidence_pack(pack)
    staging = stage_publication_items(arguments.staging_root, items)

    logical = semantic.statistics["logical_execution_count"]
    attempts = semantic.statistics["physical_attempt_count"]
    if (
        logical != execution["logical_execution_count"]
        or attempts != execution["attempt_count"]
        or attempts - logical != execution["infrastructure_failure_attempt_count"]
    ):
        raise RuntimeError("partition semantic and execution counts differ")
    record = {
        "attempt_count": attempts,
        "campaign_manifest_id": partition["campaign_manifest_id"],
        "cloud_publication_performed": False,
        "evidence_manifest_sha256": source.manifest.sha256,
        "execution_report_sha256": hashlib.sha256(execution_bytes).hexdigest(),
        "infrastructure_failure_attempt_count": attempts - logical,
        "logical_execution_count": logical,
        "manifest_key": pack.manifest_key,
        "manifest_sha256": pack.manifest_sha256,
        "object_count": len(items),
        "object_descriptors_sha256": staging.descriptors_sha256,
        "pack_digest_sha256": pack.manifest["pack_digest_sha256"],
        "parent_campaign_manifest_id": partition["parent_campaign_manifest_id"],
        "partition_count": partition["partition_count"],
        "partition_index": partition["partition_index"],
        "physical_attempt_count": attempts,
        "retained_bytes": pack.retained_bytes,
        "schema_version": "million-scale-partition-local-preparation.v1",
        "source_member_count": len(source.members),
        "staging": {
            "created_local_objects": staging.created_objects,
            "reused_local_objects": staging.reused_objects,
            "verified_object_count": staging.verified_objects,
        },
        "verification": {
            "corruption_detected": certification["corruption_injection_detected"],
            "deterministic": True,
            "exact_reconstruction": certification[
                "byte_complete_legacy_reconstruction"
            ],
            "independent_attempts": certification[
                "independent_physical_attempt_count"
            ]
            == attempts,
            "independent_observations": certification[
                "independent_observation_count"
            ]
            == logical,
            "manifest_last": items[-1].manifest,
            "staged_readback": True,
        },
    }
    validate_instance(
        record,
        load_strict(
            ROOT / "schemas/json/million-scale-partition-local-preparation.schema.json"
        ),
        source="million local partition preparation",
    )
    _write_atomic(arguments.preparation_record, record)
    sys.stdout.buffer.write(canonical_bytes(record) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
