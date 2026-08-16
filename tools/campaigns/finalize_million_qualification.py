#!/usr/bin/env python3
"""Reconcile 64 published partitions and publish the final 1M manifest."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
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

from regex_conformance_scale.evidence_pack_v2 import (
    PACK_MANIFEST_PREFIX,
    verify_pack_structure,
)
from regex_conformance_scale.million_compiler import (
    build_partition_plans,
    compile_million_scale_plan,
)
from regex_conformance_scale.r2_publication import (
    EvidencePackPublisher,
    PublicationItem,
    PublicationReceiptLedger,
    R2Configuration,
    R2HttpTransport,
    million_partition_receipt_key,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance


SOFT_STOP_BYTES = 8_000_000_000
HARD_CAP_BYTES = 10_000_000_000
CANARY_BYTES = 461
READ_REQUEST_LIMIT = 10_000


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
        raise RuntimeError("million execution report read-back differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipts-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()

    configuration = R2Configuration.from_environment()
    compiled = compile_million_scale_plan(ROOT)
    master = compiled.plan
    partitions = build_partition_plans(ROOT, compiled)
    receipt_paths = sorted(arguments.receipts_root.rglob("partition-receipt.json"))
    if len(receipt_paths) != 64:
        raise RuntimeError("final reconciliation requires exactly 64 receipts")
    receipts = [load_strict(path) for path in receipt_paths]
    receipt_schema = load_strict(
        ROOT / "schemas/json/million-scale-partition-publication-receipt.schema.json"
    )
    pack_manifest_schema = load_strict(
        ROOT / "schemas/json/evidence-pack-v2-manifest.schema.json"
    )
    for path, receipt in zip(receipt_paths, receipts, strict=True):
        validate_instance(receipt, receipt_schema, source=str(path))
    receipts.sort(key=lambda item: item["partition_index"])
    if [item["partition_index"] for item in receipts] != list(range(64)):
        raise RuntimeError("partition receipt indexes are not closed")
    for partition, receipt in zip(partitions, receipts, strict=True):
        if (
            receipt["campaign_manifest_id"] != partition["campaign_manifest_id"]
            or receipt["parent_campaign_manifest_id"] != master["campaign_manifest_id"]
            or receipt["logical_execution_count"]
            != partition["denominator"]["included_count"]
        ):
            raise RuntimeError("partition receipt differs from the deterministic plan")

    transport = R2HttpTransport(configuration)
    pack_manifests: list[dict[str, object]] = []
    class_b_verification = 0
    coordinate_receipt_bytes = 0
    for receipt in receipts:
        coordinate_encoded = canonical_bytes(receipt) + b"\n"
        coordinate_receipt_bytes += len(coordinate_encoded)
        coordinate = transport.get_exact(
            million_partition_receipt_key(
                receipt["parent_campaign_manifest_id"], receipt["partition_index"]
            )
        )
        class_b_verification += 1
        if class_b_verification > READ_REQUEST_LIMIT:
            raise RuntimeError("final verification request budget exceeded")
        if coordinate.data != coordinate_encoded:
            raise RuntimeError("published partition coordinate receipt differs")
        fetched = transport.get_exact(receipt["manifest_key"])
        class_b_verification += 1
        if class_b_verification > READ_REQUEST_LIMIT:
            raise RuntimeError("final verification request budget exceeded")
        if hashlib.sha256(fetched.data).hexdigest() != receipt["manifest_sha256"]:
            raise RuntimeError("published pack manifest hash differs")
        manifest = loads_strict(fetched.data.decode("utf-8"))
        validate_instance(
            manifest,
            pack_manifest_schema,
            source=f"published partition {receipt['partition_index']} pack manifest",
        )
        if manifest["pack_digest_sha256"] != receipt["pack_digest_sha256"]:
            raise RuntimeError("published pack digest differs")
        pack_manifests.append(manifest)

    unique_objects: dict[str, tuple[str, int]] = {}
    for manifest in pack_manifests:
        for descriptor in manifest["objects"]:
            value = (descriptor["key"], descriptor["stored_size_bytes"])
            previous = unique_objects.setdefault(descriptor["stored_sha256"], value)
            if previous != value:
                raise RuntimeError("pack object identity conflicts across partitions")
    object_bytes: dict[str, bytes] = {}
    for digest, (key, size_bytes) in sorted(unique_objects.items()):
        fetched = transport.get_exact(key)
        class_b_verification += 1
        if class_b_verification > READ_REQUEST_LIMIT:
            raise RuntimeError("final verification request budget exceeded")
        if len(fetched.data) != size_bytes or hashlib.sha256(fetched.data).hexdigest() != digest:
            raise RuntimeError("published pack object bytes differ")
        object_bytes[digest] = fetched.data
    for manifest in pack_manifests:
        subset = {
            item["stored_sha256"]: object_bytes[item["stored_sha256"]]
            for item in manifest["objects"]
        }
        verify_pack_structure(manifest, subset)

    logical_count = sum(item["logical_execution_count"] for item in receipts)
    attempt_count = sum(item["physical_attempt_count"] for item in receipts)
    result_shards = sum(len(item["shards"]) for item in partitions)
    infrastructure_attempts = attempt_count - logical_count
    upper_bound = (
        CANARY_BYTES
        + sum(item["retained_bytes"] for item in receipts)
        + coordinate_receipt_bytes
    )
    unique_campaign_bytes = sum(len(value) for value in object_bytes.values()) + sum(
        len(canonical_bytes(item) + b"\n") for item in pack_manifests
    ) + coordinate_receipt_bytes
    aggregate_body = {
        "accepted_observation_count": logical_count,
        "attempt_count": attempt_count,
        "campaign_manifest_id": master["campaign_manifest_id"],
        "capacity": {
            "canary_bytes": CANARY_BYTES,
            "hard_cap_bytes": HARD_CAP_BYTES,
            "projected_upper_bound_bytes": upper_bound,
            "soft_stop_bytes": SOFT_STOP_BYTES,
            "unique_campaign_bytes": unique_campaign_bytes,
        },
        "infrastructure_failure_attempt_count": infrastructure_attempts,
        "logical_execution_count": logical_count,
        "normal_list_requests": 0,
        "partition_receipts": receipts,
        "result_shard_count": result_shards,
        "schema_version": "million-scale-evidence-pack-aggregate-manifest.v1",
    }
    if logical_count != 1_000_000 or upper_bound >= SOFT_STOP_BYTES:
        raise RuntimeError("million aggregate fails denominator or capacity admission")
    aggregate_bytes = canonical_bytes(aggregate_body) + b"\n"
    aggregate_sha = hashlib.sha256(aggregate_bytes).hexdigest()
    aggregate_key = f"{PACK_MANIFEST_PREFIX}/{aggregate_sha}.json"
    projected_total = upper_bound + len(aggregate_bytes)
    if projected_total >= SOFT_STOP_BYTES or projected_total > HARD_CAP_BYTES:
        raise RuntimeError("final aggregate would cross campaign capacity admission")
    state_root = arguments.state_root.expanduser().resolve(strict=False)
    state_root.mkdir(parents=True, exist_ok=True)
    with PublicationReceiptLedger(state_root / "aggregate-publication.sqlite") as ledger:
        aggregate_publication = EvidencePackPublisher(
            transport,
            ledger,
            class_a_request_limit=2,
            class_b_request_limit=2,
        ).publish(
            [
                PublicationItem(
                    key=aggregate_key,
                    data=aggregate_bytes,
                    evidence_class="manifests_integrity",
                    manifest=True,
                )
            ]
        )
    report = {
        "accepted_observation_count": logical_count,
        "aggregate_manifest_key": aggregate_key,
        "aggregate_manifest_sha256": aggregate_sha,
        "attempt_count": attempt_count,
        "campaign_manifest_id": master["campaign_manifest_id"],
        "capacity": {
            **aggregate_body["capacity"],
            "projected_upper_bound_bytes": projected_total,
            "unique_campaign_bytes": unique_campaign_bytes + len(aggregate_bytes),
        },
        "class_a_requests": sum(item["class_a_requests"] for item in receipts)
        + len(receipts)
        + aggregate_publication["class_a_requests"],
        "class_b_requests": sum(item["class_b_requests"] for item in receipts)
        + len(receipts) * 2
        + class_b_verification
        + aggregate_publication["class_b_requests"],
        "infrastructure_failure_attempt_count": infrastructure_attempts,
        "logical_execution_count": logical_count,
        "object_count": len(unique_objects) + len(pack_manifests) + len(receipts) + 1,
        "pack_manifest_count": len(pack_manifests),
        "partition_count": len(partitions),
        "reconciliation": "exact",
        "result_shard_count": result_shards,
        "schema_version": "million-scale-execution-report.v1",
        "verification": {
            "duplicate_logical_completion": False,
            "manifest_last": True,
            "normal_list_requests": 0,
            "pack_structures": len(pack_manifests),
            "partition_indexes": "0-63-exact",
            "physical_attempt_distinction": attempt_count >= logical_count,
            "source_reconstruction_certified": all(
                item["verification"]["exact_reconstruction"] for item in receipts
            ),
        },
    }
    validate_instance(
        report,
        load_strict(ROOT / "schemas/json/million-scale-execution-report.schema.json"),
        source="million scale execution report",
    )
    _write_atomic(arguments.report, report)
    sys.stdout.buffer.write(canonical_bytes(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
