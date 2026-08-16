#!/usr/bin/env python3
"""Certify and incrementally publish one completed 1M Evidence Pack v2."""

from __future__ import annotations

import argparse
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
    build_evidence_pack,
    certify_pack,
)
from regex_conformance_scale.factorized_evidence import (
    build_semantic_corpus,
    discover_scale_corpus,
)
from regex_conformance_scale.million_compiler import verify_partition_plan
from regex_conformance_scale.r2_publication import (
    EvidencePackPublisher,
    PublicationItem,
    PublicationReceiptLedger,
    R2Configuration,
    R2HttpTransport,
    million_partition_receipt_key,
    publication_items_from_evidence_pack,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance


PARTITION_SOFT_STOP_BYTES = 8_000_000
PARTITION_HARD_CAP_BYTES = 8_000_001
REQUEST_LIMIT = 512


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
        raise RuntimeError("partition publication receipt read-back differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--master-plan",
        type=Path,
        default=ROOT / "campaigns/million/compiled/million-qualification.v1.json",
    )
    parser.add_argument("--partition-plan", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args()

    configuration = R2Configuration.from_environment()
    master = load_strict(arguments.master_plan)
    partition = load_strict(arguments.partition_plan)
    verify_partition_plan(ROOT, master, partition)
    source = discover_scale_corpus(arguments.campaign_root)
    semantic = build_semantic_corpus(ROOT, source, plan=partition)
    pack = build_evidence_pack(ROOT, source, semantic)
    second = build_evidence_pack(ROOT, source, semantic)
    if (
        pack.manifest_bytes != second.manifest_bytes
        or pack.object_map() != second.object_map()
    ):
        raise RuntimeError("partition Evidence Pack v2 is not deterministic")
    certification = certify_pack(ROOT, source, semantic, pack)
    if pack.retained_bytes >= PARTITION_SOFT_STOP_BYTES:
        raise RuntimeError("partition pack reaches its closed capacity allocation")
    items = publication_items_from_evidence_pack(pack)
    state_root = arguments.state_root.expanduser().resolve(strict=False)
    state_root.mkdir(parents=True, exist_ok=True)
    with PublicationReceiptLedger(state_root / "publication.sqlite") as ledger:
        publication = EvidencePackPublisher(
            R2HttpTransport(configuration),
            ledger,
            soft_stop_bytes=PARTITION_SOFT_STOP_BYTES,
            hard_cap_bytes=PARTITION_HARD_CAP_BYTES,
            class_a_request_limit=REQUEST_LIMIT,
            class_b_request_limit=REQUEST_LIMIT,
        ).publish(items)
    manifest_sha = source.manifest.sha256
    receipt = {
        "attempt_count": semantic.statistics["physical_attempt_count"],
        "campaign_manifest_id": partition["campaign_manifest_id"],
        "class_a_requests": publication["class_a_requests"],
        "class_b_requests": publication["class_b_requests"],
        "created_objects": publication["created_objects"],
        "evidence_manifest_sha256": manifest_sha,
        "logical_execution_count": semantic.statistics["logical_execution_count"],
        "manifest_key": pack.manifest_key,
        "manifest_sha256": pack.manifest_sha256,
        "object_count": len(items),
        "pack_digest_sha256": pack.manifest["pack_digest_sha256"],
        "parent_campaign_manifest_id": partition["parent_campaign_manifest_id"],
        "partition_count": partition["partition_count"],
        "partition_index": partition["partition_index"],
        "physical_attempt_count": semantic.statistics["physical_attempt_count"],
        "recovered_existing_objects": publication["recovered_existing_objects"],
        "retained_bytes": pack.retained_bytes,
        "schema_version": "million-scale-partition-publication-receipt.v1",
        "source_member_count": len(source.members),
        "verification": {
            "corruption_detected": certification["corruption_injection_detected"],
            "deterministic": True,
            "exact_reconstruction": certification[
                "byte_complete_legacy_reconstruction"
            ],
            "independent_attempts": certification[
                "independent_physical_attempt_count"
            ]
            == semantic.statistics["physical_attempt_count"],
            "independent_observations": certification[
                "independent_observation_count"
            ]
            == semantic.statistics["observation_count"],
            "list_requests": publication["list_requests"],
        },
    }
    validate_instance(
        receipt,
        load_strict(
            ROOT
            / "schemas/json/million-scale-partition-publication-receipt.schema.json"
        ),
        source="million partition publication receipt",
    )
    receipt_bytes = canonical_bytes(receipt) + b"\n"
    coordinate_key = million_partition_receipt_key(
        partition["parent_campaign_manifest_id"], partition["partition_index"]
    )
    with PublicationReceiptLedger(state_root / "coordinate-receipt.sqlite") as ledger:
        EvidencePackPublisher(
            R2HttpTransport(configuration),
            ledger,
            soft_stop_bytes=PARTITION_SOFT_STOP_BYTES,
            hard_cap_bytes=PARTITION_HARD_CAP_BYTES,
            class_a_request_limit=2,
            class_b_request_limit=2,
        ).publish(
            [
                PublicationItem(
                    key=coordinate_key,
                    data=receipt_bytes,
                    evidence_class="publication_receipt",
                    manifest=True,
                )
            ]
        )
    _write_atomic(arguments.receipt, receipt)
    sys.stdout.buffer.write(canonical_bytes(receipt) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
