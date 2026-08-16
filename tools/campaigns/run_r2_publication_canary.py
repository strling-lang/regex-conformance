#!/usr/bin/env python3
"""Run the smallest stable Evidence Pack v2 publication/recovery canary.

The two immutable objects are intentionally byte-stable across runs.  A repeat
therefore exercises exact-key recovery without adding retained R2 bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.r2_publication import (  # noqa: E402
    EvidencePackPublisher,
    PublicationItem,
    PublicationReceiptLedger,
    R2Configuration,
    R2HttpTransport,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _items() -> list[PublicationItem]:
    raw = _canonical(
        {
            "authority": "non-corpus-publication-canary",
            "decision": "D103",
            "payload": "Evidence Pack v2 exact immutable read-back canary",
            "schema_version": "evidence-pack-v2-r2-canary-object.v1",
        }
    )
    stored = lzma.compress(
        raw, format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, preset=9
    )
    object_digest = hashlib.sha256(stored).hexdigest()
    object_item = PublicationItem(
        key=f"regex-conformance/evidence-pack-v2/canary/objects/sha256/{object_digest}.xz",
        data=stored,
        evidence_class="publication_canary",
    )
    manifest = _canonical(
        {
            "authority": "non-corpus-publication-canary",
            "decision": "D103",
            "object_sha256": object_digest,
            "object_size_bytes": len(stored),
            "schema_version": "evidence-pack-v2-r2-canary-manifest.v1",
        }
    ) + b"\n"
    manifest_digest = hashlib.sha256(manifest).hexdigest()
    return [
        object_item,
        PublicationItem(
            key=f"regex-conformance/evidence-pack-v2/canary/manifests/sha256/{manifest_digest}.json",
            data=manifest,
            evidence_class="publication_canary",
            manifest=True,
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--check-configuration", action="store_true")
    args = parser.parse_args()
    configuration = R2Configuration.from_environment()
    if args.check_configuration:
        print(
            json.dumps(
                {
                    "configuration_names_present": True,
                    "repository": "strling-lang/regex-conformance",
                    "schema_version": "evidence-pack-v2-r2-configuration-check.v1",
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    if args.state_root is None:
        parser.error("--state-root is required unless --check-configuration is used")
    state_root = args.state_root.expanduser().absolute()
    state_root.mkdir(parents=True, exist_ok=True)
    items = _items()

    with PublicationReceiptLedger(state_root / "primary.sqlite") as primary:
        first = EvidencePackPublisher(
            R2HttpTransport(configuration), primary,
            class_a_request_limit=8, class_b_request_limit=8,
        ).publish(items)
        repeated = EvidencePackPublisher(
            R2HttpTransport(configuration), primary,
            class_a_request_limit=8, class_b_request_limit=8,
        ).publish(items)
    with PublicationReceiptLedger(state_root / "recovery.sqlite") as recovery:
        recovered = EvidencePackPublisher(
            R2HttpTransport(configuration), recovery,
            class_a_request_limit=8, class_b_request_limit=8,
        ).publish(items)

    if repeated["skipped_verified_receipts"] != 2:
        raise RuntimeError("publication canary idempotence proof differs")
    if recovered["recovered_existing_objects"] != 2:
        raise RuntimeError("publication canary exact-key recovery proof differs")
    if any(report["list_requests"] != 0 for report in (first, repeated, recovered)):
        raise RuntimeError("publication canary used a forbidden LIST request")
    result = {
        "class_a_requests": first["class_a_requests"] + recovered["class_a_requests"],
        "class_b_requests": first["class_b_requests"] + recovered["class_b_requests"],
        "first_pass_created_objects": first["created_objects"],
        "first_pass_recovered_objects": first["recovered_existing_objects"],
        "idempotent_receipt_skips": repeated["skipped_verified_receipts"],
        "list_requests": 0,
        "manifest_sha256": items[-1].sha256,
        "object_sha256": items[0].sha256,
        "recovery_verified_objects": recovered["recovered_existing_objects"],
        "retained_canary_bytes": sum(len(item.data) for item in items),
        "schema_version": "evidence-pack-v2-r2-canary-result.v1",
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
