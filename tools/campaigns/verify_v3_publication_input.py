#!/usr/bin/env python3
"""Verify an exact Evidence Pack v3 publication input locally."""

from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "campaigns/python", ROOT / "matrix/python", ROOT / "scheduler/python", ROOT / "schemas/tooling/python"):
    sys.path.insert(0, str(source))

from regex_conformance_scale.evidence_pack_v3 import (  # noqa: E402
    HARD_LIMIT_BYTES,
    PACK_MANIFEST_PREFIX,
    PACK_OBJECT_PREFIX,
    SOFT_LIMIT_BYTES,
)
from regex_conformance_schema.errors import fail  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


MANIFEST_SCHEMA = ROOT / "schemas/json/evidence-pack-v3-manifest.schema.json"
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
READ_CHUNK_BYTES = 1024 * 1024


def verify_publication_input(
    pack_root: Path, *, manifest_sha256: str, campaign_manifest_sha256: str,
    already_retained_bytes: int, reserve_bytes: int,
) -> dict:
    """Verify stored bytes using separately supplied commitments and exact keys."""
    for digest in (manifest_sha256, campaign_manifest_sha256):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            fail("v3-publication-digest", "expected a pinned lowercase SHA-256")
    for amount in (already_retained_bytes, reserve_bytes):
        if type(amount) is not int or amount < 0:
            fail("v3-publication-accounting", "retained and reserve bytes must be nonnegative integers")

    path = pack_root / "manifests" / "sha256" / f"{manifest_sha256}.json"
    with path.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES or sha256(raw).hexdigest() != manifest_sha256:
        fail("v3-publication-manifest-integrity", "manifest bytes differ from the committed identity")
    manifest = loads_strict(raw.decode("utf-8"))
    validate_instance(manifest, load_strict(MANIFEST_SCHEMA), source="v3 publication manifest")
    if canonical_bytes(manifest) + b"\n" != raw:
        fail("v3-publication-manifest-integrity", "manifest bytes are not canonical")
    body = dict(manifest)
    pack_digest = body.pop("pack_digest_sha256")
    if sha256(canonical_bytes(body)).hexdigest() != pack_digest:
        fail("v3-publication-manifest-integrity", "internal pack digest differs")
    if manifest["source_binding"]["campaign_manifest_sha256"] != campaign_manifest_sha256:
        fail("v3-publication-campaign", "manifest binds a different campaign")

    objects = {}
    coordinates = set()
    for ordinal, block in enumerate(manifest["blocks"]):
        digest = block["stored_sha256"]
        coordinate = (block["evidence_class"], block["role"], block["lookup_group"])
        if coordinate in coordinates or block["ordinal"] != ordinal:
            fail("v3-publication-block-coordinate", "block order or coordinate is inconsistent")
        coordinates.add(coordinate)
        if block["key"] != f"{PACK_OBJECT_PREFIX}/{digest}.xz":
            fail("v3-publication-object-key", "block key does not address its declared bytes")
        facts = (block["stored_size_bytes"], block["raw_size_bytes"], block["raw_sha256"])
        if objects.setdefault(digest, facts) != facts:
            fail("v3-publication-object-conflict", "descriptors disagree about the same stored object")

    pack_bytes = len(raw) + sum(size for size, _, _ in objects.values())
    upper_bound = already_retained_bytes + pack_bytes + reserve_bytes
    if upper_bound > HARD_LIMIT_BYTES:
        fail("v3-publication-hard-cap", "retained bytes plus reserve exceed the hard cap")
    if upper_bound >= SOFT_LIMIT_BYTES:
        fail("v3-publication-soft-stop", "retained bytes plus reserve reach the operational soft stop")

    for digest, (expected_size, _, _) in sorted(objects.items()):
        path = pack_root / "objects" / "sha256" / f"{digest}.xz"
        hasher = sha256()
        size = 0
        with path.open("rb") as stream:
            while chunk := stream.read(min(READ_CHUNK_BYTES, expected_size - size + 1)):
                size += len(chunk)
                if size > expected_size:
                    fail("v3-publication-object-integrity", "stored object exceeds its committed size", digest)
                hasher.update(chunk)
        if size != expected_size or hasher.hexdigest() != digest:
            fail("v3-publication-object-integrity", "stored object size or digest differs", digest)

    return {
        "scope": "local-stored-byte-verification",
        "campaign_manifest_sha256": campaign_manifest_sha256,
        "manifest_key": f"{PACK_MANIFEST_PREFIX}/{manifest_sha256}.json",
        "manifest_sha256": manifest_sha256,
        "object_count_including_manifest": len(objects) + 1,
        "unique_pack_bytes_including_manifest": pack_bytes,
        "retained_byte_upper_bound_including_reserve": upper_bound,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack_root", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--campaign-manifest-sha256", required=True)
    parser.add_argument("--already-retained-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, required=True)
    arguments = parser.parse_args()
    print(canonical_bytes(verify_publication_input(**vars(arguments))).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
