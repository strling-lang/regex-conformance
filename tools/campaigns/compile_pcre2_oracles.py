#!/usr/bin/env python3
"""Compile or verify the source-backed PCRE2 oracle review without executing a target."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas/tooling/python"))

from regex_conformance_schema.errors import fail  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict  # noqa: E402
from regex_conformance_schema.pcre2_oracle_review import build_pcre2_oracle_report  # noqa: E402
from regex_conformance_schema.production_vectors import load_vector_compiler_inputs  # noqa: E402


def bounded_read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        fail("production-oracle-input-size", "input exceeds the offline review byte limit", str(path))
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--expected-manifest-digest", required=True)
    parser.add_argument("--expected-preflight-digest", required=True)
    parser.add_argument("--frozen-at", required=True)
    parser.add_argument("--manual", type=Path, help="immutable PCRE2 10.47 pcre2pattern.3 bytes")
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--detached-signature", type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--output", type=Path)
    selection.add_argument("--check", type=Path)
    args = parser.parse_args()
    if (args.source_archive is None) != (args.detached_signature is None):
        parser.error("supply the source archive and detached signature together")
    raw = bounded_read(args.manifest, 16 * 1024 * 1024)
    manifest = loads_strict(raw.decode("utf-8"))
    if canonical_bytes(manifest) + b"\n" != raw:
        fail("production-oracle-manifest-bytes", "candidate manifest is not canonical")
    family_paths = {path.name.removesuffix(".v1.json"): path for path in (ROOT / "vectors/families").glob("*.v1.json")}
    missing = {item["key"] for item in manifest["families"]} - family_paths.keys()
    if missing:
        fail("production-oracle-family-source", "manifest refers to unavailable definitions", ", ".join(sorted(missing)))
    families = [load_strict(family_paths[item["key"]]) for item in manifest["families"]]
    manual = bounded_read(args.manual, 512 * 1024) if args.manual is not None else None
    release = None if args.source_archive is None else (
        bounded_read(args.source_archive, 3_000_000), bounded_read(args.detached_signature, 16384),
    )
    report = build_pcre2_oracle_report(
        ROOT, load_vector_compiler_inputs(ROOT), manifest, families, manual,
        expected_manifest_digest=args.expected_manifest_digest, expected_preflight_digest=args.expected_preflight_digest,
        frozen_at=args.frozen_at,
        release_artifacts=release,
    )
    encoded = canonical_bytes(report) + b"\n"
    if args.output is not None:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    if args.check is not None and bounded_read(args.check, len(encoded)) != encoded:
        fail("production-oracle-report-drift", "review report differs from exact recomputation", str(args.check))
    if args.output is None and args.check is None:
        print(encoded.decode("utf-8"), end="")
    else:
        print(report["report_digest_sha256"])


if __name__ == "__main__":
    main()
