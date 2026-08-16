#!/usr/bin/env python3
"""Compile and certify the P20-T01C production Evidence Pack v2 design."""

from __future__ import annotations

import argparse
import os
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

from regex_conformance_scale.evidence_pack_v2 import (  # noqa: E402
    build_certification_report,
    build_evidence_pack,
    certify_pack,
    verify_certification_report,
)
from regex_conformance_scale.factorized_evidence import (  # noqa: E402
    build_semantic_corpus,
    discover_p19_corpus,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


REPORT = ROOT / "reports/scale/evidence-pack-v2-certification.json"
SCHEMA = ROOT / "schemas/json/evidence-pack-v2-certification.schema.json"
MANIFEST_SCHEMA = ROOT / "schemas/json/evidence-pack-v2-manifest.schema.json"


def _validate(report: dict) -> None:
    validate_instance(report, load_strict(SCHEMA), source="P20-T01C Evidence Pack v2 report")
    verify_certification_report(report)


def _write_exact(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError(f"immutable output already exists with different bytes: {path}")
        return
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != data:
        raise RuntimeError(f"read-after-write differs: {path}")


def _write_pack(output: Path, pack) -> None:
    destination = output.expanduser().absolute()
    try:
        destination.resolve(strict=False).relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise RuntimeError("raw Evidence Pack v2 objects must remain outside Git")
    for item in pack.objects:
        _write_exact(destination / "objects/sha256" / f"{item.stored_sha256}.xz", item.data)
    _write_exact(
        destination / "manifests/sha256" / f"{pack.manifest_sha256}.json",
        pack.manifest_bytes,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--pack-output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.evidence_root is None:
        if not args.check:
            parser.error("--evidence-root is required when compiling the measured report")
        report = load_strict(REPORT)
        _validate(report)
        print(f"verified tracked P20-T01C report {report['report_digest_sha256']}")
        return 0

    print("discovering the certified immutable P19 corpus", flush=True)
    source = discover_p19_corpus(args.evidence_root)
    print("building the lossless semantic source model", flush=True)
    semantic = build_semantic_corpus(ROOT, source)
    print("encoding independently addressable Evidence Pack v2 objects", flush=True)
    pack = build_evidence_pack(ROOT, source, semantic)
    validate_instance(
        pack.manifest,
        load_strict(MANIFEST_SCHEMA),
        source="P20-T01C Evidence Pack v2 manifest",
    )
    rebuilt = build_evidence_pack(ROOT, source, semantic)
    if rebuilt.manifest_bytes != pack.manifest_bytes or rebuilt.object_map() != pack.object_map():
        raise RuntimeError("Evidence Pack v2 is not deterministic")
    print("reconstructing all legacy members and checking bounded lookup", flush=True)
    certification = certify_pack(ROOT, source, semantic, pack)
    report = build_certification_report(source, semantic, pack, certification)
    _validate(report)
    encoded = canonical_bytes(report) + b"\n"
    if args.check:
        tracked = load_strict(REPORT)
        _validate(tracked)
        if tracked != report or REPORT.read_bytes() != encoded:
            raise RuntimeError("tracked P20-T01C report differs from measured rebuild")
    else:
        _write_exact(REPORT, encoded)
    if args.pack_output is not None:
        _write_pack(args.pack_output, pack)
    conservative = report["forecast"]["cases"]["conservative"]
    print(
        f"pack={pack.retained_bytes} objects={len(pack.objects) + 1} "
        f"expected={report['forecast']['cases']['expected']['total_retained_bytes']} "
        f"conservative={conservative['total_retained_bytes']} "
        f"soft_reserve={report['forecast']['conservative_operating_reserve_below_soft_stop_bytes']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
