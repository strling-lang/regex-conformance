#!/usr/bin/env python3
"""Compile and verify the P20-T01B factorized-evidence forecast."""

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

from regex_conformance_scale.factorized_evidence import (  # noqa: E402
    build_factorized_forecast,
    build_semantic_corpus,
    certify_reconstruction,
    discover_p19_corpus,
    encode_semantic_archive,
    measure_lossy_performance_upper_bound,
    measure_source_representations,
    verify_factorized_forecast,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


REPORT = ROOT / "reports" / "scale" / "factorized-raw-evidence-forecast.json"
SCHEMA = ROOT / "schemas" / "json" / "factorized-evidence-forecast.schema.json"


def _validate_report(report: dict) -> None:
    validate_instance(
        report,
        load_strict(SCHEMA),
        source="P20-T01B factorized raw-evidence forecast",
    )


def _write_exact(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != data:
        raise RuntimeError(f"read-after-write differs: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence-root",
        type=Path,
        help="explicit immutable P19 campaign root for read-only measurement",
    )
    parser.add_argument("--archive-output", type=Path, help="optional disposable factorized archive output")
    parser.add_argument("--check", action="store_true", help="verify the tracked compact report")
    args = parser.parse_args()

    if args.evidence_root is None:
        if not args.check:
            parser.error("--evidence-root is required when compiling measurements")
        report = load_strict(REPORT)
        _validate_report(report)
        verify_factorized_forecast(report)
        print(f"verified tracked P20-T01B report {report['report_digest_sha256']}")
        return 0

    print("discovering certified immutable P19 source members", flush=True)
    source = discover_p19_corpus(args.evidence_root)
    print("measuring canonical, gzip, and deterministic tar representations", flush=True)
    source_measurements = measure_source_representations(source)
    print("building schema-aware lossless semantic factorization", flush=True)
    semantic = build_semantic_corpus(ROOT, source)
    print("encoding independently checksummed binary blocks", flush=True)
    archive = encode_semantic_archive(semantic)
    rebuilt = encode_semantic_archive(semantic)
    if rebuilt.data != archive.data:
        raise RuntimeError("factorized archive is not deterministic")
    print("measuring the non-authoritative performance-trimming upper bound", flush=True)
    performance_upper_bound = measure_lossy_performance_upper_bound(semantic, archive)
    print("reconstructing and hashing all canonical members", flush=True)
    certification = certify_reconstruction(ROOT, source, archive.data)
    certification["deterministic_second_encoding_identical"] = True
    report = build_factorized_forecast(
        ROOT,
        source,
        source_measurements,
        semantic,
        archive,
        certification,
        performance_upper_bound,
    )
    _validate_report(report)
    verify_factorized_forecast(report)
    encoded_report = canonical_bytes(report) + b"\n"
    if args.check:
        tracked = load_strict(REPORT)
        _validate_report(tracked)
        verify_factorized_forecast(tracked)
        if tracked != report or REPORT.read_bytes() != encoded_report:
            raise RuntimeError("tracked P20-T01B report differs from measured rebuild")
    else:
        _write_exact(REPORT, encoded_report)
    if args.archive_output is not None:
        output = args.archive_output.expanduser().absolute()
        try:
            output.resolve(strict=False).relative_to(ROOT)
        except ValueError:
            pass
        else:
            raise RuntimeError("raw factorized archives must remain outside Git")
        _write_exact(output, archive.data)
    gate = report["decision_gate"]
    print(
        f"factorized={len(archive.data)} expected={report['forecast']['cases']['expected']['total_retained_bytes']} "
        f"conservative={report['forecast']['cases']['conservative']['total_retained_bytes']} "
        f"owner_gate={not gate['strongest_lossless_fits_expected_and_conservative_below_hard_cap']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
