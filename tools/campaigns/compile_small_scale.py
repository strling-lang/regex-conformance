#!/usr/bin/env python3
"""Materialize and independently verify the P18 qualification plan and coverage report."""

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

from regex_conformance_qualification import (
    build_coverage_report,
    compile_qualification,
    verify_compiled_qualification,
    verify_coverage_report,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


def write_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(payload) + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError("qualification artifact failed read-after-write verification")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "campaigns" / "compiled" / "small-scale-qualification.v1.json")
    parser.add_argument("--report", type=Path, default=ROOT / "reports" / "small-scale" / "qualification-coverage.json")
    arguments = parser.parse_args()
    compiled = compile_qualification(ROOT)
    report = build_coverage_report(ROOT, compiled)
    write_atomic(arguments.output, compiled)
    write_atomic(arguments.report, report)
    verify_compiled_qualification(ROOT, load_strict(arguments.output))
    verify_coverage_report(
        ROOT, load_strict(arguments.output), load_strict(arguments.report)
    )
    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "campaign_manifest_id": compiled["campaign_manifest_id"],
                "candidate_count": compiled["denominator"]["candidate_count"],
                "included_count": compiled["denominator"]["included_count"],
                "excluded_count": compiled["denominator"]["excluded_count"],
                "category_count": len(report["categories"]),
                "ok": True,
            }
        ) + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
