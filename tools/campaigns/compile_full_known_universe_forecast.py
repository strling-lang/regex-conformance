#!/usr/bin/env python3
"""Compile and verify the P20-T01A full-universe raw-corpus forecast."""

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

from regex_conformance_scale.universe_forecast import (  # noqa: E402
    build_full_known_universe_forecast,
    verify_full_known_universe_forecast,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify the tracked report without writing")
    args = parser.parse_args()
    index = load_strict(ROOT / "registries/universe/full-known-universe-2026-08-15.v1.json")
    index_schema = load_strict(ROOT / "schemas/json/full-known-universe-index.schema.json")
    validate_instance(index, index_schema, source="P20-T01A known-universe planning index")
    report_path = ROOT / "reports/scale/full-known-universe-corpus-forecast.json"
    built = build_full_known_universe_forecast(ROOT)
    report_schema = load_strict(ROOT / "schemas/json/full-known-universe-forecast.schema.json")
    validate_instance(built, report_schema, source="P20-T01A full-universe corpus forecast")
    encoded = canonical_bytes(built) + b"\n"
    if args.check:
        tracked = load_strict(report_path)
        verify_full_known_universe_forecast(ROOT, tracked)
        if report_path.read_bytes() != encoded:
            raise ValueError("tracked forecast differs from deterministic rebuild")
    else:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = report_path.with_suffix(report_path.suffix + ".tmp")
        with temporary.open("wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, report_path)
        if report_path.read_bytes() != encoded:
            raise RuntimeError("full-universe forecast failed read-after-write verification")
        verify_full_known_universe_forecast(ROOT, load_strict(report_path))
        if canonical_bytes(build_full_known_universe_forecast(ROOT)) + b"\n" != encoded:
            raise RuntimeError("full-universe forecast is not deterministic")
    gate = built["decision_gate"]
    print(
        f"{gate['outcome']}: expected={gate['expected_final_packed_bytes']} "
        f"conservative={gate['conservative_final_packed_bytes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
