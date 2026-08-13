#!/usr/bin/env python3
"""Regenerate the deterministic seeded evidence-corruption contract."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
    ROOT / "verifier" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_schema.jsonio import dump_pretty
from regex_conformance_verifier.qualification import build_reference_report


def main() -> int:
    destination = ROOT / "reports" / "small-scale" / "evidence-verification-qualification.json"
    destination.write_text(dump_pretty(build_reference_report()), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
