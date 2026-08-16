#!/usr/bin/env python3
"""Independently reconcile the safe million-scale qualification artifacts."""

from __future__ import annotations

import argparse
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

from regex_conformance_scale.million_reconciliation import (
    verify_million_final_artifacts,
)
from regex_conformance_schema.jsonio import canonical_bytes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--receipts-root", type=Path, required=True)
    arguments = parser.parse_args()
    result = verify_million_final_artifacts(
        ROOT,
        arguments.report,
        arguments.receipts_root,
    )
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
