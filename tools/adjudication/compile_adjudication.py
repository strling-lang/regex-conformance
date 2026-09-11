#!/usr/bin/env python3
"""Build or verify the observation-to-claim adjudication artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(SCHEMA_TOOLING) not in sys.path:
    sys.path.insert(0, str(SCHEMA_TOOLING))

from regex_conformance_schema.adjudication import materialize, verify_current  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify tracked artifacts")
    parser.add_argument("--bounded", action="store_true", help="skip redundant broad-foundation rechecks")
    arguments = parser.parse_args()
    result = verify_current(ROOT, broad_foundations=not arguments.bounded) if arguments.check else materialize(ROOT, broad_foundations=not arguments.bounded)
    print(
        f"result={result['result']} valid={result['valid_case_count']} "
        f"adversarial={result['adversarial_case_count']} states={result['coordinate_state_count']} "
        f"C4={result['c4']} {result['c4_completed']}/{result['c4_denominator']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
