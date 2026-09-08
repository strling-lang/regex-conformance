#!/usr/bin/env python3
"""Materialize, verify, or explain the prospective obligation derivation rules.

This command performs design analysis only. It never advances denominator
authority, mints canonical obligation IDs, authors vectors, or executes targets.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.obligation_derivation import (  # noqa: E402
    explain_feature,
    materialize,
    verify_current,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify tracked rules and reports against a deterministic rebuild")
    mode.add_argument("--explain", metavar="FEATURE_ID", help="print the complete derivation trace for one frozen feature")
    arguments = parser.parse_args()
    if arguments.explain:
        print(json.dumps(explain_feature(ROOT, arguments.explain), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    result = verify_current(ROOT) if arguments.check else materialize(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
