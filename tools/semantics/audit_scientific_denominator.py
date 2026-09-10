#!/usr/bin/env python3
"""Materialize, verify, or explain the independent denominator audit.

This command audits the semantic-side denominator only.  It does not expand
profiles, author vectors, execute targets, or issue a scientific certificate.
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

from regex_conformance_schema.denominator_audit import (  # noqa: E402
    explain,
    materialize,
    verify_current,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify every tracked audit artifact by independent recomputation")
    mode.add_argument("--explain", metavar="REQUIREMENT", help="explain one requirement's accounting classification")
    arguments = parser.parse_args()
    if arguments.check:
        result = verify_current(ROOT)
    elif arguments.explain:
        print(json.dumps(explain(ROOT, arguments.explain), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    else:
        result = materialize(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
