#!/usr/bin/env python3
"""Materialize or verify the prospective oracle foundation.

The command does not author vectors, evaluate applicability, execute targets,
or adjudicate findings.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.oracle import materialize, verify_current  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify exact committed artifacts without writing")
    parser.add_argument("--bounded", action="store_true", help="verify oracle closure without replaying broad identity and derivation catalog checks")
    arguments = parser.parse_args()
    result = verify_current(ROOT, broad_foundations=not arguments.bounded) if arguments.check else materialize(ROOT, broad_foundations=not arguments.bounded)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
