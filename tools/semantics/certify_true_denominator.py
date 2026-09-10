#!/usr/bin/env python3
"""Materialize or verify the true obligation denominator acceptance gate.

The command consumes committed semantic-side denominator artifacts only.  It
does not author vectors, evaluate real profiles, execute targets, or issue a
full scientific certificate.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.denominator_foundation import materialize, verify_current  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="freshly recompute every gate predicate from committed canonical inputs")
    parser.add_argument("--bounded", action="store_true", help="skip broad predecessor suites while retaining exact denominator checks")
    arguments = parser.parse_args()
    result = verify_current(ROOT, broad_foundations=not arguments.bounded) if arguments.check else materialize(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
