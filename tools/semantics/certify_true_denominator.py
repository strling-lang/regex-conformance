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

from regex_conformance_schema.denominator_foundation import materialize, verify_current, verify_history  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="freshly recompute every gate predicate from committed canonical inputs")
    mode.add_argument("--history", action="store_true", help="validate the immutable accepted gate without rebinding later catalog additions")
    parser.add_argument("--bounded", action="store_true", help="skip broad predecessor suites while retaining exact denominator checks")
    arguments = parser.parse_args()
    if arguments.check:
        result = verify_current(ROOT, broad_foundations=not arguments.bounded)
    elif arguments.history:
        result = verify_history(ROOT)
    else:
        result = materialize(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
