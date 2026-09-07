#!/usr/bin/env python3
"""Materialize or verify the integrated scientific foundation acceptance."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.foundation import (  # noqa: E402
    materialize_foundation,
    verify_current_foundation,
    verify_foundation_history,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="re-evaluate the acceptance against current bound inputs")
    mode.add_argument("--history", action="store_true", help="validate the immutable historical acceptance record only")
    arguments = parser.parse_args()
    if arguments.check:
        result = verify_current_foundation(ROOT)
    elif arguments.history:
        result = verify_foundation_history(ROOT)
    else:
        result = materialize_foundation(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
