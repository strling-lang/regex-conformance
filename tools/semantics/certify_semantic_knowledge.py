#!/usr/bin/env python3
"""Materialize or verify the semantic knowledge architecture acceptance gate."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.semantic_foundation import (  # noqa: E402
    materialize_semantic_foundation,
    verify_current_semantic_foundation,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="re-evaluate the gate against current bound inputs")
    arguments = parser.parse_args()
    result = verify_current_semantic_foundation(ROOT) if arguments.check else materialize_semantic_foundation(ROOT)
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
