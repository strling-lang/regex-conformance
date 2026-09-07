#!/usr/bin/env python3
"""Build or verify the prospective execution-lineage reference contract."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(SCHEMA_TOOLING) not in sys.path:
    sys.path.insert(0, str(SCHEMA_TOOLING))

from regex_conformance_schema.execution_provenance import (  # noqa: E402
    materialize_repository_execution_provenance,
    verify_repository_execution_provenance,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify tracked policy and lineage artifacts")
    arguments = parser.parse_args()
    result = (
        verify_repository_execution_provenance(ROOT)
        if arguments.check
        else materialize_repository_execution_provenance(ROOT)
    )
    print(" ".join(f"{key}={result[key]}" for key in sorted(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
