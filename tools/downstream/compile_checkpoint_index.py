#!/usr/bin/env python3
"""Build or verify the append-only Coverage Shard checkpoint index."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_SOURCE = ROOT / "schemas" / "tooling" / "python"
if str(SCHEMA_SOURCE) not in sys.path:
    sys.path.insert(0, str(SCHEMA_SOURCE))

from regex_conformance_schema.downstream import (  # noqa: E402
    build_checkpoint_index,
    load_and_validate_downstream_records,
    write_checkpoint_index,
)
from regex_conformance_schema.schema import validate_instance  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the tracked index instead of appending newly sealed checkpoints",
    )
    args = parser.parse_args()
    if args.check:
        counts = load_and_validate_downstream_records(
            ROOT, validate_instance=validate_instance
        )
        count = counts["coverage_shard_checkpoints"]
    else:
        index = write_checkpoint_index(ROOT, validate_instance=validate_instance)
        count = index["checkpoint_count"]
        rebuilt = build_checkpoint_index(ROOT, validate_instance=validate_instance)
        if rebuilt != index:
            raise RuntimeError("checkpoint index second build is not deterministic")
    print(f"coverage_shard_checkpoints={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
