#!/usr/bin/env python3
"""Materialize and independently re-read the deterministic first campaign."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_campaign import compile_vertical_slice, verify_compiled_campaign
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


def write_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(payload) + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError("compiled campaign failed read-after-write verification")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "campaigns" / "compiled" / "first-vertical-slice.v1.json",
    )
    arguments = parser.parse_args()
    compiled = compile_vertical_slice(ROOT)
    write_atomic(arguments.output, compiled)
    verify_compiled_campaign(ROOT, load_strict(arguments.output))
    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "campaign_manifest_id": compiled["campaign_manifest_id"],
                "candidate_count": compiled["denominator"]["candidate_count"],
                "excluded_count": compiled["denominator"]["excluded_count"],
                "logical_execution_count": compiled["denominator"]["included_count"],
                "ok": True,
                "shard_count": len(compiled["shards"]),
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
