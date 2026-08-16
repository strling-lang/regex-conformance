#!/usr/bin/env python3
"""Compile, verify, and optionally materialize the 1M distributed plan."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns/python",
    ROOT / "matrix/python",
    ROOT / "scheduler/python",
    ROOT / "schemas/tooling/python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.million_compiler import (
    PLAN_RELATIVE,
    build_partition_plans,
    compile_million_scale_plan,
    materialize_partition_inputs,
    verify_million_scale_plan,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


def _write_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(value) + b"\n"
    if path.exists() and path.read_bytes() == encoded:
        return
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError("million qualification artifact read-back differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / PLAN_RELATIVE)
    parser.add_argument("--partition-root", type=Path)
    parser.add_argument("--partition-index", type=int, action="append")
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    compiled = compile_million_scale_plan(ROOT)
    partitions = build_partition_plans(ROOT, compiled)
    if arguments.check:
        tracked = load_strict(arguments.output)
        verify_million_scale_plan(ROOT, tracked, deterministic=False)
        if canonical_bytes(tracked) != canonical_bytes(compiled.plan):
            raise RuntimeError("tracked million plan differs")
    else:
        _write_atomic(arguments.output, compiled.plan)
    if arguments.partition_index is not None and arguments.partition_root is None:
        raise RuntimeError("--partition-index requires --partition-root")
    materialized: tuple[dict[str, object], ...] = ()
    if arguments.partition_root is not None:
        materialized = materialize_partition_inputs(
            ROOT,
            compiled,
            arguments.partition_root,
            arguments.partition_index,
        )
    summary = {
        "campaign_manifest_id": compiled.plan["campaign_manifest_id"],
        "logical_execution_count": 1_000_000,
        "maximum_partition_logical_executions": max(
            item["denominator"]["included_count"] for item in partitions
        ),
        "maximum_partition_shards": max(len(item["shards"]) for item in partitions),
        "minimum_partition_logical_executions": min(
            item["denominator"]["included_count"] for item in partitions
        ),
        "ok": True,
        "partition_count": len(partitions),
        "materialized_partition_count": len(materialized),
        "shard_count": len(compiled.plan["shards"]),
    }
    if arguments.summary is not None:
        _write_atomic(arguments.summary, summary)
    sys.stdout.buffer.write(canonical_bytes(summary) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
