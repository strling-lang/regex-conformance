#!/usr/bin/env python3
"""Materialize and verify the compact 100K plan and optional external segments."""

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

from regex_conformance_scale import (
    build_design_report,
    compile_scale_plan,
    verify_design_report,
    verify_scale_plan,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


def _write_atomic(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(payload) + b"\n"
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError("100K artifact failed read-after-write verification")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "campaigns" / "compiled" / "100k-qualification.v1.json",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "reports" / "scale" / "100k-qualification-design.json",
    )
    parser.add_argument("--segment-root", type=Path)
    arguments = parser.parse_args()
    plan = compile_scale_plan(ROOT, segment_root=arguments.segment_root)
    report = build_design_report(ROOT, plan)
    _write_atomic(arguments.output, plan)
    _write_atomic(arguments.report, report)
    verify_scale_plan(ROOT, load_strict(arguments.output))
    verify_design_report(
        ROOT, load_strict(arguments.output), load_strict(arguments.report)
    )
    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "campaign_manifest_id": plan["campaign_manifest_id"],
                "logical_execution_count": plan["denominator"]["included_count"],
                "ok": True,
                "profile_coordinate_count": len(
                    plan["workload_distribution"]["profiles"]
                ),
                "required_category_count": len(
                    plan["workload_distribution"]["categories"]
                ),
                "shard_count": len(plan["shards"]),
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
