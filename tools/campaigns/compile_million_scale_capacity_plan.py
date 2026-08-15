#!/usr/bin/env python3
"""Materialize the deterministic P20-T01 1M capacity and cost plan."""

from __future__ import annotations

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

from regex_conformance_scale.capacity_plan import (
    build_million_scale_capacity_plan,
    verify_million_scale_capacity_plan,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance


def main() -> int:
    report = build_million_scale_capacity_plan(ROOT)
    schema = load_strict(
        ROOT / "schemas" / "json" / "million-scale-capacity-plan.schema.json"
    )
    validate_instance(report, schema, source="compiled million-scale capacity plan")
    verify_million_scale_capacity_plan(ROOT, report)

    destination = ROOT / "reports" / "scale" / "million-scale-capacity-plan.json"
    encoded = canonical_bytes(report) + b"\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("million-scale capacity plan failed read-after-write verification")
    if canonical_bytes(build_million_scale_capacity_plan(ROOT)) + b"\n" != encoded:
        raise RuntimeError("million-scale capacity plan is not deterministic")

    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "logical_execution_count": report["workload_plan"][
                    "logical_execution_count"
                ],
                "ok": True,
                "plan_digest_sha256": report["plan_digest_sha256"],
                "result_shard_count": report["workload_plan"]["result_shard_count"],
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
