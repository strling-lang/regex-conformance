#!/usr/bin/env python3
"""Recover a completed partition receipt by exact coordinate without LIST."""

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

from regex_conformance_scale.million_compiler import verify_partition_plan
from regex_conformance_scale.r2_publication import (
    R2Configuration,
    R2HttpTransport,
    R2TransportError,
    million_partition_receipt_key,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance


def _write_atomic(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError("recovered partition receipt read-back differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--master-plan",
        type=Path,
        default=ROOT / "campaigns/million/compiled/million-qualification.v1.json",
    )
    parser.add_argument("--partition-plan", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args()
    configuration = R2Configuration.from_environment()
    master = load_strict(arguments.master_plan)
    partition = load_strict(arguments.partition_plan)
    verify_partition_plan(ROOT, master, partition)
    key = million_partition_receipt_key(
        partition["parent_campaign_manifest_id"], partition["partition_index"]
    )
    try:
        fetched = R2HttpTransport(configuration).get_exact(key)
    except R2TransportError as failure:
        if failure.status == 404:
            sys.stdout.buffer.write(
                canonical_bytes(
                    {
                        "completed": False,
                        "partition_index": partition["partition_index"],
                        "schema_version": "million-scale-partition-recovery.v1",
                    }
                )
                + b"\n"
            )
            return 0
        raise
    receipt = loads_strict(fetched.data.decode("utf-8"))
    validate_instance(
        receipt,
        load_strict(
            ROOT
            / "schemas/json/million-scale-partition-publication-receipt.schema.json"
        ),
        source="recovered million partition receipt",
    )
    if (
        receipt["campaign_manifest_id"] != partition["campaign_manifest_id"]
        or receipt["parent_campaign_manifest_id"]
        != partition["parent_campaign_manifest_id"]
        or receipt["partition_index"] != partition["partition_index"]
        or canonical_bytes(receipt) + b"\n" != fetched.data
    ):
        raise RuntimeError("recovered partition receipt differs from the plan")
    _write_atomic(arguments.receipt, fetched.data)
    sys.stdout.buffer.write(
        canonical_bytes(
            {
                "completed": True,
                "partition_index": partition["partition_index"],
                "schema_version": "million-scale-partition-recovery.v1",
            }
        )
        + b"\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
