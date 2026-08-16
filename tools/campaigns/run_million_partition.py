#!/usr/bin/env python3
"""Execute or resume one trusted 1M qualification partition."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "adapters/python",
    ROOT / "campaigns/python",
    ROOT / "control-plane/python",
    ROOT / "matrix/python",
    ROOT / "scheduler/python",
    ROOT / "schemas/tooling/python",
    ROOT / "tools/adapters",
    ROOT / "tools/environments",
    ROOT / "verifier/python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

import certify_minimal as environment_certification
from regex_conformance_scale.distributed_execution import (
    DistributedLogicalStore,
    DistributedPartitionController,
)
from regex_conformance_scale.execution import PlannedInterruption
from regex_conformance_scale.million_compiler import verify_partition_plan
from regex_conformance_scheduler import ScaleRecoveryLedger
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_verifier import ScaleEvidenceStore


_WORKER_SPEC = importlib.util.spec_from_file_location(
    "million_scale_worker", ROOT / "tools/campaigns/run_100k_qualification.py"
)
if _WORKER_SPEC is None or _WORKER_SPEC.loader is None:
    raise RuntimeError("cannot load certified scale worker")
worker_module = importlib.util.module_from_spec(_WORKER_SPEC)
_WORKER_SPEC.loader.exec_module(worker_module)
CertifiedScaleWorker = worker_module.CertifiedScaleWorker


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    destination = path.expanduser().resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(payload) + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("partition report read-back differs")


def _external(path: Path, label: str) -> Path:
    result = environment_certification._outside_repository(path, label)
    worker_module._require_durable_external(result, label)
    return result


@contextmanager
def _lock(state_root: Path):
    with environment_certification._exclusive_certification_lock(state_root):
        yield


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--master-plan",
        type=Path,
        default=ROOT / "campaigns/million/compiled/million-qualification.v1.json",
    )
    parser.add_argument("--partition-plan", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--state-db", type=Path)
    parser.add_argument("--logical-segment-root", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--compact-report", type=Path)
    arguments = parser.parse_args()

    master = load_strict(arguments.master_plan)
    partition = load_strict(arguments.partition_plan)
    verify_partition_plan(ROOT, master, partition)
    state_root = _external(arguments.state_root, "million partition state root")
    state_db = _external(
        arguments.state_db or state_root / "scale-recovery.sqlite",
        "million partition recovery database",
    )
    logical_root = _external(
        arguments.logical_segment_root, "million partition logical root"
    )
    evidence_root = _external(
        arguments.evidence_dir, "million partition evidence root"
    )
    worker: Any | None = None
    try:
        with _lock(state_root):
            logical_store = DistributedLogicalStore(
                ROOT, master, partition, logical_root
            )
            evidence = ScaleEvidenceStore(ROOT, evidence_root)
            with ScaleRecoveryLedger(
                state_db, partition["campaign_manifest_id"]
            ) as ledger:
                worker = CertifiedScaleWorker(state_root, "trusted_executioner")
                controller = DistributedPartitionController(
                    ROOT,
                    master,
                    partition,
                    logical_store,
                    ledger,
                    evidence,
                    worker,
                )
                _manifest, report = controller.execute("trusted_executioner")
                worker.close()
                worker = None
                if arguments.compact_report is not None:
                    _write_atomic(arguments.compact_report, report)
                sys.stdout.buffer.write(canonical_bytes({"ok": True, **report}) + b"\n")
        return 0
    except PlannedInterruption as interruption:
        sys.stdout.buffer.write(
            canonical_bytes(
                {
                    "event": interruption.event,
                    "ok": True,
                    "planned_interruption": True,
                    "progress": interruption.progress,
                }
            )
            + b"\n"
        )
        return 75
    except Exception as error:
        worker_module.adapter_helpers._report_failure(error)
        return 1
    finally:
        if worker is not None:
            worker.close()


if __name__ == "__main__":
    raise SystemExit(main())
