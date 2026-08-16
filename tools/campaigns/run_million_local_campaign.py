#!/usr/bin/env python3
"""Execute, stage, and reconcile the complete million-scale campaign locally."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns/python",
    ROOT / "matrix/python",
    ROOT / "scheduler/python",
    ROOT / "schemas/tooling/python",
    ROOT / "tools/environments",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

import certify_minimal as environment_certification
from regex_conformance_scale.million_compiler import (
    compile_million_scale_plan,
    materialize_partition_inputs,
)
from regex_conformance_schema.jsonio import canonical_bytes


PROTECTED_FREE_SPACE_BYTES = 40_000_000_000
PROTECTED_SPOOL_BYTES = 6_000_000_000
GIB = 1024**3


def _external(path: Path, label: str) -> Path:
    return environment_certification._outside_repository(path, label)


def _private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    details = path.stat()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise RuntimeError(
            "local recovery state requires a native filesystem with POSIX 0700 modes"
        )
    return path


def _state_root(path: Path) -> Path:
    result = _external(path, "local million state root")
    for temporary_root in (Path("/tmp"), Path("/var/tmp")):
        try:
            result.relative_to(temporary_root.resolve(strict=False))
        except ValueError:
            continue
        raise RuntimeError("local recovery state must use durable storage")
    return _private_directory(result)


def _available_memory_bytes() -> int:
    try:
        values = (Path("/proc/meminfo").read_text(encoding="ascii")).splitlines()
        available = next(item for item in values if item.startswith("MemAvailable:"))
        return int(available.split()[1]) * 1024
    except (OSError, StopIteration, ValueError) as error:
        raise RuntimeError("local memory admission requires Linux MemAvailable") from error


def _required_memory_bytes(concurrency: int) -> int:
    return 8 * GIB + concurrency * 6 * GIB + 8 * GIB


def _tree_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            total += path.stat().st_size
    return total


def _preflight(
    campaign_root: Path, state_root: Path, concurrency: int
) -> dict[str, int]:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("local million-scale execution requires a governed Linux host")
    missing = [name for name in ("cmake", "cc", "docker") if shutil.which(name) is None]
    if missing:
        raise RuntimeError("local execution prerequisites are absent: " + ",".join(missing))
    available_memory = _available_memory_bytes()
    required_memory = _required_memory_bytes(concurrency)
    if available_memory < required_memory:
        raise RuntimeError(
            f"local memory admission failed: {available_memory} < {required_memory}"
        )
    free_space = shutil.disk_usage(campaign_root).free
    if free_space < PROTECTED_FREE_SPACE_BYTES:
        raise RuntimeError(
            f"local disk admission failed: {free_space} < {PROTECTED_FREE_SPACE_BYTES}"
        )
    state_free_space = shutil.disk_usage(state_root).free
    if state_free_space < PROTECTED_FREE_SPACE_BYTES:
        raise RuntimeError(
            "local state-disk admission failed: "
            f"{state_free_space} < {PROTECTED_FREE_SPACE_BYTES}"
        )
    checked = subprocess.run(
        ("docker", "version", "--format", "{{.Server.Version}}"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if checked.returncode != 0 or not checked.stdout.strip():
        raise RuntimeError("local Docker provider is unavailable")
    existing = subprocess.run(
        ("docker", "ps", "--all", "--quiet", "--filter", "name=strling-rc-"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if existing.returncode != 0 or existing.stdout.strip():
        raise RuntimeError("program target containers are not initially clean")
    return {
        "available_memory_bytes": available_memory,
        "free_space_bytes": free_space,
        "state_free_space_bytes": state_free_space,
    }


def _program_containers() -> bytes:
    result = subprocess.run(
        ("docker", "ps", "--all", "--quiet", "--filter", "name=strling-rc-"),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError("program target-container cleanup could not be verified")
    return result.stdout.strip()


def _run_logged(command: list[str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("ab") as stream:
        stream.write(("\n$ " + " ".join(command) + "\n").encode("utf-8"))
        stream.flush()
        return subprocess.run(
            command,
            cwd=ROOT,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        ).returncode


def _partition(
    index: int,
    campaign_root: Path,
    state_base: Path,
    inputs_root: Path,
    handoffs_root: Path,
    staging_root: Path,
) -> dict[str, object]:
    partition = f"{index:03d}"
    input_root = inputs_root / f"partition-{partition}"
    handoff = handoffs_root / f"partition-{partition}"
    state_root = state_base / f"partition-{partition}"
    report = handoff / "execution-report.json"
    preparation = handoff / "partition-preparation.json"
    log = campaign_root / "logs" / f"partition-{partition}.log"
    if not preparation.exists():
        if not report.exists():
            completed = False
            for _session in range(4):
                result = _run_logged(
                    [
                        sys.executable,
                        str(ROOT / "tools/campaigns/run_million_partition.py"),
                        "--partition-plan",
                        str(input_root / "partition-plan.json"),
                        "--state-root",
                        str(state_root),
                        "--logical-segment-root",
                        str(input_root / "logical"),
                        "--evidence-dir",
                        str(input_root / "evidence"),
                        "--compact-report",
                        str(report),
                    ],
                    log,
                )
                if result == 0:
                    completed = True
                    break
                if result != 75:
                    raise RuntimeError(f"partition {partition} execution failed: {result}")
            if not completed:
                raise RuntimeError(f"partition {partition} did not close four sessions")
        result = _run_logged(
            [
                sys.executable,
                str(ROOT / "tools/campaigns/prepare_million_partition.py"),
                "--partition-plan",
                str(input_root / "partition-plan.json"),
                "--campaign-root",
                str(input_root),
                "--execution-report",
                str(report),
                "--staging-root",
                str(staging_root),
                "--preparation-record",
                str(preparation),
            ],
            log,
        )
        if result != 0:
            raise RuntimeError(f"partition {partition} preparation failed: {result}")
    if _tree_bytes(campaign_root) >= PROTECTED_SPOOL_BYTES:
        raise RuntimeError("local protected spool reached its 6 GB hard boundary")
    return {"partition_index": index, "status": "prepared"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=4, choices=range(1, 5))
    arguments = parser.parse_args()
    campaign_root = _external(arguments.campaign_root, "local million campaign root")
    campaign_root.mkdir(parents=True, exist_ok=True)
    state_root = _state_root(arguments.state_root)
    preflight = _preflight(campaign_root, state_root, arguments.concurrency)
    inputs_root = campaign_root / "inputs"
    handoffs_root = campaign_root / "handoffs"
    staging_root = campaign_root / "publication-staging"
    compiled = compile_million_scale_plan(ROOT)
    materialize_partition_inputs(ROOT, compiled, inputs_root)
    started = time.monotonic()
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=arguments.concurrency) as pool:
        futures = {
            pool.submit(
                _partition,
                index,
                campaign_root,
                state_root,
                inputs_root,
                handoffs_root,
                staging_root,
            ): index
            for index in range(64)
        }
        try:
            for future in as_completed(futures):
                results.append(future.result())
        except BaseException:
            for pending in futures:
                pending.cancel()
            raise
    if _program_containers():
        raise RuntimeError("program target containers remain after local execution")
    final_report = campaign_root / "million-local-readiness-report.json"
    finalize_log = campaign_root / "logs" / "finalize.log"
    result = _run_logged(
        [
            sys.executable,
            str(ROOT / "tools/campaigns/finalize_million_local_artifacts.py"),
            "--preparations-root",
            str(handoffs_root),
            "--staging-root",
            str(staging_root),
            "--report",
            str(final_report),
        ],
        finalize_log,
    )
    if result != 0:
        raise RuntimeError(f"local final reconciliation failed: {result}")
    output = {
        "campaign_root": str(campaign_root),
        "concurrency": arguments.concurrency,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "final_report": str(final_report),
        "ok": True,
        "partition_count": len(results),
        "preflight": preflight,
        "schema_version": "million-scale-local-campaign-run.v1",
        "state_root": str(state_root),
    }
    sys.stdout.buffer.write(canonical_bytes(output) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
