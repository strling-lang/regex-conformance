#!/usr/bin/env python3
"""Execute and resume a measured, non-semantic sustained workload."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence
import uuid


ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.configuration import DoctorConfiguration  # noqa: E402
from regex_conformance_control_plane.controller import build_default_controller  # noqa: E402
from regex_conformance_control_plane.operating_envelope import (  # noqa: E402
    CHECKPOINT_SCHEMA_VERSION,
    CLASSIFICATION,
    COUNTER_FIELDS,
    FAILURE_FIELDS,
    OperatingEnvelopeError,
    build_report,
    canonical_artifact_bytes,
    finalize_checkpoint,
    finalize_workload_binding,
    load_checkpoint_chain,
    load_plan,
    load_workload_binding,
    validate_checkpoint_chain,
    validate_workload_binding,
    verify_plan_source_bindings,
)
from regex_conformance_control_plane.state_models import canonical_json  # noqa: E402


DEFAULT_PLAN = ROOT / "control-plane" / "qualification" / "sustained-operating-envelope.v1.json"
MACHINE_INVENTORY_NAME = "machine-inventory.json"
WORKLOAD_BINDING_NAME = "workload-binding.json"
REPORT_NAME = "operating-envelope-report.json"


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _reject_linked_ancestors(path: Path, label: str) -> None:
    candidate = path.expanduser().absolute()
    for current in (candidate, *candidate.parents):
        if current.exists() and _is_link(current):
            raise OperatingEnvelopeError(f"{label} must not traverse a symlink or junction")


def _external(path: Path, label: str, *, must_exist: bool) -> Path:
    _reject_linked_ancestors(path, label)
    candidate = path.expanduser().absolute().resolve(strict=must_exist)
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        return candidate
    raise OperatingEnvelopeError(f"{label} must remain outside the repository")


def _private_directory(path: Path) -> Path:
    _reject_linked_ancestors(path, "operating-envelope directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(path, 0o700)
    if _is_link(path) or not path.is_dir():
        raise OperatingEnvelopeError("operating-envelope paths must be non-link directories")
    return path.resolve(strict=True)


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists() or _is_link(path):
        raise OperatingEnvelopeError(f"immutable operating-envelope artifact already exists: {path}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise OperatingEnvelopeError("immutable artifact publication raced with another writer") from error
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _uuid7(namespace: str) -> str:
    milliseconds = int(datetime.now(timezone.utc).timestamp() * 1000)
    randomness = secrets.randbits(74)
    integer = (
        ((milliseconds & ((1 << 48) - 1)) << 80)
        | (0x7 << 76)
        | (((randomness >> 62) & 0xFFF) << 64)
        | (0b10 << 62)
        | (randomness & ((1 << 62) - 1))
    )
    return f"opid:v1:{namespace}:u7:{uuid.UUID(int=integer)}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _git_revision() -> str:
    status = subprocess.run(
        ("git", "status", "--porcelain"), cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    if status.returncode != 0 or status.stdout:
        raise OperatingEnvelopeError("sustained qualification requires a clean source worktree")
    revision = subprocess.run(
        ("git", "rev-parse", "HEAD"), cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    value = revision.stdout.decode("ascii", "strict").strip()
    if revision.returncode != 0 or len(value) != 40:
        raise OperatingEnvelopeError("sustained qualification cannot resolve the exact source revision")
    return value


def _parse_input_binding(value: str) -> tuple[str, Path]:
    label, separator, raw_path = value.partition("=")
    if not separator or not label or not raw_path:
        raise argparse.ArgumentTypeError("input bindings must use LABEL=PATH")
    return (label, Path(raw_path))


def _file_digest(path: Path) -> tuple[str, int]:
    if _is_link(path) or not path.is_file():
        raise OperatingEnvelopeError(f"workload input must be a regular non-link file: {path}")
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def _tree_digest(path: Path) -> tuple[str, int]:
    if _is_link(path) or not path.is_dir():
        raise OperatingEnvelopeError(f"workload input must be a non-link directory: {path}")
    entries: list[dict[str, object]] = []
    total = 0
    for child in sorted(path.rglob("*")):
        if _is_link(child):
            raise OperatingEnvelopeError(f"workload input tree contains a link: {child}")
        if child.is_dir():
            continue
        digest, size = _file_digest(child)
        entries.append(
            {
                "path": child.relative_to(path).as_posix(),
                "sha256": digest,
                "size_bytes": size,
            }
        )
        total += size
    if not entries:
        raise OperatingEnvelopeError("workload input directory cannot be empty")
    return hashlib.sha256(canonical_json({"entries": entries})).hexdigest(), total


def _input_bindings(values: Sequence[tuple[str, Path]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for label, raw_path in values:
        path = _external(raw_path, f"workload input {label}", must_exist=True)
        digest, size = _tree_digest(path) if path.is_dir() else _file_digest(path)
        result.append({"label": label, "path": str(path), "sha256": digest, "size_bytes": size})
    result.sort(key=lambda item: (item["label"], item["path"]))
    return result


def _directory_allocated_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if _is_link(path):
            raise OperatingEnvelopeError(f"measured resource tree contains a link: {path}")
        if not path.is_file():
            continue
        details = path.stat(follow_symlinks=False)
        total += getattr(details, "st_blocks", 0) * 512 or details.st_size
    return total


def _cpu_times() -> tuple[int, int]:
    fields = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()
    if not fields or fields[0] != "cpu" or len(fields) < 5:
        raise OperatingEnvelopeError("CPU sampling requires the Linux /proc/stat aggregate")
    values = [int(value) for value in fields[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return sum(values), idle


def _process_group_rss_bytes(process_group: int) -> int:
    total = 0
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            stat_line = (process / "stat").read_text(encoding="ascii")
            fields = stat_line[stat_line.rfind(")") + 2 :].split()
            if int(fields[2]) != process_group:
                continue
            for line in (process / "status").read_text(encoding="ascii").splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1]) * 1024
                    break
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
            continue
    return total


def _temperature() -> tuple[int | None, str | None]:
    values: list[int] = []
    thermal_root = Path("/sys/class/thermal")
    if thermal_root.is_dir():
        for path in sorted(thermal_root.glob("thermal_zone*/temp")):
            try:
                value = int(path.read_text(encoding="ascii").strip())
                if value >= 0:
                    values.append(value)
            except (OSError, ValueError):
                continue
    if values:
        return max(values), None
    return None, "processor temperature telemetry is unavailable from the Linux guest"


class WindowSampler:
    def __init__(self, paths: Mapping[str, Path]) -> None:
        self._paths = paths
        self._samples: dict[str, list[int]] = {
            "cpu-utilization": [],
            "environment-cache-size": [],
            "execution-scratch-size": [],
            "persistent-disk-available": [],
            "processor-temperature": [],
            "ram-working-set": [],
            "result-spool-size": [],
        }
        self._temperature_diagnostic: str | None = None
        self._previous_cpu: tuple[int, int] | None = None
        self.overhead_ns = 0

    def sample(self, process_group: int) -> None:
        started = time.monotonic_ns()
        current_cpu = _cpu_times()
        if self._previous_cpu is not None:
            total_delta = current_cpu[0] - self._previous_cpu[0]
            idle_delta = current_cpu[1] - self._previous_cpu[1]
            if total_delta > 0:
                self._samples["cpu-utilization"].append(
                    max(0, min(10_000, ((total_delta - idle_delta) * 10_000) // total_delta))
                )
        self._previous_cpu = current_cpu
        self._samples["ram-working-set"].append(_process_group_rss_bytes(process_group))
        self._samples["environment-cache-size"].append(
            _directory_allocated_bytes(self._paths["environment_cache"])
        )
        self._samples["execution-scratch-size"].append(
            _directory_allocated_bytes(self._paths["execution_scratch"])
        )
        self._samples["result-spool-size"].append(
            _directory_allocated_bytes(self._paths["result_spool"])
        )
        self._samples["persistent-disk-available"].append(
            shutil.disk_usage(self._paths["persistent_disk"]).free
        )
        temperature, diagnostic = _temperature()
        if temperature is None:
            self._temperature_diagnostic = diagnostic
        else:
            self._samples["processor-temperature"].append(temperature)
        self.overhead_ns += time.monotonic_ns() - started

    def summaries(self, plan: Mapping[str, Any]) -> list[dict[str, object]]:
        units = {item["measurement"]: item["unit"] for item in plan["measurement_policy"]}
        result: list[dict[str, object]] = []
        for name in sorted(units):
            values = self._samples[name]
            if values:
                result.append(
                    {
                        "diagnostic": None,
                        "last": values[-1],
                        "maximum": max(values),
                        "measurement": name,
                        "minimum": min(values),
                        "sample_count": len(values),
                        "status": "observed",
                        "unit": units[name],
                    }
                )
            else:
                result.append(
                    {
                        "diagnostic": self._temperature_diagnostic,
                        "last": None,
                        "maximum": None,
                        "measurement": name,
                        "minimum": None,
                        "sample_count": 0,
                        "status": "unavailable",
                        "unit": units[name],
                    }
                )
        return result


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def _baseline_window(plan: Mapping[str, Any], paths: Mapping[str, Path]) -> dict[str, object]:
    sampler = WindowSampler(paths)
    started = time.monotonic()
    duration_seconds = plan["baseline_duration_ms"] / 1000
    interval_seconds = plan["sampling_interval_ms"] / 1000
    while time.monotonic() - started < duration_seconds:
        sampler.sample(os.getpgrp())
        remaining = duration_seconds - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(min(interval_seconds, remaining))
    sampler.sample(os.getpgrp())
    elapsed_ms = max(1, int((time.monotonic() - started) * 1000))
    return {
        "completed_work_count": 0,
        "duration_ms": elapsed_ms,
        "measurement_summaries": sampler.summaries(plan),
        "sampling_overhead_ms": (sampler.overhead_ns + 999_999) // 1_000_000,
    }


def _workload_window(
    plan: Mapping[str, Any], paths: Mapping[str, Path], command: Sequence[str]
) -> tuple[dict[str, object], dict[str, int]]:
    sampler = WindowSampler(paths)
    completed = 0
    failures = {field: 0 for field in FAILURE_FIELDS}
    target_seconds = (
        plan["minimum_stability_duration_ms"] / plan["minimum_stability_window_count"] / 1000
    )
    interval_seconds = plan["sampling_interval_ms"] / 1000
    maximum_iteration_seconds = plan["maximum_workload_iteration_ms"] / 1000
    started = time.monotonic()
    while time.monotonic() - started < target_seconds:
        process = subprocess.Popen(
            tuple(command), cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        iteration_started = time.monotonic()
        try:
            while process.poll() is None:
                sampler.sample(process.pid)
                if time.monotonic() - iteration_started > maximum_iteration_seconds:
                    failures["containment_failure_count"] = 1
                    _terminate(process)
                    break
                try:
                    process.wait(timeout=interval_seconds)
                except subprocess.TimeoutExpired:
                    pass
        except BaseException:
            _terminate(process)
            raise
        sampler.sample(process.pid)
        if failures["containment_failure_count"]:
            break
        if process.returncode != 0:
            failures["integrity_failure_count"] = 1
            break
        completed += 1
    elapsed_ms = max(1, int((time.monotonic() - started) * 1000))
    summaries = sampler.summaries(plan)
    failures["resource_boundary_breach_count"] = _resource_boundary_breach(plan, summaries)
    return (
        {
            "completed_work_count": completed,
            "duration_ms": elapsed_ms,
            "measurement_summaries": summaries,
            "sampling_overhead_ms": (sampler.overhead_ns + 999_999) // 1_000_000,
        },
        failures,
    )


def _resource_boundary_breach(
    plan: Mapping[str, Any], summaries: Sequence[Mapping[str, object]]
) -> int:
    boundaries = {item["measurement"]: item for item in plan["resource_boundaries"]}
    for summary in summaries:
        boundary = boundaries.get(summary["measurement"])
        if boundary is None or summary["status"] != "observed":
            continue
        if (
            boundary["boundary"] == "minimum" and summary["minimum"] < boundary["value"]
        ) or (
            boundary["boundary"] == "maximum" and summary["maximum"] > boundary["value"]
        ):
            return 1
    return 0


def _append_checkpoint(
    root: Path,
    plan: Mapping[str, Any],
    chain: list[dict[str, Any]],
    *,
    qualification_id: str,
    logical_execution_id: str,
    workload_digest: str,
    attempt_id: str,
    session_index: int,
    phase: str,
    window: Mapping[str, Any] | None,
    failure_increments: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    previous = chain[-1] if chain else None
    counters = {field: 0 for field in COUNTER_FIELDS} if previous is None else dict(previous["counters"])
    failures = {field: 0 for field in FAILURE_FIELDS}
    failures.update(failure_increments or {})
    for field, increment in failures.items():
        counters[field] += increment
    if window is not None:
        counters["completed_work_count"] += window["completed_work_count"]
        counters["sampler_overhead_ms"] += window["sampling_overhead_ms"]
        if phase in {"steady-load", "post-recovery"}:
            counters["stability_duration_ms"] += window["duration_ms"]
            counters["stability_window_count"] += 1
            if phase == "post-recovery":
                counters["post_recovery_duration_ms"] += window["duration_ms"]
    if phase == "interruption":
        counters["interruption_count"] += 1
    elif phase == "recovery":
        counters["successful_resume_count"] += 1
    elif phase == "complete":
        counters["logical_completion_count"] += 1
    sequence = len(chain) + 1
    checkpoint = finalize_checkpoint(
        {
            "attempt_id": attempt_id,
            "checkpoint_digest_sha256": "0" * 64,
            "checkpoint_id": _uuid7("operating-envelope-checkpoint"),
            "classification": dict(CLASSIFICATION),
            "counters": counters,
            "failure_increments": failures,
            "logical_execution_id": logical_execution_id,
            "observed_at": _now(),
            "phase": phase,
            "plan_digest_sha256": plan["plan_digest_sha256"],
            "previous_checkpoint_digest_sha256": (
                None if previous is None else previous["checkpoint_digest_sha256"]
            ),
            "qualification_id": qualification_id,
            "record_type": "checkpoint",
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "sequence": sequence,
            "session_index": session_index,
            "window": dict(window) if window is not None else None,
            "workload_digest_sha256": workload_digest,
        }
    )
    validate_checkpoint_chain(plan, (*chain, checkpoint))
    _write_new(root / f"checkpoint-{sequence:06d}.json", canonical_artifact_bytes(checkpoint))
    chain.append(checkpoint)
    return checkpoint


def _machine_inventory(paths: Mapping[str, Path]) -> dict[str, Any]:
    configuration = DoctorConfiguration.from_environment(
        {},
        trust_override="trusted_executioner",
        pool_overrides={
            "persistent_disk": paths["persistent_disk"],
            "environment_cache": paths["environment_cache"],
            "build_scratch": paths["execution_scratch"],
            "execution_scratch": paths["execution_scratch"],
            "result_spool": paths["result_spool"],
        },
        inventory_max_age_seconds=300,
    )
    report = build_default_controller().inspect_machine(configuration)
    if report.status == "unsupported":
        raise OperatingEnvelopeError("machine inventory is unsupported for sustained qualification")
    return report.to_dict()


def _prepare_binding(
    root: Path,
    plan: Mapping[str, Any],
    paths: Mapping[str, Path],
    command: Sequence[str],
    inputs: Sequence[tuple[str, Path]],
    revision: str,
) -> dict[str, Any]:
    inventory_path = root / MACHINE_INVENTORY_NAME
    if inventory_path.exists():
        inventory_bytes = inventory_path.read_bytes()
    else:
        inventory_bytes = canonical_artifact_bytes(_machine_inventory(paths))
        _write_new(inventory_path, inventory_bytes)
    machine_digest = hashlib.sha256(inventory_bytes).hexdigest()
    binding = finalize_workload_binding(
        {
            "classification": dict(CLASSIFICATION),
            "command": list(command),
            "input_bindings": _input_bindings(inputs),
            "machine_inventory_sha256": machine_digest,
            "measurement_paths": {key: str(paths[key]) for key in sorted(paths)},
            "plan_digest_sha256": plan["plan_digest_sha256"],
            "record_type": "workload",
            "schema_version": "sustained-operating-envelope-workload.v1",
            "source_revision": revision,
            "workload_digest_sha256": "0" * 64,
        }
    )
    binding_path = root / WORKLOAD_BINDING_NAME
    if binding_path.exists():
        existing = load_workload_binding(binding_path)
        if existing != binding:
            raise OperatingEnvelopeError("resume workload binding differs from the immutable first session")
        return existing
    _write_new(binding_path, canonical_artifact_bytes(binding))
    return binding


def _ensure_report(
    root: Path, plan: Mapping[str, Any], chain: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    report = build_report(plan, chain)
    payload = canonical_artifact_bytes(report)
    path = root / REPORT_NAME
    if path.exists() or _is_link(path):
        if _is_link(path) or not path.is_file() or path.read_bytes() != payload:
            raise OperatingEnvelopeError(
                "immutable operating-envelope report differs from the checkpoint chain"
            )
    else:
        _write_new(path, payload)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run or resume the governed sustained operating-envelope workload."
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--checkpoint-root", type=Path, required=True)
    parser.add_argument("--environment-cache-root", type=Path, required=True)
    parser.add_argument("--execution-scratch-root", type=Path, required=True)
    parser.add_argument("--persistent-disk-root", type=Path, required=True)
    parser.add_argument("--input-binding", action="append", default=[], type=_parse_input_binding)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    if not arguments.execute or not arguments.yes:
        parser.error("sustained workload mutation requires both --execute and --yes")
    if not arguments.input_binding:
        parser.error("at least one immutable --input-binding LABEL=PATH is required")
    command = list(arguments.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        parser.error("a workload command is required after --")
    try:
        if sys.platform != "linux":
            raise OperatingEnvelopeError("sustained workload execution requires a native Linux host")
        plan = load_plan(arguments.plan)
        verify_plan_source_bindings(ROOT, plan)
        revision = _git_revision()
        checkpoint_root = _private_directory(
            _external(arguments.checkpoint_root, "checkpoint root", must_exist=False)
        )
        paths = {
            "environment_cache": _private_directory(
                _external(arguments.environment_cache_root, "environment cache", must_exist=False)
            ),
            "execution_scratch": _private_directory(
                _external(arguments.execution_scratch_root, "execution scratch", must_exist=False)
            ),
            "persistent_disk": _external(
                arguments.persistent_disk_root, "persistent disk", must_exist=True
            ),
            "result_spool": checkpoint_root,
        }
        binding = _prepare_binding(
            checkpoint_root, plan, paths, command, arguments.input_binding, revision
        )
        validate_workload_binding(binding)
        files = sorted(checkpoint_root.glob("checkpoint-*.json"))
        chain = list(load_checkpoint_chain(checkpoint_root, plan)) if files else []
        workload_digest = binding["workload_digest_sha256"]
        if chain and chain[-1]["workload_digest_sha256"] != workload_digest:
            raise OperatingEnvelopeError("checkpoint chain does not match the immutable workload binding")
        if chain and chain[-1]["phase"] == "complete":
            report = _ensure_report(checkpoint_root, plan, chain)
            print(f"operating-envelope already complete: {report['summary']['status']}")
            return 0 if report["summary"]["status"] == "passed" else 3

        if not chain:
            qualification_id = _uuid7("operating-envelope")
            logical_execution_id = _uuid7("logical-execution")
            attempt_id = _uuid7("execution-attempt")
            session_index = 1
            baseline = _baseline_window(plan, paths)
            baseline_failures = {field: 0 for field in FAILURE_FIELDS}
            baseline_failures["resource_boundary_breach_count"] = _resource_boundary_breach(
                plan, baseline["measurement_summaries"]
            )
            _append_checkpoint(
                checkpoint_root, plan, chain,
                qualification_id=qualification_id,
                logical_execution_id=logical_execution_id,
                workload_digest=workload_digest,
                attempt_id=attempt_id,
                session_index=session_index,
                phase="baseline",
                window=baseline,
                failure_increments=baseline_failures,
            )
            if any(chain[-1]["counters"][field] for field in FAILURE_FIELDS):
                print(
                    "operating-envelope stopped after a fail-closed baseline resource boundary",
                    file=sys.stderr,
                )
                return 3
            phase = "steady-load"
        else:
            final = chain[-1]
            qualification_id = final["qualification_id"]
            logical_execution_id = final["logical_execution_id"]
            if final["phase"] != "interruption":
                _append_checkpoint(
                    checkpoint_root, plan, chain,
                    qualification_id=qualification_id,
                    logical_execution_id=logical_execution_id,
                    workload_digest=workload_digest,
                    attempt_id=final["attempt_id"],
                    session_index=final["session_index"],
                    phase="interruption",
                    window=None,
                )
            attempt_id = _uuid7("execution-attempt")
            session_index = chain[-1]["session_index"] + 1
            _append_checkpoint(
                checkpoint_root, plan, chain,
                qualification_id=qualification_id,
                logical_execution_id=logical_execution_id,
                workload_digest=workload_digest,
                attempt_id=attempt_id,
                session_index=session_index,
                phase="recovery",
                window=None,
            )
            phase = "post-recovery"

        interruption_window = max(1, plan["minimum_stability_window_count"] // 2)
        while chain[-1]["counters"]["stability_window_count"] < plan["minimum_stability_window_count"]:
            window, failures = _workload_window(plan, paths, command)
            checkpoint = _append_checkpoint(
                checkpoint_root, plan, chain,
                qualification_id=qualification_id,
                logical_execution_id=logical_execution_id,
                workload_digest=workload_digest,
                attempt_id=attempt_id,
                session_index=session_index,
                phase=phase,
                window=window,
                failure_increments=failures,
            )
            if any(checkpoint["counters"][field] for field in FAILURE_FIELDS):
                print("operating-envelope stopped after a fail-closed workload or resource boundary", file=sys.stderr)
                return 3
            if (
                checkpoint["counters"]["interruption_count"] < plan["minimum_recovery_count"]
                and checkpoint["counters"]["stability_window_count"] >= interruption_window
            ):
                _append_checkpoint(
                    checkpoint_root, plan, chain,
                    qualification_id=qualification_id,
                    logical_execution_id=logical_execution_id,
                    workload_digest=workload_digest,
                    attempt_id=attempt_id,
                    session_index=session_index,
                    phase="interruption",
                    window=None,
                )
                print("operating-envelope controlled interruption committed; resume the same command")
                return 75

        _append_checkpoint(
            checkpoint_root, plan, chain,
            qualification_id=qualification_id,
            logical_execution_id=logical_execution_id,
            workload_digest=workload_digest,
            attempt_id=attempt_id,
            session_index=session_index,
            phase="complete",
            window=None,
        )
        report = _ensure_report(checkpoint_root, plan, chain)
        print(f"operating-envelope complete: {report['summary']['status']}")
        return 0 if report["summary"]["status"] == "passed" else 3
    except KeyboardInterrupt:
        print("operating-envelope interrupted; resume will add a new physical attempt", file=sys.stderr)
        return 75
    except (OSError, OperatingEnvelopeError, ValueError) as error:
        print(f"operating-envelope failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
