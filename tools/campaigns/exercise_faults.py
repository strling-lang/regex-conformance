#!/usr/bin/env python3
"""Exercise the closed P18 fault set and emit immutable external evidence."""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import errno
import hashlib
import io
import os
from pathlib import Path
import sys
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "adapters" / "python",
    ROOT / "control-plane" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_adapters.errors import AdapterError
from regex_conformance_adapters.jsonio import read_frame
from regex_conformance_control_plane.containment import ContainedProcessSupervisor, ExecutionLimits
from regex_conformance_control_plane.fault_attribution import (
    build_reference_report,
    classify_fault,
    reference_stimuli,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance, validate_repository


PROCESS_LIMITS = ExecutionLimits(
    wall_time_ms=2000,
    stdout_bytes=65_536,
    stderr_bytes=65_536,
)
TIMEOUT_LIMITS = ExecutionLimits(wall_time_ms=75, stdout_bytes=65_536, stderr_bytes=65_536)



def _outside_repository(path: Path, label: str) -> Path:
    candidate = path.expanduser().resolve(strict=False)
    try:
        candidate.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        return candidate
    raise ValueError(f"{label} must remain outside the Git repository")


def _contained(command: tuple[str, ...], limits: ExecutionLimits = PROCESS_LIMITS) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    result = ContainedProcessSupervisor(maximum_concurrency=1).run(
        command,
        limits=limits,
        cwd=ROOT,
        environment={
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC",
        },
    )
    return {"exit_code": result.exit_code, "outcome": result.outcome}, result.to_dict(), result.stdout


def _inject_network_failure() -> None:
    raise ConnectionError("allowlisted injected acquisition transport failure")


def _inject_storage_failure() -> None:
    raise OSError(errno.ENOSPC, "allowlisted injected evidence publication failure")


def _require_injected(function: Callable[[], None], expected: type[BaseException]) -> str:
    try:
        function()
    except expected as error:
        return type(error).__name__
    raise RuntimeError(f"{function.__name__} did not inject {expected.__name__}")


def _live_stimuli() -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    stimuli = {item["fault_key"]: deepcopy(item) for item in reference_stimuli()}
    executions: dict[str, dict[str, Any]] = {}

    facts, metadata, _ = _contained((sys.executable, "-I", "-c", "import time;time.sleep(2)"), limits=TIMEOUT_LIMITS)
    stimuli["target-timeout"]["containment"] = facts
    executions["target-timeout"] = metadata

    crash = "import os,signal;os.kill(os.getpid(),signal.SIGABRT)"
    for key in ("adapter-process-crash", "target-process-crash"):
        facts, metadata, _ = _contained((sys.executable, "-I", "-c", crash))
        stimuli[key]["containment"] = facts
        executions[key] = metadata

    killed = "import os,signal;os.kill(os.getpid(),signal.SIGKILL)"
    facts, metadata, _ = _contained((sys.executable, "-I", "-c", killed))
    stimuli["worker-kill"]["containment"] = facts
    executions["worker-kill"] = metadata

    malformed = "import struct,sys;sys.stdout.buffer.write(struct.pack('>I',1)+b'{');sys.stdout.flush()"
    facts, metadata, stdout = _contained((sys.executable, "-I", "-c", malformed))
    malformed_detected = False
    try:
        read_frame(io.BytesIO(stdout))
    except AdapterError:
        malformed_detected = True
    if not malformed_detected:
        raise RuntimeError("malformed adapter response was not rejected by the protocol decoder")
    stimuli["malformed-adapter-response"]["containment"] = facts
    executions["malformed-adapter-response"] = {**metadata, "strict_decoder_rejected": True}

    executions["network-acquisition-failure"] = {
        "injected_exception": _require_injected(_inject_network_failure, ConnectionError)
    }
    executions["storage-publication-failure"] = {
        "injected_exception": _require_injected(_inject_storage_failure, OSError)
    }
    return [stimuli[key] for key in sorted(stimuli)], executions


def _atomic_evidence(directory: Path, payload: dict[str, Any]) -> tuple[str, Path]:
    encoded = canonical_bytes(payload) + b"\n"
    digest = hashlib.sha256(encoded).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"deliberate-fault-execution-sha256-{digest}.json"
    if destination.exists():
        if destination.read_bytes() != encoded:
            raise RuntimeError("content-addressed fault evidence path contains different bytes")
        return digest, destination
    temporary = directory / f".{destination.name}.tmp"
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("fault evidence failed read-after-write verification")
    return digest, destination


def exercise(evidence_dir: Path) -> dict[str, Any]:
    counts = validate_repository(ROOT)
    reference = build_reference_report()
    checked_in = load_strict(ROOT / "reports" / "small-scale" / "fault-classification.json")
    validate_instance(
        checked_in,
        load_strict(ROOT / "schemas" / "json" / "fault-classification-report.schema.json"),
        source="checked-in fault classification report",
    )
    if canonical_bytes(reference) != canonical_bytes(checked_in):
        raise RuntimeError("checked-in fault outcomes differ from deterministic classification")
    stimuli, executions = _live_stimuli()
    cases = []
    expected = {item["stimulus"]["fault_key"]: item["assessment"] for item in reference["cases"]}
    for stimulus in stimuli:
        assessment = classify_fault(stimulus)
        key = stimulus["fault_key"]
        projection = {
            field: assessment[field]
            for field in (
                "attribution_layer",
                "c5_terminal_eligible",
                "completion_disposition",
                "logical_execution_satisfied",
                "outcome_class",
                "reason_code",
            )
        }
        expected_projection = {field: expected[key][field] for field in projection}
        if projection != expected_projection:
            raise RuntimeError(f"live fault classification differed for {key}: {projection!r}")
        cases.append(
            {
                "assessment": assessment,
                "execution": executions[key],
                "stimulus": stimulus,
            }
        )
    payload = {
        "cases": cases,
        "classification": reference["classification"],
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "reference_report_sha256": hashlib.sha256(canonical_bytes(reference) + b"\n").hexdigest(),
        "schema_validation_counts": counts,
        "schema_version": "deliberate-fault-execution-evidence.v1",
        "summary": reference["summary"],
    }
    digest, path = _atomic_evidence(evidence_dir, payload)
    return {
        "accepted_terminal_count": reference["summary"]["accepted_terminal_count"],
        "case_count": reference["summary"]["case_count"],
        "evidence_path": str(path),
        "evidence_sha256": digest,
        "inconclusive_attempt_count": reference["summary"]["inconclusive_attempt_count"],
        "ok": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    arguments = parser.parse_args()
    report = exercise(_outside_repository(arguments.evidence_dir, "evidence directory"))
    sys.stdout.buffer.write(canonical_bytes(report) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
