#!/usr/bin/env python3
"""Run one exact CPython target call with a per-request target timer."""

from __future__ import annotations

from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT / "adapters" / "python"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from regex_conformance_adapters.jsonio import canonical_bytes, strict_loads
from regex_conformance_adapters.manifest import load_manifest
from regex_conformance_adapters.python_re import PythonReBackend
from regex_conformance_adapters.server import AdapterServer


MAXIMUM_INPUT_BYTES = 1_048_576


class TargetDeadline(BaseException):
    """The exact target invocation exceeded its requested wall time."""


def _expired(_signal_number: int, _frame: object) -> None:
    raise TargetDeadline()


def main() -> int:
    encoded = sys.stdin.buffer.read(MAXIMUM_INPUT_BYTES + 1)
    if not encoded or len(encoded) > MAXIMUM_INPUT_BYTES:
        raise RuntimeError("isolated target input is empty or exceeds its bound")
    request = strict_loads(encoded)
    if request.get("schema_version") != "adapter-request.v1":
        raise RuntimeError("isolated target input is not an adapter request")
    implementation = PythonReBackend(load_manifest(ROOT, "python-re"))
    runtime_identity = implementation.runtime_identity().to_record()
    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer != (0.0, 0.0):
        raise RuntimeError("isolated target inherited an active wall timer")
    signal.signal(signal.SIGALRM, _expired)
    wall_time_ms = request["limits"]["wall_time_ms"]
    signal.setitimer(signal.ITIMER_REAL, wall_time_ms / 1000)
    try:
        response = AdapterServer(implementation).execute(request)
    except TargetDeadline:
        result = {
            "adapter_release_manifest_id": implementation.manifest.manifest_id,
            "canonical_authority": False,
            "logical_execution_id": request["correlation_id"],
            "outcome": "target-timeout",
            "profile_id": implementation.manifest.profile_id,
            "runtime_identity": runtime_identity,
            "schema_version": "scale-target-timeout.v1",
            "semantic_authority": False,
            "target_release_id": implementation.manifest.target_release_id,
            "timer": {
                "implementation": "posix-itimer-real",
                "wall_time_ms": wall_time_ms,
            },
            "trace_reference": request["trace_reference"],
        }
    else:
        result = {
            "outcome": "adapter-response",
            "response": response,
            "schema_version": "scale-isolated-target-result.v1",
        }
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
    sys.stdout.buffer.write(canonical_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
