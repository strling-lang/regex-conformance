"""Provider-aware hard containment for adapter and probe subprocesses."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Mapping, Sequence

from .resource_models import SAFE_INTEGER_MAX, TOKEN_PATTERN
from .state_models import canonical_object


LIMIT_OUTCOMES = frozenset(
    {"completed", "wall-time-limit", "stdout-limit", "stderr-limit", "cpu-time-limit", "launch-failed"}
)
HARD_LIMIT_NAMES = frozenset({"cpu-time", "memory", "process-tree", "stderr", "stdout", "wall-time"})


def _positive_safe(label: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= SAFE_INTEGER_MAX:
        raise ValueError(f"{label} must be a positive safe integer")


@dataclass(frozen=True)
class ExecutionLimits:
    wall_time_ms: int
    stdout_bytes: int
    stderr_bytes: int
    memory_bytes: int | None = None
    cpu_time_seconds: int | None = None

    def __post_init__(self) -> None:
        _positive_safe("wall-time limit", self.wall_time_ms)
        _positive_safe("stdout limit", self.stdout_bytes)
        _positive_safe("stderr limit", self.stderr_bytes)
        if self.memory_bytes is not None:
            _positive_safe("memory limit", self.memory_bytes)
        if self.cpu_time_seconds is not None:
            _positive_safe("CPU-time limit", self.cpu_time_seconds)
            if self.cpu_time_seconds > 86_400:
                raise ValueError("CPU-time limit cannot exceed 24 hours")

    def to_dict(self) -> dict[str, int | None]:
        return {
            "cpu_time_seconds": self.cpu_time_seconds,
            "memory_bytes": self.memory_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_bytes": self.stdout_bytes,
            "wall_time_ms": self.wall_time_ms,
        }


@dataclass(frozen=True)
class ProviderLimitPlan:
    provider: str
    enforced_limits: tuple[str, ...]
    launch_arguments: tuple[str, ...] = ()
    process_tree_containment: bool = True
    canonical_authority: bool = False
    semantic_authority: bool = False

    def __post_init__(self) -> None:
        if TOKEN_PATTERN.fullmatch(self.provider) is None:
            raise ValueError("containment provider must be a canonical token")
        if (
            not isinstance(self.enforced_limits, tuple)
            or not self.enforced_limits
            or len(self.enforced_limits) != len(set(self.enforced_limits))
            or any(not isinstance(value, str) or value not in HARD_LIMIT_NAMES for value in self.enforced_limits)
        ):
            raise ValueError("provider limit plans require unique enforced limits")
        if tuple(sorted(self.enforced_limits)) != self.enforced_limits:
            raise ValueError("provider limit names must use deterministic order")
        if (
            not isinstance(self.launch_arguments, tuple)
            or len(self.launch_arguments) > 64
            or any(
                not isinstance(value, str) or not value or "\x00" in value or len(value) > 1024
                for value in self.launch_arguments
            )
        ):
            raise ValueError("provider launch arguments must be bounded non-empty strings")
        if not isinstance(self.process_tree_containment, bool) or not self.process_tree_containment:
            raise ValueError("provider plans must contain the complete process tree")
        if (
            not isinstance(self.canonical_authority, bool)
            or not isinstance(self.semantic_authority, bool)
            or self.canonical_authority
            or self.semantic_authority
        ):
            raise ValueError("containment plans are operational and non-semantic")
        canonical_object(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_authority": False,
            "enforced_limits": list(self.enforced_limits),
            "launch_arguments": list(self.launch_arguments),
            "process_tree_containment": True,
            "provider": self.provider,
            "semantic_authority": False,
        }


class UnsupportedContainmentError(RuntimeError):
    """A requested hard limit cannot be independently enforced by the provider."""


class NativeSafetyLimitAdapter:
    """Compile host-native limits, refusing unsupported resource requests pre-launch."""

    provider = "native"

    def plan(self, limits: ExecutionLimits) -> ProviderLimitPlan:
        if os.name != "posix":
            raise UnsupportedContainmentError(
                "native containment requires POSIX process groups and rlimits; "
                "Windows Job Object support is not implemented"
            )
        enforced = {"process-tree", "stderr", "stdout", "wall-time"}
        if limits.memory_bytes is not None:
            enforced.add("memory")
        if limits.cpu_time_seconds is not None:
            enforced.add("cpu-time")
        return ProviderLimitPlan(self.provider, tuple(sorted(enforced)))


class OciSafetyLimitAdapter:
    """Compile provider-side OCI limits; the supervisor still owns wall/output caps."""

    provider = "oci"

    def plan(self, limits: ExecutionLimits) -> ProviderLimitPlan:
        enforced = {"process-tree", "stderr", "stdout", "wall-time"}
        arguments: list[str] = ["--init", "--network=none"]
        if limits.memory_bytes is not None:
            enforced.add("memory")
            arguments.extend(("--memory", str(limits.memory_bytes), "--memory-swap", str(limits.memory_bytes)))
        if limits.cpu_time_seconds is not None:
            raise UnsupportedContainmentError(
                "OCI CPU quotas do not enforce a total CPU-time budget; use native in-container RLIMIT_CPU"
            )
        return ProviderLimitPlan(self.provider, tuple(sorted(enforced)), tuple(arguments))


@dataclass(frozen=True)
class ContainedExecutionResult:
    outcome: str
    exit_code: int | None
    wall_time_ms: int
    stdout: bytes
    stderr: bytes
    stdout_total_bytes: int
    stderr_total_bytes: int
    stdout_sha256: str
    stderr_sha256: str
    provider_plan: ProviderLimitPlan
    diagnostic: str | None = None
    canonical_authority: bool = False
    semantic_authority: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, str) or self.outcome not in LIMIT_OUTCOMES:
            raise ValueError("unknown contained-execution outcome")
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise ValueError("contained-execution exit code must be an integer or null")
        if self.outcome == "launch-failed" and self.exit_code is not None:
            raise ValueError("launch failures cannot claim a target exit code")
        if self.outcome != "launch-failed" and self.exit_code is None:
            raise ValueError("launched contained processes require a target exit code")
        for label, value in (
            ("wall time", self.wall_time_ms),
            ("stdout total", self.stdout_total_bytes),
            ("stderr total", self.stderr_total_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= SAFE_INTEGER_MAX:
                raise ValueError(f"contained-execution {label} must be a non-negative safe integer")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ValueError("captured output must remain bytes")
        if len(self.stdout) > self.stdout_total_bytes or len(self.stderr) > self.stderr_total_bytes:
            raise ValueError("captured output cannot exceed observed output volume")
        if not isinstance(self.provider_plan, ProviderLimitPlan):
            raise ValueError("contained executions require a typed provider plan")
        for digest in (self.stdout_sha256, self.stderr_sha256):
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise ValueError("contained output digests must be SHA-256")
        if (
            self.stdout_total_bytes == len(self.stdout)
            and hashlib.sha256(self.stdout).hexdigest() != self.stdout_sha256
        ):
            raise ValueError("complete captured stdout does not match its digest")
        if (
            self.stderr_total_bytes == len(self.stderr)
            and hashlib.sha256(self.stderr).hexdigest() != self.stderr_sha256
        ):
            raise ValueError("complete captured stderr does not match its digest")
        if self.diagnostic is not None:
            if (
                not isinstance(self.diagnostic, str)
                or not self.diagnostic
                or len(self.diagnostic) > 512
                or any(c in self.diagnostic for c in "\r\n\x00")
            ):
                raise ValueError("containment diagnostic must be bounded single-line text")
            canonical_object({"diagnostic": self.diagnostic})
        if (
            not isinstance(self.canonical_authority, bool)
            or not isinstance(self.semantic_authority, bool)
            or self.canonical_authority
            or self.semantic_authority
        ):
            raise ValueError("containment results cannot claim scientific authority")
        canonical_object(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Return safe metadata only; raw target output is deliberately excluded."""

        return {
            "canonical_authority": False,
            "diagnostic": self.diagnostic,
            "exit_code": self.exit_code,
            "outcome": self.outcome,
            "provider_plan": self.provider_plan.to_dict(),
            "semantic_authority": False,
            "stderr_sha256": self.stderr_sha256,
            "stderr_total_bytes": self.stderr_total_bytes,
            "stdout_sha256": self.stdout_sha256,
            "stdout_total_bytes": self.stdout_total_bytes,
            "wall_time_ms": self.wall_time_ms,
        }


class _BoundedPipe:
    def __init__(self, stream: Any, limit: int, exceeded: threading.Event) -> None:
        self._stream = stream
        self._limit = limit
        self._exceeded = exceeded
        self.kept = bytearray()
        self.total = 0
        self.digest = hashlib.sha256()
        self.done = threading.Event()

    def read(self) -> None:
        try:
            while True:
                reader = getattr(self._stream, "read1", self._stream.read)
                chunk = reader(65_536)
                if not chunk:
                    break
                self.total = min(SAFE_INTEGER_MAX, self.total + len(chunk))
                self.digest.update(chunk)
                if len(self.kept) < self._limit:
                    self.kept.extend(chunk[: self._limit - len(self.kept)])
                if self.total > self._limit:
                    self._exceeded.set()
        except (OSError, ValueError):
            pass
        finally:
            try:
                self._stream.close()
            except OSError:
                pass
            self.done.set()


class ContainedProcessSupervisor:
    """Run shell-free child processes with independent, fail-closed safety limits."""

    def __init__(self, *, maximum_concurrency: int = 1, adapter: NativeSafetyLimitAdapter | None = None) -> None:
        _positive_safe("maximum containment concurrency", maximum_concurrency)
        if maximum_concurrency > 4096:
            raise ValueError("maximum containment concurrency cannot exceed 4096")
        self._semaphore = threading.BoundedSemaphore(maximum_concurrency)
        self._adapter = adapter or NativeSafetyLimitAdapter()

    @staticmethod
    def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
        if isinstance(command, (str, bytes)) or not command or len(command) > 256:
            raise ValueError("contained commands require a bounded argument sequence")
        result = tuple(command)
        if any(not isinstance(value, str) or not value or "\x00" in value or len(value) > 32_768 for value in result):
            raise ValueError("contained command arguments must be bounded non-empty strings")
        return result

    @staticmethod
    def _posix_command(argv: tuple[str, ...], limits: ExecutionLimits) -> tuple[str, ...]:
        if limits.memory_bytes is None and limits.cpu_time_seconds is None:
            return argv
        runner = Path(__file__).with_name("containment_runner.py")
        result = [sys.executable, str(runner)]
        if limits.memory_bytes is not None:
            result.extend(("--memory-bytes", str(limits.memory_bytes)))
        if limits.cpu_time_seconds is not None:
            result.extend(("--cpu-seconds", str(limits.cpu_time_seconds)))
        result.extend(("--", *argv))
        return tuple(result)

    @staticmethod
    def _terminate_tree(process: subprocess.Popen[bytes]) -> None:
        if os.name != "posix":
            raise UnsupportedContainmentError("native process-tree termination is unavailable on this host")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 0.25
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.01)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def run(
        self,
        command: Sequence[str],
        *,
        limits: ExecutionLimits,
        cwd: str | os.PathLike[str] | None = None,
        environment: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
    ) -> ContainedExecutionResult:
        argv = self._validate_command(command)
        provider_plan = self._adapter.plan(limits)
        if provider_plan.provider != "native":
            raise UnsupportedContainmentError("the native supervisor cannot execute another provider's limit plan")
        if cwd is not None:
            working_directory = Path(cwd)
            if working_directory.is_symlink() or not working_directory.is_dir():
                raise ValueError("contained working directory must be an existing non-link directory")
        else:
            working_directory = None
        if environment is not None:
            if any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or not key
                or "\x00" in key
                or "=" in key
                or "\x00" in value
                for key, value in environment.items()
            ):
                raise ValueError("contained environment must contain valid string entries")
            child_environment = dict(environment)
        else:
            child_environment = None
        if stdin is not None and (not isinstance(stdin, bytes) or len(stdin) > 16 * 1024 * 1024):
            raise ValueError("contained stdin must be bytes no larger than 16 MiB")

        with self._semaphore:
            started = time.monotonic()
            launch: dict[str, Any] = {
                "args": self._posix_command(argv, limits) if os.name == "posix" else argv,
                "cwd": working_directory,
                "env": child_environment,
                "stdin": subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "shell": False,
            }
            if os.name == "posix":
                launch["start_new_session"] = True
            try:
                process = subprocess.Popen(**launch)
            except (OSError, subprocess.SubprocessError) as error:
                elapsed = min(SAFE_INTEGER_MAX, max(0, math.ceil((time.monotonic() - started) * 1000)))
                empty = hashlib.sha256(b"").hexdigest()
                return ContainedExecutionResult(
                    "launch-failed", None, elapsed, b"", b"", 0, 0, empty, empty,
                    provider_plan, f"{type(error).__name__}: process launch failed",
                )

            assert process.stdout is not None and process.stderr is not None
            stdout_limit = threading.Event()
            stderr_limit = threading.Event()
            stdout_reader = _BoundedPipe(process.stdout, limits.stdout_bytes, stdout_limit)
            stderr_reader = _BoundedPipe(process.stderr, limits.stderr_bytes, stderr_limit)
            threads = (
                threading.Thread(target=stdout_reader.read, name="contained-stdout", daemon=True),
                threading.Thread(target=stderr_reader.read, name="contained-stderr", daemon=True),
            )
            for thread in threads:
                thread.start()
            if stdin is not None:
                assert process.stdin is not None
                try:
                    process.stdin.write(stdin)
                    process.stdin.close()
                except BrokenPipeError:
                    pass

            outcome = "completed"
            deadline = started + (limits.wall_time_ms / 1000)
            while True:
                if stdout_limit.is_set():
                    outcome = "stdout-limit"
                    break
                if stderr_limit.is_set():
                    outcome = "stderr-limit"
                    break
                if time.monotonic() >= deadline:
                    outcome = "wall-time-limit"
                    break
                if process.poll() is not None and stdout_reader.done.is_set() and stderr_reader.done.is_set():
                    break
                time.sleep(0.005)

            if process.poll() is None and outcome == "completed":
                process.wait(timeout=1)
            self._terminate_tree(process)
            if process.poll() is None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)
            exit_code = process.poll()
            if outcome == "completed" and os.name == "posix" and exit_code == -getattr(signal, "SIGXCPU", 24):
                outcome = "cpu-time-limit"
            for thread in threads:
                thread.join(timeout=1)
            if not stdout_reader.done.is_set() or not stderr_reader.done.is_set():
                self._terminate_tree(process)
                if not stdout_reader.done.is_set():
                    process.stdout.close()
                if not stderr_reader.done.is_set():
                    process.stderr.close()
                for thread in threads:
                    thread.join(timeout=1)
            if not stdout_reader.done.is_set() or not stderr_reader.done.is_set():
                raise RuntimeError("contained process pipes did not close after process-tree termination")
            if outcome == "completed":
                if stdout_reader.total > limits.stdout_bytes:
                    outcome = "stdout-limit"
                elif stderr_reader.total > limits.stderr_bytes:
                    outcome = "stderr-limit"
            elapsed = min(SAFE_INTEGER_MAX, max(0, math.ceil((time.monotonic() - started) * 1000)))
            return ContainedExecutionResult(
                outcome=outcome,
                exit_code=exit_code,
                wall_time_ms=elapsed,
                stdout=bytes(stdout_reader.kept),
                stderr=bytes(stderr_reader.kept),
                stdout_total_bytes=stdout_reader.total,
                stderr_total_bytes=stderr_reader.total,
                stdout_sha256=stdout_reader.digest.hexdigest(),
                stderr_sha256=stderr_reader.digest.hexdigest(),
                provider_plan=provider_plan,
            )
