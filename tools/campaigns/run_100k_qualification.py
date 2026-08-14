#!/usr/bin/env python3
"""Execute and resume the 100K qualification through exact certified runtimes."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "adapters" / "python",
    ROOT / "campaigns" / "python",
    ROOT / "control-plane" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
    ROOT / "tools" / "adapters",
    ROOT / "tools" / "environments",
    ROOT / "verifier" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

import certify_minimal as environment_certification
from regex_conformance_adapters.jsonio import encode_frame
from regex_conformance_adapters.manifest import AdapterManifest, load_manifest
from regex_conformance_adapters.qualification_manifest import (
    load_qualification_manifest,
)
from regex_conformance_control_plane.certified_environments import (
    CertifiedEnvironmentProvider,
    build_certified_providers,
    load_certified_recipes,
    load_qualification_recipes,
)
from regex_conformance_control_plane.containment import ContainedProcessSupervisor
from regex_conformance_control_plane.discovery import StandardLibraryMachineDiscovery
from regex_conformance_control_plane.doctor import MachineDoctor, UtcClock
from regex_conformance_control_plane.environment_manager import EnvironmentManager
from regex_conformance_control_plane.environment_providers import ProviderRegistry
from regex_conformance_control_plane.resource_models import ResourceEstimate
from regex_conformance_control_plane.resource_planner import ResourcePlanner
from regex_conformance_scale.execution import (
    PlannedInterruption,
    ScaleCampaignController,
    ScaleLogicalStore,
)
from regex_conformance_scheduler import ScaleRecoveryLedger, utc_now
from regex_conformance_schema.jsonio import canonical_bytes, load_strict, loads_strict
from regex_conformance_schema.schema import validate_instance
from regex_conformance_verifier import ScaleEvidenceStore


_ADAPTER_SPEC = importlib.util.spec_from_file_location(
    "scale_adapter_helpers", ROOT / "tools" / "adapters" / "certify_minimal.py"
)
if _ADAPTER_SPEC is None or _ADAPTER_SPEC.loader is None:
    raise RuntimeError("cannot load adapter certification helpers")
adapter_helpers = importlib.util.module_from_spec(_ADAPTER_SPEC)
_ADAPTER_SPEC.loader.exec_module(adapter_helpers)


ORDER = {
    "pcre2-ordinary": 0,
    "pcre2-dfa": 1,
    "python-re": 2,
    "mysql-regex": 3,
}

MAXIMUM_ISOLATED_TARGET_WALL_TIME_MS = 1_000



def _kill_forced_worker(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        process.kill()
    else:
        os.killpg(process.pid, signal.SIGKILL)


class CertifiedScaleWorker:
    """Reuse one verified realized environment per selection within a session."""

    def __init__(self, state_root: Path, trust_class: str) -> None:
        definitions = tuple(
            sorted(
                (*load_certified_recipes(ROOT), *load_qualification_recipes(ROOT)),
                key=lambda item: ORDER[item.selection_key],
            )
        )
        providers = build_certified_providers(definitions, state_root)
        self.definitions = {item.selection_key: item for item in definitions}
        self.providers = {
            item.selection_key: provider
            for item, provider in zip(definitions, providers, strict=True)
        }
        self.managers = {
            item.selection_key: EnvironmentManager(ProviderRegistry((provider,)))
            for item, provider in zip(definitions, providers, strict=True)
        }
        self.planner = ResourcePlanner(environment_certification._policy())
        self.doctor = MachineDoctor(StandardLibraryMachineDiscovery(), UtcClock())
        self.configuration = environment_certification._doctor_configuration(
            state_root, trust_class
        )
        self.trust_class = trust_class
        self.ready: dict[str, Any] = {}

    def _realize(self, selection_key: str) -> Any:
        existing = self.ready.get(selection_key)
        if existing is not None:
            return existing
        definition = self.definitions[selection_key]
        provider = self.providers[selection_key]
        manager = self.managers[selection_key]
        assert isinstance(provider, CertifiedEnvironmentProvider)
        planned = manager.plan(definition.lifecycle, provider.descriptor.name)
        if planned.state != "planned":
            raise RuntimeError(f"environment planning failed: {planned.failure}")
        inventory = adapter_helpers._health_checked_inventory(
            self.doctor.inspect(self.configuration), provider
        )
        memory = definition.limits.memory_bytes
        supplemental = (
            ()
            if memory is None
            else (
                ResourceEstimate(
                    "environment-memory-ceiling",
                    "ram",
                    "bytes",
                    memory,
                    memory,
                    "bounded",
                    "isolation-policy",
                ),
            )
        )
        resource_plan = self.planner.environment_plan(
            planned,
            machine_provider_name=provider.machine_provider_name,
            estimate_confidence="bounded",
            supplemental_estimates=supplemental,
            eligible_trust_classes=(self.configuration.trust_class,),
        )
        admission = self.planner.preflight(resource_plan, inventory)
        admitted = manager.admit(
            planned, self.planner.environment_decision(planned, admission)
        )
        if admitted.state != "admitted":
            raise RuntimeError("resource admission refused the scale environment")
        ready = manager.realize(admitted)
        if ready.state != "ready":
            raise RuntimeError(
                f"environment realization failed: {manager.diagnose(ready).to_dict()}"
            )
        self.ready[selection_key] = ready
        return ready

    @staticmethod
    def _package(selection_key: str) -> AdapterManifest:
        if selection_key == "pcre2-dfa":
            return load_qualification_manifest(ROOT, selection_key)
        return load_manifest(ROOT, selection_key)

    @staticmethod
    def _command(
        selection_key: str, ready: Any
    ) -> tuple[tuple[str, ...], dict[str, str], str | None]:
        if selection_key != "pcre2-dfa":
            return adapter_helpers._adapter_command(selection_key, ready)
        root = Path(ready.provider_handle).resolve(strict=True)
        library = adapter_helpers._shared_pcre2_library(root)
        environment = {
            "HOME": str(root / "adapter-home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_LIBRARY_PATH": str(library.parent),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "TZ": "UTC",
        }
        Path(environment["HOME"]).mkdir(exist_ok=True)
        return (
            (
                sys.executable,
                "-I",
                str(ROOT / "adapters" / "python" / "run_qualification.py"),
                "--selection-key",
                selection_key,
                "--runtime-binding",
                str(library),
            ),
            environment,
            str(library),
        )

    @staticmethod
    def _limits(selection_key: str) -> Any:
        if selection_key == "pcre2-dfa":
            return adapter_helpers.ExecutionLimits(
                wall_time_ms=120_000,
                stdout_bytes=4 * 1024 * 1024,
                stderr_bytes=1 * 1024 * 1024,
                memory_bytes=4_294_967_296,
                cpu_time_seconds=120,
            )
        return adapter_helpers._adapter_process_limits(selection_key)

    @staticmethod
    def _invoke_isolated_python_target(
        command: tuple[str, ...],
        environment: dict[str, str],
        package: AdapterManifest,
        logical: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        request = logical["request"]
        execution = ContainedProcessSupervisor(maximum_concurrency=1).run(
            (
                command[0],
                "-I",
                str(ROOT / "tools" / "campaigns" / "run_isolated_python_target.py"),
            ),
            limits=adapter_helpers.ExecutionLimits(
                wall_time_ms=30_000,
                stdout_bytes=1_048_576,
                stderr_bytes=1_048_576,
                memory_bytes=2_147_483_648,
                cpu_time_seconds=30,
            ),
            cwd=ROOT,
            environment=environment,
            stdin=canonical_bytes(request),
        )
        if execution.outcome != "completed" or execution.exit_code != 0:
            diagnostic = execution.stderr.decode("utf-8", "replace")[:1024]
            raise RuntimeError(
                "isolated CPython target process failed before a qualified "
                f"observation: {execution.outcome}/{execution.exit_code}: {diagnostic}"
            )
        try:
            wrapper = loads_strict(execution.stdout.decode("utf-8", "strict"))
        except Exception as error:
            raise RuntimeError(
                "isolated CPython target emitted invalid strict UTF-8 JSON"
            ) from error
        if (
            not isinstance(wrapper, dict)
            or canonical_bytes(wrapper) + b"\n" != execution.stdout
        ):
            raise RuntimeError("isolated CPython target output is not canonical JSON")
        if wrapper.get("schema_version") == "scale-isolated-target-result.v1":
            if (
                set(wrapper) != {"outcome", "response", "schema_version"}
                or wrapper["outcome"] != "adapter-response"
            ):
                raise RuntimeError("isolated CPython response wrapper is malformed")
            result = wrapper["response"]
        elif wrapper.get("schema_version") == "scale-target-timeout.v1":
            result = {**wrapper, "process_execution": execution.to_dict()}
            validate_instance(
                result,
                load_strict(
                    ROOT / "schemas" / "json" / "scale-target-timeout.schema.json"
                ),
                source="isolated CPython target timeout",
            )
            if (
                result["logical_execution_id"] != logical["logical_execution_id"]
                or result["adapter_release_manifest_id"] != package.manifest_id
                or result["profile_id"] != package.profile_id
                or result["target_release_id"] != package.target_release_id
                or result["trace_reference"] != request["trace_reference"]
                or result["timer"]["wall_time_ms"] != request["limits"]["wall_time_ms"]
                or {
                    fact["name"]: fact["value"]
                    for fact in result["runtime_identity"]["facts"]
                }
                != dict(package.runtime_constraints)
            ):
                raise RuntimeError(
                    "isolated CPython timeout did not bind the exact target request"
                )
        else:
            raise RuntimeError("isolated CPython target result kind is unknown")
        return result, execution.to_dict()

    def _invoke(
        self,
        selection_key: str,
        ready: Any,
        package: AdapterManifest,
        logicals: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        offer = adapter_helpers._offer(package)
        offer["correlation_id"] = f"scale-{selection_key}"
        requests = [item["request"] for item in logicals]
        request_schema = load_strict(
            ROOT / "schemas" / "json" / "adapter-request.schema.json"
        )
        for index, request in enumerate(requests):
            validate_instance(request, request_schema, source=f"scale request[{index}]")
        command, environment, binding = self._command(selection_key, ready)
        isolated_logicals = [
            item
            for item in logicals
            if selection_key == "python-re"
            and item["request"]["limits"]["wall_time_ms"]
            <= MAXIMUM_ISOLATED_TARGET_WALL_TIME_MS
        ]
        isolated_ids = {item["logical_execution_id"] for item in isolated_logicals}
        batched_logicals = [
            item
            for item in logicals
            if item["logical_execution_id"] not in isolated_ids
        ]
        batched_requests = [item["request"] for item in batched_logicals]
        execution = ContainedProcessSupervisor(maximum_concurrency=1).run(
            command,
            limits=self._limits(selection_key),
            cwd=ROOT,
            environment=environment,
            stdin=b"".join(encode_frame(item) for item in [offer, *batched_requests]),
        )
        if execution.outcome != "completed" or execution.exit_code != 0:
            diagnostic = execution.stderr.decode("utf-8", "replace")[:1024]
            raise RuntimeError(
                f"scale adapter failed for {selection_key}: "
                f"{execution.outcome}/{execution.exit_code}: {diagnostic}"
            )
        frames = adapter_helpers._decode_frames(execution.stdout)
        if len(frames) != len(batched_requests) + 1:
            raise RuntimeError("scale adapter response count differs from its shard")
        handshake, *responses = frames
        validate_instance(
            handshake,
            load_strict(ROOT / "schemas" / "json" / "adapter-handshake.schema.json"),
            source="scale handshake",
        )
        response_schema = load_strict(
            ROOT / "schemas" / "json" / "adapter-response.schema.json"
        )
        for index, response in enumerate(responses):
            validate_instance(
                response, response_schema, source=f"scale response[{index}]"
            )
        if (
            handshake["outcome"] != "accepted"
            or handshake["adapter_release_manifest_id"] != package.manifest_id
            or handshake["runtime_identity"]["profile_id"] != package.profile_id
            or handshake["runtime_identity"]["target_release_id"]
            != package.target_release_id
            or handshake["canonical_authority"]
            or handshake["semantic_authority"]
        ):
            raise RuntimeError("scale handshake did not bind the exact runtime")
        batched_ids = [item["logical_execution_id"] for item in batched_logicals]
        if [item["correlation_id"] for item in responses] != batched_ids:
            raise RuntimeError("scale responses changed logical correlation order")
        results_by_logical = {item["correlation_id"]: item for item in responses}
        isolated_processes: list[dict[str, Any]] = []
        for logical in isolated_logicals:
            result, process_execution = self._invoke_isolated_python_target(
                command, environment, package, logical
            )
            if result.get("schema_version") == "adapter-response.v1":
                validate_instance(
                    result,
                    response_schema,
                    source="isolated CPython adapter response",
                )
                result_id = result["correlation_id"]
            elif result.get("schema_version") == "scale-target-timeout.v1":
                result_id = result["logical_execution_id"]
            else:
                raise RuntimeError(
                    "isolated CPython result kind changed after validation"
                )
            if (
                result_id != logical["logical_execution_id"]
                or result_id in results_by_logical
            ):
                raise RuntimeError(
                    "isolated CPython result changed or duplicated logical identity"
                )
            results_by_logical[result_id] = result
            isolated_processes.append(
                {
                    "logical_execution_id": result_id,
                    "process_execution": process_execution,
                }
            )
        logical_ids = [item["logical_execution_id"] for item in logicals]
        if set(results_by_logical) != set(logical_ids):
            raise RuntimeError("scale target results do not cover the exact shard")
        results = [results_by_logical[logical_id] for logical_id in logical_ids]
        provider = self.providers[selection_key]
        definition = self.definitions[selection_key]
        assert isinstance(provider, CertifiedEnvironmentProvider)
        provenance = {
            "adapter_release_manifest_id": package.manifest_id,
            "adapter_source_digest": package.source_digest,
            "environment_fingerprint_id": ready.environment_fingerprint_id,
            "environment_recipe_revision_id": definition.lifecycle.recipe_revision_id,
            "environment_verification_digest": ready.verification_digest,
            "handshake_transcript_sha256": handshake["transcript_sha256"],
            "isolated_target_processes": isolated_processes,
            "process_execution": execution.to_dict(),
            "protocol_revision_id": package.protocol_revision_id,
            "provider_implementation_digest": provider.descriptor.implementation_digest,
            "runtime_binding": binding,
            "selection_key": selection_key,
        }
        return results, provenance

    def execute_shard(
        self,
        selection_key: str,
        logical_executions: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        ready = self._realize(selection_key)
        return self._invoke(
            selection_key,
            ready,
            self._package(selection_key),
            logical_executions,
        )

    def force_kill(self, selection_key: str) -> dict[str, Any]:
        ready = self._realize(selection_key)
        package = self._package(selection_key)
        offer = adapter_helpers._offer(package)
        offer["correlation_id"] = f"forced-kill-{selection_key}"
        command, environment, _binding = self._command(selection_key, ready)
        started_at = utc_now()
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        if process.stdin is None:
            raise RuntimeError("forced worker process has no controlled input")
        process.stdin.write(encode_frame(offer))
        process.stdin.flush()
        _kill_forced_worker(process)
        stdout, stderr = process.communicate(timeout=10)
        if process.returncode == 0:
            raise RuntimeError(
                "forced worker process exited successfully instead of dying"
            )
        if len(stdout) > 1_048_576 or len(stderr) > 1_048_576:
            raise RuntimeError("forced worker process exceeded bounded diagnostics")
        return {
            "ended_at": utc_now(),
            "exit_code": int(process.returncode),
            "forced": True,
            "selection_key": selection_key,
            "started_at": started_at,
            "trust_class": self.trust_class,
        }

    def close(self) -> None:
        failures: list[str] = []
        for selection_key in sorted(
            self.ready, key=lambda key: ORDER[key], reverse=True
        ):
            released = self.managers[selection_key].release(self.ready[selection_key])
            if released.state != "released":
                failures.append(selection_key)
        self.ready.clear()
        if failures:
            raise RuntimeError(
                "scale environments did not release cleanly: " + ",".join(failures)
            )


def _write_report(path: Path, report: dict[str, Any]) -> None:
    destination = path.expanduser().resolve(strict=False)
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        destination.relative_to((ROOT / "reports").resolve(strict=False))
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(report) + b"\n"
    temporary = destination.with_name(f".{destination.name}.tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if destination.read_bytes() != encoded:
        raise RuntimeError("scale compact report failed read-after-write verification")


@contextmanager
def _exclusive_lock(state_root: Path):
    with environment_certification._exclusive_certification_lock(state_root):
        yield


def _require_durable_external(path: Path, label: str) -> None:
    resolved = path.expanduser().resolve(strict=False)
    for temporary_root in (Path("/tmp"), Path("/var/tmp")):
        temporary = temporary_root.resolve(strict=False)
        try:
            resolved.relative_to(temporary)
        except ValueError:
            continue
        raise RuntimeError(
            f"{label} must use durable external storage, not {temporary}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--state-db", type=Path)
    parser.add_argument("--logical-segment-root", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--compact-report", type=Path)
    parser.add_argument(
        "--trust-class",
        choices=("development", "trusted_executioner"),
        default="development",
    )
    arguments = parser.parse_args()
    state_root = environment_certification._outside_repository(
        arguments.state_root, "scale state root"
    )
    state_db = environment_certification._outside_repository(
        arguments.state_db or state_root / "scale-recovery.sqlite",
        "scale recovery database",
    )
    logical_root = environment_certification._outside_repository(
        arguments.logical_segment_root, "logical segment root"
    )
    evidence_root = environment_certification._outside_repository(
        arguments.evidence_dir, "scale evidence directory"
    )
    for path, label in (
        (state_root, "scale state root"),
        (state_db, "scale recovery database"),
        (logical_root, "logical segment root"),
        (evidence_root, "scale evidence directory"),
    ):
        _require_durable_external(path, label)
    plan = load_strict(ROOT / "campaigns" / "compiled" / "100k-qualification.v1.json")
    worker: CertifiedScaleWorker | None = None
    try:
        with _exclusive_lock(state_root):
            logical_store = ScaleLogicalStore(ROOT, plan, logical_root)
            evidence = ScaleEvidenceStore(ROOT, evidence_root)
            with ScaleRecoveryLedger(state_db, plan["campaign_manifest_id"]) as ledger:
                worker = CertifiedScaleWorker(state_root, arguments.trust_class)
                controller = ScaleCampaignController(
                    ROOT, plan, logical_store, ledger, evidence, worker
                )
                _manifest, report = controller.execute(arguments.trust_class)
                worker.close()
                worker = None
                if arguments.compact_report is not None:
                    _write_report(arguments.compact_report, report)
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
        adapter_helpers._report_failure(error)
        return 1
    finally:
        if worker is not None:
            worker.close()


if __name__ == "__main__":
    raise SystemExit(main())
