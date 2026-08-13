#!/usr/bin/env python3
"""Certify the three thin adapters against exact realized P17 runtimes."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable

import rfc8785

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "adapters" / "python",
    ROOT / "control-plane" / "python",
    ROOT / "schemas" / "tooling" / "python",
    ROOT / "tools" / "environments",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

import certify_minimal as environment_certification
from regex_conformance_adapters.jsonio import encode_frame, read_frame
from regex_conformance_adapters.manifest import AdapterManifest, load_manifest
from regex_conformance_control_plane.certified_environments import (
    CertifiedEnvironmentProvider,
    build_certified_providers,
    load_certified_recipes,
)
from regex_conformance_control_plane.configuration import DoctorConfiguration
from regex_conformance_control_plane.containment import ContainedProcessSupervisor, ExecutionLimits
from regex_conformance_control_plane.discovery import StandardLibraryMachineDiscovery
from regex_conformance_control_plane.doctor import MachineDoctor, UtcClock
from regex_conformance_control_plane.environment_manager import EnvironmentManager
from regex_conformance_control_plane.environment_providers import ProviderRegistry
from regex_conformance_control_plane.models import DoctorReport, ProviderCapability
from regex_conformance_control_plane.resource_models import ResourceEstimate
from regex_conformance_control_plane.resource_planner import ResourcePlanner
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.schema import validate_instance, validate_repository

ORDER = {"pcre2-ordinary": 0, "python-re": 1, "mysql-regex": 2}
CASE_COUNT = 3
MAXIMUM_PROCESS_ATTEMPTS = 2
RETRYABLE_INFRASTRUCTURE_FAILURES = {
    "mysql-regex": frozenset(
        {
            "mysql-client-failed",
            "mysql-client-launch-failed",
            "mysql-client-timeout",
            "mysql-service-unavailable",
            "runtime-identity-failed",
        }
    ),
}


def _outside_repository(path: Path, label: str) -> Path:
    return environment_certification._outside_repository(path, label)


def _health_checked_inventory(report: DoctorReport, provider: CertifiedEnvironmentProvider) -> DoctorReport:
    diagnosis = provider.health_check()
    if diagnosis.status != "healthy":
        raise RuntimeError("; ".join(diagnosis.diagnostics))
    observations = list(report.providers)
    matches = [index for index, item in enumerate(observations) if item.name == provider.machine_provider_name]
    if len(matches) != 1:
        raise RuntimeError(f"machine provider inventory is ambiguous for {provider.machine_provider_name}")
    original = observations[matches[0]]
    observations[matches[0]] = ProviderCapability(
        name=provider.machine_provider_name,
        availability="available",
        strategies=tuple(sorted(set(original.strategies) | {provider.definition.lifecycle.strategy})),
        source=f"certified-provider-health-check:{provider.descriptor.implementation_digest}",
        observed_at=report.observed_at,
        accuracy="exact",
        visibility="process",
        staleness_seconds=0,
        executable=original.executable,
        diagnostic="; ".join(diagnosis.diagnostics),
    )
    return replace(report, providers=tuple(sorted(observations, key=lambda item: item.name)))


def _scalar(value: str) -> dict[str, Any]:
    return {
        "domain": "unicode-scalars",
        "encoding": "unicode-scalar-values",
        "endianness": None,
        "text": value,
        "unit_width_bits": None,
    }


def _octets(value: bytes) -> dict[str, Any]:
    return {
        "data": base64.urlsafe_b64encode(value).decode("ascii").rstrip("="),
        "domain": "octets",
        "encoding": None,
        "endianness": None,
        "unit_width_bits": 8,
    }


def _offer(package: AdapterManifest) -> dict[str, Any]:
    required = ["observation-runtime-identity", "operation-search"]
    return {
        "correlation_id": f"certify-{package.selection_key}",
        "limits": {
            "maximum_frame_bytes": 1_048_576,
            "maximum_list_items": 65_536,
            "maximum_message_count": 1_000_000,
            "maximum_nesting_depth": 32,
        },
        "message_type": "handshake-offer",
        "offered_schema_versions": list(package.schema_versions),
        "optional_capabilities": sorted(set(package.capabilities) - set(required)),
        "protocol": {"major": 1, "maximum_minor": 0, "minimum_minor": 0},
        "required_capabilities": required,
        "schema_version": "adapter-handshake-offer.v1",
    }


def _target_values(selection_key: str) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    if selection_key == "pcre2-ordinary":
        return (
            _octets(b"a+"),
            [],
            [
                {"name": "locale", "value": "C.UTF-8"},
                {"name": "newline", "value": "LF"},
                {"name": "timezone", "value": "UTC"},
            ],
        )
    if selection_key == "python-re":
        return (
            _scalar("a+"),
            [],
            [{"name": "locale", "value": "C.UTF-8"}, {"name": "timezone", "value": "UTC"}],
        )
    return (
        _scalar("a+"),
        [{"name": "match-type", "value": "c"}],
        [
            {"name": "character-set", "value": "utf8mb4"},
            {"name": "collation", "value": "utf8mb4_0900_ai_ci"},
            {"name": "regexp-time-limit-ms", "value": 1_000},
            {"name": "timezone", "value": "UTC"},
        ],
    )


def _request(
    package: AdapterManifest,
    *,
    correlation_id: str,
    pattern: dict[str, Any],
    subject: dict[str, Any],
    options: list[dict[str, Any]],
    environment: list[dict[str, Any]],
    operation: str = "search",
    callback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "adapter_release_manifest_id": package.manifest_id,
        "callback_fixture": callback,
        "correlation_id": correlation_id,
        "environment_inputs": environment,
        "initial_state": {"occurrence": 1, "start_offset": 0},
        "limits": {
            "maximum_diagnostic_bytes": 65_536,
            "maximum_matches": 100,
            "maximum_output_bytes": 1_048_576,
            "wall_time_ms": 30_000,
        },
        "message_type": "execute",
        "operation": {"name": operation, "version": "1.0.0"},
        "options": options,
        "pattern": pattern,
        "profile_id": package.profile_id,
        "replacement": None,
        "requested_observations": [
            "captures",
            "compile-diagnostics",
            "match-state",
            "native-errors",
            "runtime-identity",
            "spans",
        ],
        "schema_version": "adapter-request.v1",
        "subjects": [subject],
        "target_release_id": package.target_release_id,
        "trace_reference": f"minimal-adapter-certification:{package.selection_key}:{correlation_id}",
    }


def _requests(package: AdapterManifest) -> list[dict[str, Any]]:
    pattern, options, environment = _target_values(package.selection_key)
    subject = _octets(b"baaac") if package.selection_key == "pcre2-ordinary" else _scalar("baaac")
    invalid = _octets(b"(") if package.selection_key == "pcre2-ordinary" else _scalar("(")
    return [
        _request(
            package,
            correlation_id="positive-match",
            pattern=pattern,
            subject=subject,
            options=options,
            environment=environment,
        ),
        _request(
            package,
            correlation_id="native-compile-error",
            pattern=invalid,
            subject=subject,
            options=options,
            environment=environment,
        ),
        _request(
            package,
            correlation_id="unsupported-callback",
            pattern=pattern,
            subject=subject,
            options=options,
            environment=environment,
            operation="callback-replacement",
            callback={"fixture_id": "literal", "parameters": []},
        ),
    ]


def _shared_pcre2_library(root: Path) -> Path:
    install = root / "install"
    candidates = sorted(path for path in install.rglob("libpcre2-8.so*") if path.is_file() and not path.is_symlink())
    if len(candidates) != 1:
        raise RuntimeError(f"expected one exact non-link PCRE2 shared library, observed {len(candidates)}")
    resolved = candidates[0].resolve(strict=True)
    resolved.relative_to(install.resolve(strict=True))
    return resolved


def _adapter_command(selection_key: str, ready: Any) -> tuple[tuple[str, ...], dict[str, str], str | None]:
    root = Path(ready.provider_handle).resolve(strict=True)
    environment = {
        "HOME": str(root / "adapter-home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TZ": "UTC",
    }
    Path(environment["HOME"]).mkdir(exist_ok=True)
    binding: str | None = None
    if selection_key == "python-re":
        runtime = root / "runtime"
        executable = runtime / "bin" / "python3.14"
        environment["LD_LIBRARY_PATH"] = str(runtime / "lib")
        command = (str(executable), "-I", str(ROOT / "adapters" / "python" / "run.py"), "--selection-key", selection_key)
    elif selection_key == "pcre2-ordinary":
        library = _shared_pcre2_library(root)
        binding = str(library)
        environment["LD_LIBRARY_PATH"] = str(library.parent)
        command = (
            sys.executable,
            "-I",
            str(ROOT / "adapters" / "python" / "run.py"),
            "--selection-key",
            selection_key,
            "--runtime-binding",
            binding,
        )
    else:
        suffix = ready.transaction_id.rsplit(":", 1)[-1]
        container = "strling-rc-" + suffix.replace("-", "")
        metadata = load_strict(root / "provider-state.json")
        if metadata.get("container") != container:
            raise RuntimeError("MySQL provider container identity did not match transaction metadata")
        binding = container
        command = (
            sys.executable,
            "-I",
            str(ROOT / "adapters" / "python" / "run.py"),
            "--selection-key",
            selection_key,
            "--runtime-binding",
            binding,
        )
    return command, environment, binding


def _decode_frames(payload: bytes) -> list[dict[str, Any]]:
    stream = BytesIO(payload)
    result: list[dict[str, Any]] = []
    while True:
        frame = read_frame(stream)
        if frame is None:
            break
        if not isinstance(frame, dict):
            raise RuntimeError("adapter emitted a non-object frame")
        result.append(frame)
    return result


def _adapter_process_limits(selection_key: str) -> ExecutionLimits:
    memory = {
        "pcre2-ordinary": 4_294_967_296,
        "python-re": 2_147_483_648,
    }.get(selection_key)
    cpu = 120 if selection_key in {"pcre2-ordinary", "python-re"} else None
    return ExecutionLimits(
        wall_time_ms=120_000,
        stdout_bytes=4 * 1024 * 1024,
        stderr_bytes=1 * 1024 * 1024,
        memory_bytes=memory,
        cpu_time_seconds=cpu,
    )


def _adapter_failure_code(stderr: bytes) -> str | None:
    try:
        lines = [line for line in stderr.decode("utf-8", "strict").splitlines() if line]
        value = json.loads(lines[-1]) if lines else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("ok") is not False:
        return None
    error = value.get("error")
    code = error.get("code") if isinstance(error, dict) else None
    return code if isinstance(code, str) else None


def _run_adapter_process_attempts(
    selection_key: str,
    run_attempt: Callable[[], Any],
    completed_failure_code: Callable[[Any], str | None] | None = None,
) -> tuple[Any, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    retryable = RETRYABLE_INFRASTRUCTURE_FAILURES.get(selection_key, frozenset())
    for attempt_number in range(1, MAXIMUM_PROCESS_ATTEMPTS + 1):
        execution = run_attempt()
        process_succeeded = execution.outcome == "completed" and execution.exit_code == 0
        if process_succeeded:
            failure_code = None if completed_failure_code is None else completed_failure_code(execution)
        else:
            failure_code = _adapter_failure_code(execution.stderr)
        succeeded = process_succeeded and failure_code is None
        attempts.append(
            {
                "attempt_number": attempt_number,
                "execution": execution.to_dict(),
                "failure_code": failure_code,
                "selected": succeeded,
            }
        )
        if succeeded:
            return execution, attempts
        if attempt_number < MAXIMUM_PROCESS_ATTEMPTS and failure_code in retryable:
            continue
        diagnostic = execution.stderr.decode("utf-8", "replace")[:1024]
        raise RuntimeError(
            f"adapter process failed for {selection_key}: "
            f"{execution.outcome}/{execution.exit_code}, failure_code={failure_code}: {diagnostic}"
        )
    raise AssertionError("bounded adapter attempt loop terminated without a result")


def _completed_invocation_failure_code(
    execution: Any,
    response_schema: dict[str, Any] | None = None,
) -> str | None:
    try:
        frames = _decode_frames(execution.stdout)
    except Exception:
        return None
    if len(frames) != CASE_COUNT + 1 or not isinstance(frames[1], dict):
        return None
    response = frames[1]
    if response_schema is not None:
        try:
            validate_instance(response, response_schema, source="retry-candidate-response")
        except Exception:
            return None
    failure = response.get("failure")
    if (
        response.get("status") != "failed"
        or not isinstance(failure, dict)
        or failure.get("layer") != "invocation"
        or failure.get("kind") != "adapter-invocation"
    ):
        return None
    code = failure.get("code")
    return code if isinstance(code, str) else None


def _invoke_adapter(selection_key: str, ready: Any, package: AdapterManifest) -> dict[str, Any]:
    requests = _requests(package)
    stdin = b"".join(encode_frame(item) for item in [_offer(package), *requests])
    command, environment, binding = _adapter_command(selection_key, ready)
    limits = _adapter_process_limits(selection_key)
    response_schema = load_strict(ROOT / "schemas" / "json" / "adapter-response.schema.json")
    supervisor = ContainedProcessSupervisor(maximum_concurrency=1)
    execution, process_attempts = _run_adapter_process_attempts(
        selection_key,
        lambda: supervisor.run(
            command,
            limits=limits,
            cwd=ROOT,
            environment=environment,
            stdin=stdin,
        ),
        lambda execution: _completed_invocation_failure_code(execution, response_schema),
    )
    frames = _decode_frames(execution.stdout)
    if len(frames) != CASE_COUNT + 1:
        raise RuntimeError(f"adapter emitted {len(frames)} frames; expected {CASE_COUNT + 1}")
    handshake, *responses = frames
    validate_instance(handshake, load_strict(ROOT / "schemas" / "json" / "adapter-handshake.schema.json"), source="handshake")
    for index, response in enumerate(responses):
        validate_instance(response, response_schema, source=f"response[{index}]")
    if (
        handshake["outcome"] != "accepted"
        or handshake["adapter_release_manifest_id"] != package.manifest_id
        or handshake["runtime_identity"]["profile_id"] != package.profile_id
        or handshake["runtime_identity"]["target_release_id"] != package.target_release_id
        or set(handshake["capabilities"]) != set(package.capabilities)
        or handshake["canonical_authority"]
        or handshake["semantic_authority"]
    ):
        raise RuntimeError("adapter handshake did not bind the exact package/runtime identity")
    observed_facts = {item["name"]: item["value"] for item in handshake["runtime_identity"]["facts"]}
    for name, value in package.runtime_constraints:
        if observed_facts.get(name) != value:
            raise RuntimeError(f"adapter runtime fact mismatch for {selection_key}: {name}")
    positive, native_error, unsupported = responses
    if positive["status"] != "completed" or positive["observation"]["match_state"] != "match":
        failure_code = None if positive["failure"] is None else positive["failure"]["code"]
        observation = positive["observation"]
        match_state = None if observation is None else observation["match_state"]
        target_error = None if observation is None else observation["native_error"]
        native_code = None if target_error is None else target_error["code"]
        native_message = None if target_error is None else target_error["message"][:512]
        raise RuntimeError(
            "positive adapter case did not preserve the target match observation "
            f"for {selection_key}: status={positive['status']}, "
            f"failure={failure_code}, match_state={match_state}, "
            f"native_code={native_code}, native_message={native_message}"
        )
    if (
        native_error["status"] != "completed"
        or native_error["observation"]["compile_status"] != "rejected"
        or native_error["observation"]["native_error"] is None
    ):
        raise RuntimeError("native compile rejection was not preserved as a target observation")
    if (
        unsupported["status"] != "unsupported"
        or unsupported["observation"] is not None
        or unsupported["failure"]["layer"] != "materialization"
    ):
        raise RuntimeError("unsupported operation was not distinguished from target behavior")
    for response in responses:
        if response["canonical_authority"] or response["semantic_authority"] or "verdict" in response:
            raise RuntimeError("adapter response claimed forbidden semantic authority")
    return {
        "runtime_binding": binding,
        "handshake": handshake,
        "responses": responses,
        "process_execution": execution.to_dict(),
        "process_attempts": process_attempts,
    }


def _atomic_content_addressed(directory: Path, payload: dict[str, Any]) -> tuple[str, Path]:
    encoded = rfc8785.dumps(payload) + b"\n"
    digest = hashlib.sha256(encoded).hexdigest()
    path = directory / f"minimal-adapter-certification-sha256-{digest}.json"
    directory.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != encoded:
            raise RuntimeError("content-addressed adapter certification path contains different bytes")
        return digest, path
    temporary = directory / f".{path.name}.tmp"
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return digest, path


def _write_compact(path: Path, payload: dict[str, Any]) -> None:
    destination = path.expanduser().resolve(strict=False)
    try:
        destination.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        destination.relative_to((ROOT / "reports").resolve())
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = rfc8785.dumps(payload) + b"\n"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


def _report_failure(error: Exception) -> None:
    """Preserve machine output and expose a bounded public-CI annotation."""
    diagnostic = str(error)
    failure = {
        "error_type": type(error).__name__,
        "diagnostic": diagnostic,
        "ok": False,
    }
    print(rfc8785.dumps(failure).decode("utf-8"), file=sys.stderr)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        bounded = diagnostic[:1_000]
        escaped = bounded.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(
            f"::error title=Minimal adapter certification failed::{type(error).__name__}: {escaped}",
            file=sys.stderr,
        )


def certify(state_root: Path, evidence_dir: Path, trust_class: str, compact_report: Path | None) -> dict[str, Any]:
    schema_counts = validate_repository(ROOT)
    definitions = tuple(sorted(load_certified_recipes(ROOT), key=lambda item: ORDER[item.selection_key]))
    providers = build_certified_providers(definitions, state_root)
    manager = EnvironmentManager(ProviderRegistry(providers))
    planner = ResourcePlanner(environment_certification._policy())
    doctor = MachineDoctor(StandardLibraryMachineDiscovery(), UtcClock())
    configuration: DoctorConfiguration = environment_certification._doctor_configuration(state_root, trust_class)
    results: list[dict[str, Any]] = []

    for definition, untyped_provider in zip(definitions, providers, strict=True):
        provider = untyped_provider
        assert isinstance(provider, CertifiedEnvironmentProvider)
        package = load_manifest(ROOT, definition.selection_key)
        planned = manager.plan(definition.lifecycle, provider.descriptor.name)
        if planned.state != "planned":
            raise RuntimeError(f"environment planning failed for {definition.selection_key}: {planned.failure}")
        inventory = _health_checked_inventory(doctor.inspect(configuration), provider)
        memory = definition.limits.memory_bytes
        supplemental = () if memory is None else (
            ResourceEstimate("environment-memory-ceiling", "ram", "bytes", memory, memory, "bounded", "isolation-policy"),
        )
        resource_plan = planner.environment_plan(
            planned,
            machine_provider_name=provider.machine_provider_name,
            estimate_confidence="bounded",
            supplemental_estimates=supplemental,
            eligible_trust_classes=(trust_class,),
        )
        admission_report = planner.preflight(resource_plan, inventory)
        admitted = manager.admit(planned, planner.environment_decision(planned, admission_report))
        if admitted.state != "admitted":
            raise RuntimeError(
                f"resource admission rejected {definition.selection_key}: "
                + "; ".join(f"{item.code}: {item.message}" for item in admission_report.issues)
            )
        ready = manager.realize(admitted)
        if ready.state != "ready":
            raise RuntimeError(f"environment realization failed: {manager.diagnose(ready).to_dict()}")
        adapter_result: dict[str, Any] | None = None
        released = None
        try:
            adapter_result = _invoke_adapter(definition.selection_key, ready, package)
        finally:
            released = manager.release(ready)
        if released.state != "released":
            raise RuntimeError(f"environment release failed for {definition.selection_key}: {released.failure}")
        assert adapter_result is not None
        response_hash = hashlib.sha256(rfc8785.dumps(adapter_result["responses"])).hexdigest()
        process_hash = hashlib.sha256(rfc8785.dumps(adapter_result["process_execution"])).hexdigest()
        process_attempts_hash = hashlib.sha256(rfc8785.dumps(adapter_result["process_attempts"])).hexdigest()
        results.append(
            {
                "selection_key": definition.selection_key,
                "adapter_id": package.adapter_id,
                "adapter_release_id": package.adapter_release_id,
                "adapter_release_manifest_id": package.manifest_id,
                "adapter_source_digest": package.source_digest,
                "protocol_revision_id": package.protocol_revision_id,
                "recipe_revision_id": definition.lifecycle.recipe_revision_id,
                "target_profile_id": package.profile_id,
                "target_release_id": package.target_release_id,
                "environment_fingerprint_id": ready.environment_fingerprint_id,
                "environment_verification_digest": ready.verification_digest,
                "provider_implementation_digest": provider.descriptor.implementation_digest,
                "handshake_transcript_sha256": adapter_result["handshake"]["transcript_sha256"],
                "response_set_sha256": response_hash,
                "process_execution_sha256": process_hash,
                "process_execution": adapter_result["process_execution"],
                "process_attempts_sha256": process_attempts_hash,
                "process_attempt_count": len(adapter_result["process_attempts"]),
                "infrastructure_retry_count": len(adapter_result["process_attempts"]) - 1,
                "process_attempts": adapter_result["process_attempts"],
                "certified_case_count": CASE_COUNT,
                "case_statuses": [item["status"] for item in adapter_result["responses"]],
                "release_state": released.state,
                "runtime_binding": adapter_result["runtime_binding"],
                "responses": adapter_result["responses"],
            }
        )

    payload = {
        "schema_version": "minimal-adapter-certification-evidence.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "repository_state": environment_certification._repository_state(),
        "adapter_certification_evidence": True,
        "normative_authority": False,
        "semantic_authority": False,
        "trust_class": trust_class,
        "schema_validation_counts": schema_counts,
        "protocol_revision_id": results[0]["protocol_revision_id"],
        "results": results,
    }
    evidence_digest, evidence_path = _atomic_content_addressed(evidence_dir, payload)
    compact = {
        "schema_version": "minimal-adapter-certification.v1",
        "repository_state": payload["repository_state"],
        "observed_at": payload["observed_at"],
        "evidence_sha256": evidence_digest,
        "evidence_filename": evidence_path.name,
        "trust_class": trust_class,
        "protocol_revision_id": payload["protocol_revision_id"],
        "all_ready_exercised_and_released": len(results) == 3 and all(item["release_state"] == "released" for item in results),
        "results": [
            {
                key: item[key]
                for key in (
                    "selection_key",
                    "adapter_release_manifest_id",
                    "adapter_source_digest",
                    "recipe_revision_id",
                    "target_profile_id",
                    "target_release_id",
                    "environment_fingerprint_id",
                    "environment_verification_digest",
                    "provider_implementation_digest",
                    "handshake_transcript_sha256",
                    "response_set_sha256",
                    "process_execution_sha256",
                    "process_attempts_sha256",
                    "process_attempt_count",
                    "infrastructure_retry_count",
                    "certified_case_count",
                    "case_statuses",
                )
            }
            for item in results
        ],
    }
    if compact_report is not None:
        _write_compact(compact_report, compact)
    return compact


@contextmanager
def _exclusive_lock(state_root: Path):
    with environment_certification._exclusive_certification_lock(state_root):
        yield


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument(
        "--trust-class",
        choices=("development", "trusted_executioner", "untrusted_public"),
        default="development",
    )
    parser.add_argument("--compact-report", type=Path)
    arguments = parser.parse_args()
    state_root = _outside_repository(arguments.state_root, "state root")
    evidence_dir = _outside_repository(arguments.evidence_dir, "evidence directory")
    try:
        with _exclusive_lock(state_root):
            compact = certify(state_root, evidence_dir, arguments.trust_class, arguments.compact_report)
    except Exception as error:
        _report_failure(error)
        return 1
    sys.stdout.buffer.write(rfc8785.dumps({"ok": True, **compact}) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
