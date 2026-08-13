#!/usr/bin/env python3
"""Realize, independently verify, fingerprint, and release the P17 environments."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sys
from typing import Any

import rfc8785

ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "control-plane" / "python", ROOT / "schemas" / "tooling" / "python"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_control_plane.certified_environments import (
    CertifiedEnvironmentProvider,
    build_certified_providers,
    load_certified_recipes,
)
from regex_conformance_control_plane.configuration import DoctorConfiguration
from regex_conformance_control_plane.discovery import StandardLibraryMachineDiscovery
from regex_conformance_control_plane.doctor import MachineDoctor, UtcClock
from regex_conformance_control_plane.environment_manager import EnvironmentManager
from regex_conformance_control_plane.environment_providers import ProviderRegistry
from regex_conformance_control_plane.models import DoctorReport, ProviderCapability
from regex_conformance_control_plane.resource_models import (
    AdmissionPolicy,
    ConfidenceMargin,
    PoolSafetyReserve,
    ResourceEstimate,
)
from regex_conformance_control_plane.resource_planner import ResourcePlanner
from regex_conformance_schema.schema import validate_repository


def _outside_repository(path: Path, label: str) -> Path:
    candidate = path.expanduser().resolve(strict=False)
    try:
        candidate.relative_to(ROOT)
    except ValueError:
        return candidate
    raise ValueError(f"{label} must remain outside the Git repository")


def _policy() -> AdmissionPolicy:
    return AdmissionPolicy(
        confidence_margins=(
            ConfidenceMargin("bounded", 2500),
            ConfidenceMargin("estimated", 1500),
            ConfidenceMargin("known", 0),
            ConfidenceMargin("measured", 500),
        ),
        pool_reserves=(
            PoolSafetyReserve("build_scratch", 512 * 1024 * 1024, 500),
            PoolSafetyReserve("environment_cache", 512 * 1024 * 1024, 500),
            PoolSafetyReserve("persistent_disk", 256 * 1024 * 1024, 250),
        ),
        max_concurrency=1,
        inventory_max_age_seconds=300,
    )


def _doctor_configuration(state_root: Path, trust_class: str) -> DoctorConfiguration:
    pool_base = state_root.parent / "resource-pools"
    return DoctorConfiguration.from_environment(
        {},
        trust_override=trust_class,
        inventory_max_age_seconds=300,
        system="Linux",
        pool_overrides={
            "persistent_disk": pool_base / "persistent",
            "environment_cache": state_root,
            "build_scratch": pool_base / "build",
            "execution_scratch": pool_base / "execution",
            "result_spool": pool_base / "spool",
        },
    )


def _health_checked_inventory(
    report: DoctorReport,
    provider: CertifiedEnvironmentProvider,
) -> DoctorReport:
    diagnosis = provider.health_check()
    if diagnosis.status != "healthy":
        raise RuntimeError("; ".join(diagnosis.diagnostics))
    name = provider.machine_provider_name
    observations = list(report.providers)
    matches = [index for index, item in enumerate(observations) if item.name == name]
    if len(matches) != 1:
        raise RuntimeError(f"machine provider inventory is ambiguous for {name}")
    original = observations[matches[0]]
    observations[matches[0]] = ProviderCapability(
        name=name,
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


def _atomic_content_addressed(directory: Path, payload: dict[str, Any]) -> tuple[str, Path]:
    encoded = rfc8785.dumps(payload) + b"\n"
    digest = hashlib.sha256(encoded).hexdigest()
    path = directory / f"minimal-environment-certification-sha256-{digest}.json"
    directory.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != encoded:
            raise RuntimeError("content-addressed certification path contains different bytes")
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
    repository_root = ROOT.resolve()
    reports_root = (ROOT / "reports").resolve()
    try:
        destination.relative_to(repository_root)
    except ValueError:
        pass
    else:
        try:
            destination.relative_to(reports_root)
        except ValueError as error:
            raise ValueError("in-repository compact reports must remain inside reports") from error
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = rfc8785.dumps(payload) + b"\n"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


def certify(state_root: Path, evidence_dir: Path, trust_class: str, compact_report: Path | None) -> dict[str, Any]:
    schema_counts = validate_repository(ROOT)
    definitions = load_certified_recipes(ROOT)
    order = {"pcre2-ordinary": 0, "python-re": 1, "mysql-regex": 2}
    definitions = tuple(sorted(definitions, key=lambda item: order[item.selection_key]))
    providers = build_certified_providers(definitions, state_root)
    registry = ProviderRegistry(providers)
    manager = EnvironmentManager(registry)
    planner = ResourcePlanner(_policy())
    doctor = MachineDoctor(StandardLibraryMachineDiscovery(), UtcClock())
    configuration = _doctor_configuration(state_root, trust_class)
    results: list[dict[str, Any]] = []

    for definition, untyped_provider in zip(definitions, providers, strict=True):
        provider = untyped_provider
        assert isinstance(provider, CertifiedEnvironmentProvider)
        planned = manager.plan(definition.lifecycle, provider.descriptor.name)
        if planned.state != "planned":
            raise RuntimeError(f"environment planning failed for {definition.selection_key}: {planned.failure}")
        inventory = _health_checked_inventory(doctor.inspect(configuration), provider)
        memory = definition.limits.memory_bytes
        supplemental = () if memory is None else (
            ResourceEstimate(
                "environment-memory-ceiling", "ram", "bytes", memory, memory, "bounded", "isolation-policy"
            ),
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
            diagnosis = manager.diagnose(ready)
            raise RuntimeError(f"environment realization failed for {definition.selection_key}: {diagnosis.to_dict()}")
        released = manager.release(ready)
        if released.state != "released":
            raise RuntimeError(f"environment release failed for {definition.selection_key}: {released.failure}")
        results.append(
            {
                "selection_key": definition.selection_key,
                "environment_recipe_id": definition.record["environment_recipe_id"],
                "recipe_revision_id": definition.lifecycle.recipe_revision_id,
                "target_profile_id": definition.lifecycle.target_profile_id,
                "target_release_id": definition.lifecycle.target_release_id,
                "provider_name": provider.descriptor.name,
                "provider_implementation_digest": provider.descriptor.implementation_digest,
                "machine_provider": provider.machine_provider_name,
                "inventory_sha256": hashlib.sha256(rfc8785.dumps(inventory.to_dict())).hexdigest(),
                "admission_sha256": hashlib.sha256(rfc8785.dumps(admission_report.to_dict())).hexdigest(),
                "environment_fingerprint_id": ready.environment_fingerprint_id,
                "verification_digest": ready.verification_digest,
                "verified_artifacts": [item.to_dict() for item in ready.verified_artifacts],
                "runtime_identity": ready.runtime_identity.to_dict() if ready.runtime_identity else None,
                "smoke_observations": [item.to_dict() for item in ready.smoke_observations],
                "ready_transition_count": len(ready.transitions),
                "release_state": released.state,
                "trust_class": inventory.trust.trust_class,
            }
        )

    payload = {
        "schema_version": "minimal-environment-certification-evidence.v1",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "repository_state": _repository_state(),
        "environment_certification_evidence": True,
        "normative_authority": False,
        "semantic_authority": False,
        "trust_class": trust_class,
        "schema_validation_counts": schema_counts,
        "results": results,
    }
    evidence_digest, evidence_path = _atomic_content_addressed(evidence_dir, payload)
    compact = {
        "schema_version": "minimal-environment-certification.v1",
        "repository_state": payload["repository_state"],
        "observed_at": payload["observed_at"],
        "evidence_sha256": evidence_digest,
        "evidence_filename": evidence_path.name,
        "trust_class": trust_class,
        "all_ready_and_released": len(results) == 3 and all(item["release_state"] == "released" for item in results),
        "results": [
            {
                "selection_key": item["selection_key"],
                "recipe_revision_id": item["recipe_revision_id"],
                "target_profile_id": item["target_profile_id"],
                "target_release_id": item["target_release_id"],
                "environment_fingerprint_id": item["environment_fingerprint_id"],
                "verification_digest": item["verification_digest"],
                "provider_implementation_digest": item["provider_implementation_digest"],
                "smoke_probe_count": len(item["smoke_observations"]),
            }
            for item in results
        ],
    }
    if compact_report is not None:
        _write_compact(compact_report, compact)
    return compact


def _repository_state() -> dict[str, Any]:
    import subprocess

    revision = subprocess.run(
        ("git", "rev-parse", "HEAD"), cwd=ROOT, check=True, capture_output=True, text=True, timeout=10
    )
    value = revision.stdout.strip()
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("repository HEAD is not a full SHA-1 commit identity")
    status = subprocess.run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return {"head_commit": value, "worktree_clean": not bool(status.stdout)}


@contextmanager
def _exclusive_certification_lock(state_root: Path):
    """Prevent concurrent certification against the same operational state root."""
    import fcntl
    import stat

    state_root.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_root.parent / f".{state_root.name}.minimal-certification.lock"
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError("certification lock path is not a regular file")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(f"certification is already active for state root {state_root}") from error
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


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
    with _exclusive_certification_lock(state_root):
        compact = certify(state_root, evidence_dir, arguments.trust_class, arguments.compact_report)
    sys.stdout.buffer.write(rfc8785.dumps({"ok": True, **compact}) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
