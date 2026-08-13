#!/usr/bin/env python3
"""Execute the first campaign through exact environments, thin adapters, evidence, and warehouse."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
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
    ROOT / "warehouse" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

import certify_minimal as environment_certification
from regex_conformance_adapters.jsonio import encode_frame
from regex_conformance_adapters.manifest import AdapterManifest, load_manifest
from regex_conformance_campaign import compile_vertical_slice, verify_compiled_campaign
from regex_conformance_control_plane.campaign_manager import CampaignCoordinator
from regex_conformance_control_plane.certified_environments import (
    CertifiedEnvironmentProvider,
    build_certified_providers,
    load_certified_recipes,
)
from regex_conformance_control_plane.containment import ContainedProcessSupervisor
from regex_conformance_control_plane.discovery import StandardLibraryMachineDiscovery
from regex_conformance_control_plane.doctor import MachineDoctor, UtcClock
from regex_conformance_control_plane.environment_manager import EnvironmentManager
from regex_conformance_control_plane.environment_providers import ProviderRegistry
from regex_conformance_control_plane.resource_models import ResourceEstimate
from regex_conformance_control_plane.resource_planner import ResourcePlanner
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance
from regex_conformance_verifier import ImmutableEvidenceStore
from regex_conformance_warehouse import build_warehouse

import importlib.util

_ADAPTER_SPEC = importlib.util.spec_from_file_location(
    "adapter_certification_helpers", ROOT / "tools" / "adapters" / "certify_minimal.py"
)
if _ADAPTER_SPEC is None or _ADAPTER_SPEC.loader is None:
    raise RuntimeError("cannot load adapter certification helpers")
adapter_certification = importlib.util.module_from_spec(_ADAPTER_SPEC)
_ADAPTER_SPEC.loader.exec_module(adapter_certification)


ORDER = {"pcre2-ordinary": 0, "python-re": 1, "mysql-regex": 2}


class CertifiedAdapterCampaignWorker:
    def __init__(self, state_root: Path, trust_class: str) -> None:
        definitions = tuple(sorted(load_certified_recipes(ROOT), key=lambda item: ORDER[item.selection_key]))
        providers = build_certified_providers(definitions, state_root)
        self.definitions = {item.selection_key: item for item in definitions}
        self.providers = {
            item.selection_key: provider for item, provider in zip(definitions, providers, strict=True)
        }
        self.manager = EnvironmentManager(ProviderRegistry(providers))
        self.planner = ResourcePlanner(environment_certification._policy())
        self.doctor = MachineDoctor(StandardLibraryMachineDiscovery(), UtcClock())
        self.configuration = environment_certification._doctor_configuration(state_root, trust_class)

    def _invoke(
        self,
        selection_key: str,
        ready: Any,
        package: AdapterManifest,
        logicals: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], str | None]:
        offer = adapter_certification._offer(package)
        offer["correlation_id"] = f"campaign-{selection_key}"
        requests = [item["request"] for item in logicals]
        request_schema = load_strict(ROOT / "schemas" / "json" / "adapter-request.schema.json")
        for index, request in enumerate(requests):
            validate_instance(request, request_schema, source=f"campaign request[{index}]")
        stdin = b"".join(encode_frame(item) for item in [offer, *requests])
        command, environment, binding = adapter_certification._adapter_command(selection_key, ready)
        execution = ContainedProcessSupervisor(maximum_concurrency=1).run(
            command,
            limits=adapter_certification._adapter_process_limits(selection_key),
            cwd=ROOT,
            environment=environment,
            stdin=stdin,
        )
        if execution.outcome != "completed" or execution.exit_code != 0:
            diagnostic = execution.stderr.decode("utf-8", "replace")[:1024]
            raise RuntimeError(
                f"adapter process failed for {selection_key}: {execution.outcome}/{execution.exit_code}: {diagnostic}"
            )
        frames = adapter_certification._decode_frames(execution.stdout)
        if len(frames) != len(requests) + 1:
            raise RuntimeError("adapter response count did not equal the shard request count")
        handshake, *responses = frames
        validate_instance(
            handshake,
            load_strict(ROOT / "schemas" / "json" / "adapter-handshake.schema.json"),
            source="campaign handshake",
        )
        response_schema = load_strict(ROOT / "schemas" / "json" / "adapter-response.schema.json")
        for index, response in enumerate(responses):
            validate_instance(response, response_schema, source=f"campaign response[{index}]")
        if (
            handshake["outcome"] != "accepted"
            or handshake["adapter_release_manifest_id"] != package.manifest_id
            or handshake["runtime_identity"]["profile_id"] != package.profile_id
            or handshake["runtime_identity"]["target_release_id"] != package.target_release_id
            or handshake["canonical_authority"]
            or handshake["semantic_authority"]
        ):
            raise RuntimeError("adapter handshake did not bind the exact campaign runtime")
        expected = [item["logical_execution_id"] for item in logicals]
        if [item["correlation_id"] for item in responses] != expected:
            raise RuntimeError("adapter responses did not preserve logical execution correlation order")
        return handshake, responses, execution.to_dict(), binding

    def execute_shard(
        self,
        selection_key: str,
        logical_executions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        definition = self.definitions[selection_key]
        provider = self.providers[selection_key]
        assert isinstance(provider, CertifiedEnvironmentProvider)
        package = load_manifest(ROOT, selection_key)
        ready = None
        released = None
        result: tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], str | None] | None = None
        try:
            planned = self.manager.plan(definition.lifecycle, provider.descriptor.name)
            if planned.state != "planned":
                raise RuntimeError(f"environment planning failed: {planned.failure}")
            inventory = adapter_certification._health_checked_inventory(
                self.doctor.inspect(self.configuration), provider
            )
            memory = definition.limits.memory_bytes
            supplemental = () if memory is None else (
                ResourceEstimate(
                    "environment-memory-ceiling", "ram", "bytes", memory, memory, "bounded", "isolation-policy"
                ),
            )
            resource_plan = self.planner.environment_plan(
                planned,
                machine_provider_name=provider.machine_provider_name,
                estimate_confidence="bounded",
                supplemental_estimates=supplemental,
                eligible_trust_classes=(self.configuration.trust_class,),
            )
            admission = self.planner.preflight(resource_plan, inventory)
            admitted = self.manager.admit(planned, self.planner.environment_decision(planned, admission))
            if admitted.state != "admitted":
                raise RuntimeError("resource admission refused the campaign shard")
            ready = self.manager.realize(admitted)
            if ready.state != "ready":
                raise RuntimeError(f"environment realization failed: {self.manager.diagnose(ready).to_dict()}")
            result = self._invoke(selection_key, ready, package, logical_executions)
        except Exception as error:
            failure = {"code": "campaign-shard-infrastructure-failure", "message": str(error)[:2048]}
            return [
                {
                    "logical_execution_id": item["logical_execution_id"],
                    "infrastructure_failure": failure,
                    "provenance": {"selection_key": selection_key},
                }
                for item in logical_executions
            ]
        finally:
            if ready is not None and ready.state == "ready":
                released = self.manager.release(ready)
        if released is None or released.state != "released":
            failure = {"code": "environment-release-failed", "message": "realized environment did not release cleanly"}
            return [
                {
                    "logical_execution_id": item["logical_execution_id"],
                    "infrastructure_failure": failure,
                    "provenance": {"selection_key": selection_key},
                }
                for item in logical_executions
            ]
        assert result is not None
        handshake, responses, process, binding = result
        provenance = {
            "adapter_release_manifest_id": package.manifest_id,
            "adapter_source_digest": package.source_digest,
            "environment_fingerprint_id": ready.environment_fingerprint_id,
            "environment_recipe_revision_id": definition.lifecycle.recipe_revision_id,
            "environment_verification_digest": ready.verification_digest,
            "handshake_transcript_sha256": handshake["transcript_sha256"],
            "process_execution": process,
            "protocol_revision_id": package.protocol_revision_id,
            "provider_implementation_digest": provider.descriptor.implementation_digest,
            "runtime_binding": binding,
            "selection_key": selection_key,
        }
        return [
            {
                "logical_execution_id": logical["logical_execution_id"],
                "response": response,
                "provenance": provenance,
            }
            for logical, response in zip(logical_executions, responses, strict=True)
        ]


def _write_compact(path: Path, payload: dict[str, Any]) -> None:
    destination = path.expanduser().resolve(strict=False)
    try:
        destination.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        destination.relative_to((ROOT / "reports").resolve(strict=False))
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = canonical_bytes(payload) + b"\n"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


@contextmanager
def _exclusive_lock(state_root: Path):
    with environment_certification._exclusive_certification_lock(state_root):
        yield


def execute(
    state_root: Path,
    evidence_dir: Path,
    warehouse_dir: Path,
    trust_class: str,
    compact_report: Path | None,
) -> dict[str, Any]:
    compiled_path = ROOT / "campaigns" / "compiled" / "first-vertical-slice.v1.json"
    compiled = load_strict(compiled_path)
    verify_compiled_campaign(ROOT, compiled)
    if canonical_bytes(compiled) != canonical_bytes(compile_vertical_slice(ROOT)):
        raise RuntimeError("checked-in campaign differs from deterministic compilation")
    evidence = ImmutableEvidenceStore(ROOT, evidence_dir)
    worker = CertifiedAdapterCampaignWorker(state_root, trust_class)
    coordinator = CampaignCoordinator(
        NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")
    )
    evidence_manifest = coordinator.execute(compiled, worker, evidence)
    warehouse = build_warehouse(ROOT, warehouse_dir, compiled, evidence_manifest, evidence)
    report = {
        "schema_version": "first-campaign-report.v1",
        "campaign_manifest_id": compiled["campaign_manifest_id"],
        "evidence_manifest_id": evidence_manifest["evidence_manifest_id"],
        "evidence_manifest_sha256": evidence_manifest["manifest_reference"]["sha256"],
        "warehouse_build_id": warehouse["warehouse_build_id"],
        "warehouse_sha256": warehouse["warehouse_sha256"],
        "candidate_count": compiled["denominator"]["candidate_count"],
        "excluded_count": compiled["denominator"]["excluded_count"],
        "logical_execution_count": compiled["denominator"]["included_count"],
        "accepted_observation_count": evidence_manifest["accepted_observation_count"],
        "infrastructure_failure_count": evidence_manifest["infrastructure_failure_count"],
        "result_shard_count": len(evidence_manifest["result_shards"]),
        "reconciliation": "exact",
        "classification": compiled["classification"],
        "trust_class": trust_class,
    }
    validate_instance(
        report,
        load_strict(ROOT / "schemas" / "json" / "first-campaign-report.schema.json"),
        source="first campaign report",
    )
    if compact_report is not None:
        _write_compact(compact_report, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--warehouse-dir", type=Path, required=True)
    parser.add_argument(
        "--trust-class",
        choices=("development", "trusted_executioner", "untrusted_public"),
        default="development",
    )
    parser.add_argument("--compact-report", type=Path)
    arguments = parser.parse_args()
    state_root = environment_certification._outside_repository(arguments.state_root, "state root")
    evidence_dir = environment_certification._outside_repository(arguments.evidence_dir, "evidence directory")
    warehouse_dir = environment_certification._outside_repository(arguments.warehouse_dir, "warehouse directory")
    try:
        with _exclusive_lock(state_root):
            report = execute(
                state_root,
                evidence_dir,
                warehouse_dir,
                arguments.trust_class,
                arguments.compact_report,
            )
    except Exception as error:
        adapter_certification._report_failure(error)
        return 1
    sys.stdout.buffer.write(canonical_bytes({"ok": True, **report}) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
