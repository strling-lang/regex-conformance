"""Reusable Control Plane service container and controller facade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .configuration import DoctorConfiguration
from .discovery import StandardLibraryMachineDiscovery
from .doctor import MachineDoctor, UtcClock
from .models import DoctorReport

if TYPE_CHECKING:
    from .cache_manager import CacheProvider, Cancellation, ChunkSource
    from .cache_models import (
        CacheEntry,
        CacheInventory,
        CacheReconciliation,
        CleanupPlan,
        CleanupReport,
        EvictionPolicy,
        TransferRecord,
    )
    from .environment_models import AdmissionDecision, EnvironmentDiagnosis, EnvironmentLifecycleRecord, EnvironmentRecipe
    from .resource_models import (
        AdmissionContext,
        ResourceAdmissionReport,
        ResourceEstimate,
        TransferForecast,
        WorkloadResourcePlan,
    )


class MachineDoctorService(Protocol):
    def inspect(self, configuration: DoctorConfiguration) -> DoctorReport: ...


class EnvironmentManagerService(Protocol):
    def plan(self, recipe: "EnvironmentRecipe", provider_name: str) -> "EnvironmentLifecycleRecord": ...

    def admit(
        self,
        record: "EnvironmentLifecycleRecord",
        decision: "AdmissionDecision",
    ) -> "EnvironmentLifecycleRecord": ...

    def realize(self, record: "EnvironmentLifecycleRecord") -> "EnvironmentLifecycleRecord": ...

    def cancel(self, record: "EnvironmentLifecycleRecord", reason: str) -> "EnvironmentLifecycleRecord": ...

    def release(self, record: "EnvironmentLifecycleRecord") -> "EnvironmentLifecycleRecord": ...

    def diagnose(self, record: "EnvironmentLifecycleRecord") -> "EnvironmentDiagnosis": ...


class ResourcePlannerService(Protocol):
    def workload_plan(
        self,
        *,
        operation_kind: str,
        operation_id: str,
        estimates: tuple["ResourceEstimate", ...],
        transfers: tuple["TransferForecast", ...] = (),
        provider_name: str | None = None,
        provider_strategy: str | None = None,
        required_capabilities: tuple[str, ...] = (),
        eligible_trust_classes: tuple[str, ...] = ("development", "trusted_executioner"),
        requested_concurrency: int = 1,
    ) -> "WorkloadResourcePlan": ...

    def environment_plan(
        self,
        record: "EnvironmentLifecycleRecord",
        *,
        machine_provider_name: str,
        estimate_confidence: str = "estimated",
        supplemental_estimates: tuple["ResourceEstimate", ...] = (),
        required_capabilities: tuple[str, ...] = (),
        eligible_trust_classes: tuple[str, ...] = ("development", "trusted_executioner"),
    ) -> "WorkloadResourcePlan": ...

    def preflight(
        self,
        plan: "WorkloadResourcePlan",
        inventory: DoctorReport,
        context: "AdmissionContext | None" = None,
    ) -> "ResourceAdmissionReport": ...

    def dynamic_admit(
        self,
        plan: "WorkloadResourcePlan",
        inventory: DoctorReport,
        context: "AdmissionContext | None" = None,
    ) -> "ResourceAdmissionReport": ...

    def environment_decision(
        self,
        record: "EnvironmentLifecycleRecord",
        report: "ResourceAdmissionReport",
    ) -> "AdmissionDecision": ...


class CacheManagerService(Protocol):
    def inventory(
        self,
        entries: tuple["CacheEntry", ...],
        *,
        observed_at: str | None = None,
    ) -> "CacheInventory": ...

    def reconcile(
        self,
        inventory: "CacheInventory",
        provider: "CacheProvider",
    ) -> "CacheReconciliation": ...

    def plan_cleanup(
        self,
        inventory: "CacheInventory",
        reconciliation: "CacheReconciliation",
        target_reclaim_bytes: int,
        policy: "EvictionPolicy",
    ) -> "CleanupPlan": ...

    def execute_cleanup(
        self,
        plan: "CleanupPlan",
        inventory: "CacheInventory",
        provider: "CacheProvider",
        cancellation: "Cancellation | None" = None,
    ) -> "CleanupReport": ...


class TransferManagerService(Protocol):
    def plan(
        self,
        *,
        operation: str,
        locator: str,
        expected_sha256: str,
        expected_size_bytes: int,
        relative_path: str,
        cache_key: str | None = None,
    ) -> "TransferRecord": ...

    def record_external_attempt(
        self,
        record: "TransferRecord",
        *,
        bytes_completed: int,
        checkpoint_sha256: str,
        outcome: str,
        code: str,
        detail: str,
    ) -> "TransferRecord": ...

    def resume_download(
        self,
        record: "TransferRecord",
        source: "ChunkSource",
        *,
        chunk_size: int = 1024 * 1024,
        maximum_chunks: int | None = None,
        cancellation: "Cancellation | None" = None,
    ) -> "TransferRecord": ...


@dataclass(frozen=True)
class ControlPlaneServices:
    machine_doctor: MachineDoctorService
    environment_manager: EnvironmentManagerService | None = None
    resource_planner: ResourcePlannerService | None = None
    cache_manager: CacheManagerService | None = None
    transfer_manager: TransferManagerService | None = None


class ControlPlaneController:
    """Client-neutral orchestration surface; no rendering or CLI parsing lives here."""

    def __init__(self, services: ControlPlaneServices) -> None:
        self._services = services

    def inspect_machine(self, configuration: DoctorConfiguration) -> DoctorReport:
        return self._services.machine_doctor.inspect(configuration)

    def plan_environment(self, recipe: "EnvironmentRecipe", provider_name: str) -> "EnvironmentLifecycleRecord":
        return self._environment_manager().plan(recipe, provider_name)

    def admit_environment(
        self,
        record: "EnvironmentLifecycleRecord",
        decision: "AdmissionDecision",
    ) -> "EnvironmentLifecycleRecord":
        return self._environment_manager().admit(record, decision)

    def realize_environment(self, record: "EnvironmentLifecycleRecord") -> "EnvironmentLifecycleRecord":
        return self._environment_manager().realize(record)

    def cancel_environment(self, record: "EnvironmentLifecycleRecord", reason: str) -> "EnvironmentLifecycleRecord":
        return self._environment_manager().cancel(record, reason)

    def release_environment(self, record: "EnvironmentLifecycleRecord") -> "EnvironmentLifecycleRecord":
        return self._environment_manager().release(record)

    def diagnose_environment(self, record: "EnvironmentLifecycleRecord") -> "EnvironmentDiagnosis":
        return self._environment_manager().diagnose(record)

    def plan_resources(
        self,
        *,
        operation_kind: str,
        operation_id: str,
        estimates: tuple["ResourceEstimate", ...],
        transfers: tuple["TransferForecast", ...] = (),
        provider_name: str | None = None,
        provider_strategy: str | None = None,
        required_capabilities: tuple[str, ...] = (),
        eligible_trust_classes: tuple[str, ...] = ("development", "trusted_executioner"),
        requested_concurrency: int = 1,
    ) -> "WorkloadResourcePlan":
        return self._resource_planner().workload_plan(
            operation_kind=operation_kind,
            operation_id=operation_id,
            estimates=estimates,
            transfers=transfers,
            provider_name=provider_name,
            provider_strategy=provider_strategy,
            required_capabilities=required_capabilities,
            eligible_trust_classes=eligible_trust_classes,
            requested_concurrency=requested_concurrency,
        )

    def plan_environment_resources(
        self,
        record: "EnvironmentLifecycleRecord",
        *,
        machine_provider_name: str,
        estimate_confidence: str = "estimated",
        supplemental_estimates: tuple["ResourceEstimate", ...] = (),
        required_capabilities: tuple[str, ...] = (),
        eligible_trust_classes: tuple[str, ...] = ("development", "trusted_executioner"),
    ) -> "WorkloadResourcePlan":
        return self._resource_planner().environment_plan(
            record,
            machine_provider_name=machine_provider_name,
            estimate_confidence=estimate_confidence,
            supplemental_estimates=supplemental_estimates,
            required_capabilities=required_capabilities,
            eligible_trust_classes=eligible_trust_classes,
        )

    def preflight_resources(
        self,
        plan: "WorkloadResourcePlan",
        inventory: DoctorReport,
        context: "AdmissionContext | None" = None,
    ) -> "ResourceAdmissionReport":
        return self._resource_planner().preflight(plan, inventory, context)

    def reevaluate_resource_admission(
        self,
        plan: "WorkloadResourcePlan",
        inventory: DoctorReport,
        context: "AdmissionContext | None" = None,
    ) -> "ResourceAdmissionReport":
        return self._resource_planner().dynamic_admit(plan, inventory, context)

    def admit_environment_from_preflight(
        self,
        record: "EnvironmentLifecycleRecord",
        report: "ResourceAdmissionReport",
    ) -> "EnvironmentLifecycleRecord":
        decision = self._resource_planner().environment_decision(record, report)
        return self._environment_manager().admit(record, decision)

    def inventory_cache(
        self,
        entries: tuple["CacheEntry", ...],
        *,
        observed_at: str | None = None,
    ) -> "CacheInventory":
        return self._cache_manager().inventory(entries, observed_at=observed_at)

    def reconcile_cache(
        self,
        inventory: "CacheInventory",
        provider: "CacheProvider",
    ) -> "CacheReconciliation":
        return self._cache_manager().reconcile(inventory, provider)

    def plan_cache_cleanup(
        self,
        inventory: "CacheInventory",
        reconciliation: "CacheReconciliation",
        target_reclaim_bytes: int,
        policy: "EvictionPolicy",
    ) -> "CleanupPlan":
        return self._cache_manager().plan_cleanup(
            inventory,
            reconciliation,
            target_reclaim_bytes,
            policy,
        )

    def execute_cache_cleanup(
        self,
        plan: "CleanupPlan",
        inventory: "CacheInventory",
        provider: "CacheProvider",
        cancellation: "Cancellation | None" = None,
    ) -> "CleanupReport":
        return self._cache_manager().execute_cleanup(plan, inventory, provider, cancellation)

    def plan_transfer(
        self,
        *,
        operation: str,
        locator: str,
        expected_sha256: str,
        expected_size_bytes: int,
        relative_path: str,
        cache_key: str | None = None,
    ) -> "TransferRecord":
        return self._transfer_manager().plan(
            operation=operation,
            locator=locator,
            expected_sha256=expected_sha256,
            expected_size_bytes=expected_size_bytes,
            relative_path=relative_path,
            cache_key=cache_key,
        )

    def record_transfer_attempt(
        self,
        record: "TransferRecord",
        *,
        bytes_completed: int,
        checkpoint_sha256: str,
        outcome: str,
        code: str,
        detail: str,
    ) -> "TransferRecord":
        return self._transfer_manager().record_external_attempt(
            record,
            bytes_completed=bytes_completed,
            checkpoint_sha256=checkpoint_sha256,
            outcome=outcome,
            code=code,
            detail=detail,
        )

    def resume_transfer_download(
        self,
        record: "TransferRecord",
        source: "ChunkSource",
        *,
        chunk_size: int = 1024 * 1024,
        maximum_chunks: int | None = None,
        cancellation: "Cancellation | None" = None,
    ) -> "TransferRecord":
        return self._transfer_manager().resume_download(
            record,
            source,
            chunk_size=chunk_size,
            maximum_chunks=maximum_chunks,
            cancellation=cancellation,
        )

    def _environment_manager(self) -> EnvironmentManagerService:
        if self._services.environment_manager is None:
            raise RuntimeError("environment manager service is not configured")
        return self._services.environment_manager

    def _resource_planner(self) -> ResourcePlannerService:
        if self._services.resource_planner is None:
            raise RuntimeError("resource planner service is not configured")
        return self._services.resource_planner

    def _cache_manager(self) -> CacheManagerService:
        if self._services.cache_manager is None:
            raise RuntimeError("cache manager service is not configured")
        return self._services.cache_manager

    def _transfer_manager(self) -> TransferManagerService:
        if self._services.transfer_manager is None:
            raise RuntimeError("transfer manager service is not configured")
        return self._services.transfer_manager


def build_default_controller() -> ControlPlaneController:
    return ControlPlaneController(
        ControlPlaneServices(
            machine_doctor=MachineDoctor(StandardLibraryMachineDiscovery(), UtcClock()),
        )
    )
