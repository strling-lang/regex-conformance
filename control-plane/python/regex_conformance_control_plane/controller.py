"""Reusable Control Plane service container and controller facade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .configuration import DoctorConfiguration
from .discovery import StandardLibraryMachineDiscovery
from .doctor import MachineDoctor, UtcClock
from .models import DoctorReport

if TYPE_CHECKING:
    from .environment_models import AdmissionDecision, EnvironmentDiagnosis, EnvironmentLifecycleRecord, EnvironmentRecipe


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


@dataclass(frozen=True)
class ControlPlaneServices:
    machine_doctor: MachineDoctorService
    environment_manager: EnvironmentManagerService | None = None


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

    def _environment_manager(self) -> EnvironmentManagerService:
        if self._services.environment_manager is None:
            raise RuntimeError("environment manager service is not configured")
        return self._services.environment_manager


def build_default_controller() -> ControlPlaneController:
    return ControlPlaneController(
        ControlPlaneServices(
            machine_doctor=MachineDoctor(StandardLibraryMachineDiscovery(), UtcClock()),
        )
    )
