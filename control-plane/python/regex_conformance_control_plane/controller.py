"""Reusable Control Plane service container and controller facade."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .configuration import DoctorConfiguration
from .discovery import StandardLibraryMachineDiscovery
from .doctor import MachineDoctor, UtcClock
from .models import DoctorReport


class MachineDoctorService(Protocol):
    def inspect(self, configuration: DoctorConfiguration) -> DoctorReport: ...


@dataclass(frozen=True)
class ControlPlaneServices:
    machine_doctor: MachineDoctorService


class ControlPlaneController:
    """Client-neutral orchestration surface; no rendering or CLI parsing lives here."""

    def __init__(self, services: ControlPlaneServices) -> None:
        self._services = services

    def inspect_machine(self, configuration: DoctorConfiguration) -> DoctorReport:
        return self._services.machine_doctor.inspect(configuration)


def build_default_controller() -> ControlPlaneController:
    return ControlPlaneController(
        ControlPlaneServices(
            machine_doctor=MachineDoctor(StandardLibraryMachineDiscovery(), UtcClock()),
        )
    )
