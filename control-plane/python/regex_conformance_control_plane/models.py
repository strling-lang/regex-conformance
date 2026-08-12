"""Typed, immutable machine-inventory and diagnostic records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

SCHEMA_VERSION = "machine-inventory.v1"
ACCURACY_CLASSES = frozenset({"exact", "bounded", "estimated", "unknown"})
VISIBILITY_CLASSES = frozenset({"host", "process", "configured"})
RESOURCE_STATES = frozenset({"observed", "partial", "unknown"})
PROVIDER_STATES = frozenset({"available", "detected_unverified", "unavailable", "unknown"})
CAPABILITY_STATES = frozenset({"supported", "unsupported", "unknown"})
DIAGNOSTIC_SEVERITIES = frozenset({"info", "warning", "error"})
REPORT_STATES = frozenset({"healthy", "degraded", "unsupported"})


def require_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"invalid RFC 3339 timestamp: {value!r}") from error
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")


def _require_nonnegative(name: str, value: int | None) -> None:
    if value is not None and value < 0:
        raise ValueError(f"{name} must be non-negative or unknown")


@dataclass(frozen=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    remediation: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in DIAGNOSTIC_SEVERITIES:
            raise ValueError(f"invalid diagnostic severity: {self.severity}")
        if not self.code or not self.message:
            raise ValueError("diagnostic code and message are required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "remediation": self.remediation,
            "severity": self.severity,
        }


@dataclass(frozen=True)
class MachineIdentity:
    os_family: str
    os_name: str
    os_release: str
    architecture: str
    architecture_raw: str
    python_implementation: str
    python_version: str

    def to_dict(self) -> dict[str, str]:
        return {
            "architecture": self.architecture,
            "architecture_raw": self.architecture_raw,
            "os_family": self.os_family,
            "os_name": self.os_name,
            "os_release": self.os_release,
            "python_implementation": self.python_implementation,
            "python_version": self.python_version,
        }


@dataclass(frozen=True)
class ResourcePool:
    kind: str
    unit: str
    status: str
    capacity: int | None
    used: int | None
    reserved: int
    available: int | None
    source: str
    accuracy: str
    visibility: str
    observed_at: str
    staleness_seconds: int
    configured_path: str | None = None
    observed_path: str | None = None
    backing_store: str | None = None
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        if not self.kind or not self.unit or not self.source:
            raise ValueError("resource kind, unit, and source are required")
        if self.status not in RESOURCE_STATES:
            raise ValueError(f"invalid resource status: {self.status}")
        if self.accuracy not in ACCURACY_CLASSES:
            raise ValueError(f"invalid resource accuracy: {self.accuracy}")
        if self.visibility not in VISIBILITY_CLASSES:
            raise ValueError(f"invalid resource visibility: {self.visibility}")
        require_timestamp(self.observed_at)
        for name in ("capacity", "used", "reserved", "available", "staleness_seconds"):
            _require_nonnegative(name, getattr(self, name))
        if self.status == "unknown" and any(value is not None for value in (self.capacity, self.used, self.available)):
            raise ValueError("unknown resource measurements must remain null")
        if self.capacity is not None:
            for name, value in (("used", self.used), ("reserved", self.reserved), ("available", self.available)):
                if value is not None and value > self.capacity:
                    raise ValueError(f"{name} exceeds resource capacity")
            if self.used is not None and self.available is not None:
                if self.used + self.reserved + self.available > self.capacity:
                    raise ValueError("resource accounting exceeds capacity")

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "available": self.available,
            "backing_store": self.backing_store,
            "capacity": self.capacity,
            "configured_path": self.configured_path,
            "diagnostic": self.diagnostic,
            "kind": self.kind,
            "observed_at": self.observed_at,
            "observed_path": self.observed_path,
            "reserved": self.reserved,
            "source": self.source,
            "staleness_seconds": self.staleness_seconds,
            "status": self.status,
            "unit": self.unit,
            "used": self.used,
            "visibility": self.visibility,
        }


@dataclass(frozen=True)
class ProviderCapability:
    name: str
    availability: str
    strategies: tuple[str, ...]
    source: str
    observed_at: str
    accuracy: str = "exact"
    visibility: str = "process"
    staleness_seconds: int = 0
    executable: str | None = None
    diagnostic: str | None = None

    def __post_init__(self) -> None:
        if self.availability not in PROVIDER_STATES:
            raise ValueError(f"invalid provider availability: {self.availability}")
        require_timestamp(self.observed_at)
        if self.accuracy not in ACCURACY_CLASSES or self.visibility not in VISIBILITY_CLASSES:
            raise ValueError("provider accuracy and visibility must use registered classes")
        _require_nonnegative("staleness_seconds", self.staleness_seconds)
        if self.availability == "unknown" and self.accuracy != "unknown":
            raise ValueError("unknown provider availability must have unknown accuracy")
        if self.availability not in {"available", "detected_unverified"} and self.executable is not None:
            raise ValueError("only an available or detected provider may expose an executable")

    def to_dict(self) -> dict[str, Any]:
        return {
            "availability": self.availability,
            "accuracy": self.accuracy,
            "diagnostic": self.diagnostic,
            "executable": self.executable,
            "name": self.name,
            "observed_at": self.observed_at,
            "source": self.source,
            "staleness_seconds": self.staleness_seconds,
            "strategies": list(self.strategies),
            "visibility": self.visibility,
        }


@dataclass(frozen=True)
class Capability:
    name: str
    status: str
    source: str
    observed_at: str
    value: Any = None
    diagnostic: str | None = None
    accuracy: str = "exact"
    visibility: str = "process"
    staleness_seconds: int = 0

    def __post_init__(self) -> None:
        if self.status not in CAPABILITY_STATES:
            raise ValueError(f"invalid capability status: {self.status}")
        require_timestamp(self.observed_at)
        if self.accuracy not in ACCURACY_CLASSES or self.visibility not in VISIBILITY_CLASSES:
            raise ValueError("capability accuracy and visibility must use registered classes")
        _require_nonnegative("staleness_seconds", self.staleness_seconds)
        if self.status == "unknown" and self.accuracy != "unknown":
            raise ValueError("unknown capability status must have unknown accuracy")
        if self.status in {"unsupported", "unknown"} and self.value is not None:
            raise ValueError("unsupported or unknown capability values must remain null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "accuracy": self.accuracy,
            "diagnostic": self.diagnostic,
            "name": self.name,
            "observed_at": self.observed_at,
            "source": self.source,
            "staleness_seconds": self.staleness_seconds,
            "status": self.status,
            "value": self.value,
            "visibility": self.visibility,
        }


@dataclass(frozen=True)
class DiscoverySnapshot:
    observed_at: str
    machine: MachineIdentity
    resources: tuple[ResourcePool, ...]
    providers: tuple[ProviderCapability, ...]
    capabilities: tuple[Capability, ...]
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self) -> None:
        require_timestamp(self.observed_at)


@dataclass(frozen=True)
class TrustObservation:
    trust_class: str
    source: str
    configured: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "source": self.source,
            "trust_class": self.trust_class,
        }


@dataclass(frozen=True)
class SafetyConfigurationView:
    inventory_only: bool
    mutation_permitted: bool
    inventory_max_age_seconds: int
    configured_pool_paths: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured_pool_paths": dict(sorted(self.configured_pool_paths.items())),
            "inventory_max_age_seconds": self.inventory_max_age_seconds,
            "inventory_only": self.inventory_only,
            "mutation_permitted": self.mutation_permitted,
        }


@dataclass(frozen=True)
class DoctorReport:
    status: str
    observed_at: str
    valid_until: str
    machine: MachineIdentity
    trust: TrustObservation
    resources: tuple[ResourcePool, ...]
    providers: tuple[ProviderCapability, ...]
    capabilities: tuple[Capability, ...]
    safety_configuration: SafetyConfigurationView
    diagnostics: tuple[Diagnostic, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in REPORT_STATES:
            raise ValueError(f"invalid doctor status: {self.status}")
        require_timestamp(self.observed_at)
        require_timestamp(self.valid_until)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": [item.to_dict() for item in sorted(self.capabilities, key=lambda item: item.name)],
            "diagnostics": [item.to_dict() for item in sorted(self.diagnostics, key=lambda item: (item.severity, item.code))],
            "machine": self.machine.to_dict(),
            "observed_at": self.observed_at,
            "providers": [item.to_dict() for item in sorted(self.providers, key=lambda item: item.name)],
            "resource_pools": [item.to_dict() for item in sorted(self.resources, key=lambda item: item.kind)],
            "safety_configuration": self.safety_configuration.to_dict(),
            "schema_version": self.schema_version,
            "status": self.status,
            "trust": self.trust.to_dict(),
            "valid_until": self.valid_until,
        }
