"""Machine-doctor service that converts discovery facts into safe diagnostics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol

from .configuration import DoctorConfiguration, POOL_KINDS, TRUST_CLASSES
from .discovery import MachineDiscovery
from .models import (
    Diagnostic,
    DoctorReport,
    SafetyConfigurationView,
    TrustObservation,
)

SUPPORTED_OS_FAMILIES = frozenset({"linux", "windows", "macos"})


def rfc3339(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("clock values must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Clock(Protocol):
    def now(self) -> datetime: ...


class UtcClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class MachineDoctor:
    def __init__(self, discovery: MachineDiscovery, clock: Clock) -> None:
        self._discovery = discovery
        self._clock = clock

    def inspect(self, configuration: DoctorConfiguration) -> DoctorReport:
        now = self._clock.now()
        observed_at = rfc3339(now)
        snapshot = self._discovery.discover(configuration, observed_at)
        diagnostics = list(snapshot.diagnostics)

        if snapshot.observed_at != observed_at:
            diagnostics.append(
                Diagnostic(
                    "error",
                    "inventory-time-mismatch",
                    "Discovery returned facts for a different observation instant.",
                    "Refresh the machine inventory through one controller transaction.",
                )
            )
        if snapshot.machine.os_family not in SUPPORTED_OS_FAMILIES:
            diagnostics.append(
                Diagnostic(
                    "error",
                    "unsupported-operating-system",
                    f"Operating system {snapshot.machine.os_name!r} is not a supported controller host.",
                    "Use Linux, Windows, or macOS, or add a certified discovery implementation.",
                )
            )

        trust_class = configuration.trust_class if configuration.trust_is_valid else "unknown"
        if not configuration.trust_is_valid:
            diagnostics.append(
                Diagnostic(
                    "error",
                    "invalid-trust-class",
                    f"Configured trust class {configuration.trust_class!r} is not recognized.",
                    f"Choose one of: {', '.join(sorted(TRUST_CLASSES))}.",
                )
            )
        elif trust_class == "unknown":
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "trust-class-unconfigured",
                    "Trust class is unknown and was not inferred from hardware or provider availability.",
                    "Set STRLING_REGEX_TRUST_CLASS or pass --trust-class before admitting trusted work.",
                )
            )

        resource_names = [resource.kind for resource in snapshot.resources]
        resource_kinds = set(resource_names)
        if len(resource_names) != len(resource_kinds):
            diagnostics.append(
                Diagnostic(
                    "error",
                    "resource-pool-identity-collision",
                    "Resource discovery returned duplicate typed pool names.",
                    "Fix resource discovery before capacity planning.",
                )
            )
        for kind in (*POOL_KINDS, "ram", "swap", "cpu"):
            if kind not in resource_kinds:
                diagnostics.append(
                    Diagnostic(
                        "error",
                        "required-resource-pool-missing",
                        f"Required typed resource pool {kind!r} is absent.",
                        "Refresh discovery with an implementation that preserves distinct resource pools.",
                    )
                )
        ram = next((resource for resource in snapshot.resources if resource.kind == "ram"), None)
        if ram is not None and ram.capacity is None:
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "ram-capacity-unknown",
                    "Physical RAM capacity is unknown; it is not treated as zero or available capacity.",
                    "Enable a supported host memory probe before resource admission.",
                )
            )

        backing_stores: dict[str, list[str]] = {}
        for resource in snapshot.resources:
            if resource.backing_store:
                backing_stores.setdefault(resource.backing_store, []).append(resource.kind)
        for backing_store, kinds in sorted(backing_stores.items()):
            if len(kinds) > 1:
                diagnostics.append(
                    Diagnostic(
                        "info",
                        "resource-pools-share-backing-store",
                        f"Pools {', '.join(sorted(kinds))} share {backing_store}; their capacities are not additive.",
                        "Resource planning must reserve against the shared backing store as well as each logical pool.",
                    )
                )

        provider_names = [provider.name for provider in snapshot.providers]
        if len(provider_names) != len(set(provider_names)):
            diagnostics.append(
                Diagnostic(
                    "error",
                    "provider-identity-collision",
                    "Provider discovery returned duplicate provider names.",
                    "Fix the provider registry before environment planning.",
                )
            )

        capability_names = [capability.name for capability in snapshot.capabilities]
        if len(capability_names) != len(set(capability_names)):
            diagnostics.append(
                Diagnostic(
                    "error",
                    "capability-identity-collision",
                    "Capability discovery returned duplicate capability names.",
                    "Fix capability discovery before admission decisions.",
                )
            )
        if not any(provider.name == "native" and provider.availability == "available" for provider in snapshot.providers):
            diagnostics.append(
                Diagnostic(
                    "error",
                    "native-provider-missing",
                    "The native execution strategy is not represented as available.",
                    "Repair base provider discovery before acquiring environments.",
                )
            )

        if any(item.severity == "error" for item in diagnostics):
            status = "unsupported"
        elif any(item.severity == "warning" for item in diagnostics):
            status = "degraded"
        else:
            status = "healthy"
        valid_until = rfc3339(now + timedelta(seconds=configuration.inventory_max_age_seconds))
        return DoctorReport(
            status=status,
            observed_at=observed_at,
            valid_until=valid_until,
            machine=snapshot.machine,
            trust=TrustObservation(
                trust_class=trust_class,
                source=configuration.trust_source,
                configured=configuration.trust_source != "default" and configuration.trust_is_valid,
            ),
            resources=tuple(sorted(snapshot.resources, key=lambda resource: resource.kind)),
            providers=tuple(sorted(snapshot.providers, key=lambda provider: provider.name)),
            capabilities=tuple(sorted(snapshot.capabilities, key=lambda capability: capability.name)),
            safety_configuration=SafetyConfigurationView(
                inventory_only=True,
                mutation_permitted=False,
                inventory_max_age_seconds=configuration.inventory_max_age_seconds,
                configured_pool_paths={kind: str(path) for kind, path in configuration.pool_paths},
            ),
            diagnostics=tuple(diagnostics),
        )
