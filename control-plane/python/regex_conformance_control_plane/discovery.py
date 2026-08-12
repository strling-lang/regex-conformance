"""Provider-neutral, read-only host capability discovery."""

from __future__ import annotations

import ctypes
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Protocol

from .configuration import DoctorConfiguration
from .models import (
    Capability,
    Diagnostic,
    DiscoverySnapshot,
    MachineIdentity,
    ProviderCapability,
    ResourcePool,
)

MemoryMeasurements = tuple[int, int, int, int | None, int | None, int | None]


class MachineDiscovery(Protocol):
    def discover(self, configuration: DoctorConfiguration, observed_at: str) -> DiscoverySnapshot: ...


def normalize_os(value: str) -> str:
    return {
        "linux": "linux",
        "windows": "windows",
        "darwin": "macos",
        "freebsd": "freebsd",
    }.get(value.casefold(), "unknown")


def normalize_architecture(value: str) -> str:
    folded = value.casefold().replace("-", "_")
    return {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "i386": "x86_32",
        "i686": "x86_32",
        "x86": "x86_32",
        "armv7l": "armv7",
    }.get(folded, folded or "unknown")


def _nearest_existing(path: Path) -> Path:
    candidate = path.expanduser().absolute()
    while not candidate.exists() and candidate.parent != candidate:
        candidate = candidate.parent
    return candidate


def _backing_store(path: Path) -> str:
    try:
        return f"device:{os.stat(path).st_dev}"
    except OSError:
        return f"volume:{path.anchor.casefold()}" if path.anchor else "unknown"


def _unknown_pool(kind: str, unit: str, observed_at: str, source: str, diagnostic: str) -> ResourcePool:
    return ResourcePool(
        kind=kind,
        unit=unit,
        status="unknown",
        capacity=None,
        used=None,
        reserved=0,
        available=None,
        source=source,
        accuracy="unknown",
        visibility="process",
        observed_at=observed_at,
        staleness_seconds=0,
        diagnostic=diagnostic,
    )


def _disk_pool(kind: str, configured: Path, observed_at: str) -> tuple[ResourcePool, Diagnostic | None]:
    observed = _nearest_existing(configured)
    try:
        usage = shutil.disk_usage(observed)
    except OSError as error:
        return (
            ResourcePool(
                kind=kind,
                unit="bytes",
                status="unknown",
                capacity=None,
                used=None,
                reserved=0,
                available=None,
                source="shutil.disk_usage",
                accuracy="unknown",
                visibility="process",
                observed_at=observed_at,
                staleness_seconds=0,
                configured_path=str(configured),
                observed_path=str(observed),
                diagnostic=str(error),
            ),
            Diagnostic(
                severity="error",
                code=f"{kind}-unobservable",
                message=f"Cannot inspect the filesystem backing {kind}: {error}",
                remediation="Choose an accessible path for this resource pool before planning work.",
            ),
        )
    fallback = observed != configured.expanduser().absolute()
    message = f"configured path does not exist; capacity observed at nearest ancestor {observed}" if fallback else None
    diagnostic = None
    if fallback:
        diagnostic = Diagnostic(
            severity="info",
            code=f"{kind}-path-not-created",
            message=message or "configured pool path does not exist",
            remediation="No action is required for inspection; the Control Plane will plan creation before mutation.",
        )
    return (
        ResourcePool(
            kind=kind,
            unit="bytes",
            status="observed",
            capacity=usage.total,
            used=usage.used,
            reserved=0,
            available=usage.free,
            source="shutil.disk_usage",
            accuracy="exact",
            visibility="process",
            observed_at=observed_at,
            staleness_seconds=0,
            configured_path=str(configured),
            observed_path=str(observed),
            backing_store=_backing_store(observed),
            diagnostic=message,
        ),
        diagnostic,
    )


def _parse_linux_memory() -> MemoryMeasurements | None:
    try:
        fields: dict[str, int] = {}
        for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
            match = re.fullmatch(r"([A-Za-z_()]+):\s+(\d+)\s+kB", line)
            if match:
                fields[match.group(1)] = int(match.group(2)) * 1024
        ram_total = fields["MemTotal"]
        ram_available = fields.get("MemAvailable")
        if ram_available is None:
            ram_available = fields.get("MemFree", 0) + fields.get("Buffers", 0) + fields.get("Cached", 0)
        swap_total = fields.get("SwapTotal")
        swap_available = fields.get("SwapFree")
        swap_used = None if swap_total is None or swap_available is None else swap_total - swap_available
        return (
            ram_total,
            ram_total - ram_available,
            ram_available,
            swap_total,
            swap_used,
            swap_available,
        )
    except (OSError, KeyError, ValueError):
        return None


def _parse_windows_memory() -> MemoryMeasurements | None:
    if not hasattr(ctypes, "windll"):
        return None

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        return None
    swap_total = max(0, status.ullTotalPageFile - status.ullTotalPhys)
    swap_available = max(0, status.ullAvailPageFile - status.ullAvailPhys)
    return (
        status.ullTotalPhys,
        status.ullTotalPhys - status.ullAvailPhys,
        status.ullAvailPhys,
        swap_total,
        swap_total - swap_available,
        swap_available,
    )


def _run_text(*arguments: str) -> str | None:
    try:
        result = subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=2)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip()


def _parse_macos_memory() -> MemoryMeasurements | None:
    total_text = _run_text("/usr/sbin/sysctl", "-n", "hw.memsize")
    vm_text = _run_text("/usr/bin/vm_stat")
    swap_text = _run_text("/usr/sbin/sysctl", "-n", "vm.swapusage")
    if total_text is None or vm_text is None:
        return None
    try:
        total = int(total_text)
        page_match = re.search(r"page size of (\d+) bytes", vm_text)
        if page_match is None:
            return None
        page_size = int(page_match.group(1))
        pages: dict[str, int] = {}
        for line in vm_text.splitlines():
            match = re.fullmatch(r"([^:]+):\s+(\d+)\.", line.strip())
            if match:
                pages[match.group(1)] = int(match.group(2))
        available = page_size * sum(pages.get(name, 0) for name in ("Pages free", "Pages inactive", "Pages speculative"))
        swap_total = swap_used = swap_available = None
        if swap_text:
            swap_match = re.search(r"total = ([0-9.]+)([MG])\s+used = ([0-9.]+)([MG])\s+free = ([0-9.]+)([MG])", swap_text)
            if swap_match:
                def amount(value: str, unit: str) -> int:
                    return int(float(value) * (1024**2 if unit == "M" else 1024**3))
                swap_total = amount(swap_match.group(1), swap_match.group(2))
                swap_used = amount(swap_match.group(3), swap_match.group(4))
                swap_available = amount(swap_match.group(5), swap_match.group(6))
        return total, total - available, available, swap_total, swap_used, swap_available
    except (ValueError, KeyError):
        return None


def _fallback_memory() -> MemoryMeasurements | None:
    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, TypeError, ValueError):
        return None
    total = pages * page_size
    return total, 0, total, None, None, None


def _memory_pools(os_family: str, observed_at: str) -> tuple[ResourcePool, ResourcePool]:
    measurements = None
    source = "unknown"
    accuracy = "unknown"
    if os_family == "linux":
        measurements = _parse_linux_memory()
        source = "/proc/meminfo"
        accuracy = "exact"
    elif os_family == "windows":
        measurements = _parse_windows_memory()
        source = "GlobalMemoryStatusEx"
        accuracy = "exact"
    elif os_family == "macos":
        measurements = _parse_macos_memory()
        source = "sysctl+vm_stat"
        accuracy = "estimated"
    if measurements is None:
        measurements = _fallback_memory()
        source = "os.sysconf" if measurements is not None else source
        accuracy = "bounded" if measurements is not None else "unknown"
    if measurements is None:
        return (
            _unknown_pool("ram", "bytes", observed_at, source, "physical memory is not observable"),
            _unknown_pool("swap", "bytes", observed_at, source, "virtual memory or swap is not observable"),
        )
    ram_total, ram_used, ram_available, swap_total, swap_used, swap_available = measurements
    ram = ResourcePool(
            kind="ram",
            unit="bytes",
            status="observed" if accuracy in {"exact", "estimated"} else "partial",
            capacity=ram_total,
            used=ram_used if accuracy != "bounded" else None,
            reserved=0,
            available=ram_available if accuracy != "bounded" else None,
            source=source,
            accuracy=accuracy,
            visibility="process",
            observed_at=observed_at,
            staleness_seconds=0,
        )
    if os_family == "windows":
        swap = _unknown_pool(
            "swap",
            "bytes",
            observed_at,
            "GlobalMemoryStatusEx",
            "Windows commit-limit fields do not prove exact swap capacity",
        )
    elif accuracy == "bounded":
        swap = _unknown_pool(
            "swap",
            "bytes",
            observed_at,
            source,
            "portable fallback discovery cannot observe swap capacity",
        )
    elif swap_total is None or swap_used is None or swap_available is None:
        swap = _unknown_pool(
            "swap",
            "bytes",
            observed_at,
            source,
            "swap capacity is not observable from the selected host probe",
        )
    else:
        swap = ResourcePool(
            kind="swap",
            unit="bytes",
            status="observed" if accuracy in {"exact", "estimated"} else "partial",
            capacity=swap_total,
            used=swap_used if accuracy != "bounded" else None,
            reserved=0,
            available=swap_available if accuracy != "bounded" else None,
            source=source,
            accuracy=accuracy,
            visibility="process",
            observed_at=observed_at,
            staleness_seconds=0,
        )
    return ram, swap


def _cpu_pool(observed_at: str) -> tuple[ResourcePool, Capability]:
    logical = os.cpu_count()
    affinity = None
    if hasattr(os, "sched_getaffinity"):
        try:
            affinity = len(os.sched_getaffinity(0))
        except OSError:
            affinity = None
    visible = affinity if affinity is not None else logical
    status = "partial" if visible is not None else "unknown"
    pool = ResourcePool(
        kind="cpu",
        unit="logical_cpu",
        status=status,
        capacity=visible,
        used=None,
        reserved=0,
        available=None,
        source="os.sched_getaffinity" if affinity is not None else "os.cpu_count",
        accuracy="bounded" if visible is not None else "unknown",
        visibility="process",
        observed_at=observed_at,
        staleness_seconds=0,
        diagnostic="current free CPU capacity is not inferred from logical CPU visibility",
    )
    capability = Capability(
        name="logical_cpu_visibility",
        status="supported" if visible is not None else "unknown",
        value=visible,
        source=pool.source,
        observed_at=observed_at,
        diagnostic=None if visible is not None else "logical CPU visibility is unavailable",
        accuracy="bounded" if visible is not None else "unknown",
    )
    return pool, capability


def _process_capabilities(os_family: str, observed_at: str) -> list[Capability]:
    capabilities = [
        Capability("subprocess_execution", "supported", "python-standard-library", observed_at, True),
        Capability(
            "process_tree_termination",
            "supported" if os_family in {"linux", "macos", "freebsd", "windows"} else "unknown",
            "platform-process-model",
            observed_at,
            True if os_family in {"linux", "macos", "freebsd", "windows"} else None,
            accuracy="exact" if os_family in {"linux", "macos", "freebsd", "windows"} else "unknown",
        ),
        Capability(
            "windows_job_objects",
            "supported" if os_family == "windows" else "unsupported",
            "platform-system",
            observed_at,
            True if os_family == "windows" else None,
        ),
        Capability(
            "cgroup_v2",
            "supported" if os_family == "linux" and Path("/sys/fs/cgroup/cgroup.controllers").is_file() else "unsupported",
            "filesystem-probe",
            observed_at,
            True if os_family == "linux" and Path("/sys/fs/cgroup/cgroup.controllers").is_file() else None,
        ),
        Capability(
            "network_capacity_telemetry",
            "unknown",
            "not-probed",
            observed_at,
            diagnostic="network throughput is not safely inferable during read-only inspection",
            accuracy="unknown",
        ),
        Capability(
            "thermal_throttling_telemetry",
            "unknown",
            "not-probed",
            observed_at,
            diagnostic="portable thermal telemetry is not available from the standard library",
            accuracy="unknown",
        ),
    ]
    try:
        interface_count = len(socket.if_nameindex())
    except OSError:
        interface_count = None
    capabilities.append(
        Capability(
            "network_interface_visibility",
            "supported" if interface_count is not None else "unknown",
            "socket.if_nameindex",
            observed_at,
            interface_count,
            None if interface_count is not None else "network interfaces are not visible to this process",
            accuracy="exact" if interface_count is not None else "unknown",
        )
    )
    try:
        import resource

        limits: dict[str, dict[str, int | str]] = {}
        for name in ("RLIMIT_NOFILE", "RLIMIT_NPROC", "RLIMIT_AS", "RLIMIT_CORE"):
            identifier = getattr(resource, name, None)
            if identifier is None:
                continue
            soft, hard = resource.getrlimit(identifier)
            infinity = resource.RLIM_INFINITY
            limits[name.casefold()] = {
                "hard": "unlimited" if hard == infinity else hard,
                "soft": "unlimited" if soft == infinity else soft,
            }
        capabilities.append(Capability("posix_resource_limits", "supported", "resource.getrlimit", observed_at, limits))
    except (ImportError, OSError, ValueError):
        capabilities.append(Capability("posix_resource_limits", "unsupported", "python-resource-module", observed_at))
    return capabilities


def _program_provider(name: str, programs: tuple[str, ...], strategies: tuple[str, ...], observed_at: str) -> ProviderCapability:
    executable = None
    for program in programs:
        executable = shutil.which(program)
        if executable is not None:
            break
    return ProviderCapability(
        name=name,
        availability="detected_unverified" if executable else "unavailable",
        strategies=strategies,
        source="shutil.which",
        observed_at=observed_at,
        executable=executable,
        diagnostic=(
            "executable is visible but provider identity, health, and limits are not verified"
            if executable
            else f"no {name} executable is visible on PATH"
        ),
    )


def _providers(os_family: str, observed_at: str) -> tuple[ProviderCapability, ...]:
    providers = [
        ProviderCapability("native", "available", ("native",), "platform-system", observed_at),
        _program_provider("docker", ("docker",), ("oci",), observed_at),
        _program_provider("podman", ("podman",), ("oci",), observed_at),
        _program_provider("qemu", ("qemu-system-x86_64", "qemu-system-aarch64", "qemu-system-arm"), ("vm", "emulated"), observed_at),
    ]
    if os_family == "windows":
        providers.extend(
            [
                _program_provider("wsl", ("wsl.exe", "wsl"), ("linux-hosted",), observed_at),
                ProviderCapability("hyperv", "unknown", ("vm",), "not-probed", observed_at, accuracy="unknown", diagnostic="Hyper-V state requires provider-specific verification"),
            ]
        )
    else:
        providers.extend(
            [
                ProviderCapability("wsl", "unavailable", ("linux-hosted",), "platform-system", observed_at, diagnostic="WSL is Windows-specific"),
                ProviderCapability("hyperv", "unavailable", ("vm",), "platform-system", observed_at, diagnostic="Hyper-V is Windows-specific"),
            ]
        )
    providers.append(
        ProviderCapability(
            "apple-virtualization",
            "unknown" if os_family == "macos" else "unavailable",
            ("vm",),
            "not-probed" if os_family == "macos" else "platform-system",
            observed_at,
            accuracy="unknown" if os_family == "macos" else "exact",
            diagnostic="Apple virtualization requires provider-specific verification" if os_family == "macos" else "Apple virtualization is macOS-specific",
        )
    )
    return tuple(sorted(providers, key=lambda provider: provider.name))


class StandardLibraryMachineDiscovery:
    """Discovers process-visible host facts without creating or modifying state."""

    def discover(self, configuration: DoctorConfiguration, observed_at: str) -> DiscoverySnapshot:
        system = platform.system()
        raw_architecture = platform.machine()
        os_family = normalize_os(system)
        machine = MachineIdentity(
            os_family=os_family,
            os_name=system or "unknown",
            os_release=platform.release() or "unknown",
            architecture=normalize_architecture(raw_architecture),
            architecture_raw=raw_architecture or "unknown",
            python_implementation=platform.python_implementation(),
            python_version=platform.python_version(),
        )
        resources: list[ResourcePool] = []
        diagnostics: list[Diagnostic] = []
        for kind, path in configuration.pool_paths:
            pool, diagnostic = _disk_pool(kind, path, observed_at)
            resources.append(pool)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
        resources.extend(_memory_pools(os_family, observed_at))
        cpu, cpu_capability = _cpu_pool(observed_at)
        resources.append(cpu)
        capabilities = _process_capabilities(os_family, observed_at)
        capabilities.append(cpu_capability)
        return DiscoverySnapshot(
            observed_at=observed_at,
            machine=machine,
            resources=tuple(resources),
            providers=_providers(os_family, observed_at),
            capabilities=tuple(sorted(capabilities, key=lambda capability: capability.name)),
            diagnostics=tuple(diagnostics),
        )
