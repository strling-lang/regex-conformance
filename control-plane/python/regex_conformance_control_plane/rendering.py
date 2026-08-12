"""Human and machine rendering derived from the same doctor report."""

from __future__ import annotations

import json

from .models import DoctorReport


def render_json(report: DoctorReport, *, compact: bool = False) -> str:
    return json.dumps(
        report.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":") if compact else None,
        indent=None if compact else 2,
    ) + "\n"


def _quantity(value: int | None, unit: str) -> str:
    if value is None:
        return "unknown"
    if unit != "bytes":
        return f"{value} {unit}"
    amount = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or suffix == "TiB":
            return f"{amount:.1f} {suffix}" if suffix != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{value} B"


def render_human(report: DoctorReport) -> str:
    lines = [
        f"Machine doctor: {report.status}",
        f"OS: {report.machine.os_family} {report.machine.architecture} ({report.machine.os_release})",
        f"Trust: {report.trust.trust_class} [{report.trust.source}]",
        f"Inventory: {report.observed_at} through {report.valid_until}",
        "Providers:",
    ]
    for provider in report.providers:
        strategies = ",".join(provider.strategies)
        lines.append(f"  - {provider.name}: {provider.availability} ({strategies})")
    lines.append("Resource pools:")
    for resource in report.resources:
        lines.append(
            f"  - {resource.kind}: status={resource.status} capacity={_quantity(resource.capacity, resource.unit)} "
            f"available={_quantity(resource.available, resource.unit)} reserved={_quantity(resource.reserved, resource.unit)}"
        )
    lines.append("Diagnostics:")
    if not report.diagnostics:
        lines.append("  - none")
    for diagnostic in report.diagnostics:
        lines.append(f"  - [{diagnostic.severity}] {diagnostic.code}: {diagnostic.message}")
        if diagnostic.remediation:
            lines.append(f"    remediation: {diagnostic.remediation}")
    return "\n".join(lines) + "\n"
