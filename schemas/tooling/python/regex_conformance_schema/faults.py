"""Repository validation for deliberate-fault reference outcomes."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable

from .errors import fail
from .jsonio import canonical_bytes, load_strict


def load_and_validate_fault_records(
    root: Path,
    *,
    validate_instance: Callable[..., None],
) -> dict[str, int]:
    control_plane = root / "control-plane" / "python"
    if str(control_plane) not in sys.path:
        sys.path.insert(0, str(control_plane))
    from regex_conformance_control_plane.fault_attribution import build_reference_report

    path = root / "reports" / "small-scale" / "fault-classification.json"
    report = load_strict(path)
    validate_instance(
        report,
        load_strict(root / "schemas" / "json" / "fault-classification-report.schema.json"),
        source=str(path),
    )
    expected = build_reference_report()
    if canonical_bytes(report) != canonical_bytes(expected):
        fail(
            "fault-reference-drift",
            "fault reference report differs from fail-closed deterministic classification",
            str(path),
        )
    keys = [item["stimulus"]["fault_key"] for item in report["cases"]]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        fail(
            "fault-reference-order",
            "fault reference keys must be unique and code-point ordered",
            str(path),
        )
    return {"fault_classification_reports": 1, "fault_classification_cases": len(keys)}
