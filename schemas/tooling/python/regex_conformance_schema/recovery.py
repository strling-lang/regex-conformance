"""Repository validation for restart/resume qualification outcomes."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable

from .errors import fail
from .jsonio import canonical_bytes, load_strict


def load_and_validate_recovery_records(
    root: Path,
    *,
    validate_instance: Callable[..., None],
) -> dict[str, int]:
    scheduler = root / "scheduler" / "python"
    if str(scheduler) not in sys.path:
        sys.path.insert(0, str(scheduler))
    from regex_conformance_scheduler.recovery import build_restart_resume_reference_report

    path = root / "reports" / "small-scale" / "restart-resume-qualification.json"
    report = load_strict(path)
    validate_instance(
        report,
        load_strict(root / "schemas" / "json" / "restart-resume-qualification.schema.json"),
        source=str(path),
    )
    expected = build_restart_resume_reference_report()
    if canonical_bytes(report) != canonical_bytes(expected):
        fail(
            "restart-resume-reference-drift",
            "restart/resume report differs from the deterministic D090 recovery matrix",
            str(path),
        )
    keys = [item["case_key"] for item in report["cases"]]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        fail(
            "restart-resume-reference-order",
            "restart/resume case keys must be unique and code-point ordered",
            str(path),
        )
    return {"restart_resume_reports": 1, "restart_resume_cases": len(keys)}
