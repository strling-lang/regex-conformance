"""Repository validation for deterministic evidence-corruption qualifications."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable

from .errors import fail
from .jsonio import canonical_bytes, load_strict


def load_and_validate_evidence_records(
    root: Path,
    *,
    validate_instance: Callable[..., None],
) -> dict[str, int]:
    verifier = root / "verifier" / "python"
    campaigns = root / "campaigns" / "python"
    matrix = root / "matrix" / "python"
    scheduler = root / "scheduler" / "python"
    for source_root in (campaigns, matrix, scheduler, verifier):
        if str(source_root) not in sys.path:
            sys.path.insert(0, str(source_root))
    from regex_conformance_verifier.qualification import build_reference_report

    path = root / "reports" / "small-scale" / "evidence-verification-qualification.json"
    report = load_strict(path)
    validate_instance(
        report,
        load_strict(
            root / "schemas" / "json" / "evidence-verification-qualification.schema.json"
        ),
        source=str(path),
    )
    if canonical_bytes(report) != canonical_bytes(build_reference_report()):
        fail(
            "evidence-verification-reference-drift",
            "evidence verification report differs from the deterministic seeded-corruption matrix",
            str(path),
        )
    keys = [item["case_key"] for item in report["cases"]]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        fail(
            "evidence-verification-reference-order",
            "evidence verification case keys must be unique and code-point ordered",
            str(path),
        )
    return {
        "evidence_verification_reports": 1,
        "evidence_verification_cases": len(keys),
    }
