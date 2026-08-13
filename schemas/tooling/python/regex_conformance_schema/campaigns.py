"""Repository validation for campaign source and compiled immutable manifests."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Callable

from .errors import ConformanceDataError
from .jsonio import load_strict


def load_and_validate_campaign_records(
    root: Path,
    *,
    validate_instance: Callable[..., None],
) -> dict[str, int]:
    definition_schema = load_strict(root / "schemas" / "json" / "vertical-slice-campaign-definition.schema.json")
    report_schema = load_strict(root / "schemas" / "json" / "first-campaign-report.schema.json")
    compiled_schema = load_strict(root / "schemas" / "json" / "compiled-campaign.schema.json")
    definitions = sorted((root / "campaigns" / "definitions").glob("*.json"))
    compiled = sorted((root / "campaigns" / "compiled").glob("*.json"))
    vector_sets = sorted((root / "vectors" / "definitions").glob("*.json"))
    reports = sorted((root / "reports" / "vertical-slice").glob("first-campaign*.json"))
    policies = sorted((root / "applicability" / "policies").glob("*.json"))
    for source in definitions:
        validate_instance(load_strict(source), definition_schema, source=str(source))
    for source in vector_sets:
        validate_instance(load_strict(source), load_strict(root / "schemas" / "json" / "probe-vector-set.schema.json"), source=str(source))
    for source in policies:
        validate_instance(load_strict(source), load_strict(root / "schemas" / "json" / "applicability-policy.schema.json"), source=str(source))
    if compiled:
        for source_root in (
            root / "campaigns" / "python",
            root / "matrix" / "python",
            root / "scheduler" / "python",
        ):
            if str(source_root) not in sys.path:
                sys.path.insert(0, str(source_root))
        from regex_conformance_campaign.compiler import verify_compiled_campaign

        for source in compiled:
            record = load_strict(source)
            validate_instance(record, compiled_schema, source=str(source))
            verify_compiled_campaign(root, record)
    compiled_ids = {load_strict(source)["campaign_manifest_id"] for source in compiled}
    for source in reports:
        report = load_strict(source)
        validate_instance(report, report_schema, source=str(source))
        if report["campaign_manifest_id"] not in compiled_ids:
            raise ConformanceDataError("campaign-report-drift", "compact report references an unknown campaign manifest", path=str(source))
    return {
        "applicability_policies": len(policies),
        "campaign_definitions": len(definitions),
        "first_campaign_reports": len(reports),
        "compiled_campaigns": len(compiled),
        "probe_vector_sets": len(vector_sets),
    }
