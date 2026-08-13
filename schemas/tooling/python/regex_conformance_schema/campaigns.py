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
    definition_schemas = {
        "first-vertical-slice.v1.json": definition_schema,
        "small-scale-qualification.v1.json": load_strict(
            root / "schemas" / "json" / "small-scale-campaign-definition.schema.json"
        ),
    }
    vector_schemas = {
        "first-positive-probes.v1.json": load_strict(
            root / "schemas" / "json" / "probe-vector-set.schema.json"
        ),
        "small-scale-qualification.v1.json": load_strict(
            root / "schemas" / "json" / "qualification-probe-vector-set.schema.json"
        ),
    }
    if set(definition_schemas) != {item.name for item in definitions}:
        raise ConformanceDataError(
            "campaign-definition-accounting",
            "campaign definitions are not fully governed",
            path="campaigns/definitions",
        )
    if set(vector_schemas) != {item.name for item in vector_sets}:
        raise ConformanceDataError(
            "probe-vector-accounting",
            "probe vector sets are not fully governed",
            path="vectors/definitions",
        )
    for source in definitions:
        validate_instance(load_strict(source), definition_schemas[source.name], source=str(source))
    for source in vector_sets:
        validate_instance(load_strict(source), vector_schemas[source.name], source=str(source))
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
        from regex_conformance_qualification.compiler import (
            verify_compiled_qualification,
            verify_coverage_report,
        )

        for source in compiled:
            record = load_strict(source)
            validate_instance(record, compiled_schema, source=str(source))
            if source.name == "first-vertical-slice.v1.json":
                verify_compiled_campaign(root, record)
            elif source.name == "small-scale-qualification.v1.json":
                verify_compiled_qualification(root, record)
            else:
                raise ConformanceDataError(
                    "compiled-campaign-accounting",
                    "compiled campaign is not governed",
                    path=str(source),
                )
    compiled_by_id = {
        record["campaign_manifest_id"]: record
        for record in (load_strict(source) for source in compiled)
    }
    for source in reports:
        report = load_strict(source)
        validate_instance(report, report_schema, source=str(source))
        if report["campaign_manifest_id"] not in compiled_by_id:
            raise ConformanceDataError("campaign-report-drift", "compact report references an unknown campaign manifest", path=str(source))
    coverage_reports = sorted(
        (root / "reports" / "small-scale").glob("qualification-coverage*.json")
    )
    coverage_schema = load_strict(
        root / "schemas" / "json" / "qualification-coverage-report.schema.json"
    )
    for source in coverage_reports:
        report = load_strict(source)
        validate_instance(report, coverage_schema, source=str(source))
        compiled_record = compiled_by_id.get(report["campaign_manifest_id"])
        if compiled_record is None:
            raise ConformanceDataError(
                "campaign-report-drift",
                "qualification report references an unknown campaign",
                path=str(source),
            )
        verify_coverage_report(root, compiled_record, report)
    return {
        "applicability_policies": len(policies),
        "campaign_definitions": len(definitions),
        "first_campaign_reports": len(reports),
        "compiled_campaigns": len(compiled),
        "probe_vector_sets": len(vector_sets),
        "qualification_coverage_reports": len(coverage_reports),
    }
