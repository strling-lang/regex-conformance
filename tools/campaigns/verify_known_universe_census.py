from __future__ import annotations

import argparse
import csv
from collections import Counter
from copy import deepcopy
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
import math
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
import rfc8785


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "reports" / "scale" / "known-universe-census-forecast.json"
SCHEMA = ROOT / "schemas" / "json" / "known-universe-census-forecast.schema.json"


class CensusVerificationError(ValueError):
    pass


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CensusVerificationError(f"{path} must contain a JSON object")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rounded(value: Decimal) -> int:
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def verify_report(
    report: dict,
    *,
    ledger_root: Path | None = None,
    million_readiness_report: Path | None = None,
) -> None:
    schema = load_json(SCHEMA)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(report),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        rendered = "; ".join(
            f"{'/'.join(map(str, error.absolute_path))}: {error.message}"
            for error in errors
        )
        raise CensusVerificationError(rendered)

    digest_input = deepcopy(report)
    claimed_digest = digest_input.pop("report_digest_sha256")
    actual_digest = hashlib.sha256(rfc8785.dumps(digest_input)).hexdigest()
    if claimed_digest != actual_digest:
        raise CensusVerificationError(
            f"report digest mismatch: expected {claimed_digest}, got {actual_digest}"
        )

    for binding in report["repository_source_bindings"]:
        path = ROOT / binding["path"]
        if sha256(path) != binding["sha256"]:
            raise CensusVerificationError(f"repository source binding changed: {path}")

    ledger = report["ledger"]
    if sum(ledger["candidate_disposition_counts"].values()) != ledger["candidate_facts"]:
        raise CensusVerificationError("candidate disposition counts do not close")
    if sum(ledger["catalog_disposition_counts"].values()) != ledger["catalog_leads"]:
        raise CensusVerificationError("catalog disposition counts do not close")
    if ledger["catalog_disposition_counts"]["pending"] != 0:
        raise CensusVerificationError("catalog lead remains pending")

    bounds = report["material_surface_accounting"]["bounds"]
    expected = rounded(Decimal(bounds["lower"] * bounds["conservative"]).sqrt())
    if bounds["expected"] != expected:
        raise CensusVerificationError("expected material-surface bound is not the geometric mean")

    release_basis = report["release_profile_forecast"]["planning_density_basis"]
    for case_name in ("lower", "expected", "conservative"):
        case = report["release_profile_forecast"]["cases"][case_name]
        surface_count = bounds[case_name]
        if case["modeled_facility_or_material_surface_count"] != surface_count:
            raise CensusVerificationError(f"{case_name} release/profile surface count mismatch")
        expected_values = {
            "current_stable_release_line_representatives": rounded(
                Decimal(surface_count)
                * Decimal(release_basis["current_stable_release_line_representatives"])
                / Decimal(release_basis["facility_count"])
            ),
            "current_profiles": rounded(
                Decimal(surface_count)
                * Decimal(release_basis["current_profiles"])
                / Decimal(release_basis["facility_count"])
            ),
            "historical_profiles": rounded(
                Decimal(surface_count)
                * Decimal(release_basis["historical_profiles"][case_name])
                / Decimal(release_basis["facility_count"])
            ),
        }
        for field, value in expected_values.items():
            if case[field] != value:
                raise CensusVerificationError(f"{case_name} {field} mismatch")

    forecast = report["evidence_pack_v2_storage_forecast"]
    forecast_basis = forecast["planning_basis"]
    for case_name in ("lower", "expected", "conservative"):
        case = forecast["cases"][case_name]
        basis = forecast_basis[case_name]
        surface_count = bounds[case_name]
        factor = Decimal(surface_count) / Decimal(forecast_basis["facility_count"])
        expected_values = {
            "surface_count_basis": surface_count,
            "scale_from_planning_index": format(factor, ".12f"),
            "logical_executions": rounded(Decimal(basis["logical_executions"]) * factor),
            "physical_attempts": rounded(Decimal(basis["physical_attempts"]) * factor),
            "bytes_before_growth_allowances": rounded(
                Decimal(basis["bytes_before_growth_allowances"]) * factor
            ),
            "object_count": math.ceil(basis["object_count"] * float(factor)),
        }
        for field, value in expected_values.items():
            if case[field] != value:
                raise CensusVerificationError(f"{case_name} forecast {field} mismatch")
        for field in (
            "fixed_targeted_and_general_reserve_bytes",
            "qualification_corpus_bytes",
        ):
            if case[field] != basis[field]:
                raise CensusVerificationError(f"{case_name} forecast {field} mismatch")
        if case["class_a_requests"] != case["object_count"]:
            raise CensusVerificationError(f"{case_name} Class A count mismatch")
        if case["class_b_requests"] != case["object_count"]:
            raise CensusVerificationError(f"{case_name} Class B count mismatch")
        before = case["bytes_before_growth_allowances"]
        if case["diagnostic_growth_allowance_bytes"] != rounded(
            Decimal(before) * Decimal(basis["diagnostic_growth_rate"])
        ):
            raise CensusVerificationError(f"{case_name} diagnostic allowance mismatch")
        if case["performance_growth_allowance_bytes"] != rounded(
            Decimal(before) * Decimal(basis["performance_growth_rate"])
        ):
            raise CensusVerificationError(f"{case_name} performance allowance mismatch")
        retained = (
            before
            + case["diagnostic_growth_allowance_bytes"]
            + case["performance_growth_allowance_bytes"]
            + case["fixed_targeted_and_general_reserve_bytes"]
            + case["qualification_corpus_bytes"]
        )
        if case["total_retained_bytes"] != retained:
            raise CensusVerificationError(f"{case_name} retained-byte total mismatch")
        if case["soft_stop_delta_bytes"] != forecast["soft_stop_bytes"] - retained:
            raise CensusVerificationError(f"{case_name} soft-stop delta mismatch")
        if case["hard_cap_delta_bytes"] != forecast["hard_cap_bytes"] - retained:
            raise CensusVerificationError(f"{case_name} hard-cap delta mismatch")
        if case["exceeds_soft_stop"] != (retained > forecast["soft_stop_bytes"]):
            raise CensusVerificationError(f"{case_name} soft-stop gate mismatch")
        if case["exceeds_hard_cap"] != (retained > forecast["hard_cap_bytes"]):
            raise CensusVerificationError(f"{case_name} hard-cap gate mismatch")

    gate = report["capacity_gate"]
    if not gate["program_owner_decision_required"]:
        raise CensusVerificationError("capacity gate must require a Program Owner decision")
    if gate["publication_admission"] != "blocked":
        raise CensusVerificationError("publication must remain blocked")
    if gate["paid_capacity_authorized"] or gate["scientific_scope_reduction_authorized"]:
        raise CensusVerificationError("report cannot authorize capacity or scope changes")

    million = report["local_million_qualification_retention"]
    if million["cloud_publication_performed"] or any(million["cloud_requests"].values()):
        raise CensusVerificationError("local qualification cannot claim cloud publication")
    for case_name in ("lower", "expected", "conservative"):
        combined = million["combined_if_later_published"][case_name]
        retained = (
            forecast["cases"][case_name]["total_retained_bytes"]
            + million["projected_remote_upper_bound_bytes"]
        )
        if combined["retained_bytes"] != retained:
            raise CensusVerificationError(f"{case_name} combined retained bytes mismatch")
        if combined["soft_stop_delta_bytes"] != forecast["soft_stop_bytes"] - retained:
            raise CensusVerificationError(f"{case_name} combined soft-stop delta mismatch")
        if combined["hard_cap_delta_bytes"] != forecast["hard_cap_bytes"] - retained:
            raise CensusVerificationError(f"{case_name} combined hard-cap delta mismatch")

    if ledger_root is not None:
        filenames = {
            "language_screening": "language-screening.tsv",
            "catalog": "wikipedia-programming-languages-2026-08-17.tsv",
            "candidate_ledger": "candidate-ledger.tsv",
            "source_scans": "source-scans.tsv",
            "non_language_audit": "non-language-surface-audit-2026-08-19.tsv",
        }
        for key, filename in filenames.items():
            path = ledger_root / filename
            if sha256(path) != ledger["sha256"][key]:
                raise CensusVerificationError(f"external ledger binding changed: {path}")
        candidates = read_tsv(ledger_root / filenames["candidate_ledger"])
        languages = read_tsv(ledger_root / filenames["language_screening"])
        catalog = read_tsv(ledger_root / filenames["catalog"])
        scans = read_tsv(ledger_root / filenames["source_scans"])
        non_language = read_tsv(ledger_root / filenames["non_language_audit"])
        if len(candidates) != ledger["candidate_facts"]:
            raise CensusVerificationError("candidate ledger row count mismatch")
        if len(languages) != ledger["language_roots"]:
            raise CensusVerificationError("language ledger row count mismatch")
        if len(catalog) != ledger["catalog_leads"]:
            raise CensusVerificationError("catalog ledger row count mismatch")
        if len(scans) != ledger["source_scans"]:
            raise CensusVerificationError("source-scan row count mismatch")
        if Counter(row["disposition"] for row in candidates) != Counter(
            ledger["candidate_disposition_counts"]
        ):
            raise CensusVerificationError("candidate ledger dispositions changed")
        if Counter(row["status"] for row in catalog) != Counter(
            ledger["catalog_disposition_counts"]
        ):
            raise CensusVerificationError("catalog dispositions changed")
        for name, rows, identity_field in (
            ("candidate ledger", candidates, "candidate_id"),
            ("language screening", languages, "language"),
            ("catalog", catalog, "source_label"),
            ("source scans", scans, "scan_id"),
            ("non-language audit", non_language, "surface_id"),
        ):
            identities = [row[identity_field] for row in rows]
            if len(identities) != len(set(identities)):
                raise CensusVerificationError(f"{name} contains duplicate identities")
            if any(not value.strip() for row in rows for value in row.values()):
                raise CensusVerificationError(f"{name} contains a blank required field")

    if million_readiness_report is not None:
        if sha256(million_readiness_report) != million["source_report_sha256"]:
            raise CensusVerificationError("million-scale readiness report binding changed")
        readiness = load_json(million_readiness_report)
        expected_fields = {
            "logical_execution_count": million["logical_executions"],
            "attempt_count": million["physical_attempts"],
            "infrastructure_failure_attempt_count": million[
                "infrastructure_failure_attempts"
            ],
            "interruption_count": million["planned_interruptions"],
            "partition_count": million["partitions"],
            "result_shard_count": million["result_shards"],
            "content_addressed_object_count": million["content_addressed_objects"],
        }
        for field, expected_value in expected_fields.items():
            if readiness[field] != expected_value:
                raise CensusVerificationError(f"million readiness {field} mismatch")
        if (
            readiness["capacity"]["projected_remote_upper_bound_bytes"]
            != million["projected_remote_upper_bound_bytes"]
        ):
            raise CensusVerificationError("million readiness remote-byte bound mismatch")
        if readiness["cloud_publication_performed"] or any(
            readiness["cloud_requests"].values()
        ):
            raise CensusVerificationError("million readiness report contains cloud activity")
        if not readiness["ready_for_cloudflare_integrity_check"]:
            raise CensusVerificationError("million readiness report is not terminal-ready")
        if not all(readiness["verification"].values()):
            raise CensusVerificationError("million readiness verification is incomplete")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify the compact known-universe census and its fail-closed forecast."
    )
    parser.add_argument(
        "--ledger-root",
        type=Path,
        help="Optional external exhaustion-ledger directory for exact hash and row verification.",
    )
    parser.add_argument(
        "--million-readiness-report",
        type=Path,
        help="Optional terminal local-readiness report for exact qualification reconciliation.",
    )
    args = parser.parse_args()
    report = load_json(REPORT)
    verify_report(
        report,
        ledger_root=args.ledger_root,
        million_readiness_report=args.million_readiness_report,
    )
    print(
        "known-universe census verified: "
        f"{report['ledger']['language_roots']} roots, "
        f"{report['ledger']['candidate_facts']} candidate facts, "
        f"{report['evidence_pack_v2_storage_forecast']['cases']['conservative']['total_retained_bytes']} conservative universe bytes, "
        f"{report['local_million_qualification_retention']['combined_if_later_published']['conservative']['retained_bytes']} combined bytes"
    )


if __name__ == "__main__":
    main()
