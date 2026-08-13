"""Deterministic seeded-corruption qualification contract for result verification."""

from __future__ import annotations

from typing import Any


_CASES = (
    ("artifact-digest-substitution", "integrity", "artifact-digest-mismatch"),
    ("artifact-reference-category", "reference", "artifact-reference-invalid"),
    ("artifact-size-truncation", "truncation", "artifact-size-mismatch"),
    ("artifact-symlink-indirection", "reference", "artifact-path-indirect"),
    ("attempt-timestamp-naive", "malformed", "attempt-timestamp-invalid"),
    ("duplicate-json-member", "malformed", "duplicate-json-key"),
    ("invalid-json-truncation", "truncation", "invalid-json"),
    ("manifest-root-substitution", "integrity", "manifest-root-digest-mismatch"),
    ("match-state-empty", "semantic", "match-state-without-match"),
    ("noncanonical-json", "canonicalization", "artifact-not-canonical"),
    ("nonmatch-with-matches", "semantic", "nonmatch-state-with-matches"),
    ("observation-attempt-substitution", "reconciliation", "observation-reconciliation-inconsistent"),
    ("response-correlation-substitution", "semantic", "response-correlation-mismatch"),
    ("response-plan-substitution", "semantic", "response-plan-mismatch"),
    ("response-schema-violation", "malformed", "response-schema-invalid"),
    ("shard-membership-substitution", "reconciliation", "shard-membership-inconsistent"),
    ("span-order-impossible", "semantic", "span-order-impossible"),
    ("unknown-artifact-field", "malformed", "artifact-schema-invalid"),
)


def corruption_cases() -> tuple[tuple[str, str, str], ...]:
    return _CASES


def build_reference_report() -> dict[str, Any]:
    cases = [
        {
            "case_key": case_key,
            "analytical_admissible": False,
            "certification_admissible": False,
            "corruption_class": corruption_class,
            "expected_code": expected_code,
            "immutable_source_preserved": True,
            "quarantine_disposition": "quarantined",
            "warehouse_excluded": True,
        }
        for case_key, corruption_class, expected_code in _CASES
    ]
    return {
        "cases": cases,
        "classification": {
            "canonical_authority": False,
            "normative_authority": False,
            "operational_qualification_only": True,
            "semantic_authority": False,
        },
        "schema_version": "evidence-verification-qualification.v1",
        "summary": {
            "case_count": len(cases),
            "quarantined_count": len(cases),
            "warehouse_excluded_count": len(cases),
        },
    }
