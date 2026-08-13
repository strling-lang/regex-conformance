"""Semantic validation for the governed P17 archetype selection."""

from __future__ import annotations

from typing import Any

from .errors import fail


_REQUIRED_SURFACE_COVERAGE = {
    "standalone": "standalone-library-api",
    "host-runtime": "host-runtime-api",
    "embedded-api-distinct": "database-sql-api",
}
_REQUIRED_ENVIRONMENT_STRATEGIES = {
    "native-source-build",
    "native-runtime",
    "oci-service",
}


def validate_vertical_slice_selection(record: dict[str, Any], *, source: str) -> None:
    """Reject structurally valid selections that violate cross-record invariants."""

    selected = record["selected_archetypes"]
    deferred = record["deferred_candidates"]
    selection_keys = [item["selection_key"] for item in selected]
    selected_handles = [item["seed_handle"] for item in selected]
    deferred_handles = [item["seed_handle"] for item in deferred]

    _require_unique("selection keys", selection_keys, source)
    _require_unique("selected seed handles", selected_handles, source)
    _require_unique("deferred seed handles", deferred_handles, source)
    overlap = sorted(set(selected_handles) & set(deferred_handles))
    if overlap:
        fail(
            "selection-accounting-overlap",
            f"seed candidates cannot be selected and deferred: {', '.join(overlap)}",
            source,
        )
    _require_sorted("deferred seed handles", deferred_handles, source)
    if [item["surface_class"] for item in selected] != [
        "standalone-library-api",
        "host-runtime-api",
        "database-sql-api",
    ]:
        fail(
            "selection-order-nondeterministic",
            "selected archetypes must be ordered standalone, host/runtime, then embedded API",
            source,
        )

    accounting = record["seed_accounting"]
    if accounting["selected_count"] != len(selected):
        fail("selection-count-mismatch", "selected_count does not match selected_archetypes", source)
    if accounting["deferred_count"] != len(deferred):
        fail("selection-count-mismatch", "deferred_count does not match deferred_candidates", source)
    if accounting["candidate_count"] != len(selected) + len(deferred):
        fail("selection-count-mismatch", "candidate_count does not conserve the seed ledger", source)

    by_key = {item["selection_key"]: item for item in selected}
    coverage = record["coverage_claims"]
    for category, surface_class in _REQUIRED_SURFACE_COVERAGE.items():
        references = coverage[category]
        _require_known_references(category, references, by_key, source)
        if not any(by_key[key]["surface_class"] == surface_class for key in references):
            fail(
                "selection-coverage-mismatch",
                f"{category} does not reference a {surface_class} archetype",
                source,
            )

    environment_references = coverage["environment-strategy-diversity"]
    _require_known_references("environment-strategy-diversity", environment_references, by_key, source)
    if set(environment_references) != set(selection_keys):
        fail(
            "selection-coverage-mismatch",
            "environment strategy coverage must account for every selected archetype",
            source,
        )
    strategies = {by_key[key]["required_environment_strategy"] for key in environment_references}
    if strategies != _REQUIRED_ENVIRONMENT_STRATEGIES:
        fail(
            "selection-environment-diversity-missing",
            "vertical slice must cover native source build, native runtime, and OCI service strategies",
            source,
        )

    for item in selected:
        if item["registry_disposition"] != "in-scope":
            fail("selection-not-executable", "selected archetypes must be in-scope registry subjects", source)
        if not item["architecture_purposes"]:
            fail("selection-purpose-missing", "every archetype requires an architecture-testing purpose", source)

    expected_deferral_reason = {
        "in-scope": "backend-node-not-root-target",
        "normative-only-authority": "non-executable-authority",
        "pending-investigation": "pending-investigation",
    }
    for item in deferred:
        if item["reason_code"] != expected_deferral_reason[item["registry_disposition"]]:
            fail(
                "selection-deferral-mismatch",
                "deferral reason must agree with the governed registry disposition",
                source,
            )


def _require_unique(label: str, values: list[str], source: str) -> None:
    if len(values) != len(set(values)):
        fail("selection-identity-collision", f"{label} must be unique", source)


def _require_sorted(label: str, values: list[str], source: str) -> None:
    if values != sorted(values):
        fail("selection-order-nondeterministic", f"{label} must use ascending code-point order", source)


def _require_known_references(
    category: str,
    references: list[str],
    by_key: dict[str, dict[str, Any]],
    source: str,
) -> None:
    unknown = sorted(set(references) - set(by_key))
    if unknown:
        fail(
            "selection-reference-unknown",
            f"{category} references unknown selections: {', '.join(unknown)}",
            source,
        )
