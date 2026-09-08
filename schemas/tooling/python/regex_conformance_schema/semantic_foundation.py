"""Integrated acceptance for the frozen semantic knowledge architecture."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import re
from typing import Any

from .certification import CURRENT_REPORT_PATH, verify_repository_certification
from .derivation import (
    CATALOG_PATH as DERIVATION_CATALOG_PATH,
    DERIVATION_IDS,
    require_gate,
    verify_catalog as verify_derivation_catalog,
)
from .errors import fail
from .foundation import verify_foundation_history
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import verify_catalog as verify_identity_catalog


ACCEPTED_INPUT_SHA = "0e84c40ca087e56b9d95441ef5a7681783db9d8b"
PUBLISHED_ON = "2026-09-08"
ALLOCATION_PATH = Path("semantic-corpus/research/semantic-knowledge-foundation-identities-2026-09-08.v1.json")
MANIFEST_PATH = Path("semantic-corpus/foundation/semantic-knowledge-architecture.v1.json")
ACCEPTANCE_PATH = Path("reports/semantics/semantic-knowledge-architecture-acceptance-2026-09-08.v1.json")
ALLOCATION_SCHEMA_PATH = Path("schemas/json/semantic-knowledge-foundation-allocation.schema.json")
MANIFEST_SCHEMA_PATH = Path("schemas/json/semantic-knowledge-foundation-manifest.schema.json")
ACCEPTANCE_SCHEMA_PATH = Path("schemas/json/semantic-knowledge-foundation-acceptance.schema.json")
PROFILE_PATH = Path("schemas/identity-profiles/semantic-research-artifact.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")

SNAPSHOT_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json")
PREDECESSOR_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v3.json")
RESEARCHED_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json")
LEGACY_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json")
FREEZE_PATH = Path("semantic-corpus/freeze/regex-semantic-universe-2026-09-08.v1.json")
AUTHORITY_PATH = Path("semantic-corpus/authority/current.v1.json")
FEATURE_LEDGER_PATH = Path("semantic-corpus/research/regex-semantic-feature-research-2026-09-07.v1.json")
FEATURE_REPORT_PATH = Path("reports/semantics/researched-feature-semantics-2026-09-07.v1.json")
ARCHITECTURE_LEDGER_PATH = Path("semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json")
ARCHITECTURE_REPORT_PATH = Path("reports/semantics/semantic-architecture-disposition-2026-09-07.v1.json")
AUDIT_PLAN_PATH = Path("semantic-corpus/research/regex-semantic-universe-adversarial-plan-2026-09-08.v1.json")
CANDIDATE_LEDGER_PATH = Path("semantic-corpus/research/regex-semantic-universe-candidates-2026-09-08.v1.json")
SOURCE_COVERAGE_PATH = Path("reports/semantics/regex-semantic-source-coverage-2026-09-08.v1.json")
AUDIT_REPORT_PATH = Path("reports/semantics/regex-semantic-universe-adversarial-audit-2026-09-08.v1.json")
FOUNDATION_MANIFEST_PATH = Path("foundation/scientific-foundation.v1.json")
FOUNDATION_ACCEPTANCE_PATH = Path("foundation/scientific-foundation-acceptance.v1.json")

DENOMINATOR_PATHS = {
    "obligation_projection": Path("ontology/projections/regex-semantic-projection-2026-08-22.v1.json"),
    "vector_requirements": Path("vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json"),
    "denominator_forecast": Path("reports/scale/regex-semantic-denominator-forecast.json"),
}
DENOMINATOR_SHA256 = {
    "obligation_projection": "b25fbeaf80fc8e77f92fb5b36a094896bf30e86d4550ad62982f80a028b605b2",
    "vector_requirements": "a03feacf51bf3af241a7ab4fe0ea74bd29981670de93ec3d880a27516232cca7",
    "denominator_forecast": "dab61b42376d757eadada26c31d8fb5c173a508bb6ce780e98a220449ce6e871",
}
PREDECESSOR_SNAPSHOT_SHA256 = {
    LEGACY_PATH: "a1a684abea7cc5a5224b4f94004ee21f05efd2cf5306ce4711dcbe437ff84645",
    RESEARCHED_PATH: "25642d3e5bc7788e4135c0e846e164fb4a69afdee3c86787594cc0f65aeca748",
    PREDECESSOR_PATH: "0365f7c6d6c0899c46670260c9e4a38454d625ef183f7b165b5082fb7acfae95",
}

SEMANTIC_FIELDS = (
    "capture_result",
    "definition",
    "diagnostic_error",
    "host_operation",
    "options_state",
    "replacement",
    "resource_termination",
    "search_iteration",
    "syntax_grammar",
    "unicode_encoding",
)
SEMANTIC_STATES = (
    "implementation-defined",
    "intentionally-under-specified",
    "known",
    "no-feature-specific-implication",
    "not-applicable",
    "profile-dependent",
    "unresolved",
)
SEMANTIC_SCOPES = {
    "canonical-invariant",
    "manifestation-specific",
    "operation-specific",
    "profile-dependent",
    "variant-specific",
}

FACET_INPUTS: dict[str, tuple[tuple[str, ...], str]] = {
    "facet.capture": (("semantic_assertions.capture_result",), "Use the structured capture state and scope; no-effect and unknown states remain distinct."),
    "facet.complexity-guarantee": (("semantic_assertions.resource_termination",), "Inspect documented resource and termination semantics; observed timing cannot create an algorithmic guarantee."),
    "facet.core-match": (("semantic_assertions.definition", "semantic_variants"), "Use the canonical definition and only separately scoped variant distinctions."),
    "facet.error-diagnostics": (("semantic_assertions.diagnostic_error", "semantic_assertions.syntax_grammar"), "Preserve rejection phase, unsupported, and runtime outcome distinctions."),
    "facet.host-api": (("semantic_assertions.host_operation", "supported_operation_ids"), "Resolve feature applicability against canonical operation identities, not vendor method names."),
    "facet.interaction-composition": (("typed_relations", "prerequisite_feature_ids", "modifier_ids"), "Consume explicit typed relations and prerequisites without expanding all pairs."),
    "facet.option-state": (("semantic_assertions.options_state", "modifier_ids"), "Use explicit state semantics and referenced modifiers."),
    "facet.phase": (("semantic_assertions.syntax_grammar", "semantic_assertions.diagnostic_error", "semantic_assertions.replacement", "semantic_assertions.host_operation", "supported_operation_ids"), "Resolve lifecycle phase from structured semantic dimensions and canonical operations."),
    "facet.replacement": (("semantic_assertions.replacement", "supported_operation_ids"), "Emit replacement candidates only from the structured replacement state and replacement operations."),
    "facet.resource-termination": (("semantic_assertions.resource_termination",), "Keep semantic resource contracts distinct from physical telemetry."),
    "facet.search-boundary": (("semantic_assertions.search_iteration", "supported_operation_ids"), "Use explicit search and advancement semantics for applicable operations."),
    "facet.security-context": (("semantic_assertions.syntax_grammar", "semantic_assertions.options_state", "semantic_assertions.host_operation", "semantic_assertions.resource_termination"), "Inspect source-bound trust, injection, and denial-of-service semantics without inventing policy prose."),
    "facet.syntax": (("semantic_assertions.syntax_grammar", "manifestation_ids"), "Separate canonical grammar semantics from manifestation spellings."),
    "facet.unicode-encoding": (("semantic_assertions.unicode_encoding", "modifier_ids"), "Preserve byte, code-unit, code-point, and grapheme distinctions and their governing modes."),
    "facet.version-platform-differential": (("semantic_assertions", "semantic_variants", "manifestation_ids", "source_ids"), "Retain source version, scope, variant, and manifestation boundaries for conditional applicability."),
}

AUTHORITY_MATRIX = (
    ("feature-identity", "scientific-identity", (), ("semantic-snapshot", "certification"), "Scientific identity alone decides which enduring entity a feature record denotes."),
    ("feature-meaning", "semantic-snapshot", ("scientific-identity", "source-registry"), ("variants", "manifestations", "profiles"), "The frozen snapshot owns canonical feature invariants; narrower layers cannot promote behavior to universal meaning."),
    ("variant-behavior", "variants", ("semantic-snapshot", "source-registry"), ("manifestations", "profiles"), "Variant records own source-bound semantic alternatives while preserving their canonical feature parent."),
    ("manifestation-behavior", "manifestations", ("semantic-snapshot", "source-registry"), ("profiles",), "Manifestations own syntax and API forms, not canonical semantic identity."),
    ("operation-meaning", "operation-registry", ("source-registry",), ("features", "manifestations"), "Canonical operations own invocation and result contracts; vendor methods map to them."),
    ("facet-semantics", "facet-model", ("source-registry",), ("denominator-compiler",), "The facet registry owns dimensions and vocabularies; later derivation only applies them."),
    ("source-authority", "source-registry", (), ("derivation-catalog", "generator"), "Source records and assertion bindings preserve publisher scope; a generator cannot become semantic authority."),
    ("candidate-completeness", "freeze-candidate-ledgers", ("source-registry", "semantic-snapshot"), ("generator", "certification"), "Declared-cutoff completeness comes from the audited search and terminal dispositions, never row construction alone."),
)

REQUIRED_CHECKS = (
    "accepted-candidate-realization",
    "adversarial-freeze-closure",
    "authority-boundaries",
    "candidate-disposition-closure",
    "denominator-baseline",
    "denominator-readiness",
    "derivation-integrity",
    "deterministic-regeneration",
    "facet-architecture",
    "feature-research-completeness",
    "identity-lineage",
    "operation-taxonomy",
    "scientific-foundation",
    "semantic-authority-pointer",
    "source-authority-coverage",
    "variant-manifestation-isolation",
)

ACCEPTED_TARGET_EXCEPTIONS = {
    "candidate.feature.full-code-point-complement-policy": ("facet.unicode-encoding",),
    "candidate.feature.generated-regex-build-time": ("facet.phase",),
    "candidate.manifestation.replacement-backslash-reference": ("manifestation.replacement-numbered-group.python-backslash",),
    "candidate.manifestation.replacement-dollar-reference": ("manifestation.replacement-numbered-group.java-dollar",),
    "candidate.manifestation.replacement-g-reference": ("manifestation.replacement-numbered-group.python-g",),
    "candidate.source.lucene": ("lucene-regexp",),
    "candidate.source.smtlib": ("smtlib-unicode-strings",),
    "candidate.source.swift": ("swift-regex-builder", "swift-regex-literals", "swift-regex-type"),
    "candidate.source.unicode-database": ("unicode-uax44",),
    "candidate.source.unicode-line-break": ("unicode-tr14",),
    "candidate.taxonomy.resource-versus-complexity": ("facet.complexity-guarantee",),
    "candidate.taxonomy.result-span-mutators": ("feature.reset-reported-match-end", "feature.reset-reported-match-start"),
}


def _raw_sha(root: Path, relative: Path) -> str:
    return hashlib.sha256((root / relative).read_bytes()).hexdigest()


def _record_digest(record: dict[str, Any], *excluded: str) -> str:
    body = {key: value for key, value in record.items() if key not in excluded}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _families(root: Path) -> dict[str, str]:
    allocation = load_strict(root / ALLOCATION_PATH)
    validate_instance(allocation, load_strict(root / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_PATH.as_posix())
    values = {item["canonical_key"]: item["assigned_id"] for item in allocation["allocations"]}
    expected = {"schema.semantic-knowledge-foundation.manifest", "schema.semantic-knowledge-foundation.acceptance"}
    if set(values) != expected:
        fail("semantic-foundation-allocation", "the allocation must contain exactly the manifest and acceptance schema families")
    return {key.rsplit(".", 1)[-1]: value for key, value in values.items()}


def _finalize(root: Path, body: dict[str, Any], *, namespace: str, family: str, id_field: str, digest_field: str) -> dict[str, Any]:
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    identity = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=family,
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": digest},
    )["content_id"]
    return {**body, id_field: identity, digest_field: digest}


def _file_ref(root: Path, role: str, path: Path) -> dict[str, str]:
    return {"role": role, "path": path.as_posix(), "file_sha256": _raw_sha(root, path)}


def _artifact_ref(root: Path, role: str, path: Path, id_field: str, digest_field: str) -> dict[str, str]:
    artifact = load_strict(root / path)
    return {
        "role": role,
        "path": path.as_posix(),
        "artifact_id": artifact[id_field],
        "content_digest_sha256": artifact[digest_field],
        "file_sha256": _raw_sha(root, path),
    }


def _derivation_bindings(root: Path) -> list[dict[str, str]]:
    catalog = load_strict(root / DERIVATION_CATALOG_PATH)
    by_id = {item["derivation_id"]: item for item in catalog["derivations"]}
    specs = (
        ("artifact-bytes", "artifact-measurement", "independent-evidence"),
        ("authority-selection", "manual-registry-decision", "governance-policy"),
        ("gate-conjunction", "reconciliation-calculation", "structural-integrity"),
        ("semantic-closure", "semantic-universe-freeze", "semantic-completeness"),
    )
    bindings = []
    for binding_key, key, gate_kind in specs:
        identifier = DERIVATION_IDS[key]
        record = by_id[identifier]
        bindings.append({
            "binding_key": binding_key,
            "derivation_id": identifier,
            "derivation_revision_id": record["derivation_revision_id"],
            "derivation_class": record["derivation_class"],
            "gate_kind": gate_kind,
        })
    return bindings


def _population(root: Path, snapshot: dict[str, Any], identity_count: int) -> dict[str, int]:
    typed_interaction_count = len(load_strict(root / LEGACY_PATH)["interactions"])
    return {
        "features": len(snapshot["features"]),
        "operations": len(snapshot["operations"]),
        "facets": len(snapshot["semantic_facets"]),
        "sources": len(snapshot["sources"]),
        "variants": sum(len(feature["semantic_variants"]) for feature in snapshot["features"]),
        "manifestations": len(snapshot["manifestations"]),
        "modifiers": len(snapshot["modifiers"]),
        "typed_interactions": typed_interaction_count,
        "scientific_identities": identity_count,
    }


def _denominator_baseline(root: Path) -> dict[str, Any]:
    actual = {key: _raw_sha(root, path) for key, path in DENOMINATOR_PATHS.items()}
    return {
        "state": "pre-rederivation-predecessor-bound",
        "obligation_templates": 12048,
        "vector_requirements": 9506,
        "artifact_sha256": actual,
    }


def build_manifest(root: Path) -> dict[str, Any]:
    families = _families(root)
    snapshot = load_strict(root / SNAPSHOT_PATH)
    foundation_acceptance = load_strict(root / FOUNDATION_ACCEPTANCE_PATH)
    identity_count = load_strict(root / "registries/identity/scientific-identities.v1.json")["counts"]["total"]
    facet_inputs = [
        {"facet_id": facet_id, "source_selectors": list(selectors), "resolution_rule": rule}
        for facet_id, (selectors, rule) in sorted(FACET_INPUTS.items())
    ]
    matrix = [
        {
            "decision_domain": domain,
            "canonical_owner": owner,
            "consumes_from": list(consumes),
            "forbidden_alternate_owners": list(forbidden),
            "rule": rule,
        }
        for domain, owner, consumes, forbidden, rule in AUTHORITY_MATRIX
    ]
    body = {
        "schema_version": "semantic-knowledge-foundation-manifest.v1",
        "accepted_input_repository_sha": ACCEPTED_INPUT_SHA,
        "declared_cutoff": snapshot["authority"]["cutoff"],
        "identity_schema_family_id": families["manifest"],
        "identity_schema_version": "1.0.0",
        "implementation": [
            _file_ref(root, "gate-evaluator", Path("schemas/tooling/python/regex_conformance_schema/semantic_foundation.py")),
            _file_ref(root, "gate-tool", Path("tools/semantics/certify_semantic_knowledge.py")),
            _file_ref(root, "allocation-schema", ALLOCATION_SCHEMA_PATH),
            _file_ref(root, "manifest-schema", MANIFEST_SCHEMA_PATH),
            _file_ref(root, "acceptance-schema", ACCEPTANCE_SCHEMA_PATH),
        ],
        "semantic_authority": {
            "snapshot": _artifact_ref(root, "current-semantic-snapshot", SNAPSHOT_PATH, "snapshot_id", "snapshot_digest_sha256"),
            "freeze_manifest": _artifact_ref(root, "declared-cutoff-freeze", FREEZE_PATH, "manifest_id", "manifest_digest_sha256"),
            "authority_index": _artifact_ref(root, "semantic-authority-index", AUTHORITY_PATH, "index_id", "index_digest_sha256"),
            "predecessor": _artifact_ref(root, "semantic-predecessor", PREDECESSOR_PATH, "snapshot_id", "snapshot_digest_sha256"),
        },
        "research_evidence": [
            _artifact_ref(root, "feature-research-ledger", FEATURE_LEDGER_PATH, "research_ledger_id", "research_ledger_digest_sha256"),
            _artifact_ref(root, "feature-research-report", FEATURE_REPORT_PATH, "report_id", "report_digest_sha256"),
            _artifact_ref(root, "architecture-candidate-ledger", ARCHITECTURE_LEDGER_PATH, "ledger_id", "ledger_digest_sha256"),
            _artifact_ref(root, "architecture-disposition-report", ARCHITECTURE_REPORT_PATH, "report_id", "report_digest_sha256"),
            _artifact_ref(root, "adversarial-audit-plan", AUDIT_PLAN_PATH, "plan_id", "plan_digest_sha256"),
            _artifact_ref(root, "adversarial-candidate-ledger", CANDIDATE_LEDGER_PATH, "ledger_id", "ledger_digest_sha256"),
            _artifact_ref(root, "source-coverage-report", SOURCE_COVERAGE_PATH, "report_id", "report_digest_sha256"),
            _artifact_ref(root, "adversarial-audit-report", AUDIT_REPORT_PATH, "report_id", "report_digest_sha256"),
        ],
        "semantic_population": _population(root, snapshot, identity_count),
        "scientific_foundation": {
            "foundation_manifest": _artifact_ref(root, "scientific-foundation-manifest", FOUNDATION_MANIFEST_PATH, "foundation_manifest_id", "foundation_manifest_digest_sha256"),
            "acceptance_report": _artifact_ref(root, "scientific-foundation-acceptance", FOUNDATION_ACCEPTANCE_PATH, "acceptance_report_id", "acceptance_report_digest_sha256"),
            "acceptance_state": foundation_acceptance["foundation_acceptance"],
        },
        "authority_matrix": matrix,
        "denominator_input_contract": {
            "feature_state_vocabulary": list(SEMANTIC_STATES),
            "facet_inputs": facet_inputs,
            "operation_rule": "Feature rows expose applicable canonical operation IDs; operation-only surfaces remain independently inspectable from the operation registry and do not require duplicate feature identities.",
            "variant_rule": "Variant-specific assertions remain separate inputs and cannot redefine the canonical feature invariant.",
            "manifestation_rule": "Manifestations provide syntax or API applicability and retain their canonical semantic owner.",
            "template_fallback_permitted": False,
        },
        "denominator_baseline": _denominator_baseline(root),
        "assertion_derivations": _derivation_bindings(root),
    }
    return _finalize(root, body, namespace="artifact-set-manifest", family=families["manifest"], id_field="manifest_id", digest_field="manifest_digest_sha256")


def _authority_sets(snapshot: dict[str, Any]) -> dict[str, set[str]]:
    return {
        "accept-canonical": {item["feature_id"] for item in snapshot["features"]},
        "accept-as-operation": {item["operation_id"] for item in snapshot["operations"]},
        "accept-as-facet": {item["facet_id"] for item in snapshot["semantic_facets"]},
        "accept-as-source": {item["source_id"] for item in snapshot["sources"]},
        "accept-as-variant": {variant["variant_id"] for item in snapshot["features"] for variant in item["semantic_variants"]},
        "accept-as-manifestation": {item["manifestation_id"] for item in snapshot["manifestations"]},
        "accept-as-modifier": {item["modifier_id"] for item in snapshot["modifiers"]},
    }


def _candidate_targets(candidate: dict[str, Any]) -> tuple[str, ...]:
    key = candidate["candidate_key"]
    if key in ACCEPTED_TARGET_EXCEPTIONS:
        return ACCEPTED_TARGET_EXCEPTIONS[key]
    parts = key.split(".")
    if parts[1] == "residual":
        parts.pop(1)
    prefixes = {
        "accept-canonical": "feature",
        "accept-as-operation": "operation",
        "accept-as-facet": "facet",
        "accept-as-source": "",
        "accept-as-variant": "variant",
        "accept-as-manifestation": "manifestation",
        "accept-as-modifier": "modifier",
    }
    disposition = candidate["disposition"]
    tail = parts[-1] if disposition == "accept-as-source" else ".".join(parts[2:])
    prefix = prefixes[disposition]
    return ((f"{prefix}.{tail}" if prefix else tail),)


def _validate_authority_matrix(matrix: list[dict[str, Any]]) -> None:
    domains = [item["decision_domain"] for item in matrix]
    if len(domains) != len(set(domains)) or set(domains) != {item[0] for item in AUTHORITY_MATRIX}:
        fail("semantic-authority-conflict", "each semantic decision domain must have exactly one canonical owner")
    owners = {item["canonical_owner"] for item in matrix}
    for item in matrix:
        if item["canonical_owner"] in item["forbidden_alternate_owners"]:
            fail("semantic-authority-conflict", "a canonical owner cannot also be forbidden", item["decision_domain"])
        if not set(item["consumes_from"]) <= owners | {"scientific-identity", "source-registry"}:
            fail("semantic-authority-owner", "authority matrix names an unknown input owner", item["decision_domain"])


def _validate_features(root: Path, snapshot: dict[str, Any]) -> None:
    known_sources = {item["source_id"] for item in snapshot["sources"]}
    known_operations = {item["operation_id"].removeprefix("operation.") for item in snapshot["operations"]}
    known_manifestations = {item["manifestation_id"] for item in snapshot["manifestations"]}
    known_modifiers = {item["modifier_id"] for item in snapshot["modifiers"]}
    legacy = load_strict(root / LEGACY_PATH)
    legacy_values = {
        value
        for feature in legacy["features"]
        for key, value in feature.items()
        if key in {"capture_result_semantics", "diagnostic_semantics", "replacement_implications", "resource_termination_implications", "unicode_encoding_implications"} and isinstance(value, str)
    }
    scientific_ids: set[str] = set()
    names: set[str] = set()
    variant_ids: set[str] = set()
    variant_scientific_ids: set[str] = set()
    for feature in snapshot["features"]:
        path = feature["feature_id"]
        if feature["scientific_id"] in scientific_ids:
            fail("duplicate-canonical-ownership", "two features claim one scientific identity", path)
        scientific_ids.add(feature["scientific_id"])
        name = " ".join(feature["canonical_name"].casefold().split())
        if name in names:
            fail("duplicate-canonical-ownership", "two features claim one normalized canonical name", path)
        names.add(name)
        if set(feature["semantic_assertions"]) != set(SEMANTIC_FIELDS):
            fail("semantic-feature-incomplete", "feature does not expose the exact researched semantic dimensions", path)
        if not set(feature["supported_operation_ids"]) <= known_operations:
            fail("semantic-operation-reference", "feature references an unknown operation", path)
        if not set(feature["manifestation_ids"]) <= known_manifestations or not set(feature["modifier_ids"]) <= known_modifiers:
            fail("semantic-parent-reference", "feature references an unknown manifestation or modifier", path)
        for field, assertion in feature["semantic_assertions"].items():
            if assertion["field"] != field or assertion["state"] not in SEMANTIC_STATES or assertion["scope"] not in SEMANTIC_SCOPES:
                fail("semantic-assertion-state", "semantic assertion state, scope, or field is invalid", f"{path}/{field}")
            if not assertion["source_ids"] or not set(assertion["source_ids"]) <= known_sources:
                fail("semantic-source-reference", "semantic assertion lacks a resolvable source", f"{path}/{field}")
            if assertion["statement"] in legacy_values or re.search(r"\bbehavior may vary\b", assertion["statement"], re.IGNORECASE):
                fail("template-semantic-regression", "legacy or vague template semantics re-entered the frozen snapshot", f"{path}/{field}")
        for variant in feature["semantic_variants"]:
            if variant["semantic_assertion"]["scope"] != "variant-specific":
                fail("variant-authority-leak", "variant behavior was promoted outside variant scope", variant["variant_id"])
            if variant["variant_id"] in variant_ids or variant["scientific_id"] in variant_scientific_ids:
                fail("duplicate-canonical-ownership", "two variants claim one canonical key or scientific identity", variant["variant_id"])
            variant_ids.add(variant["variant_id"])
            variant_scientific_ids.add(variant["scientific_id"])
            assertion = variant["semantic_assertion"]
            if not assertion["source_ids"] or not set(assertion["source_ids"]) <= known_sources:
                fail("semantic-source-reference", "variant assertion lacks a resolvable source", variant["variant_id"])
        if any(question.get("blocking") for question in feature.get("unresolved_semantic_questions", [])):
            fail("blocking-semantic-question", "feature retains a blocking unresolved semantic question", path)
    if len(scientific_ids) != 269:
        fail("semantic-feature-population", "the frozen snapshot must contain exactly 269 unique canonical features")
    if len(variant_ids) != 93:
        fail("semantic-variant-population", "the frozen snapshot must contain exactly 93 unique semantic variants")


def _validate_operations_and_facets(root: Path, snapshot: dict[str, Any]) -> None:
    source_ids = [item["source_id"] for item in snapshot["sources"]]
    if len(source_ids) != 60 or len(set(source_ids)) != 60:
        fail("semantic-source-population", "the source registry must contain exactly 60 unique identities")
    for source in snapshot["sources"]:
        if not source["scope"] or not source["version_or_revision"] or not source["authority"]:
            fail("semantic-source-precision", "source scope, version, and authority must be explicit", source["source_id"])
    source_id_set = set(source_ids)
    operation_ids = [item["operation_id"] for item in snapshot["operations"]]
    if len(operation_ids) != 33 or len(set(operation_ids)) != 33:
        fail("semantic-operation-population", "the canonical operation registry must contain 33 unique operations")
    for operation in snapshot["operations"]:
        if not operation["semantic_contract"] or not operation["source_ids"] or not set(operation["source_ids"]) <= source_id_set:
            fail("semantic-operation-authority", "operation lacks its scientific contract or source authority", operation["operation_id"])
    facets = {item["facet_id"]: item for item in snapshot["semantic_facets"]}
    if set(facets) != set(FACET_INPUTS):
        fail("semantic-facet-population", "the canonical facet model must equal the fifteen denominator-input dimensions")
    expected_special = {
        "facet.phase": {"build-source-generation", "compile", "match-search", "replacement-substitution", "stream-session", "serialization-deserialization"},
        "facet.complexity-guarantee": {"none-declared", "worst-case-time", "worst-case-memory", "subset-conditional", "resource-budget"},
        "facet.security-context": {"trusted-pattern", "untrusted-pattern", "trusted-subject", "untrusted-subject", "trusted-serialized-input", "untrusted-serialized-input", "injection-boundary", "denial-of-service-posture"},
    }
    for facet_id, facet in facets.items():
        if not facet["domain"] or len(facet["domain"]) != len(set(facet["domain"])) or not facet["source_ids"] or not set(facet["source_ids"]) <= source_id_set:
            fail("semantic-facet-authority", "facet lacks a unique vocabulary or source authority", facet_id)
        if facet_id in expected_special and set(facet["domain"]) != expected_special[facet_id]:
            fail("semantic-facet-vocabulary", "a newly accepted facet vocabulary drifted", facet_id)
    modifiers = [item["modifier_id"] for item in snapshot["modifiers"]]
    if len(modifiers) != 33 or len(set(modifiers)) != 33:
        fail("semantic-modifier-population", "the modifier registry must contain exactly 33 unique modifiers")
    catalog = load_strict(root / "registries/identity/scientific-identities.v1.json")
    locked_modifiers = {item["canonical_key"] for item in catalog["bindings"] if item["entity_class"] == "modifier"}
    if set(modifiers) != locked_modifiers:
        fail("semantic-modifier-identity", "modifier registry does not reconcile with the scientific identity lock")


def _validate_manifestations(snapshot: dict[str, Any]) -> None:
    feature_scientific_ids = {item["scientific_id"] for item in snapshot["features"]}
    feature_keys = {item["feature_id"] for item in snapshot["features"]}
    source_ids = {item["source_id"] for item in snapshot["sources"]}
    identities: set[str] = set()
    for item in snapshot["manifestations"]:
        if item["scientific_id"] in identities:
            fail("duplicate-canonical-ownership", "two manifestations claim one scientific identity", item["manifestation_id"])
        identities.add(item["scientific_id"])
        if item.get("semantic_scope") != "manifestation-specific" or item["canonical_semantics_owner"] not in feature_scientific_ids:
            fail("manifestation-authority-leak", "manifestation does not retain its canonical semantic owner", item["manifestation_id"])
        if item["semantic_feature_id"] not in feature_keys or item["source_id"] not in source_ids:
            fail("manifestation-parent-reference", "manifestation references an unknown feature or source", item["manifestation_id"])
    if len(identities) != 326:
        fail("semantic-manifestation-population", "the frozen snapshot must contain exactly 326 unique manifestations")


def _validate_candidates(snapshot: dict[str, Any], prior: dict[str, Any], ledger: dict[str, Any]) -> None:
    prior_ids = {item["candidate_id"] for item in prior["candidates"]}
    current_ids = {item["candidate_id"] for item in ledger["candidates"]}
    if not prior_ids <= current_ids or ledger["counts"]["prior_revalidated"] != len(prior_ids):
        fail("semantic-candidate-disappeared", "a predecessor candidate lacks explicit revalidation")
    if ledger["counts"]["blocking_unresolved"] or any(item["blocking"] for item in ledger["candidates"]):
        fail("semantic-candidate-blocking", "a blocking semantic candidate prevents acceptance")
    if len(current_ids) != len(ledger["candidates"]) or ledger["counts"]["total"] != len(current_ids):
        fail("semantic-candidate-accounting", "candidate identities or declared population do not reconcile")
    authority = _authority_sets(snapshot)
    source_ids = authority["accept-as-source"]
    for candidate in ledger["candidates"]:
        if not candidate["rationale"] or not candidate["evidence_source_ids"] or not candidate["downstream_consequence"]:
            fail("semantic-candidate-evidence", "candidate lacks rationale, evidence, or downstream disposition", candidate["candidate_key"])
        if not set(candidate["evidence_source_ids"]) <= source_ids:
            fail("semantic-candidate-evidence", "candidate evidence references an unknown semantic source", candidate["candidate_key"])
        if candidate["disposition"] in authority:
            targets = _candidate_targets(candidate)
            if not set(targets) <= authority[candidate["disposition"]]:
                fail("accepted-candidate-missing", "accepted candidate is absent from its canonical layer", candidate["candidate_key"])


def _validate_source_coverage(snapshot: dict[str, Any], coverage: dict[str, Any]) -> None:
    feature_ids = {item["feature_id"] for item in snapshot["features"]}
    coverage_ids = {item["feature_id"] for item in coverage["features"]}
    if feature_ids != coverage_ids or coverage["summary"]["feature_count"] != 269:
        fail("semantic-source-coverage", "source coverage does not reconcile with the frozen feature population")
    if coverage["summary"]["source_orphan_count"] or coverage["summary"]["secondary_only_count"]:
        fail("semantic-source-orphan", "an accepted canonical feature lacks primary authority")


def _validate_authority_pointer(snapshot: dict[str, Any], authority: dict[str, Any], freeze: dict[str, Any]) -> None:
    if authority["current_snapshot"]["id"] != snapshot["snapshot_id"] or authority["freeze_manifest"]["id"] != freeze["manifest_id"]:
        fail("stale-semantic-authority", "the semantic authority index does not point to the frozen snapshot and manifest")
    if authority["denominator_authority"]["state"] != "pre-rederivation-predecessor-bound":
        fail("semantic-denominator-authority", "denominator authority advanced before dedicated rederivation")


def _validate_identity_evolution(root: Path, snapshot: dict[str, Any]) -> None:
    researched = load_strict(root / RESEARCHED_PATH)
    predecessor = load_strict(root / PREDECESSOR_PATH)
    current = {item["feature_id"]: item["scientific_id"] for item in snapshot["features"]}
    original = {item["feature_id"]: item["scientific_id"] for item in researched["features"]}
    if original != {key: current[key] for key in original} or len(original) != 251:
        fail("semantic-identity-churn", "an original researched feature identity changed")
    if len(predecessor["features"]) != 268 or len(snapshot["features"]) != 269:
        fail("semantic-identity-evolution", "semantic successor feature populations drifted")
    if snapshot["carried_forward_by_reference"].get("typed_interactions") != (
        "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json#/interactions"
    ) or len(load_strict(root / LEGACY_PATH)["interactions"]) != 108:
        fail("semantic-interaction-authority", "the 108 typed interactions are not bound to their immutable authority")
    for path, digest in PREDECESSOR_SNAPSHOT_SHA256.items():
        if _raw_sha(root, path) != digest:
            fail("semantic-predecessor-mutation", "an immutable predecessor snapshot changed", path.as_posix())


def _validate_derivations(root: Path, snapshot: dict[str, Any], ledger: dict[str, Any]) -> None:
    catalog = load_strict(root / DERIVATION_CATALOG_PATH)
    by_id = {item["derivation_id"]: item for item in catalog["derivations"]}
    for feature in snapshot["features"]:
        for field, assertion in feature["semantic_assertions"].items():
            record = by_id.get(assertion["derivation_id"])
            if record is None or record["derivation_class"] != assertion["derivation_class"]:
                fail("semantic-derivation-reference", "assertion derivation is missing or contradictory", f"{feature['feature_id']}/{field}")
            if record["derivation_class"] not in {"research-derived", "external-evidence", "inference"}:
                fail("semantic-derivation-escalation", "construction or governance output cannot supply semantic meaning", f"{feature['feature_id']}/{field}")
    require_gate(catalog, ledger["derivation_id"], "semantic-completeness")
    for binding in _derivation_bindings(root):
        require_gate(catalog, binding["derivation_id"], binding["gate_kind"])


def _denominator_readiness(snapshot: dict[str, Any]) -> dict[str, Any]:
    features = {item["feature_id"]: item for item in snapshot["features"]}
    operations = {item["operation_id"] for item in snapshot["operations"]}
    no_capture = next(item for item in snapshot["features"] if item["semantic_assertions"]["capture_result"]["state"] == "no-feature-specific-implication")
    unicode_sensitive = next(item for item in snapshot["features"] if item["semantic_assertions"]["unicode_encoding"]["state"] == "known")
    replacement = features["feature.replacement-numbered-group"]
    implementation_defined = next(item for item in snapshot["features"] if any(value["state"] == "implementation-defined" for value in item["semantic_assertions"].values()))
    required_new_operations = {
        "operation.escape-pattern", "operation.escape-replacement", "operation.serialize-pattern", "operation.deserialize-pattern",
        "operation.inspect-pattern", "operation.stream-open", "operation.stream-close", "operation.stream-reset",
        "operation.stream-copy", "operation.stream-compress", "operation.stream-expand",
    }
    fixtures = [
        {"scenario": "no-capture-implication", "status": "PASS", "evidence": [no_capture["feature_id"], "capture state=no-feature-specific-implication, not unknown"]},
        {"scenario": "unicode-sensitive-feature", "status": "PASS", "evidence": [unicode_sensitive["feature_id"], "unicode state=known"]},
        {"scenario": "replacement-only-feature", "status": "PASS", "evidence": [replacement["feature_id"], "replacement state and canonical replacement operations are explicit"]},
        {"scenario": "implementation-defined-field", "status": "PASS", "evidence": [implementation_defined["feature_id"], "conditional applicability remains distinguishable from not-applicable"]},
        {"scenario": "new-facet-inputs", "status": "PASS", "evidence": ["phase, complexity-guarantee, and security-context have explicit source selectors"]},
        {"scenario": "operation-only-input", "status": "PASS", "evidence": ["all eleven escape, serialization, inspection, and stream-lifecycle operations are canonical registry inputs"]},
    ]
    if not required_new_operations <= operations:
        fail("denominator-operation-input", "an accepted operation-only denominator input is missing")
    return {
        "features_inspectable": len(snapshot["features"]),
        "facet_mappings": len(FACET_INPUTS),
        "operations_inspectable": len(snapshot["operations"]),
        "template_fallback_permitted": False,
        "fixtures": fixtures,
    }


def _check(check_id: str, *evidence: str) -> dict[str, Any]:
    return {"check_id": check_id, "status": "PASS", "evidence": list(evidence)}


def _acceptance_sampling(snapshot: dict[str, Any], plan: dict[str, Any], ledger: dict[str, Any], coverage: dict[str, Any]) -> list[dict[str, Any]]:
    categories = {item["category"] for item in snapshot["features"]}
    accepted_operations = sum(item["disposition"] == "accept-as-operation" for item in ledger["candidates"])
    return [
        {"strategy": "source-first", "status": "PASS", "evidence": [f"features={coverage['summary']['feature_count']}", "orphans=0", "secondary-only=0"]},
        {"strategy": "category-first", "status": "PASS", "evidence": [f"categories={len(categories)}", "each sampled through the exact ten-field research contract"]},
        {"strategy": "operation-first", "status": "PASS", "evidence": [f"operations={len(snapshot['operations'])}", f"accepted-operation-candidates={accepted_operations}"]},
        {"strategy": "test-corpus-first", "status": "PASS", "evidence": [f"authoritative-corpora={len(plan['test_corpora'])}", f"candidate-yield={ledger['counts']['new_candidate_yield_by_strategy']['test-corpus-first']}"]},
    ]


def build_acceptance_report(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    families = _families(root)
    snapshot = load_strict(root / SNAPSHOT_PATH)
    plan = load_strict(root / AUDIT_PLAN_PATH)
    prior = load_strict(root / ARCHITECTURE_LEDGER_PATH)
    ledger = load_strict(root / CANDIDATE_LEDGER_PATH)
    coverage = load_strict(root / SOURCE_COVERAGE_PATH)
    certification = load_strict(root / CURRENT_REPORT_PATH)
    identity_catalog = load_strict(root / "registries/identity/scientific-identities.v1.json")
    identity_counts = {
        "scientific_identities": identity_catalog["counts"]["total"],
        "scientific_lineage_records": identity_catalog["counts"]["lineage_records"],
    }
    readiness = _denominator_readiness(snapshot)
    denominator = _denominator_baseline(root)
    criteria = {item["criterion_id"]: item["status"] for item in certification["criteria"]}
    checks = [
        _check("accepted-candidate-realization", "all accepted candidates resolve in their canonical feature, operation, facet, source, variant, manifestation, or modifier layer"),
        _check("adversarial-freeze-closure", "freeze result=PASS", "blocking candidates=0"),
        _check("authority-boundaries", "eight semantic decision domains have one canonical owner"),
        _check("candidate-disposition-closure", f"candidates={ledger['counts']['total']}", "blocking=0"),
        _check("denominator-baseline", "obligations=12048", "requirements=9506", "C4=0/9506"),
        _check("denominator-readiness", f"features={readiness['features_inspectable']}", f"facet-mappings={readiness['facet_mappings']}", f"operations={readiness['operations_inspectable']}"),
        _check("derivation-integrity", "semantic assertions retain source-bound admissible derivations", "construction does not prove semantic closure"),
        _check("deterministic-regeneration", "manifest and acceptance report rebuild from exact inputs"),
        _check("facet-architecture", "facets=15", "phase/complexity/security vocabularies exact"),
        _check("feature-research-completeness", "features=269", "semantic assertions=2690", "template regression=0"),
        _check("identity-lineage", f"identities={identity_counts['scientific_identities']}", f"lineage={identity_counts['scientific_lineage_records']}"),
        _check("operation-taxonomy", "operations=33", "operation-only surfaces remain canonical operation inputs"),
        _check("scientific-foundation", "historical acceptance=PASS"),
        _check("semantic-authority-pointer", snapshot["snapshot_id"], "denominator authority remains predecessor-bound"),
        _check("source-authority-coverage", "features=269/269", "orphans=0", "secondary-only=0"),
        _check("variant-manifestation-isolation", "variants=93", "manifestations=326", "canonical owner retained"),
    ]
    if tuple(sorted(item["check_id"] for item in checks)) != REQUIRED_CHECKS:
        fail("semantic-foundation-check-set", "gate did not execute the exact required check set")
    body = {
        "schema_version": "semantic-knowledge-foundation-acceptance.v1",
        "identity_schema_family_id": families["acceptance"],
        "identity_schema_version": "1.0.0",
        "foundation_manifest": {
            "role": "semantic-knowledge-foundation",
            "path": MANIFEST_PATH.as_posix(),
            "artifact_id": manifest["manifest_id"],
            "content_digest_sha256": manifest["manifest_digest_sha256"],
            "file_sha256": hashlib.sha256(canonical_bytes(manifest) + b"\n").hexdigest(),
        },
        "result": "PASS",
        "checks": checks,
        "semantic_population": deepcopy(manifest["semantic_population"]),
        "acceptance_sampling": _acceptance_sampling(snapshot, plan, ledger, coverage),
        "candidate_source_closure": {
            "candidate_total": ledger["counts"]["total"],
            "blocking_unresolved": ledger["counts"]["blocking_unresolved"],
            "source_features": coverage["summary"]["feature_count"],
            "source_orphans": coverage["summary"]["source_orphan_count"],
            "secondary_only": coverage["summary"]["secondary_only_count"],
        },
        "identity_evolution": {
            "original_feature_ids_retained": 251,
            "architecture_additions": 68,
            "freeze_additions": 4,
            "current_identity_count": identity_counts["scientific_identities"],
            "lineage_records": identity_counts["scientific_lineage_records"],
        },
        "denominator_readiness": readiness,
        "denominator_baseline": {"artifacts_unchanged": denominator["artifact_sha256"] == DENOMINATOR_SHA256, **denominator},
        "current_scientific_certification": {
            "final_state": certification["final_state"],
            "certification_eligible": certification["certification_eligible"],
            "criterion_states": criteria,
            "c4_completion": "0/9506",
        },
        "assertion_derivations": deepcopy(manifest["assertion_derivations"]),
    }
    return _finalize(root, body, namespace="trust-assessment", family=families["acceptance"], id_field="report_id", digest_field="report_digest_sha256")


def validate_manifest(root: Path, manifest: dict[str, Any], *, verify_current_files: bool) -> None:
    validate_instance(manifest, load_strict(root / MANIFEST_SCHEMA_PATH), source=MANIFEST_PATH.as_posix())
    digest = _record_digest(manifest, "manifest_id", "manifest_digest_sha256")
    if manifest["manifest_digest_sha256"] != digest:
        fail("semantic-foundation-manifest-digest", "manifest digest differs from canonical content")
    families = _families(root)
    expected_id = _finalize(root, {key: value for key, value in manifest.items() if key not in {"manifest_id", "manifest_digest_sha256"}}, namespace="artifact-set-manifest", family=families["manifest"], id_field="manifest_id", digest_field="manifest_digest_sha256")["manifest_id"]
    if manifest["manifest_id"] != expected_id:
        fail("semantic-foundation-manifest-id", "manifest content-derived identity differs")
    _validate_authority_matrix(manifest["authority_matrix"])
    if set(item["facet_id"] for item in manifest["denominator_input_contract"]["facet_inputs"]) != set(FACET_INPUTS):
        fail("semantic-foundation-facet-inputs", "manifest does not expose all fifteen facet input mappings")
    if manifest["denominator_baseline"]["artifact_sha256"] != DENOMINATOR_SHA256:
        fail("semantic-denominator-mutation", "manifest denominator baseline differs from the accepted pre-rederivation bytes")
    if verify_current_files and canonical_bytes(manifest) != canonical_bytes(build_manifest(root)):
        fail("semantic-foundation-manifest-drift", "tracked manifest differs from current bound inputs")


def validate_acceptance_report(root: Path, manifest: dict[str, Any], report: dict[str, Any]) -> None:
    validate_instance(report, load_strict(root / ACCEPTANCE_SCHEMA_PATH), source=ACCEPTANCE_PATH.as_posix())
    digest = _record_digest(report, "report_id", "report_digest_sha256")
    if report["report_digest_sha256"] != digest:
        fail("semantic-foundation-report-digest", "acceptance report digest differs from canonical content")
    families = _families(root)
    expected_id = _finalize(
        root,
        {key: value for key, value in report.items() if key not in {"report_id", "report_digest_sha256"}},
        namespace="trust-assessment",
        family=families["acceptance"],
        id_field="report_id",
        digest_field="report_digest_sha256",
    )["report_id"]
    if report["report_id"] != expected_id:
        fail("semantic-foundation-report-id", "acceptance report content-derived identity differs")
    if report["foundation_manifest"]["artifact_id"] != manifest["manifest_id"] or report["foundation_manifest"]["content_digest_sha256"] != manifest["manifest_digest_sha256"]:
        fail("semantic-foundation-report-manifest", "acceptance report binds another foundation manifest")
    if report["result"] != "PASS" or any(item["status"] != "PASS" for item in report["checks"]):
        fail("semantic-foundation-failed", "semantic knowledge architecture gate is not fully passing")
    if tuple(sorted(item["check_id"] for item in report["checks"])) != REQUIRED_CHECKS:
        fail("semantic-foundation-check-set", "acceptance report does not contain the exact required checks")
    if not report["denominator_baseline"]["artifacts_unchanged"] or report["current_scientific_certification"]["final_state"] == "PASS":
        fail("semantic-foundation-conflation", "semantic acceptance cannot mutate the denominator or claim full certification")


def _run_cross_checks(
    root: Path,
    manifest: dict[str, Any],
    *,
    verify_derivations: bool,
    verify_certification: bool,
) -> None:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    authority = load_strict(root / AUTHORITY_PATH)
    prior = load_strict(root / ARCHITECTURE_LEDGER_PATH)
    ledger = load_strict(root / CANDIDATE_LEDGER_PATH)
    coverage = load_strict(root / SOURCE_COVERAGE_PATH)
    freeze = load_strict(root / FREEZE_PATH)
    audit = load_strict(root / AUDIT_REPORT_PATH)
    validate_instance(snapshot, load_strict(root / "schemas/json/regex-semantic-corpus-v4.schema.json"), source=SNAPSHOT_PATH.as_posix())
    _validate_authority_pointer(snapshot, authority, freeze)
    if freeze["closure"]["result"] != "PASS" or audit["result"] != "PASS":
        fail("semantic-freeze-open", "the declared-cutoff adversarial freeze is not closed")
    _validate_features(root, snapshot)
    _validate_operations_and_facets(root, snapshot)
    _validate_manifestations(snapshot)
    _validate_candidates(snapshot, prior, ledger)
    _validate_source_coverage(snapshot, coverage)
    _validate_identity_evolution(root, snapshot)
    if _denominator_baseline(root)["artifact_sha256"] != DENOMINATOR_SHA256:
        fail("semantic-denominator-mutation", "a predecessor denominator artifact changed")
    if verify_foundation_history(root)["foundation_acceptance"] != "PASS":
        fail("semantic-foundation-predecessor", "the scientific foundation acceptance is not historically valid")
    identity_counts = verify_identity_catalog(root)
    if identity_counts != {"scientific_identities": 22431, "scientific_lineage_records": 0}:
        fail("semantic-identity-population", "the accepted semantic identity lock does not contain exactly 22,431 active identities")
    if verify_derivations:
        verify_derivation_catalog(root)
        _validate_derivations(root, snapshot, ledger)
    certification_state = (
        verify_repository_certification(root)["current_certification_state"]
        if verify_certification
        else load_strict(root / CURRENT_REPORT_PATH)["final_state"]
    )
    if certification_state != "FAIL":
        fail("semantic-certification-state", "current incomplete repository was unexpectedly certified")
    _denominator_readiness(snapshot)
    validate_manifest(root, manifest, verify_current_files=True)


def verify_current_semantic_foundation(root: Path) -> dict[str, Any]:
    manifest = load_strict(root / MANIFEST_PATH)
    report = load_strict(root / ACCEPTANCE_PATH)
    validate_manifest(root, manifest, verify_current_files=True)
    _run_cross_checks(root, manifest, verify_derivations=True, verify_certification=True)
    expected = build_acceptance_report(root, manifest)
    validate_acceptance_report(root, manifest, report)
    if canonical_bytes(report) != canonical_bytes(expected):
        fail("semantic-foundation-report-drift", "tracked acceptance report differs from fresh evaluation")
    return {
        "semantic_foundation_acceptance": report["result"],
        "semantic_foundation_checks": len(report["checks"]),
        "semantic_features": report["semantic_population"]["features"],
        "semantic_operations": report["semantic_population"]["operations"],
        "semantic_facets": report["semantic_population"]["facets"],
        "denominator_requirements": report["denominator_baseline"]["vector_requirements"],
    }


def materialize_semantic_foundation(root: Path) -> dict[str, Any]:
    manifest = build_manifest(root)
    _run_cross_checks(root, manifest, verify_derivations=False, verify_certification=False)
    report = build_acceptance_report(root, manifest)
    validate_acceptance_report(root, manifest, report)
    for relative, value in ((MANIFEST_PATH, manifest), (ACCEPTANCE_PATH, report)):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(canonical_bytes(value) + b"\n")
        os.replace(temporary, destination)
    if build_manifest(root) != manifest or build_acceptance_report(root, manifest) != report:
        fail("semantic-foundation-nondeterministic", "semantic foundation did not rebuild deterministically")
    return {
        "semantic_foundation_acceptance": report["result"],
        "semantic_foundation_checks": len(report["checks"]),
        "manifest_id": manifest["manifest_id"],
        "report_id": report["report_id"],
    }
