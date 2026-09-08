"""Explainable, non-authoritative obligation-derivation rules and dry-run analysis."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path
from typing import Any, Iterable

from .derivation import derivation_revision_id, verify_catalog as verify_derivation_catalog
from .errors import fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import verify_catalog as verify_identity_catalog
from .semantic_foundation import verify_current_semantic_foundation


PUBLISHED_ON = "2026-09-08"
SNAPSHOT_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json")
SEMANTIC_FOUNDATION_PATH = Path("semantic-corpus/foundation/semantic-knowledge-architecture.v1.json")
LEGACY_PROJECTION_PATH = Path("ontology/projections/regex-semantic-projection-2026-08-22.v1.json")
LEGACY_REQUIREMENTS_PATH = Path("vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json")
LEGACY_FORECAST_PATH = Path("reports/scale/regex-semantic-denominator-forecast.json")
ALLOCATION_PATH = Path("ontology/derivations/obligation-derivation-identities-2026-09-08.v1.json")
CONTRACT_PATH = Path("ontology/derivations/regex-obligation-derivation-rules-2026-09-08.v1.json")
LEGACY_REPORT_PATH = Path("reports/semantics/legacy-obligation-derivation-analysis-2026-09-08.v1.json")
DRY_RUN_PATH = Path("reports/semantics/obligation-derivation-dry-run-2026-09-08.v1.json")
FIXTURE_PATH = Path("tests/fixtures/semantics/obligation-derivation-cases.v1.json")

ALLOCATION_SCHEMA_PATH = Path("schemas/json/obligation-derivation-allocation.schema.json")
CONTRACT_SCHEMA_PATH = Path("schemas/json/obligation-derivation-contract.schema.json")
LEGACY_REPORT_SCHEMA_PATH = Path("schemas/json/legacy-obligation-derivation-report.schema.json")
DRY_RUN_SCHEMA_PATH = Path("schemas/json/obligation-derivation-dry-run.schema.json")
FIXTURE_SCHEMA_PATH = Path("schemas/json/obligation-derivation-fixtures.schema.json")
ARTIFACT_PROFILE_PATH = Path("schemas/identity-profiles/semantic-research-artifact.v1.json")
DERIVATION_PROFILE_PATH = Path("schemas/identity-profiles/generated-assertion-derivation.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
DERIVATION_SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a07849-7262-7b95-8255-9fb7fc5bf310"
IDENTITY_CATALOG_PATH = Path("registries/identity/scientific-identities.v1.json")

DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a08125-97ae-7633-b217-ca1d0fa22fbf"
SCHEMA_FAMILIES = {
    "contract": "rcid:v1:schema-family:u7:01a08125-97ae-7603-becf-f90eb1dcc082",
    "legacy-report": "rcid:v1:schema-family:u7:01a08125-97ae-7dfd-9132-33eb0dbc1142",
    "dry-run": "rcid:v1:schema-family:u7:01a08125-97ae-71db-b024-032b4aa9dfb1",
}

DENOMINATOR_SHA256 = {
    "obligation_projection": "b25fbeaf80fc8e77f92fb5b36a094896bf30e86d4550ad62982f80a028b605b2",
    "vector_requirements": "a03feacf51bf3af241a7ab4fe0ea74bd29981670de93ec3d880a27516232cca7",
    "denominator_forecast": "dab61b42376d757eadada26c31d8fb5c173a508bb6ce780e98a220449ce6e871",
}

DECISIONS = (
    "required",
    "conditionally-required",
    "not-applicable",
    "not-required-by-feature-semantics",
    "blocked-by-unresolved-semantics",
)
SEMANTIC_STATES = (
    "known",
    "no-feature-specific-implication",
    "not-applicable",
    "implementation-defined",
    "profile-dependent",
    "intentionally-under-specified",
    "unresolved",
)
QUESTION_TYPES = (
    "normative/conformance-capable",
    "implementation-documentation-capable",
    "characterization-only",
    "relational/metamorphic-candidate",
    "unresolved",
)
PROFILE_PREDICATE_FIELDS = (
    "profile.feature_scientific_ids",
    "profile.operation_scientific_ids",
    "profile.manifestation_scientific_ids",
    "profile.semantic_variant_scientific_ids",
    "profile.modifier_scientific_ids",
)
PROFILE_PREDICATE_OPERATORS = ("contains", "intersects")


ARCHETYPES: tuple[dict[str, Any], ...] = (
    {"archetype_id": "archetype.defining-positive", "scientific_question": "Does the smallest attributable example exhibit the feature's defining observable behavior?", "subject_polarities": ["positive"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.defining-negative", "scientific_question": "Does a controlled non-example remain observably distinct from the feature's defining behavior?", "subject_polarities": ["negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.grammar-acceptance", "scientific_question": "Is a source-governed manifestation accepted in the phase and grammar where the feature is exposed?", "subject_polarities": ["positive"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.grammar-rejection", "scientific_question": "Is an invalid, disabled, or out-of-domain manifestation rejected with the scientifically relevant outcome class?", "subject_polarities": ["negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.boundary-behavior", "scientific_question": "What happens at the semantic boundary where the feature changes match, text-domain, capture, or advancement behavior?", "subject_polarities": ["positive", "negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.state-transition", "scientific_question": "Does entering, updating, restoring, or leaving governed state produce the specified transition?", "subject_polarities": ["positive"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.repeated-iteration", "scientific_question": "Does repeated execution preserve the specified selection, advancement, and terminal-state behavior?", "subject_polarities": ["positive", "negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.alternative-semantic-mode", "scientific_question": "Does selecting another documented mode change only the semantic dimensions that mode governs?", "subject_polarities": ["positive", "negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.host-result", "scientific_question": "Does the host operation expose the governed match, capture, span, or result shape without changing canonical feature meaning?", "subject_polarities": ["positive"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.replacement-output", "scientific_question": "Does substitution construct the governed output from the selected match, captures, template, callback, and advancement state?", "subject_polarities": ["positive", "negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.resource-limit-termination", "scientific_question": "Does a documented target resource limit or termination condition remain distinguishable from no-match and infrastructure failure?", "subject_polarities": ["boundary"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.permitted-variation", "scientific_question": "Which outcome in the documented implementation-defined or under-specified region does this exact profile exhibit?", "subject_polarities": ["characterization"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.interaction-specific", "scientific_question": "Does the exact source-bound typed interaction produce behavior not attributable from either constituent alone?", "subject_polarities": ["positive", "negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.phase-specific", "scientific_question": "At which lifecycle phase is the source-bound behavior accepted, rejected, observed, or preserved?", "subject_polarities": ["positive", "negative"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.complexity-guarantee", "scientific_question": "Does the documented algorithmic guarantee or subset restriction hold under its stated preconditions, independently of one timing sample?", "subject_polarities": ["boundary"], "parameterizable": True, "contributes_to_c4": True},
    {"archetype_id": "archetype.security-boundary", "scientific_question": "Does the documented quoting, trust, injection, or denial-of-service boundary preserve its promised semantics?", "subject_polarities": ["positive", "negative"], "parameterizable": True, "contributes_to_c4": True},
)


OPERATION_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("operation-family.construction", ("operation.compile", "operation.escape-pattern", "operation.escape-replacement")),
    ("operation-family.single-match", ("operation.test", "operation.prefix-match", "operation.full-match", "operation.search", "operation.partial-match")),
    ("operation-family.iteration-result", ("operation.next-match", "operation.find-all", "operation.find-overlapping", "operation.extract", "operation.count", "operation.position", "operation.analyze")),
    ("operation-family.replacement", ("operation.replace-first", "operation.replace-all", "operation.replace-callback", "operation.expand-replacement", "operation.split")),
    ("operation-family.multi-pattern", ("operation.set-match", "operation.block-scan", "operation.vector-scan")),
    ("operation-family.stream-session", ("operation.stream-scan", "operation.stream-open", "operation.stream-close", "operation.stream-reset", "operation.stream-copy", "operation.stream-compress", "operation.stream-expand")),
    ("operation-family.serialization", ("operation.serialize-pattern", "operation.deserialize-pattern", "operation.inspect-pattern")),
)


OPERATION_PHASES = {
    "operation.compile": "compile",
    "operation.escape-pattern": "build-source-generation",
    "operation.escape-replacement": "replacement-substitution",
    "operation.replace-first": "replacement-substitution",
    "operation.replace-all": "replacement-substitution",
    "operation.replace-callback": "replacement-substitution",
    "operation.expand-replacement": "replacement-substitution",
    "operation.split": "replacement-substitution",
    "operation.serialize-pattern": "serialization-deserialization",
    "operation.deserialize-pattern": "serialization-deserialization",
    "operation.inspect-pattern": "serialization-deserialization",
    "operation.stream-scan": "stream-session",
    "operation.stream-open": "stream-session",
    "operation.stream-close": "stream-session",
    "operation.stream-reset": "stream-session",
    "operation.stream-copy": "stream-session",
    "operation.stream-compress": "stream-session",
    "operation.stream-expand": "stream-session",
}


SPECIAL_OPERATION_SELECTORS: dict[str, dict[str, Any]] = {
    "operation.escape-pattern": {"kind": "feature-id-set", "feature_ids": ["feature.escaped-literal", "feature.literal-string", "feature.literal-unit", "feature.quoted-literal-region"]},
    "operation.escape-replacement": {"kind": "feature-id-set", "feature_ids": ["feature.replacement-escape"]},
    "operation.serialize-pattern": {"kind": "all-compilable"},
    "operation.deserialize-pattern": {"kind": "all-compilable"},
    "operation.inspect-pattern": {"kind": "feature-class-set", "feature_classes": ["capture", "host-operation", "modifier", "quantifier", "result", "special-operation"]},
    "operation.stream-open": {"kind": "stream-capable"},
    "operation.stream-close": {"kind": "stream-capable"},
    "operation.stream-reset": {"kind": "stream-capable"},
    "operation.stream-copy": {"kind": "stream-capable"},
    "operation.stream-compress": {"kind": "stream-capable"},
    "operation.stream-expand": {"kind": "stream-capable"},
}


FACET_SPECS: tuple[dict[str, Any], ...] = (
    {"facet_id": "facet.syntax", "semantic_input_selectors": ["semantic_assertions.syntax_grammar", "manifestation_ids"], "operation_family_ids": ["operation-family.construction"], "archetype_ids": ["archetype.grammar-acceptance", "archetype.grammar-rejection"], "policy": "semantic-state", "rationale": "Syntax obligations exist only for represented grammar or construction behavior; manifestation spelling is a condition, not canonical meaning."},
    {"facet_id": "facet.core-match", "semantic_input_selectors": ["semantic_assertions.definition", "semantic_variants"], "operation_family_ids": ["operation-family.single-match", "operation-family.iteration-result", "operation-family.replacement", "operation-family.multi-pattern", "operation-family.stream-session"], "archetype_ids": ["archetype.defining-positive", "archetype.defining-negative"], "policy": "core-definition", "rationale": "Every canonical feature needs one minimal attributable defining question; a negative question is added only for feature classes with an observable contrast."},
    {"facet_id": "facet.search-boundary", "semantic_input_selectors": ["semantic_assertions.search_iteration", "supported_operation_ids"], "operation_family_ids": ["operation-family.single-match", "operation-family.iteration-result", "operation-family.replacement", "operation-family.stream-session"], "archetype_ids": ["archetype.boundary-behavior", "archetype.repeated-iteration"], "policy": "semantic-state", "rationale": "Search obligations require an explicit start, selection, advancement, cursor, or terminal-state implication."},
    {"facet_id": "facet.capture", "semantic_input_selectors": ["semantic_assertions.capture_result"], "operation_family_ids": ["operation-family.single-match", "operation-family.iteration-result", "operation-family.replacement"], "archetype_ids": ["archetype.host-result"], "policy": "semantic-state", "rationale": "Capture obligations are suppressed when research found no feature-specific capture consequence."},
    {"facet_id": "facet.unicode-encoding", "semantic_input_selectors": ["semantic_assertions.unicode_encoding", "modifier_ids"], "operation_family_ids": ["operation-family.construction", "operation-family.single-match", "operation-family.iteration-result", "operation-family.replacement", "operation-family.multi-pattern", "operation-family.stream-session"], "archetype_ids": ["archetype.boundary-behavior", "archetype.alternative-semantic-mode"], "policy": "semantic-state", "rationale": "Unicode obligations require source-bound text-domain, property, folding, boundary, malformed-input, or index-unit semantics."},
    {"facet_id": "facet.option-state", "semantic_input_selectors": ["semantic_assertions.options_state", "modifier_ids"], "operation_family_ids": [item[0] for item in OPERATION_FAMILIES], "archetype_ids": ["archetype.alternative-semantic-mode", "archetype.state-transition"], "policy": "semantic-state", "rationale": "Option obligations require a material mode, scope, cursor, region, or state transition."},
    {"facet_id": "facet.host-api", "semantic_input_selectors": ["semantic_assertions.host_operation", "supported_operation_ids"], "operation_family_ids": [item[0] for item in OPERATION_FAMILIES], "archetype_ids": ["archetype.host-result"], "policy": "semantic-state", "rationale": "Host obligations exist only for a distinct invocation, state, or result contract and use canonical operation identities."},
    {"facet_id": "facet.replacement", "semantic_input_selectors": ["semantic_assertions.replacement", "supported_operation_ids"], "operation_family_ids": ["operation-family.construction", "operation-family.replacement"], "archetype_ids": ["archetype.replacement-output"], "policy": "semantic-state", "rationale": "Replacement obligations require a substitution-visible semantic implication; ordinary match influence alone is not a separate replacement obligation."},
    {"facet_id": "facet.error-diagnostics", "semantic_input_selectors": ["semantic_assertions.diagnostic_error", "semantic_assertions.syntax_grammar"], "operation_family_ids": [item[0] for item in OPERATION_FAMILIES], "archetype_ids": ["archetype.grammar-rejection"], "policy": "semantic-state", "rationale": "Diagnostic obligations preserve compile, runtime, unsupported, and target-attributable failure classes only where research identifies a meaningful distinction."},
    {"facet_id": "facet.resource-termination", "semantic_input_selectors": ["semantic_assertions.resource_termination"], "operation_family_ids": [item[0] for item in OPERATION_FAMILIES], "archetype_ids": ["archetype.resource-limit-termination"], "policy": "semantic-state", "rationale": "Resource obligations require a documented target limit, resource state, or termination behavior and never arise from generic performance variation."},
    {"facet_id": "facet.interaction-composition", "semantic_input_selectors": ["typed_relations", "prerequisite_feature_ids", "modifier_ids"], "operation_family_ids": [item[0] for item in OPERATION_FAMILIES], "archetype_ids": ["archetype.interaction-specific"], "policy": "typed-interaction", "rationale": "Only explicit typed relations, prerequisites, or modifier relations can create interaction obligations; no pairwise cross-product exists."},
    {"facet_id": "facet.version-platform-differential", "semantic_input_selectors": ["semantic_assertions", "semantic_variants", "manifestation_ids"], "operation_family_ids": [], "archetype_ids": [], "policy": "analysis-only", "rationale": "Differential is a later comparison projection over independently evidenced obligations and does not create an independent obligation denominator."},
    {"facet_id": "facet.phase", "semantic_input_selectors": ["semantic_assertions.syntax_grammar", "semantic_assertions.diagnostic_error", "semantic_assertions.replacement", "semantic_assertions.host_operation", "supported_operation_ids"], "operation_family_ids": [item[0] for item in OPERATION_FAMILIES], "archetype_ids": ["archetype.phase-specific"], "policy": "phase-sensitive", "rationale": "A phase obligation exists only where researched behavior differs across build, compile, match, replacement, stream, or serialization lifecycle phases."},
    {"facet_id": "facet.complexity-guarantee", "semantic_input_selectors": ["semantic_assertions.resource_termination"], "operation_family_ids": ["operation-family.single-match", "operation-family.iteration-result", "operation-family.multi-pattern", "operation-family.stream-session"], "archetype_ids": ["archetype.complexity-guarantee"], "policy": "documented-complexity", "rationale": "Only an explicit documented algorithmic guarantee or subset restriction creates this obligation; a timeout measurement cannot."},
    {"facet_id": "facet.security-context", "semantic_input_selectors": ["semantic_assertions.syntax_grammar", "semantic_assertions.options_state", "semantic_assertions.host_operation", "semantic_assertions.resource_termination"], "operation_family_ids": ["operation-family.construction", "operation-family.single-match", "operation-family.serialization"], "archetype_ids": ["archetype.security-boundary"], "policy": "documented-security", "rationale": "Only a concrete quoting, injection, serialized-input, or denial-of-service boundary creates a security obligation; generic security prose is forbidden."},
)


NEGATIVE_CORE_CLASSES = {
    "algebra", "assertion", "character-class", "control", "diagnostic", "grammar",
    "modifier", "pattern", "quantifier", "recursive", "replacement", "unicode",
}
COMPLEXITY_FEATURES = {"feature.linear-time-guarantee"}
SECURITY_FEATURES = {
    "feature.escaped-literal",
    "feature.quoted-literal-region",
    "feature.replacement-escape",
    "feature.linear-time-guarantee",
}


LEGACY_FACET_MAP = {
    "syntax": "facet.syntax",
    "core-semantics": "facet.core-match",
    "search-iteration": "facet.search-boundary",
    "captures": "facet.capture",
    "unicode-encoding": "facet.unicode-encoding",
    "options-state": "facet.option-state",
    "host-operation": "facet.host-api",
    "replacement": "facet.replacement",
    "errors": "facet.error-diagnostics",
    "resource-termination": "facet.resource-termination",
    "interaction": "facet.interaction-composition",
    "differential": "facet.version-platform-differential",
}

LEGACY_CASE_ARCHETYPE = {
    "acceptance": "archetype.grammar-acceptance", "rejection": "archetype.grammar-rejection",
    "ambiguity-boundary": "archetype.boundary-behavior", "positive": "archetype.defining-positive",
    "negative": "archetype.defining-negative", "boundary": "archetype.boundary-behavior",
    "competing-interpretation": "archetype.alternative-semantic-mode", "start-offset": "archetype.boundary-behavior",
    "zero-length-progress": "archetype.repeated-iteration", "repeated-next": "archetype.repeated-iteration",
    "terminal-state": "archetype.state-transition", "participation": "archetype.host-result",
    "unset-versus-empty": "archetype.host-result", "value": "archetype.host-result", "span": "archetype.host-result",
    "history-or-name": "archetype.host-result", "datum-domain": "archetype.boundary-behavior",
    "class-or-property": "archetype.boundary-behavior", "case-folding": "archetype.alternative-semantic-mode",
    "index-unit": "archetype.host-result", "malformed-input": "archetype.boundary-behavior",
    "off-versus-on": "archetype.alternative-semantic-mode", "scope": "archetype.state-transition",
    "interaction": "archetype.interaction-specific", "locale-mode-or-cursor": "archetype.state-transition",
    "success": "archetype.host-result", "no-match": "archetype.defining-negative",
    "state-transition": "archetype.state-transition", "result-shape": "archetype.host-result",
    "expansion": "archetype.replacement-output", "missing-or-unset-group": "archetype.replacement-output",
    "escaping": "archetype.replacement-output", "global-progress": "archetype.repeated-iteration",
    "callback-or-state": "archetype.state-transition", "phase": "archetype.phase-specific",
    "class": "archetype.grammar-rejection", "native-diagnostic": "archetype.grammar-rejection",
    "limit": "archetype.resource-limit-termination", "timeout": "archetype.resource-limit-termination",
    "exhaustion": "archetype.resource-limit-termination", "termination": "archetype.resource-limit-termination",
    "prerequisite": "archetype.interaction-specific", "modifier": "archetype.interaction-specific",
    "comparison-control": "archetype.interaction-specific", "confounder": "archetype.interaction-specific",
    "release": None, "profile": None, "platform-or-backend": None,
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def denominator_baseline(root: Path) -> dict[str, Any]:
    paths = {
        "obligation_projection": LEGACY_PROJECTION_PATH,
        "vector_requirements": LEGACY_REQUIREMENTS_PATH,
        "denominator_forecast": LEGACY_FORECAST_PATH,
    }
    actual = {key: _sha(root / path) for key, path in paths.items()}
    return {
        "state": "pre-rederivation-predecessor-bound",
        "obligation_templates": 12048,
        "vector_requirements": 9506,
        "artifact_sha256": actual,
        "artifacts_unchanged": actual == DENOMINATOR_SHA256,
    }


def derivation_spec(root: Path) -> dict[str, Any]:
    record = {
        "title": "Feature-specific semantic obligation derivation",
        "derivation_class": "calculation",
        "method_key": "semantic-obligation-rule-evaluation",
        "method_version": "1.0.0",
        "input_references": [SNAPSHOT_PATH.as_posix(), CONTRACT_PATH.as_posix()],
        "authority_references": [SEMANTIC_FOUNDATION_PATH.as_posix()],
        "allowed_gate_kinds": ["forecast-calculation", "structural-integrity"],
        "independent_evidence": False,
        "metadata": {
            "kind": "calculation",
            "input_references": ["the exact frozen semantic assertions, facets, operations, variants, manifestations, modifiers and typed relations named by each rule"],
            "procedure_ref": "schemas/tooling/python/regex_conformance_schema/obligation_derivation.py",
            "formula": "Evaluate one explicit facet rule per feature, preserve structured semantic state, resolve only declared operation predicates, and emit required, conditional, suppressed, or blocked decisions without a generic fallback.",
        },
        "notes": "Rule evaluation explains a prospective obligation decision; it does not strengthen its semantic inputs or advance denominator authority.",
        "derivation_id": DERIVATION_ID,
    }
    record["derivation_revision_id"] = derivation_revision_id(root, record)
    return record


def _content_id(root: Path, namespace: str, family: str, body: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / ARTIFACT_PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=family,
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": digest},
    )
    return str(result["content_id"])


def _finalize(root: Path, body: dict[str, Any], *, namespace: str, family: str, id_field: str, digest_field: str) -> dict[str, Any]:
    digest = hashlib.sha256(canonical_bytes(body)).hexdigest()
    return {**body, id_field: _content_id(root, namespace, family, body), digest_field: digest}


def build_allocation() -> dict[str, Any]:
    return {
        "schema_version": "obligation-derivation-allocation.v1",
        "allocated_on": PUBLISHED_ON,
        "allocations": [
            {"entity_class": "assertion-derivation", "canonical_key": "derivation.semantic-obligation-rule-evaluation", "assigned_id": DERIVATION_ID},
            *[
                {"entity_class": "schema-family", "canonical_key": f"schema.obligation-derivation.{key}", "assigned_id": value}
                for key, value in sorted(SCHEMA_FAMILIES.items())
            ],
        ],
    }


def _operation_rule(operation: dict[str, Any]) -> dict[str, Any]:
    operation_id = operation["operation_id"]
    selector = deepcopy(SPECIAL_OPERATION_SELECTORS.get(operation_id, {"kind": "declared-support"}))
    family_id = next(family for family, members in OPERATION_FAMILIES if operation_id in members)
    phase = OPERATION_PHASES.get(operation_id, "match-search")
    conditional = operation_id in SPECIAL_OPERATION_SELECTORS
    return {
        "rule_key": f"obligation-operation-rule.{operation_id.removeprefix('operation.')}",
        "operation_id": operation_id,
        "operation_scientific_id": operation["scientific_id"],
        "operation_family_id": family_id,
        "phase": phase,
        "feature_selector": selector,
        "applicability": "conditionally-applicable-when-profile-exposes-operation" if conditional else "intrinsically-required-when-feature-declares-operation",
        "profile_capability_predicate": {
            "operator": "all",
            "clauses": [
                {"field": "profile.operation_scientific_ids", "operator": "contains", "value": operation["scientific_id"]},
                {"field": "profile.feature_scientific_ids", "operator": "contains", "value_from": "feature.scientific_id"},
            ],
        },
        "covered_by_operation_id": None,
        "rationale": f"Apply the canonical {operation_id} contract only when the feature selector and exact profile capability predicate both hold; vendor method names do not create operations.",
    }


def _rule_revision(root: Path, rule: dict[str, Any]) -> str:
    basis = {key: value for key, value in rule.items() if key != "rule_revision_id"}
    return _content_id(root, "applicability-rule-set", SCHEMA_FAMILIES["contract"], basis)


def build_contract(root: Path) -> dict[str, Any]:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    identity_catalog = load_strict(root / IDENTITY_CATALOG_PATH)
    identity_by_key = {item["canonical_key"]: item["scientific_id"] for item in identity_catalog["bindings"]}
    derivation = derivation_spec(root)
    facets_by_id = {item["facet_id"]: item for item in snapshot["semantic_facets"]}
    facet_rules = []
    for source in FACET_SPECS:
        rule = {
            **deepcopy(source),
            "rule_key": f"obligation-facet-rule.{source['facet_id'].removeprefix('facet.')}",
            "facet_scientific_id": facets_by_id[source["facet_id"]]["scientific_id"],
            "required_semantic_states": ["known", "implementation-defined", "profile-dependent", "intentionally-under-specified"],
            "excluded_semantic_states": ["no-feature-specific-implication", "not-applicable"],
            "blocked_semantic_states": ["unresolved"],
            "profile_capability_predicate": {"operator": "all", "clauses": [{"field": "profile.feature_scientific_ids", "operator": "contains", "value_from": "feature.scientific_id"}, {"field": "profile.operation_scientific_ids", "operator": "intersects", "value_from": "derived.operation_scientific_ids"}]},
            "reason_template": "{feature_id} {decision} {facet_id} because {semantic_inputs}; apply only through {operation_condition}.",
            "depends_on_rule_ids": [],
            "derivation_id": DERIVATION_ID,
            "derivation_revision_id": derivation["derivation_revision_id"],
        }
        rule["rule_revision_id"] = _rule_revision(root, rule)
        facet_rules.append(rule)
    operation_rules = []
    for operation in snapshot["operations"]:
        rule = _operation_rule(operation)
        rule["derivation_id"] = DERIVATION_ID
        rule["derivation_revision_id"] = derivation["derivation_revision_id"]
        rule["depends_on_rule_ids"] = []
        rule["rule_revision_id"] = _rule_revision(root, rule)
        operation_rules.append(rule)
    body = {
        "schema_version": "obligation-derivation-contract.v1",
        "contract_version": "1.0.0",
        "published_on": PUBLISHED_ON,
        "classification": {"design_only": True, "authoritative_denominator": False, "production_vectors_generated": False, "profile_applicability_evaluated": False, "template_fallback_permitted": False},
        "semantic_authority": {"path": SNAPSHOT_PATH.as_posix(), "snapshot_id": snapshot["snapshot_id"], "snapshot_digest_sha256": snapshot["snapshot_digest_sha256"], "feature_count": len(snapshot["features"]), "facet_count": len(snapshot["semantic_facets"]), "operation_count": len(snapshot["operations"])},
        "semantic_foundation": {"path": SEMANTIC_FOUNDATION_PATH.as_posix(), "file_sha256": _sha(root / SEMANTIC_FOUNDATION_PATH)},
        "denominator_boundary": denominator_baseline(root),
        "decision_vocabulary": list(DECISIONS),
        "semantic_state_policy": [
            {"state": "known", "effect": "May create a required obligation when an explicit facet rule is triggered."},
            {"state": "no-feature-specific-implication", "effect": "Suppress the facet with not-required-by-feature-semantics."},
            {"state": "not-applicable", "effect": "Suppress the facet with not-applicable."},
            {"state": "implementation-defined", "effect": "Create a conditional implementation-documentation-capable obligation when the facet is testable."},
            {"state": "profile-dependent", "effect": "Create a conditional obligation with an explicit profile/capability predicate."},
            {"state": "intentionally-under-specified", "effect": "Create a characterization-only obligation without inventing one normative expected result."},
            {"state": "unresolved", "effect": "Block derivation when the unresolved point changes the scientific question."},
        ],
        "question_types": [
            {"question_type": "normative/conformance-capable", "meaning": "A normative source supplies a conformance-capable expectation."},
            {"question_type": "implementation-documentation-capable", "meaning": "Official implementation documentation can supply an exact profile-scoped expectation."},
            {"question_type": "characterization-only", "meaning": "Evidence records behavior without forcing a universal expected result."},
            {"question_type": "relational/metamorphic-candidate", "meaning": "Later vectors may use a relation between observations while preserving exact attribution."},
            {"question_type": "unresolved", "meaning": "No obligation shape may be finalized until the blocking semantic input is resolved."},
        ],
        "concept_boundaries": {
            "semantic_obligation": "One distinct scientific behavior or question that must be known.",
            "vector_requirement": "A minimum requirement for executable or otherwise admissible evidence capable of satisfying one or more explicitly attributed obligations.",
            "concrete_generated_vector": "One deterministic instantiation; it does not acquire obligation identity and may earn only explicitly declared attribution.",
            "cardinality": "Obligations, vector requirements, vector families, and concrete vectors are not required to be one-to-one.",
        },
        "obligation_identity_contract": {
            "materialization_deferred": True,
            "analysis_keys_are_not_scientific_ids": True,
            "canonical_identity_inputs": ["feature.scientific_id", "facet.scientific_id", "archetype_id", "question_type", "semantic assertion selectors", "operation scientific identities and condition", "variant scientific identity basis", "interaction scientific identity basis"],
            "excluded_presentation_inputs": ["display name", "reason prose", "file path", "report ordering", "operation label"],
        },
        "obligation_archetypes": list(ARCHETYPES),
        "modifier_identities": [
            {"modifier_id": item["modifier_id"], "modifier_scientific_id": identity_by_key[item["modifier_id"]]}
            for item in snapshot["modifiers"]
        ],
        "operation_families": [{"operation_family_id": key, "operation_ids": list(values)} for key, values in OPERATION_FAMILIES],
        "operation_rules": sorted(operation_rules, key=lambda item: item["operation_id"]),
        "facet_rules": sorted(facet_rules, key=lambda item: item["facet_id"]),
        "interaction_policy": {
            "allowed_triggers": ["typed_relations", "prerequisite_feature_ids", "modifier_ids"],
            "forbidden_trigger": "all feature pairs or any untargeted pairwise/t-wise cross-product",
            "independent_obligation_rule": "Create an interaction obligation only for an explicit accepted relation whose target and observable consequence remain attributable.",
            "constituent_coverage_rule": "Suppress an independent interaction obligation when no explicit relation exists; constituent obligations retain their own credit.",
        },
        "operation_condition_contract": {
            "missing_profile_capability_state": "conditionally-required",
            "not_applicable_requires_evidence": True,
            "final_applicability_evaluator_deferred": True,
            "allowed_profile_fields": list(PROFILE_PREDICATE_FIELDS),
            "allowed_operators": list(PROFILE_PREDICATE_OPERATORS),
            "identity_reference_requirement": "Predicate values are scientific identities or deterministic references resolving to scientific identities; mutable labels are diagnostic only.",
        },
        "explainability_contract": {"chain": ["semantic assertion(s)", "derivation rule revision", "facet and archetype", "operation/profile condition", "prospective obligation identity basis"], "every_feature_facet_has_one_decision": True, "suppression_is_explained": True, "generic_fallback_rule": None},
        "derivation_id": DERIVATION_ID,
        "derivation_revision_id": derivation["derivation_revision_id"],
    }
    return _finalize(root, body, namespace="artifact-set-manifest", family=SCHEMA_FAMILIES["contract"], id_field="contract_id", digest_field="contract_digest_sha256")


def _normalized_operation_id(value: str) -> str:
    return value if value.startswith("operation.") else f"operation.{value}"


def _selector_matches(feature: dict[str, Any], operation_id: str, selector: dict[str, Any]) -> bool:
    declared = {_normalized_operation_id(value) for value in feature["supported_operation_ids"]}
    kind = selector["kind"]
    if kind == "declared-support":
        return operation_id in declared
    if kind == "all-compilable":
        return "operation.compile" in declared
    if kind == "stream-capable":
        return "operation.stream-scan" in declared
    if kind == "feature-id-set":
        return feature["feature_id"] in selector["feature_ids"]
    if kind == "feature-class-set":
        return feature["feature_class"] in selector["feature_classes"]
    fail("unknown-operation-selector", f"unknown operation selector {kind!r}", operation_id)


def applicable_operations(feature: dict[str, Any], contract: dict[str, Any], family_ids: Iterable[str]) -> tuple[list[str], bool]:
    allowed_families = set(family_ids)
    operations: list[str] = []
    matched_intrinsic = False
    matched_conditional = False
    for rule in contract["operation_rules"]:
        if rule["operation_family_id"] not in allowed_families:
            continue
        if _selector_matches(feature, rule["operation_id"], rule["feature_selector"]):
            operations.append(rule["operation_id"])
            if rule["applicability"].startswith("conditionally"):
                matched_conditional = True
            else:
                matched_intrinsic = True
    return sorted(operations), matched_conditional and not matched_intrinsic


def _assertion_ref(feature: dict[str, Any], field: str) -> dict[str, Any]:
    assertion = feature["semantic_assertions"][field]
    return {
        "selector": f"semantic_assertions.{field}",
        "state": assertion["state"],
        "scope": assertion["scope"],
        "derivation_id": assertion["derivation_id"],
        "source_ids": assertion["source_ids"],
    }


def _state_decision(state: str, scope: str) -> tuple[str, str]:
    if state == "not-applicable":
        return "not-applicable", "characterization-only"
    if state == "no-feature-specific-implication":
        return "not-required-by-feature-semantics", "characterization-only"
    if state == "unresolved":
        return "blocked-by-unresolved-semantics", "unresolved"
    if state in {"implementation-defined", "profile-dependent"} or scope in {"profile-dependent", "manifestation-specific", "variant-specific"}:
        return "conditionally-required", "implementation-documentation-capable"
    if state == "intentionally-under-specified":
        return "required", "characterization-only"
    if state == "known":
        return "required", "normative/conformance-capable"
    fail("unknown-semantic-state", f"unknown semantic state {state!r}")


def _feature_sources_normative(feature: dict[str, Any], snapshot: dict[str, Any]) -> bool:
    source_by_id = {item["source_id"]: item for item in snapshot["sources"]}
    source_ids = {source for assertion in feature["semantic_assertions"].values() for source in assertion["source_ids"]}
    return any(source_by_id[source].get("normative", False) for source in source_ids if source in source_by_id)


def _phase_sensitive(feature: dict[str, Any], operation_ids: list[str]) -> bool:
    assertions = feature["semantic_assertions"]
    phases = {OPERATION_PHASES.get(item, "match-search") for item in operation_ids}
    meaningful = any(assertions[field]["state"] not in {"no-feature-specific-implication", "not-applicable"} for field in ("diagnostic_error", "replacement", "host_operation"))
    return meaningful and len(phases) > 1 or "stream-session" in phases or "serialization-deserialization" in phases


def _interaction_bases(snapshot: dict[str, Any], contract: dict[str, Any], feature: dict[str, Any]) -> list[dict[str, str]]:
    target_scientific_ids = {
        **{item["feature_id"]: item["scientific_id"] for item in snapshot["features"]},
        **{item["modifier_id"]: item["modifier_scientific_id"] for item in contract["modifier_identities"]},
    }
    bases = {
        (item["relation_type"], item["target_id"]): {
            "relation_type": item["relation_type"],
            "target_id": item["target_id"],
            "target_scientific_id": target_scientific_ids[item["target_id"]],
        }
        for item in feature["typed_relations"]
    }
    for target in feature["prerequisite_feature_ids"]:
        bases.setdefault(("prerequisite", target), {"relation_type": "prerequisite", "target_id": target, "target_scientific_id": target_scientific_ids[target]})
    for target in feature["modifier_ids"]:
        bases.setdefault(("modified-by", target), {"relation_type": "modified-by", "target_id": target, "target_scientific_id": target_scientific_ids[target]})
    return [bases[key] for key in sorted(bases)]


def _profile_condition(
    snapshot: dict[str, Any],
    feature: dict[str, Any],
    rule: dict[str, Any],
    inputs: list[dict[str, Any]],
    operation_scientific_ids: list[str],
    *,
    interaction: dict[str, str] | None = None,
    variant: dict[str, Any] | None = None,
) -> dict[str, Any]:
    condition = deepcopy(rule["profile_capability_predicate"])
    if any(item["scope"] == "manifestation-specific" for item in inputs) and feature["manifestation_ids"]:
        manifestation_ids = set(feature["manifestation_ids"])
        scientific_ids = sorted(
            item["scientific_id"]
            for item in snapshot["manifestations"]
            if item["manifestation_id"] in manifestation_ids
        )
        condition["clauses"].append({"field": "profile.manifestation_scientific_ids", "operator": "intersects", "values": scientific_ids})
    if variant is not None:
        condition["clauses"].append({"field": "profile.semantic_variant_scientific_ids", "operator": "contains", "value": variant["scientific_id"]})
    if interaction is not None:
        target_field = "profile.modifier_scientific_ids" if interaction["target_id"].startswith("modifier.") else "profile.feature_scientific_ids"
        condition["clauses"].append({"field": target_field, "operator": "contains", "value": interaction["target_scientific_id"]})
    if not operation_scientific_ids:
        fail("empty-operation-condition", "an obligation profile condition requires at least one operation scientific identity", feature["feature_id"])
    return condition


def _decision_reason(feature: dict[str, Any], rule: dict[str, Any], decision: str, states: list[str], operations: list[str]) -> str:
    state_text = ", ".join(states) if states else "explicit typed relation state"
    operation_text = ", ".join(operations) if operations else "no operation coordinate"
    return f"{feature['feature_id']} is {decision} for {rule['facet_id']}: rule {rule['rule_key']} consumed {state_text}; operation condition resolves to {operation_text}."


def derive_feature(snapshot: dict[str, Any], contract: dict[str, Any], feature: dict[str, Any]) -> list[dict[str, Any]]:
    rules = {item["facet_id"]: item for item in contract["facet_rules"]}
    results: list[dict[str, Any]] = []
    for facet in sorted(item["facet_id"] for item in snapshot["semantic_facets"]):
        if facet not in rules:
            fail("missing-facet-rule", "no explicit derivation rule exists", facet)
        rule = rules[facet]
        operations, operation_conditional = applicable_operations(feature, contract, rule["operation_family_ids"])
        operation_scientific_by_id = {item["operation_id"]: item["scientific_id"] for item in snapshot["operations"]}
        operation_scientific_ids = [operation_scientific_by_id[item] for item in operations]
        inputs: list[dict[str, Any]] = []
        interaction_bases: list[dict[str, str]] = []
        archetypes = list(rule["archetype_ids"])
        policy = rule["policy"]
        if policy == "analysis-only":
            decision, question_type = "not-required-by-feature-semantics", "relational/metamorphic-candidate"
            states = ["analytical-projection-only"]
            archetypes = []
        elif policy == "typed-interaction":
            interaction_bases = _interaction_bases(snapshot, contract, feature)
            states = ["explicit-typed-interaction"] if interaction_bases else ["no-explicit-interaction"]
            if interaction_bases:
                decision, question_type = "required", "relational/metamorphic-candidate"
            else:
                decision, question_type = "not-required-by-feature-semantics", "relational/metamorphic-candidate"
                archetypes = []
        elif policy == "documented-complexity":
            inputs = [_assertion_ref(feature, "resource_termination")]
            states = [inputs[0]["state"]]
            if feature["feature_id"] in COMPLEXITY_FEATURES and inputs[0]["state"] == "known":
                decision, question_type = "required", "implementation-documentation-capable"
            else:
                decision, question_type = "not-required-by-feature-semantics", "characterization-only"
                archetypes = []
        elif policy == "documented-security":
            fields = ("syntax_grammar", "options_state", "host_operation", "resource_termination")
            inputs = [_assertion_ref(feature, field) for field in fields]
            states = [item["state"] for item in inputs]
            if feature["feature_id"] in SECURITY_FEATURES:
                decision, question_type = "conditionally-required", "implementation-documentation-capable"
            else:
                decision, question_type = "not-required-by-feature-semantics", "characterization-only"
                archetypes = []
        elif policy == "phase-sensitive":
            fields = ("syntax_grammar", "diagnostic_error", "replacement", "host_operation")
            inputs = [_assertion_ref(feature, field) for field in fields]
            states = [item["state"] for item in inputs]
            if _phase_sensitive(feature, operations):
                decision = "conditionally-required" if operation_conditional or any(item["scope"] != "canonical-invariant" for item in inputs) else "required"
                question_type = "implementation-documentation-capable"
            else:
                decision, question_type = "not-required-by-feature-semantics", "characterization-only"
                archetypes = []
        else:
            primary_field = {
                "facet.syntax": "syntax_grammar", "facet.core-match": "definition", "facet.search-boundary": "search_iteration",
                "facet.capture": "capture_result", "facet.unicode-encoding": "unicode_encoding", "facet.option-state": "options_state",
                "facet.host-api": "host_operation", "facet.replacement": "replacement", "facet.error-diagnostics": "diagnostic_error",
                "facet.resource-termination": "resource_termination",
            }[facet]
            inputs = [_assertion_ref(feature, primary_field)]
            states = [inputs[0]["state"]]
            decision, question_type = _state_decision(inputs[0]["state"], inputs[0]["scope"])
            if policy == "core-definition" and feature["feature_class"] not in NEGATIVE_CORE_CLASSES:
                archetypes = ["archetype.defining-positive"]
            if facet == "facet.search-boundary" and not any(item in operations for item in ("operation.next-match", "operation.find-all", "operation.find-overlapping", "operation.replace-all", "operation.stream-scan")):
                archetypes = [item for item in archetypes if item != "archetype.repeated-iteration"]
            if facet == "facet.replacement" and "operation.replace-all" in operations and decision in {"required", "conditionally-required"}:
                archetypes.append("archetype.repeated-iteration")
            if facet == "facet.error-diagnostics" and decision in {"conditionally-required", "required"} and inputs[0]["state"] in {"implementation-defined", "profile-dependent"}:
                archetypes = ["archetype.permitted-variation"]
            if decision in {"not-applicable", "not-required-by-feature-semantics", "blocked-by-unresolved-semantics"}:
                archetypes = []
        if decision in {"required", "conditionally-required"} and not operations:
            decision = "blocked-by-unresolved-semantics"
            question_type = "unresolved"
            archetypes = []
            states.append("no-applicable-canonical-operation")
        if operation_conditional and decision == "required":
            decision = "conditionally-required"
        if question_type == "normative/conformance-capable" and not _feature_sources_normative(feature, snapshot):
            question_type = "implementation-documentation-capable"
        provisional = []
        bases = interaction_bases or [None]
        prospective_questions = [
            (archetype_id, interaction, None, decision)
            for archetype_id in sorted(set(archetypes))
            for interaction in bases
        ]
        if policy == "core-definition" and decision in {"required", "conditionally-required"}:
            prospective_questions.extend(
                ("archetype.alternative-semantic-mode", None, variant, "conditionally-required")
                for variant in feature["semantic_variants"]
            )
        for archetype_id, interaction, variant, requirement_state in prospective_questions:
            profile_condition = _profile_condition(
                snapshot,
                feature,
                rule,
                inputs,
                operation_scientific_ids,
                interaction=interaction,
                variant=variant,
            )
            variant_basis = None if variant is None else {
                "variant_id": variant["variant_id"],
                "variant_scientific_id": variant["scientific_id"],
                "derivation_id": variant["semantic_assertion"]["derivation_id"],
                "source_ids": variant["semantic_assertion"]["source_ids"],
            }
            identity_basis = {
                "feature_scientific_id": feature["scientific_id"],
                "facet_scientific_id": rule["facet_scientific_id"],
                "archetype_id": archetype_id,
                "question_type": question_type,
                "semantic_assertion_refs": sorted(item["selector"] for item in inputs),
                "operation_scientific_ids": operation_scientific_ids,
                "profile_condition": profile_condition,
                "interaction_basis": interaction,
                "semantic_variant_basis": variant_basis,
            }
            suffix = hashlib.sha256(canonical_bytes(identity_basis)).hexdigest()[:20]
            provisional.append({"analysis_key": f"analysis-obligation.{feature['feature_id'].removeprefix('feature.')}.{facet.removeprefix('facet.')}.{suffix}", "archetype_id": archetype_id, "question_type": question_type, "requirement_state": requirement_state, "operation_ids": operations, "operation_scientific_ids": operation_scientific_ids, "profile_condition": profile_condition, "interaction_basis": interaction, "semantic_variant_basis": variant_basis, "prospective_identity_basis": identity_basis})
        result = {
            "feature_id": feature["feature_id"],
            "feature_scientific_id": feature["scientific_id"],
            "facet_id": facet,
            "decision": decision,
            "question_type": question_type,
            "governing_states": states,
            "semantic_inputs": inputs,
            "rule_key": rule["rule_key"],
            "rule_revision_id": rule["rule_revision_id"],
            "operation_ids": operations,
            "operation_scientific_ids": operation_scientific_ids,
            "operation_condition": rule["profile_capability_predicate"],
            "interaction_bases": interaction_bases,
            "reason": _decision_reason(feature, rule, decision, states, operations),
            "provisional_obligations": provisional,
        }
        results.append(result)
    return results


def explain_feature(root: Path, feature_id: str) -> dict[str, Any]:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    contract = load_strict(root / CONTRACT_PATH)
    feature = next((item for item in snapshot["features"] if item["feature_id"] == feature_id), None)
    if feature is None:
        fail("unknown-feature", "feature is absent from current semantic authority", feature_id)
    decisions = derive_feature(snapshot, contract, feature)
    return {"feature_id": feature_id, "feature_scientific_id": feature["scientific_id"], "contract_id": contract["contract_id"], "decisions": decisions}


def _legacy_classification(decision: dict[str, Any], legacy_case: str) -> tuple[str, str]:
    if decision["decision"] in {"not-applicable", "not-required-by-feature-semantics"}:
        return "uniform-template-without-feature-specific-trigger", "The frozen feature semantics suppress this facet, but the predecessor emitted the case uniformly."
    expected = LEGACY_CASE_ARCHETYPE.get(legacy_case)
    actual = {item["archetype_id"] for item in decision["provisional_obligations"]}
    if expected is not None and expected in actual:
        return "semantically-supported-by-current-frozen-input", "A current feature-specific rule supports the scientific question represented by the legacy case."
    return "ambiguous-historical-rationale", "The facet is material, but the fixed predecessor case is not independently justified by the current rule's selected archetype."


def build_legacy_report(root: Path, contract: dict[str, Any], dry_decisions: list[dict[str, Any]]) -> dict[str, Any]:
    projection = load_strict(root / LEGACY_PROJECTION_PATH)
    by_pair = {(item["feature_id"], item["facet_id"]): item for item in dry_decisions}
    cases = []
    classes: Counter[str] = Counter()
    by_facet: dict[str, Counter[str]] = {}
    for obligation in projection["semantic_obligation_templates"]:
        mapped_facet = LEGACY_FACET_MAP[obligation["facet"]]
        decision = by_pair[(obligation["feature_id"], mapped_facet)]
        classification, rationale = _legacy_classification(decision, obligation["case"])
        classes[classification] += 1
        by_facet.setdefault(obligation["facet"], Counter())[classification] += 1
        cases.append({"legacy_obligation_id": obligation["obligation_id"], "feature_id": obligation["feature_id"], "legacy_facet": obligation["facet"], "legacy_case": obligation["case"], "legacy_classification": obligation["classification"], "current_facet_id": mapped_facet, "analysis_classification": classification, "current_rule_revision_id": decision["rule_revision_id"], "rationale": rationale})
    old_feature_ids = {item["feature_id"] for item in projection["feature_revisions"]}
    snapshot = load_strict(root / SNAPSHOT_PATH)
    underrepresented = [
        {"feature_id": item["feature_id"], "facet_id": item["facet_id"], "provisional_obligation_count": len(item["provisional_obligations"]), "reason": "Current feature or facet did not exist in the predecessor fixed grid."}
        for item in dry_decisions
        if item["provisional_obligations"] and (item["feature_id"] not in old_feature_ids or item["facet_id"] in {"facet.phase", "facet.complexity-guarantee", "facet.security-context"})
    ]
    body = {
        "schema_version": "legacy-obligation-derivation-report.v1",
        "published_on": PUBLISHED_ON,
        "classification": {"historical_analysis_only": True, "predecessor_artifacts_modified": False, "new_denominator_authority": False},
        "source_projection": {"path": LEGACY_PROJECTION_PATH.as_posix(), "projection_id": projection["projection_id"], "file_sha256": _sha(root / LEGACY_PROJECTION_PATH), "obligation_count": len(projection["semantic_obligation_templates"])},
        "current_semantic_authority": {"path": SNAPSHOT_PATH.as_posix(), "snapshot_id": snapshot["snapshot_id"], "snapshot_digest_sha256": snapshot["snapshot_digest_sha256"]},
        "rule_contract": {"path": CONTRACT_PATH.as_posix(), "contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "legacy_construction": {"formula": "251 canonical features × 48 fixed cases = 12,048 obligation templates", "feature_count": 251, "cases_per_feature": 48, "facet_count": 12, "obligation_count": 12048, "executable_requirement_count": 9506, "derivation_classes": ["generic-feature-independent-template", "coarse-feature-class-classification", "historical-planning-rule"]},
        "summary": {"obligations_audited": len(cases), "by_analysis_classification": dict(sorted(classes.items())), "underrepresented_current_feature_facet_pairs": len(underrepresented)},
        "by_legacy_facet": [{"legacy_facet": facet, "counts": dict(sorted(values.items()))} for facet, values in sorted(by_facet.items())],
        "obligation_cases": sorted(cases, key=lambda item: item["legacy_obligation_id"]),
        "underrepresented_current_semantics": sorted(underrepresented, key=lambda item: (item["feature_id"], item["facet_id"])),
        "denominator_boundary": denominator_baseline(root),
        "derivation_id": DERIVATION_ID,
        "derivation_revision_id": derivation_spec(root)["derivation_revision_id"],
    }
    return _finalize(root, body, namespace="finding-revision", family=SCHEMA_FAMILIES["legacy-report"], id_field="report_id", digest_field="report_digest_sha256")


def _percentile(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def build_dry_run(root: Path, contract: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    decisions = [decision for feature in snapshot["features"] for decision in derive_feature(snapshot, contract, feature)]
    obligations = [item for decision in decisions for item in decision["provisional_obligations"]]
    decision_counts = Counter(item["decision"] for item in decisions)
    facet_counts = Counter()
    operation_counts = Counter()
    question_counts = Counter(item["question_type"] for item in obligations)
    requirement_state_counts = Counter(item["requirement_state"] for item in obligations)
    archetype_counts = Counter(item["archetype_id"] for item in obligations)
    feature_counts: Counter[str] = Counter()
    conditional = 0
    for decision in decisions:
        count = len(decision["provisional_obligations"])
        feature_counts[decision["feature_id"]] += count
        facet_counts[decision["facet_id"]] += count
        conditional += sum(item["requirement_state"] == "conditionally-required" for item in decision["provisional_obligations"])
        for obligation in decision["provisional_obligations"]:
            operation_counts.update(obligation["operation_ids"])
    shapes = Counter(
        tuple((item["facet_id"], item["decision"], len(item["provisional_obligations"])) for item in derive_feature(snapshot, contract, feature))
        for feature in snapshot["features"]
    )
    count_values = list(feature_counts.values())
    anomalies = []
    for feature_id, count in sorted(feature_counts.items()):
        if count == 0:
            anomalies.append({"kind": "zero-obligation-feature", "feature_id": feature_id, "value": count, "disposition": "blocking"})
        elif count > _percentile(count_values, 0.95) * 2:
            anomalies.append({"kind": "high-obligation-feature", "feature_id": feature_id, "value": count, "disposition": "review-required"})
    total = len(obligations)
    dominant_facet, dominant_count = facet_counts.most_common(1)[0]
    if dominant_count * 2 > total:
        anomalies.append({"kind": "facet-dominance", "facet_id": dominant_facet, "value": dominant_count, "disposition": "review-required"})
    body = {
        "schema_version": "obligation-derivation-dry-run.v1",
        "published_on": PUBLISHED_ON,
        "classification": {"analysis_only": True, "authoritative_denominator": False, "canonical_obligation_ids_minted": False, "production_vectors_generated": False, "profile_applicability_evaluated": False},
        "semantic_authority": {"path": SNAPSHOT_PATH.as_posix(), "snapshot_id": snapshot["snapshot_id"], "snapshot_digest_sha256": snapshot["snapshot_digest_sha256"], "features": len(snapshot["features"])},
        "rule_contract": {"path": CONTRACT_PATH.as_posix(), "contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "summary": {"feature_count": len(snapshot["features"]), "facet_decisions": len(decisions), "provisional_obligations": total, "conditional_obligations": conditional, "suppressed_not_applicable_decisions": decision_counts["not-applicable"], "suppressed_no_feature_implication_decisions": decision_counts["not-required-by-feature-semantics"], "blocked_decisions": decision_counts["blocked-by-unresolved-semantics"], "distinct_feature_shapes": len(shapes), "most_common_feature_shape_count": max(shapes.values())},
        "distribution": {
            "obligations_per_feature": {"minimum": min(count_values), "median": _percentile(count_values, 0.5), "p95": _percentile(count_values, 0.95), "maximum": max(count_values)},
            "by_decision": dict(sorted(decision_counts.items())),
            "by_requirement_state": dict(sorted(requirement_state_counts.items())),
            "by_facet": dict(sorted(facet_counts.items())),
            "by_operation": dict(sorted(operation_counts.items())),
            "by_archetype": dict(sorted(archetype_counts.items())),
            "by_question_type": dict(sorted(question_counts.items())),
        },
        "feature_results": [
            {"feature_id": feature["feature_id"], "scientific_id": feature["scientific_id"], "provisional_obligation_count": feature_counts[feature["feature_id"]], "shape_digest_sha256": hashlib.sha256(canonical_bytes([(item["facet_id"], item["decision"], [candidate["archetype_id"] for candidate in item["provisional_obligations"]]) for item in derive_feature(snapshot, contract, feature)])).hexdigest()}
            for feature in snapshot["features"]
        ],
        "decisions": decisions,
        "anomalies": anomalies,
        "denominator_boundary": denominator_baseline(root),
        "derivation_id": DERIVATION_ID,
        "derivation_revision_id": derivation_spec(root)["derivation_revision_id"],
    }
    return _finalize(root, body, namespace="ontology-projection", family=SCHEMA_FAMILIES["dry-run"], id_field="report_id", digest_field="report_digest_sha256"), decisions


def _validate_profile_predicate(predicate: dict[str, Any], *, path: str) -> None:
    if predicate.get("operator") != "all" or not isinstance(predicate.get("clauses"), list) or not predicate["clauses"]:
        fail("invalid-obligation-predicate", "profile predicate must be a non-empty all-of clause set", path)
    for index, clause in enumerate(predicate["clauses"]):
        clause_path = f"{path}.clauses[{index}]"
        if clause.get("field") not in PROFILE_PREDICATE_FIELDS or clause.get("operator") not in PROFILE_PREDICATE_OPERATORS:
            fail("invalid-obligation-predicate", "profile predicate field or operator is outside the closed vocabulary", clause_path)
        value_keys = {key for key in ("value", "values", "value_from") if key in clause}
        if len(value_keys) != 1:
            fail("invalid-obligation-predicate", "profile predicate clause must declare exactly one value source", clause_path)
        if "values" in clause and (not isinstance(clause["values"], list) or not clause["values"]):
            fail("invalid-obligation-predicate", "profile predicate values must be a non-empty identity list", clause_path)
        if "value_from" in clause and clause["value_from"] not in {"feature.scientific_id", "derived.operation_scientific_ids"}:
            fail("invalid-obligation-predicate", "profile predicate uses an unknown deterministic value reference", clause_path)
        for value in clause.get("values", [clause.get("value")]):
            if value is not None and not str(value).startswith("rcid:v1:"):
                fail("mutable-label-in-obligation-predicate", "literal profile predicate values must be scientific identities", clause_path)


def validate_contract(root: Path, contract: dict[str, Any], snapshot: dict[str, Any] | None = None) -> None:
    snapshot = snapshot or load_strict(root / SNAPSHOT_PATH)
    validate_instance(contract, load_strict(root / CONTRACT_SCHEMA_PATH), source=CONTRACT_PATH.as_posix())
    if not contract["classification"]["design_only"] or contract["classification"]["authoritative_denominator"] or contract["classification"]["template_fallback_permitted"]:
        fail("obligation-contract-authority", "rule contract must remain design-only, non-authoritative, and fallback-free")
    expected_semantic_authority = {
        "path": SNAPSHOT_PATH.as_posix(),
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_digest_sha256": snapshot["snapshot_digest_sha256"],
        "feature_count": len(snapshot["features"]),
        "facet_count": len(snapshot["semantic_facets"]),
        "operation_count": len(snapshot["operations"]),
    }
    if contract["semantic_authority"] != expected_semantic_authority:
        fail("stale-obligation-semantic-authority", "rule contract is not bound to the current frozen semantic authority")
    if contract["semantic_foundation"] != {"path": SEMANTIC_FOUNDATION_PATH.as_posix(), "file_sha256": _sha(root / SEMANTIC_FOUNDATION_PATH)}:
        fail("stale-obligation-semantic-foundation", "rule contract semantic-foundation binding drifted")
    if contract["denominator_boundary"] != denominator_baseline(root) or not contract["denominator_boundary"]["artifacts_unchanged"]:
        fail("obligation-denominator-mutation", "predecessor denominator byte commitments changed")
    facet_ids = {item["facet_id"] for item in snapshot["semantic_facets"]}
    rules = contract["facet_rules"]
    if {item["facet_id"] for item in rules} != facet_ids or len(rules) != len(facet_ids):
        fail("obligation-facet-rule-totality", "every current facet must have exactly one rule")
    facet_scientific_by_id = {item["facet_id"]: item["scientific_id"] for item in snapshot["semantic_facets"]}
    if any(item["facet_scientific_id"] != facet_scientific_by_id[item["facet_id"]] for item in rules):
        fail("obligation-facet-identity", "facet rules must reference the frozen facet scientific identities")
    operation_ids = {item["operation_id"] for item in snapshot["operations"]}
    operation_rules = contract["operation_rules"]
    if {item["operation_id"] for item in operation_rules} != operation_ids or len(operation_rules) != len(operation_ids):
        fail("obligation-operation-rule-totality", "every current operation must have exactly one rule")
    operation_scientific_by_id = {item["operation_id"]: item["scientific_id"] for item in snapshot["operations"]}
    if any(item["operation_scientific_id"] != operation_scientific_by_id[item["operation_id"]] for item in operation_rules):
        fail("obligation-operation-identity", "operation rules must reference the frozen operation scientific identities")
    identity_catalog = load_strict(root / IDENTITY_CATALOG_PATH)
    identity_by_key = {item["canonical_key"]: item["scientific_id"] for item in identity_catalog["bindings"]}
    expected_modifiers = [
        {"modifier_id": item["modifier_id"], "modifier_scientific_id": identity_by_key[item["modifier_id"]]}
        for item in snapshot["modifiers"]
    ]
    if contract["modifier_identities"] != expected_modifiers:
        fail("obligation-modifier-identity", "modifier bindings must match the frozen scientific identity authority")
    if contract["operation_condition_contract"]["allowed_profile_fields"] != list(PROFILE_PREDICATE_FIELDS) or contract["operation_condition_contract"]["allowed_operators"] != list(PROFILE_PREDICATE_OPERATORS):
        fail("obligation-predicate-vocabulary", "profile predicate field and operator vocabularies must match the closed evaluator contract")
    archetypes = {item["archetype_id"] for item in contract["obligation_archetypes"]}
    revisions: set[str] = set()
    for rule in [*rules, *operation_rules]:
        if not rule["rationale"] or rule["depends_on_rule_ids"]:
            fail("invalid-obligation-rule", "rules require rationale and may not create rule-dependency cycles", rule["rule_key"])
        _validate_profile_predicate(rule["profile_capability_predicate"], path=rule["rule_key"])
        if rule["rule_revision_id"] != _rule_revision(root, rule):
            fail("obligation-rule-identity", "rule revision identity differs from canonical rule content", rule["rule_key"])
        if rule["rule_revision_id"] in revisions:
            fail("duplicate-obligation-rule", "rule revisions must be unique", rule["rule_key"])
        revisions.add(rule["rule_revision_id"])
        if rule["derivation_id"] != DERIVATION_ID or rule["derivation_revision_id"] != derivation_spec(root)["derivation_revision_id"]:
            fail("obligation-rule-derivation", "rule is not bound to the canonical derivation revision", rule["rule_key"])
    unknown_archetypes = {value for rule in rules for value in rule["archetype_ids"]} - archetypes
    if unknown_archetypes:
        fail("unknown-obligation-archetype", "facet rule references unknown archetype", str(sorted(unknown_archetypes)))
    family_members = [member for family in contract["operation_families"] for member in family["operation_ids"]]
    if len(family_members) != len(set(family_members)) or set(family_members) != operation_ids:
        fail("obligation-operation-family-partition", "operation families must form an exact disjoint partition")
    expected_id = _finalize(root, {key: value for key, value in contract.items() if key not in {"contract_id", "contract_digest_sha256"}}, namespace="artifact-set-manifest", family=SCHEMA_FAMILIES["contract"], id_field="contract_id", digest_field="contract_digest_sha256")
    if contract["contract_id"] != expected_id["contract_id"] or contract["contract_digest_sha256"] != expected_id["contract_digest_sha256"]:
        fail("obligation-contract-identity", "contract content identity or digest differs")


def _validate_decisions(snapshot: dict[str, Any], decisions: list[dict[str, Any]], contract: dict[str, Any]) -> None:
    expected = len(snapshot["features"]) * len(snapshot["semantic_facets"])
    if len(decisions) != expected:
        fail("obligation-decision-totality", f"expected {expected} feature/facet decisions, found {len(decisions)}")
    owners = [(item["feature_id"], item["facet_id"]) for item in decisions]
    if len(owners) != len(set(owners)):
        fail("obligation-decision-conflict", "a feature/facet pair has multiple decisions")
    provisional = [candidate for item in decisions for candidate in item["provisional_obligations"]]
    keys = [item["analysis_key"] for item in provisional]
    if len(keys) != len(set(keys)):
        fail("obligation-analysis-key-conflict", "distinct prospective meanings produced the same analysis key")
    if any(item["decision"] not in DECISIONS or item["question_type"] not in QUESTION_TYPES for item in decisions):
        fail("obligation-decision-vocabulary", "decision or question type is outside the closed contract")
    if any(item["decision"] in {"not-applicable", "not-required-by-feature-semantics", "blocked-by-unresolved-semantics"} and item["provisional_obligations"] for item in decisions):
        fail("obligation-suppression-conflict", "suppressed or blocked decisions cannot emit prospective obligations")
    operation_scientific_ids = {item["scientific_id"] for item in snapshot["operations"]}
    target_scientific_ids = {
        *[item["scientific_id"] for item in snapshot["features"]],
        *[item["modifier_scientific_id"] for item in contract["modifier_identities"]],
    }
    variant_scientific_ids = {
        variant["scientific_id"] for feature in snapshot["features"] for variant in feature["semantic_variants"]
    }
    for decision in decisions:
        if set(decision["operation_scientific_ids"]) - operation_scientific_ids:
            fail("obligation-operation-identity", "decision references an unknown operation scientific identity", decision["feature_id"])
        for candidate in decision["provisional_obligations"]:
            basis = candidate["prospective_identity_basis"]
            _validate_profile_predicate(candidate["profile_condition"], path=candidate["analysis_key"])
            if "operation_ids" in basis or set(basis["operation_scientific_ids"]) - operation_scientific_ids:
                fail("obligation-identity-basis", "prospective identity basis must use operation scientific identities, not labels", candidate["analysis_key"])
            interaction = candidate["interaction_basis"]
            if interaction and interaction["target_scientific_id"] not in target_scientific_ids:
                fail("obligation-interaction-identity", "interaction target scientific identity is unknown", candidate["analysis_key"])
            variant = candidate["semantic_variant_basis"]
            if variant and variant["variant_scientific_id"] not in variant_scientific_ids:
                fail("obligation-variant-identity", "variant scientific identity is unknown", candidate["analysis_key"])


def _validate_fixtures(root: Path, snapshot: dict[str, Any], contract: dict[str, Any]) -> int:
    fixture = load_strict(root / FIXTURE_PATH)
    validate_instance(fixture, load_strict(root / FIXTURE_SCHEMA_PATH), source=FIXTURE_PATH.as_posix())
    features = {item["feature_id"]: item for item in snapshot["features"]}
    for case in fixture["cases"]:
        feature = deepcopy(features[case["feature_id"]])
        for override in case.get("semantic_state_overrides", []):
            feature["semantic_assertions"][override["field"]]["state"] = override["state"]
            feature["semantic_assertions"][override["field"]]["scope"] = override.get("scope", feature["semantic_assertions"][override["field"]]["scope"])
        derived = {item["facet_id"]: item for item in derive_feature(snapshot, contract, feature)}
        actual = derived[case["facet_id"]]
        if actual["decision"] != case["expected_decision"] or sorted(item["archetype_id"] for item in actual["provisional_obligations"]) != sorted(case["expected_archetype_ids"]):
            fail("obligation-fixture-mismatch", "hand-enumerated derivation fixture disagrees", case["case_id"])
        if case.get("expected_question_type") and actual["question_type"] != case["expected_question_type"]:
            fail("obligation-fixture-question-type", "fixture question type disagrees", case["case_id"])
    return len(fixture["cases"])


def build_all(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    contract = build_contract(root)
    validate_contract(root, contract, snapshot)
    dry_run, decisions = build_dry_run(root, contract)
    legacy = build_legacy_report(root, contract, decisions)
    _validate_decisions(snapshot, decisions, contract)
    validate_instance(legacy, load_strict(root / LEGACY_REPORT_SCHEMA_PATH), source=LEGACY_REPORT_PATH.as_posix())
    validate_instance(dry_run, load_strict(root / DRY_RUN_SCHEMA_PATH), source=DRY_RUN_PATH.as_posix())
    if legacy["summary"]["obligations_audited"] != 12048 or dry_run["summary"]["feature_count"] != 269:
        fail("obligation-analysis-population", "legacy or current population does not close")
    if dry_run["summary"]["blocked_decisions"]:
        fail("obligation-dry-run-blocked", "frozen semantic inputs leave blocking derivation decisions")
    if dry_run["summary"]["distinct_feature_shapes"] < 10 or dry_run["summary"]["most_common_feature_shape_count"] == 269:
        fail("obligation-template-regression", "feature-specific derivation collapsed to a uniform shape")
    return contract, legacy, dry_run


def verify_current(root: Path, *, verify_foundations: bool = True) -> dict[str, Any]:
    allocation = load_strict(root / ALLOCATION_PATH)
    validate_instance(allocation, load_strict(root / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_PATH.as_posix())
    if allocation != build_allocation():
        fail("obligation-allocation-drift", "typed allocation differs from its fixed accepted keys")
    built = build_all(root)
    for expected, relative in zip(built, (CONTRACT_PATH, LEGACY_REPORT_PATH, DRY_RUN_PATH), strict=True):
        if (root / relative).read_bytes() != canonical_bytes(expected) + b"\n":
            fail("obligation-artifact-drift", "tracked artifact differs from deterministic rebuild", relative.as_posix())
    snapshot = load_strict(root / SNAPSHOT_PATH)
    fixture_count = _validate_fixtures(root, snapshot, built[0])
    if verify_identity_catalog(root)["scientific_identities"] < 22431:
        fail("obligation-identity-foundation", "scientific identity history no longer contains the frozen semantic baseline")
    verify_derivation_catalog(root)
    if verify_foundations and verify_current_semantic_foundation(root)["semantic_foundation_acceptance"] != "PASS":
        fail("obligation-semantic-foundation", "semantic knowledge architecture gate is not passing")
    if not denominator_baseline(root)["artifacts_unchanged"]:
        fail("obligation-denominator-mutation", "predecessor denominator artifacts changed")
    return {"contract_id": built[0]["contract_id"], "rules": len(built[0]["facet_rules"]) + len(built[0]["operation_rules"]), "archetypes": len(built[0]["obligation_archetypes"]), "features": built[2]["summary"]["feature_count"], "facet_decisions": built[2]["summary"]["facet_decisions"], "provisional_obligations": built[2]["summary"]["provisional_obligations"], "fixtures": fixture_count}


def _write(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def materialize(root: Path) -> dict[str, Any]:
    allocation = build_allocation()
    validate_instance(allocation, load_strict(root / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_PATH.as_posix())
    _write(root / ALLOCATION_PATH, allocation)
    contract, legacy, dry_run = build_all(root)
    for relative, value in ((CONTRACT_PATH, contract), (LEGACY_REPORT_PATH, legacy), (DRY_RUN_PATH, dry_run)):
        _write(root / relative, value)
    rebuilt = build_all(root)
    if any(canonical_bytes(left) != canonical_bytes(right) for left, right in zip((contract, legacy, dry_run), rebuilt, strict=True)):
        fail("obligation-derivation-nondeterministic", "double regeneration changed canonical bytes")
    snapshot = load_strict(root / SNAPSHOT_PATH)
    fixture_count = _validate_fixtures(root, snapshot, contract)
    return {"contract_id": contract["contract_id"], "rules": len(contract["facet_rules"]) + len(contract["operation_rules"]), "archetypes": len(contract["obligation_archetypes"]), "features": dry_run["summary"]["feature_count"], "facet_decisions": dry_run["summary"]["facet_decisions"], "provisional_obligations": dry_run["summary"]["provisional_obligations"], "fixtures": fixture_count}
