"""Generated-assertion derivation inventory and evidence-strength checks."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from .errors import fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .profile import IdentityProfile


CATALOG_PATH = Path("registries/provenance/generated-assertion-derivations.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
PROFILE_PATH = Path("schemas/identity-profiles/generated-assertion-derivation.v1.json")
SCHEMA_PATH = Path("schemas/json/generated-assertion-derivation-catalog.schema.json")
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a07849-7262-7b95-8255-9fb7fc5bf310"
SCHEMA_VERSION = "generated-assertion-derivation-catalog.v1"

ASSERTION_KEY_FRAGMENTS = (
    "admission",
    "allowance",
    "audit",
    "authori",
    "bound",
    "capacity",
    "certif",
    "claim",
    "complete",
    "conclusion",
    "count",
    "coverage",
    "disposition",
    "evidence",
    "exhaust",
    "finding",
    "forecast",
    "margin",
    "multiplier",
    "omission",
    "pass",
    "policy",
    "qualif",
    "rate",
    "ready",
    "reconcil",
    "result",
    "status",
    "total",
    "verified",
)

ASSERTION_CONTAINER_NAMES = (
    "acceptance_gates",
    "adversarial_audit",
    "certification",
    "classification",
    "counts",
    "coverage_claims",
    "decision_gate",
    "denominator",
    "forecast",
    "forecast_policy",
    "invariants",
    "methodology",
    "public_product_readiness",
    "publication_contract",
    "reconciliation",
    "retention_contract_change",
    "safety_contract",
    "second_stage_trimming_review",
    "seed_accounting",
    "summary",
)

DERIVATION_IDS = {
    "semantic-counts": "rcid:v1:assertion-derivation:u7:01a07849-7263-7f96-b423-fc949075aad8",
    "semantic-research": "rcid:v1:assertion-derivation:u7:01a07849-7263-7be0-b96c-bc5b8ad88609",
    "legacy-construction-claims": "rcid:v1:assertion-derivation:u7:01a07849-7263-79c5-9e17-e0a94a74466f",
    "sparsity-inference": "rcid:v1:assertion-derivation:u7:01a07849-7263-7a11-a84e-c22ec479891e",
    "external-restatement": "rcid:v1:assertion-derivation:u7:01a07849-7263-75a7-a771-99190a0b2dbc",
    "artifact-measurement": "rcid:v1:assertion-derivation:u7:01a07849-7263-7d1e-b3ab-fbae785e9704",
    "campaign-calculation": "rcid:v1:assertion-derivation:u7:01a07849-7263-7683-838e-ff4e38da038d",
    "forecast-calculation": "rcid:v1:assertion-derivation:u7:01a07849-7263-752c-a177-425673779495",
    "planning-assumption": "rcid:v1:assertion-derivation:u7:01a07849-7263-7110-ba16-9c2e0b0b147a",
    "storage-policy": "rcid:v1:assertion-derivation:u7:01a07849-7263-71a9-929b-a325eeee7014",
    "classification-guard": "rcid:v1:assertion-derivation:u7:01a07849-7263-776c-b039-ef151491bb89",
    "certification-measurement": "rcid:v1:assertion-derivation:u7:01a07849-7263-7545-a73c-690597869eef",
    "reconciliation-calculation": "rcid:v1:assertion-derivation:u7:01a07849-7263-7dc3-819e-a953edf1583a",
    "vector-coverage-calculation": "rcid:v1:assertion-derivation:u7:01a07849-7263-7abb-8910-ff1786f90213",
    "facet-template-construction": "rcid:v1:assertion-derivation:u7:01a07849-7263-7c28-a56f-103c3b1f15c8",
    "manual-registry-decision": "rcid:v1:assertion-derivation:u7:01a07849-7263-7a47-adb6-32ef7f4fb541",
    "certification-predicate-calculation": "rcid:v1:assertion-derivation:u7:01a079d7-da99-7de8-a311-4e0196c5e676",
    "researched-feature-semantics": "rcid:v1:assertion-derivation:u7:01a07cfa-78e3-7de8-9559-e045f4e27cc0",
    "semantic-architecture-disposition": "rcid:v1:assertion-derivation:u7:01a07d86-1c67-7e4e-9237-baaaf44f8639",
    "semantic-universe-freeze": "rcid:v1:assertion-derivation:u7:01a07e69-dfbc-7506-91ad-45f3775dc29a",
    "obligation-derivation": "rcid:v1:assertion-derivation:u7:01a08125-97ae-7633-b217-ca1d0fa22fbf",
    "denominator-materialization": "rcid:v1:assertion-derivation:u7:01a08250-8e26-7ae3-aaf5-32e23ece7dbc",
    "denominator-audit": "rcid:v1:assertion-derivation:u7:01a08bfe-f086-7b3f-bc06-0ed1f691f052",
    "oracle-foundation-governance": "rcid:v1:assertion-derivation:u7:01a08d07-ef56-7cf6-a0ec-bba01aa82e7c",
    "evidence-admissibility-governance": "rcid:v1:assertion-derivation:u7:01a08d9e-ab75-762b-8a10-90db25ccb8fb",
    "conditional-applicability-governance": "rcid:v1:assertion-derivation:u7:01a08e2e-c914-7cbf-902d-c1cbe7b120bf",
    "observation-to-claim-adjudication": "rcid:v1:assertion-derivation:u7:01a08ef7-2c40-7cc2-91f3-3debe5bd8732",
}

ALLOWED_GATES_BY_CLASS = {
    "measurement": {"certification-evidence", "empirical-state", "independent-evidence"},
    "calculation": {"arithmetic-closure", "forecast-calculation", "structural-integrity"},
    "research-derived": {"independent-discovery", "independent-evidence", "semantic-completeness"},
    "external-evidence": {"external-authority", "independent-evidence"},
    "inference": {"advisory-inference"},
    "constant-by-construction": {"structural-integrity"},
    "manual-decision": {"governance-policy"},
}

ROLE_BY_CLASS = {
    "measurement": "independent-measurement",
    "calculation": "arithmetic-result",
    "research-derived": "researched-conclusion",
    "external-evidence": "external-authority-restatement",
    "inference": "reasoned-conclusion",
    "constant-by-construction": "structural-invariant",
    "manual-decision": "governance-constraint",
}


@dataclass(frozen=True)
class BindingSpec:
    selector: str
    derivation: str
    assertion_kind: str
    current_value_source: str
    legacy_ambiguity: str = "none"
    reproducible: bool = True


@dataclass(frozen=True)
class CountSpec:
    declared: str
    rule: str
    inputs: tuple[str, ...]
    population: str
    resolution: str
    match_values: tuple[Any, ...] = ()
    ambiguous: bool = False


@dataclass(frozen=True)
class ArtifactSpec:
    path: str
    artifact_class: str
    lifecycle: str
    generators: tuple[str, ...]
    bindings: tuple[BindingSpec, ...]
    coverage_selectors: tuple[str, ...] = ()
    count_contracts: tuple[CountSpec, ...] = ()
    schema_reference: str | None = None


def _b(
    selector: str,
    derivation: str,
    assertion_kind: str,
    source: str,
    *,
    ambiguity: str = "none",
    reproducible: bool = True,
) -> BindingSpec:
    return BindingSpec(selector, derivation, assertion_kind, source, ambiguity, reproducible)


def _c(
    declared: str,
    rule: str,
    inputs: Iterable[str],
    population: str,
    resolution: str,
    *,
    values: Iterable[Any] = (),
    ambiguous: bool = False,
) -> CountSpec:
    return CountSpec(declared, rule, tuple(inputs), population, resolution, tuple(values), ambiguous)


def _derivation_specs(root: Path) -> list[dict[str, Any]]:
    semantic = load_strict(root / "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json")
    source_references = sorted(f"source-id:{item['source_id']}" for item in semantic["sources"])
    researched_ledger = load_strict(
        root / "semantic-corpus/research/regex-semantic-feature-research-2026-09-07.v1.json"
    )
    researched_source_references = sorted(
        {
            f"source-id:{source_id}"
            for feature in researched_ledger["feature_research"]
            for source_id in feature["source_ids"]
        }
    )
    return [
        {
            "key": "semantic-counts",
            "title": "Canonical collection and filtered-value aggregation",
            "derivation_class": "calculation",
            "method_key": "canonical-count-aggregation",
            "method_version": "1.0.0",
            "input_references": ["semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json"],
            "authority_references": [],
            "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": ["the exact collections and filters named by each count contract"],
                "procedure_ref": "schemas/tooling/python/regex_conformance_schema/derivation.py",
                "formula": "Count collection members, matched values, or summed integer inputs exactly as declared by the count contract.",
            },
            "notes": "Arithmetic closure proves only that the generated report agrees with its inputs.",
        },
        {
            "key": "semantic-research",
            "title": "Researched semantic disposition and source synthesis",
            "derivation_class": "research-derived",
            "method_key": "semantic-source-synthesis",
            "method_version": "1.0.0",
            "input_references": ["semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json#/sources"],
            "authority_references": source_references,
            "allowed_gate_kinds": ["independent-discovery", "independent-evidence", "semantic-completeness"],
            "independent_evidence": True,
            "metadata": {
                "kind": "research-derived",
                "source_references": source_references,
                "research_artifact_ref": "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json",
                "methodology": "Apply the snapshot's candidate, identity, source-priority, and disposition rules to its bound source identities.",
            },
            "notes": "The sources and reviewed methodology, not generator repetition, are the evidence basis.",
        },
        {
            "key": "researched-feature-semantics",
            "title": "Feature-by-feature primary-source semantic reconstruction",
            "derivation_class": "research-derived",
            "method_key": "feature-semantic-source-reconstruction",
            "method_version": "2.0.0",
            "input_references": [
                "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json",
                "semantic-corpus/research/regex-semantic-feature-research-2026-09-07.v1.json",
            ],
            "authority_references": researched_source_references,
            "allowed_gate_kinds": [
                "independent-evidence",
                "semantic-completeness",
            ],
            "independent_evidence": True,
            "metadata": {
                "kind": "research-derived",
                "source_references": researched_source_references,
                "research_artifact_ref": "semantic-corpus/research/regex-semantic-feature-research-2026-09-07.v1.json",
                "methodology": "Review every accepted feature against its exact primary or official source identities; classify each semantic dimension, isolate variant and manifestation behavior, and record unsupported claims as unresolved rather than infer them from cross-engine consensus.",
            },
            "notes": "Shared rules acquire scientific force only through an explicit feature-level applicability decision and source binding in the research ledger.",
        },
        {
            "key": "legacy-construction-claims",
            "title": "Legacy literal audit and reconciliation output",
            "derivation_class": "constant-by-construction",
            "method_key": "legacy-literal-emission",
            "method_version": "1.0.0",
            "input_references": [],
            "authority_references": ["tools/semantics/compile_semantic_baseline.py"],
            "allowed_gate_kinds": ["structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "constant-by-construction",
                "constructor_ref": "tools/semantics/compile_semantic_baseline.py",
                "construction_rule": "The constructor emits the literal or uniform sentence without evaluating independent source evidence for that row.",
            },
            "notes": "These fields preserve historical context but cannot close discovery, reconciliation, audit, or semantic-completeness gates.",
        },
        {
            "key": "sparsity-inference",
            "title": "Category sparsity threshold inference",
            "derivation_class": "inference",
            "method_key": "category-sparsity-threshold",
            "method_version": "1.0.0",
            "input_references": ["semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json#/features/*/category"],
            "authority_references": [],
            "allowed_gate_kinds": ["advisory-inference"],
            "independent_evidence": False,
            "metadata": {
                "kind": "inference",
                "supporting_evidence_references": ["calculated feature count per declared category"],
                "inference_rule": "Flag a category below five features; absence of a flag is only a threshold result and does not establish semantic completeness.",
            },
            "notes": "The former no-suspicious-sparsity prose is visibly weaker than measurement or research evidence.",
        },
        {
            "key": "external-restatement",
            "title": "Qualified external or source-bound restatement",
            "derivation_class": "external-evidence",
            "method_key": "source-bound-restatement",
            "method_version": "1.0.0",
            "input_references": ["the exact source binding or external reference serialized by the inventoried artifact"],
            "authority_references": ["artifact-local source binding"],
            "allowed_gate_kinds": ["external-authority", "independent-evidence"],
            "independent_evidence": True,
            "metadata": {
                "kind": "external-evidence",
                "source_references": ["the exact source identity, digest, or URL recorded in the inventoried artifact"],
            },
            "notes": "The restatement has only the scope and authority of the referenced source.",
        },
        {
            "key": "artifact-measurement",
            "title": "Measured artifact or execution state",
            "derivation_class": "measurement",
            "method_key": "qualified-artifact-measurement",
            "method_version": "1.0.0",
            "input_references": ["the immutable evidence or measured artifact named by the report's source bindings"],
            "authority_references": ["verifier/python/regex_conformance_verifier"],
            "allowed_gate_kinds": ["empirical-state", "independent-evidence"],
            "independent_evidence": True,
            "metadata": {
                "kind": "measurement",
                "measured_inputs": ["source-bound immutable evidence, artifact bytes, or execution records"],
                "procedure_ref": "verifier/python/regex_conformance_verifier",
                "procedure_version": "1.0.0",
            },
            "notes": "A measurement supports only the observed or measured state, not a normative expectation.",
        },
        {
            "key": "campaign-calculation",
            "title": "Deterministic campaign-plan aggregation",
            "derivation_class": "calculation",
            "method_key": "campaign-plan-aggregation",
            "method_version": "1.0.0",
            "input_references": ["campaign definition, profile, vector, applicability, and source-digest inputs named by the compiled plan"],
            "authority_references": ["campaigns/python"],
            "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": ["the exact inputs named by each compiled campaign manifest"],
                "procedure_ref": "campaigns/python",
                "formula": "Deterministically enumerate admitted logical executions, shards, partitions, and aggregate counts from the bound campaign inputs.",
            },
            "notes": "A compiled plan proves construction and arithmetic closure, not target behavior or scientific completeness.",
        },
        {
            "key": "forecast-calculation",
            "title": "Deterministic scale or storage forecast calculation",
            "derivation_class": "calculation",
            "method_key": "scale-forecast-arithmetic",
            "method_version": "1.0.0",
            "input_references": ["measured bases and planning parameters explicitly bound by each forecast"],
            "authority_references": ["campaigns/python/regex_conformance_scale"],
            "allowed_gate_kinds": ["arithmetic-closure", "forecast-calculation"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": ["source-bound measurements, denominator inputs, and separately classified assumptions"],
                "procedure_ref": "campaigns/python/regex_conformance_scale",
                "formula": "Apply the named report's deterministic lower, expected, and conservative arithmetic without upgrading the authority of its inputs.",
            },
            "notes": "Forecast arithmetic does not independently validate planning assumptions or measured bases.",
        },
        {
            "key": "planning-assumption",
            "title": "Governed planning assumption",
            "derivation_class": "manual-decision",
            "method_key": "planning-assumption-selection",
            "method_version": "1.0.0",
            "input_references": [],
            "authority_references": ["registries/universe/full-known-universe-2026-08-15.v1.json#/governance"],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
            "metadata": {
                "kind": "manual-decision",
                "governing_decision_ref": "registries/universe/full-known-universe-2026-08-15.v1.json#/governance",
                "decision_scope": "Planning archetype counts, profile/platform multipliers, retry rates, growth allowances, reserves, and bound selection remain assumptions until later empirical replacement.",
            },
            "notes": "The values are retained unchanged and are not presented as measurements.",
        },
        {
            "key": "storage-policy",
            "title": "Governed retained-storage boundary",
            "derivation_class": "manual-decision",
            "method_key": "retained-storage-policy",
            "method_version": "1.0.0",
            "input_references": [],
            "authority_references": ["registries/universe/full-known-universe-2026-08-15.v1.json#/governance/raw_storage_contract_url"],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
            "metadata": {
                "kind": "manual-decision",
                "governing_decision_ref": "registries/universe/full-known-universe-2026-08-15.v1.json#/governance/raw_storage_contract_url",
                "decision_scope": "Eight-billion-byte soft stop, ten-billion-byte hard ceiling, and no paid capacity without authorization.",
            },
            "notes": "A policy boundary is not a measured storage result.",
        },
        {
            "key": "classification-guard",
            "title": "Protective non-authority and non-execution declaration",
            "derivation_class": "constant-by-construction",
            "method_key": "protective-classification-guard",
            "method_version": "1.0.0",
            "input_references": [],
            "authority_references": ["schemas/json"],
            "allowed_gate_kinds": ["structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "constant-by-construction",
                "constructor_ref": "schemas/json",
                "construction_rule": "The schema and generator fix non-authority, planning-only, or non-execution flags as protective classification invariants.",
            },
            "notes": "A protective false flag prevents overclaiming but is not affirmative evidence that an independent audit occurred.",
        },
        {
            "key": "certification-measurement",
            "title": "Procedure-backed qualification or certification result",
            "derivation_class": "measurement",
            "method_key": "qualified-procedure-result",
            "method_version": "1.0.0",
            "input_references": ["the exact evidence, fixtures, or cases named by the certification report"],
            "authority_references": ["the report generator and validator named by each artifact inventory entry"],
            "allowed_gate_kinds": ["certification-evidence", "empirical-state", "independent-evidence"],
            "independent_evidence": True,
            "metadata": {
                "kind": "measurement",
                "measured_inputs": ["procedure inputs, cases, and immutable evidence identified by the report"],
                "procedure_ref": "the exact generator and schema named by the artifact inventory entry",
                "procedure_version": "1.0.0",
            },
            "notes": "Certification flags are admissible only with their bound procedure and inputs.",
        },
        {
            "key": "reconciliation-calculation",
            "title": "Deterministic reconciliation and summary aggregation",
            "derivation_class": "calculation",
            "method_key": "reconciliation-aggregation",
            "method_version": "1.0.0",
            "input_references": ["the exact cases, attempts, observations, shards, manifests, or rows named by the report"],
            "authority_references": ["verifier and report-builder implementations named by each artifact"],
            "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": ["source-bound cases and records"],
                "procedure_ref": "schemas/tooling/python/regex_conformance_schema/derivation.py",
                "formula": "Recompute counts, commitments, and reconciliation status from the named input population.",
            },
            "notes": "Reconciliation proves agreement with inputs; it does not upgrade those inputs to independent evidence.",
        },
        {
            "key": "vector-coverage-calculation",
            "title": "Generated vector-requirement and reuse accounting",
            "derivation_class": "calculation",
            "method_key": "vector-requirement-accounting",
            "method_version": "1.0.0",
            "input_references": ["ontology/projections/regex-semantic-projection-2026-08-22.v1.json", "vectors/definitions"],
            "authority_references": ["tools/semantics/compile_semantic_baseline.py"],
            "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": ["executable obligation templates and inspected vector-definition files"],
                "procedure_ref": "tools/semantics/compile_semantic_baseline.py",
                "formula": "Emit one requirement per executable template and calculate reuse only from exact semantic projection and obligation references.",
            },
            "notes": "Missing/reusable status is calculated coverage bookkeeping, not empirical evidence.",
        },
        {
            "key": "facet-template-construction",
            "title": "Declared facet-template construction",
            "derivation_class": "constant-by-construction",
            "method_key": "uniform-facet-template-expansion",
            "method_version": "1.0.0",
            "input_references": ["tools/semantics/compile_semantic_baseline.py#FACET_CASES"],
            "authority_references": ["tools/semantics/compile_semantic_baseline.py"],
            "allowed_gate_kinds": ["structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "constant-by-construction",
                "constructor_ref": "tools/semantics/compile_semantic_baseline.py#FACET_CASES",
                "construction_rule": "Expand every feature across the declared facet/case template and verify that the generated expansion contains the same declared facets.",
            },
            "notes": "Presence of every generated facet proves structural template closure only; it cannot prove researched semantic completeness.",
        },
        {
            "key": "manual-registry-decision",
            "title": "Governed registry selection or disposition",
            "derivation_class": "manual-decision",
            "method_key": "governed-registry-selection",
            "method_version": "1.0.0",
            "input_references": [],
            "authority_references": ["GOVERNANCE.md"],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
            "metadata": {
                "kind": "manual-decision",
                "governing_decision_ref": "GOVERNANCE.md",
                "decision_scope": "Repository-governed labels, selections, dispositions, and safety policies are decisions unless separately bound to research or external evidence.",
            },
            "notes": "Governance state is not an observed runtime fact.",
        },
        {
            "key": "semantic-architecture-disposition",
            "title": "Primary-source semantic architecture candidate disposition",
            "derivation_class": "research-derived",
            "method_key": "semantic-architecture-candidate-disposition",
            "method_version": "1.0.0",
            "input_references": [
                "semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json",
                "semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json",
            ],
            "authority_references": [
                "source-id:lucene-regexp",
                "source-id:smtlib-unicode-strings",
                "source-id:swift-regex-type",
                "source-id:unicode-tr14",
                "source-id:unicode-uax44",
                "source-id:pcre2-serialization",
                "source-id:pcre2-pattern-info",
                "source-id:perl-regex-escapes",
            ],
            "allowed_gate_kinds": [
                "independent-discovery",
                "independent-evidence",
                "semantic-completeness",
            ],
            "independent_evidence": True,
            "metadata": {
                "kind": "research-derived",
                "methodology": "Compare the researched feature corpus, operations, facets, source families and deferred audit findings against proposition-scoped primary authorities; accept only materially distinct semantics and retain a terminal disposition for every candidate.",
                "research_artifact_ref": "semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json",
                "source_references": [
                    "source-id:lucene-regexp",
                    "source-id:smtlib-unicode-strings",
                    "source-id:swift-regex-type",
                    "source-id:swift-regex-builder",
                    "source-id:swift-regex-literals",
                    "source-id:unicode-tr14",
                    "source-id:unicode-uax44",
                    "source-id:pcre2-serialization",
                    "source-id:pcre2-pattern-info",
                    "source-id:perl-regex-escapes",
                ],
            },
            "notes": "Candidate disposition is evidence for model scope, not proof that the following adversarial semantic-universe audit is exhaustive.",
        },
        {
            "key": "semantic-universe-freeze",
            "title": "Declared-cutoff adversarial semantic-universe audit",
            "derivation_class": "research-derived",
            "method_key": "semantic-universe-adversarial-freeze",
            "method_version": "1.0.0",
            "input_references": [
                "semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v3.json",
                "semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json",
                "semantic-corpus/research/regex-semantic-universe-adversarial-plan-2026-09-08.v1.json",
            ],
            "authority_references": [
                "source-id:ecma-regexp",
                "source-id:flex-manual",
                "source-id:pcre2-api",
                "source-id:pcre2-pattern",
                "source-id:pcre2-syntax",
                "source-id:python-re",
                "source-id:rust-regex",
                "source-id:unicode-tr18",
            ],
            "allowed_gate_kinds": [
                "independent-discovery",
                "independent-evidence",
                "semantic-completeness",
            ],
            "independent_evidence": True,
            "metadata": {
                "kind": "research-derived",
                "methodology": "Attack the expanded corpus independently by source, ontology, operation, test corpus, and terminology; revalidate every prior candidate; return every newly encountered concept to primary authority; and require a terminal disposition before freezing the declared cutoff.",
                "research_artifact_ref": "semantic-corpus/research/regex-semantic-universe-adversarial-plan-2026-09-08.v1.json",
                "source_references": [
                    "source-id:ecma-regexp",
                    "source-id:flex-manual",
                    "source-id:pcre2-api",
                    "source-id:pcre2-pattern",
                    "source-id:pcre2-syntax",
                    "source-id:python-re",
                    "source-id:rust-regex",
                    "source-id:unicode-tr18",
                ],
            },
            "notes": "The derivation supports only the versioned cutoff-and-methodology claim; it does not assert timeless completeness or regenerate the obligation denominator.",
        },
        {
            "key": "obligation-derivation",
            "title": "Feature-specific semantic obligation derivation",
            "derivation_class": "calculation",
            "method_key": "semantic-obligation-rule-evaluation",
            "method_version": "1.0.0",
            "input_references": [
                "semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json",
                "ontology/derivations/regex-obligation-derivation-rules-2026-09-08.v1.json",
            ],
            "authority_references": [
                "semantic-corpus/foundation/semantic-knowledge-architecture.v1.json"
            ],
            "allowed_gate_kinds": ["forecast-calculation", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": [
                    "the exact frozen semantic assertions, facets, operations, variants, manifestations, modifiers and typed relations named by each rule"
                ],
                "procedure_ref": "schemas/tooling/python/regex_conformance_schema/obligation_derivation.py",
                "formula": "Evaluate one explicit facet rule per feature, preserve structured semantic state, resolve only declared operation predicates, and emit required, conditional, suppressed, or blocked decisions without a generic fallback.",
            },
            "notes": "Rule evaluation explains a prospective obligation decision; it does not strengthen its semantic inputs or advance denominator authority.",
        },
        {
            "key": "denominator-materialization",
            "title": "Canonical semantic denominator materialization",
            "derivation_class": "calculation",
            "method_key": "semantic-denominator-materialization",
            "method_version": "1.0.0",
            "input_references": [
                "semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json",
                "ontology/derivations/regex-obligation-derivation-rules-2026-09-08.v1.json",
                "reports/semantics/obligation-derivation-dry-run-2026-09-08.v1.json",
            ],
            "authority_references": [
                "semantic-corpus/foundation/semantic-knowledge-architecture.v1.json"
            ],
            "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": [
                    "the frozen semantic snapshot, accepted rule revisions, one-time typed identity allocation, predecessor denominator, and archetype polarity cardinality contract"
                ],
                "procedure_ref": "schemas/tooling/python/regex_conformance_schema/obligation_snapshots.py",
                "formula": "Materialize one immutable obligation per accepted prospective scientific question, then one minimum requirement per archetype evidence role while preserving conditional predicates and predecessor lineage.",
            },
            "notes": "Materialization establishes current semantic-denominator authority; it does not author vectors, evaluate profiles, or provide empirical evidence.",
        },
        {
            "key": "denominator-audit",
            "title": "Independent semantic denominator accounting audit",
            "derivation_class": "calculation",
            "method_key": "semantic-denominator-independent-audit",
            "method_version": "1.0.0",
            "input_references": [
                "ontology/obligations/regex-semantic-obligations-2026-09-08.v1.json",
                "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json",
                "ontology/migrations/regex-semantic-denominator-2026-09-08.v1.json",
                "reports/semantics/obligation-derivation-dry-run-2026-09-08.v1.json",
                "ontology/derivations/regex-obligation-derivation-rules-2026-09-08.v1.json",
            ],
            "authority_references": [
                "ontology/authority/current-semantic-denominator.v1.json"
            ],
            "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": [
                    "committed semantic obligation and requirement snapshots, their predecessor migration ledger, the accepted dry-run decisions, and the rule contract"
                ],
                "procedure_ref": "schemas/tooling/python/regex_conformance_schema/denominator_audit.py",
                "formula": "Independently partition committed stable-ID populations, validate predicates and cardinality from source fields, reconcile predecessor and successor sets, and compare every recomputed aggregate with the authoritative snapshots.",
            },
            "notes": "The audit proves accounting and derivation closure. It does not supply profile facts, author vectors, or certify conformance behavior.",
        },
        {
            "key": "oracle-foundation-governance",
            "title": "Oracle epistemic classes and circularity policy",
            "derivation_class": "manual-decision",
            "method_key": "oracle-foundation-governance",
            "method_version": "1.0.0",
            "input_references": [
                "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json",
                "the accepted separation of source proposition, researched claim, expectation, vector, execution, observation, and finding",
            ],
            "authority_references": [
                "Define oracle hierarchy and circularity guards",
                "GOVERNANCE.md",
            ],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
            "metadata": {
                "kind": "manual-decision",
                "governing_decision_ref": "Define oracle hierarchy and circularity guards",
                "decision_scope": "Versioned oracle classes, permitted conclusion types, dependency independence, conflict preservation, and campaign expectation freezing.",
            },
            "notes": "This governance contract constrains admissible expectation authority. It does not itself establish a semantic expectation or empirical fact.",
        },
        {
            "key": "evidence-admissibility-governance",
            "title": "Normative and characterization evidence admissibility policy",
            "derivation_class": "manual-decision",
            "method_key": "evidence-admissibility-governance",
            "method_version": "1.0.0",
            "input_references": [
                "oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json",
                "semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json",
                "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json",
                "the accepted separation of source proposition, researched claim, expectation, execution, observation, and finding",
            ],
            "authority_references": [
                "Formalize normative vs characterization evidence",
                "GOVERNANCE.md",
            ],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
            "metadata": {
                "kind": "manual-decision",
                "governing_decision_ref": "Formalize normative vs characterization evidence",
                "decision_scope": "Evidence roles, epistemic uses, source-language strength, immutable provenance, authority-domain independence, and fail-closed admissibility.",
            },
            "notes": "This policy determines what a preserved evidence object may support. It neither changes the evidence's epistemic role nor establishes a semantic or empirical proposition by itself.",
        },
        {
            "key": "conditional-applicability-governance",
            "title": "Total proof-bearing conditional applicability policy",
            "derivation_class": "manual-decision",
            "method_key": "conditional-applicability-governance",
            "method_version": "1.0.0",
            "input_references": [
                "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json",
                "ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json",
                "oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json",
            ],
            "authority_references": [
                "Build applicability evaluation for conditional requirements",
                "GOVERNANCE.md",
            ],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
            "metadata": {
                "kind": "manual-decision",
                "governing_decision_ref": "Build applicability evaluation for conditional requirements",
                "decision_scope": "Open-world typed predicates, immutable capability-fact inputs, total applicability states, structured traces, self-reference guards, and the profile-expansion boundary.",
            },
            "notes": "This contract decides profile engagement for existing requirements. It does not create semantic requirements, expected results, support claims, observations, or conformance verdicts.",
        },
        {
            "key": "observation-to-claim-adjudication",
            "title": "Deterministic observation-to-claim adjudication policy",
            "derivation_class": "manual-decision",
            "method_key": "observation-to-claim-adjudication",
            "method_version": "1.0.0",
            "input_references": [
                "applicability/contracts/regex-conformance-conditional-applicability-2026-09-10.v1.json",
                "oracle/contracts/regex-conformance-evidence-admissibility-2026-09-10.v1.json",
                "registries/provenance/execution-provenance-policy.v1.json",
                "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json",
            ],
            "authority_references": [
                "Implement claims, discrepancies, adjudication, permitted divergence, and waivers",
                "GOVERNANCE.md",
            ],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
            "metadata": {
                "kind": "manual-decision",
                "governing_decision_ref": "Implement claims, discrepancies, adjudication, permitted divergence, and waivers",
                "decision_scope": "Coordinate states, oracle-bound comparisons, typed claims, discrepancy history, positive permitted divergence, gate-only waivers, operational quarantine, and anti-circularity.",
            },
            "notes": "This policy derives regenerable claims from exact immutable inputs. It does not redefine requirements, applicability, expectations, observations, discrepancies, or scientific truth.",
        },
        {
            "key": "certification-predicate-calculation",
            "title": "Versioned certification predicate evaluation",
            "derivation_class": "calculation",
            "method_key": "certification-predicate-evaluation",
            "method_version": "1.0.0",
            "input_references": [
                "certification/contracts/regex-conformance-certification.v1.json",
                "the exact digest-bound certification input set",
            ],
            "authority_references": [
                "schemas/tooling/python/regex_conformance_schema/certification.py"
            ],
            "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
            "independent_evidence": False,
            "metadata": {
                "kind": "calculation",
                "input_references": [
                    "the versioned predicate contract",
                    "the exact source artifacts, derivation revisions, and denominator members bound by the input set",
                ],
                "procedure_ref": "schemas/tooling/python/regex_conformance_schema/certification.py",
                "formula": "Evaluate each criterion independently over exact stable-ID sets, then compose required results with FAIL before BLOCKED before PASS precedence.",
            },
            "notes": "The evaluator derives certification state but cannot upgrade the evidence strength of its inputs.",
        },
    ]


SEMANTIC_COUNTS = (
    _c("/counts/canonical_features", "collection-length", ["/features"], "canonical feature records", "The count is the exact feature-array length."),
    _c("/counts/subfeatures_variants", "sum-collection-lengths", ["/features/*/semantic_variants"], "semantic variants attached to canonical features", "The count sums every feature's variant collection."),
    _c("/counts/aliases", "sum-collection-lengths", ["/features/*/aliases"], "aliases attached to canonical features", "The count sums every feature's alias collection."),
    _c("/counts/syntax_manifestations", "collection-length", ["/manifestations"], "syntax manifestation records", "The count is the exact manifestation-array length."),
    _c("/counts/modifiers_options", "collection-length", ["/modifiers"], "modifier records", "The count is the exact modifier-array length."),
    _c("/counts/typed_interactions", "collection-length", ["/interactions"], "typed interaction records", "The count is the exact interaction-array length."),
    _c("/counts/host_operations", "collection-length", ["/operations"], "operation records", "The count is the exact operation-array length."),
    _c("/counts/historical_only_features", "matching-value-count", ["/features/*/lifecycle/status"], "features whose lifecycle status is historical-only", "The count filters feature lifecycle status.", values=["historical-only"]),
    _c("/counts/normative_definitions", "matching-value-count", ["/sources/*/normative"], "source records marked normative", "The count filters the source normative flag.", values=[True]),
    _c("/counts/unresolved_semantic_candidates", "matching-value-count", ["/candidates/*/disposition"], "candidate records with unresolved disposition", "The count filters candidate disposition.", values=["unresolved"]),
    _c("/counts/discovery_sources", "collection-length", ["/sources"], "declared discovery source records", "The count is the exact source-array length."),
    _c("/counts/discovery_scans", "sum-collection-lengths", ["/discovery_scans", "/facility_family_reconciliations", "/adversarial_audit/passes"], "source scans, facility-family reconciliation rows, and adversarial-pass rows", "The legacy field name is broader than the discovery_scans array; this contract exposes the three counted populations without rewriting the immutable snapshot.", ambiguous=True),
    _c("/counts/candidate_records", "collection-length", ["/candidates"], "candidate records", "The count is the exact candidate-array length."),
    _c("/adversarial_audit/unresolved_candidate_count", "matching-value-count", ["/candidates/*/disposition"], "candidate records with unresolved disposition", "The audit count filters candidate disposition.", values=["unresolved"]),
)


PROJECTION_COUNTS = (
    _c("/counts/feature_revisions", "collection-length", ["/feature_revisions"], "feature revision rows", "Exact collection length."),
    _c("/counts/manifestations", "collection-length", ["/manifestations"], "manifestation rows", "Exact collection length."),
    _c("/counts/typed_interactions", "collection-length", ["/typed_interactions"], "typed interaction rows", "Exact collection length."),
    _c("/counts/obligation_templates", "collection-length", ["/semantic_obligation_templates"], "all generated obligation templates", "Exact collection length."),
    _c("/counts/executable_obligation_templates", "matching-value-count", ["/semantic_obligation_templates/*/classification"], "mandatory and conditional generated obligation templates", "Filter the template classification.", values=["mandatory", "conditional"]),
    _c("/counts/informative_templates", "matching-value-count", ["/semantic_obligation_templates/*/classification"], "informative generated obligation templates", "Filter the template classification.", values=["informative"]),
    _c("/counts/prohibited_not_applicable_templates", "matching-value-count", ["/semantic_obligation_templates/*/classification"], "prohibited/not-applicable generated obligation templates", "Filter the template classification.", values=["prohibited/not-applicable"]),
)


VECTOR_COUNTS = (
    _c("/counts/minimum_vector_definitions", "collection-length", ["/requirements"], "generated vector requirements", "Exact requirements-array length."),
    _c("/counts/missing_vector_definitions", "matching-value-count", ["/requirements/*/status"], "requirements with missing status", "Filter requirement status.", values=["missing"]),
    _c("/counts/reusable_vector_definitions", "matching-value-count", ["/requirements/*/status"], "requirements with reusable status", "Filter requirement status.", values=["reusable"]),
    _c("/counts/negative_or_error_vector_definitions", "matching-value-count", ["/requirements/*/vector_role"], "requirements whose vector role is negative, rejection, ambiguity, diagnostic, phase, termination, exhaustion, timeout, or limit", "Filter the generated vector-role field.", values=["negative", "rejection", "ambiguity-boundary", "class", "native-diagnostic", "phase", "termination", "exhaustion", "timeout", "limit"]),
    _c("/counts/interaction_vector_definitions", "matching-value-count", ["/requirements/*/facet"], "requirements in the interaction facet", "Filter requirement facet.", values=["interaction"]),
    _c("/counts/differential_vector_definitions", "matching-value-count", ["/requirements/*/facet"], "requirements in the differential facet", "Filter requirement facet.", values=["differential"]),
    _c("/counts/host_operation_vector_definitions", "matching-value-count", ["/requirements/*/facet"], "requirements in the host-operation facet", "Filter requirement facet.", values=["host-operation"]),
    _c("/reuse_audit/existing_vector_file_count", "collection-length", ["/reuse_audit/existing_vector_files_inspected"], "inspected vector-definition files", "Exact inspected-file collection length."),
    _c("/reuse_audit/reusable_vector_count", "matching-value-count", ["/requirements/*/status"], "requirements credited as reusable", "Filter requirement status; no literal can substitute for the population.", values=["reusable"]),
)


def _artifact_specs() -> tuple[ArtifactSpec, ...]:
    semantic_generator = ("tools/semantics/compile_semantic_baseline.py",)
    return (
        ArtifactSpec(
            "registries/identity/scientific-identities.v1.json",
            "identity-lock",
            "historical-immutable",
            ("tools/identity/freeze_scientific_identities.py",),
            (
                _b("/", "reconciliation-calculation", "validation", "Deterministic reconciliation of canonical semantic descriptors with the persistent identity lock."),
                _b("/adoption", "manual-registry-decision", "governance", "Governed one-time adoption boundary and compatibility declaration."),
                _b("/source_artifacts", "artifact-measurement", "measurement", "Measured byte digests for the exact semantic source artifacts."),
                _b("/bindings/*/semantic_fingerprint_history", "reconciliation-calculation", "validation", "Canonical scientific-content fingerprints and additive lineage history."),
                _b("/counts", "semantic-counts", "reconciliation", "Counts calculated from identity bindings, states, entity classes, and lineage records."),
                _b("/catalog_digest_sha256", "reconciliation-calculation", "validation", "Canonical digest calculated over the identity catalog excluding its digest field."),
            ),
            coverage_selectors=("/adoption", "/source_artifacts", "/bindings/*/status", "/bindings/*/semantic_fingerprint_history", "/counts", "/catalog_digest_sha256"),
            count_contracts=(
                _c("/counts/total", "collection-length", ["/bindings"], "all scientific identity bindings", "Exact binding collection length."),
                _c("/counts/active", "matching-value-count", ["/bindings/*/status"], "active scientific identity bindings", "Filter binding status.", values=["active"]),
                _c("/counts/historical", "matching-value-count", ["/bindings/*/status"], "non-active historical scientific identity bindings", "Filter every retired or unresolved historical status.", values=["deprecated", "erroneous-historical-classification", "merged", "out-of-scope", "split", "superseded", "unresolved"]),
                _c("/counts/lineage_records", "collection-length", ["/lineage_records"], "scientific lineage records", "Exact lineage-record collection length."),
                _c("/counts/by_class/feature", "matching-value-count", ["/bindings/*/entity_class"], "feature identity bindings", "Filter binding entity class.", values=["feature"]),
                _c("/counts/by_class/manifestation", "matching-value-count", ["/bindings/*/entity_class"], "manifestation identity bindings", "Filter binding entity class.", values=["manifestation"]),
                _c("/counts/by_class/modifier", "matching-value-count", ["/bindings/*/entity_class"], "modifier identity bindings", "Filter binding entity class.", values=["modifier"]),
                _c("/counts/by_class/obligation", "matching-value-count", ["/bindings/*/entity_class"], "obligation identity bindings", "Filter binding entity class.", values=["obligation"]),
                _c("/counts/by_class/operation", "matching-value-count", ["/bindings/*/entity_class"], "operation identity bindings", "Filter binding entity class.", values=["operation"]),
                _c("/counts/by_class/semantic-requirement", "matching-value-count", ["/bindings/*/entity_class"], "semantic requirement identity bindings", "Filter binding entity class.", values=["semantic-requirement"]),
                _c("/counts/by_class/semantic-variant", "matching-value-count", ["/bindings/*/entity_class"], "semantic variant identity bindings", "Filter binding entity class.", values=["semantic-variant"]),
                _c("/counts/by_class/typed-interaction", "matching-value-count", ["/bindings/*/entity_class"], "typed interaction identity bindings", "Filter binding entity class.", values=["typed-interaction"]),
            ),
            schema_reference="schemas/json/scientific-identity-catalog.schema.json",
        ),
        ArtifactSpec(
            "downstream/checkpoints/index.v1.json",
            "checkpoint-index",
            "current-generated",
            ("tools/downstream/compile_checkpoint_index.py",),
            (
                _b("/", "reconciliation-calculation", "reconciliation", "Deterministic projection of the complete local Coverage Shard checkpoint chain."),
                _b("/authority", "classification-guard", "structural", "Protective append-only, synchronization, and consumer-independence constants."),
                _b("/checkpoint_count", "reconciliation-calculation", "reconciliation", "Count calculated from the checkpoint index entries."),
                _b("/latest_checkpoint_digest_sha256", "reconciliation-calculation", "reconciliation", "Latest entry digest, or explicit null for an empty chain."),
                _b("/latest_checkpoint_id", "reconciliation-calculation", "reconciliation", "Latest entry identity, or explicit null for an empty chain."),
            ),
            coverage_selectors=("/authority", "/checkpoint_count", "/latest_checkpoint_digest_sha256", "/latest_checkpoint_id"),
            count_contracts=(
                _c("/checkpoint_count", "collection-length", ["/entries"], "Coverage Shard checkpoint index entries", "Exact index-entry collection length."),
            ),
            schema_reference="schemas/json/coverage-shard-checkpoint-index.schema.json",
        ),
        ArtifactSpec(
            "control-plane/qualification/sustained-operating-envelope.v1.json",
            "qualification-policy",
            "governed-registry",
            ("tools/control_plane/compile_sustained_operating_envelope.py",),
            (
                _b("/", "manual-registry-decision", "governance", "Governed qualification thresholds, resource boundaries, and sampling policy."),
                _b("/classification", "classification-guard", "structural", "Protective non-authority and non-target-behavior constants."),
                _b("/plan_digest_sha256", "reconciliation-calculation", "validation", "Canonical digest calculated from the qualification plan."),
                _b("/source_bindings", "artifact-measurement", "measurement", "Measured byte digests of the exact plan implementation and schema sources."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/sustained-operating-envelope.schema.json",
        ),
        *tuple(
            ArtifactSpec(
                path,
                "adapter-release-manifest",
                "historical-immutable",
                (generator,),
                (
                    _b("/", "reconciliation-calculation", "validation", "Self-verified adapter identity, protocol, runtime-constraint, and source-set binding."),
                    _b("/certification", "manual-registry-decision", "certification", "Static suite name, case count, and certified status recorded by the governed package manifest; no test run is performed while loading it.", ambiguity="overstated-evidence-strength"),
                    _b("/identity/source_digest", "artifact-measurement", "measurement", "Aggregate digest measured from the ordered source-file projection."),
                    _b("/source_files", "artifact-measurement", "measurement", "Measured byte digests of exact adapter source files."),
                ),
                coverage_selectors=("/certification", "/identity/source_digest", "/source_files"),
                schema_reference="schemas/json/adapter-release-manifest.schema.json",
            )
            for path, generator in (
                ("adapters/manifests/mysql-regex.v1.json", "adapters/python/regex_conformance_adapters/manifest.py"),
                ("adapters/manifests/pcre2-ordinary.v1.json", "adapters/python/regex_conformance_adapters/manifest.py"),
                ("adapters/manifests/python-re.v1.json", "adapters/python/regex_conformance_adapters/manifest.py"),
                ("adapters/qualification-manifests/pcre2-dfa.v1.json", "adapters/python/regex_conformance_adapters/qualification_manifest.py"),
            )
        ),
        ArtifactSpec(
            "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json",
            "semantic-snapshot",
            "historical-immutable",
            semantic_generator,
            (
                _b("/authority", "manual-registry-decision", "governance", "Literal authority boundary selected by repository governance."),
                _b("/status", "manual-registry-decision", "governance", "Literal frozen-snapshot status selected at publication."),
                _b("/methodology", "manual-registry-decision", "governance", "Human-selected research and cutoff methodology."),
                _b("/sources", "external-restatement", "scientific", "Source identities and authority descriptions recorded by the semantic research artifact."),
                _b("/features", "semantic-research", "scientific", "Researched feature semantics and lifecycle dispositions."),
                _b("/candidates", "semantic-research", "disposition", "Reviewed candidate dispositions bound to source identities."),
                _b("/counts", "semantic-counts", "coverage", "Counts calculated from exact snapshot collections and filtered values."),
                _b("/candidate_disposition_counts", "semantic-counts", "disposition", "Deterministic aggregation of candidate dispositions."),
                _b("/discovery_scans", "legacy-construction-claims", "discovery", "Uniform result string inserted by the compiler for every source scan.", ambiguity="overstated-evidence-strength"),
                _b("/facility_family_reconciliations", "external-restatement", "reconciliation", "Facility identity and planning values copied from the governed universe index."),
                _b("/facility_family_reconciliations/*/result", "legacy-construction-claims", "reconciliation", "Uniform reconciliation result string inserted for every facility.", ambiguity="overstated-evidence-strength"),
                _b("/adversarial_audit", "legacy-construction-claims", "audit", "Literal audit structure emitted by the semantic compiler.", ambiguity="overstated-evidence-strength"),
                _b("/adversarial_audit/category_sparsity", "sparsity-inference", "audit", "Threshold inference from calculated per-category feature counts.", ambiguity="overstated-evidence-strength"),
                _b("/adversarial_audit/category_sparsity/*/canonical_features", "semantic-counts", "audit", "Calculated count of features in the declared category."),
                _b("/adversarial_audit/category_sparsity/*/audit_state", "legacy-construction-claims", "audit", "Literal reviewed state inserted for every generated category row.", ambiguity="overstated-evidence-strength"),
                _b("/adversarial_audit/major_category_omission_count", "legacy-construction-claims", "completeness", "Literal zero inserted by the semantic compiler.", ambiguity="overstated-evidence-strength"),
                _b("/adversarial_audit/unresolved_candidate_count", "semantic-counts", "audit", "Calculated unresolved-candidate aggregation."),
            ),
            count_contracts=SEMANTIC_COUNTS,
            schema_reference="schemas/json/regex-semantic-corpus.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/research/regex-semantic-feature-research-2026-09-07.v1.json",
            "audit-or-reconciliation-report",
            "historical-immutable",
            ("tools/semantics/compile_researched_semantics.py",),
            (
                _b("/", "researched-feature-semantics", "scientific", "Feature-by-feature primary-source research decisions, explicit semantic states, and identity dispositions."),
                _b("/predecessor", "artifact-measurement", "measurement", "Measured identity and byte digest of the immutable predecessor snapshot."),
                _b("/research_standard", "manual-registry-decision", "governance", "Governed source hierarchy, uncertainty, variant-isolation, and manifestation-isolation policy."),
                _b("/baseline_template_debt", "reconciliation-calculation", "audit", "Deterministic measurement of repeated legacy field values and assertion populations."),
                _b("/counts", "reconciliation-calculation", "coverage", "Counts calculated from the exact research, rule, field, source, and unresolved-question populations."),
            ),
            coverage_selectors=("/",),
            count_contracts=(
                _c("/counts/features_researched", "collection-length", ["/feature_research"], "feature research records", "Exact feature-research collection length."),
                _c("/counts/fields_reviewed", "sum-collection-lengths", ["/feature_research/*/fields_reviewed"], "reviewed feature-field decisions", "Sum of the explicit field lists on all feature research records."),
                _c("/counts/legacy_dimensions_audited", "sum-collection-lengths", ["/feature_research/*/legacy_field_audit"], "predecessor semantic dimensions audited", "Sum of the explicit predecessor audit rows on all feature research records."),
                _c("/counts/semantic_rules", "collection-length", ["/semantic_rules"], "shared researched semantic rules", "Exact rule collection length."),
                _c("/counts/blocking_unresolved_questions", "matching-value-count", ["/feature_research/*/unresolved_questions/*/blocking"], "blocking unresolved semantic questions", "Count explicit blocking flags only.", values=[True]),
            ),
            schema_reference="schemas/json/regex-semantic-feature-research-ledger.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json",
            "semantic-snapshot",
            "historical-immutable",
            ("tools/semantics/compile_researched_semantics.py",),
            (
                _b("/", "researched-feature-semantics", "scientific", "Source-bound successor semantics over the unchanged accepted feature identities."),
                _b("/authority", "manual-registry-decision", "governance", "Repository authority, identity ownership, isolation rules, and obligation boundary."),
                _b("/predecessor", "artifact-measurement", "measurement", "Measured identity and byte digest of the immutable predecessor snapshot."),
                _b("/research_ledger", "artifact-measurement", "measurement", "Content identity and digest of the exact research ledger."),
                _b("/sources", "external-restatement", "scientific", "Qualified external source records carried forward without changing publisher authority."),
                _b("/counts", "reconciliation-calculation", "coverage", "Counts calculated from exact successor collections and dispositions."),
            ),
            coverage_selectors=("/",),
            count_contracts=(
                _c("/counts/canonical_features", "collection-length", ["/features"], "canonical successor features", "Exact feature collection length."),
                _c("/counts/semantic_variants", "sum-collection-lengths", ["/features/*/semantic_variants"], "source-bound semantic variants", "Sum every feature's variant collection."),
                _c("/counts/syntax_manifestations", "collection-length", ["/manifestations"], "source-bound syntax and API manifestations", "Exact manifestation collection length."),
                _c("/counts/source_identities", "collection-length", ["/sources"], "source registry records", "Exact source collection length."),
                _c("/counts/semantic_assertions", "sum-collection-lengths", ["/features/*/semantic_assertions"], "structured feature semantic assertions", "Sum every feature's semantic assertion map."),
                _c("/counts/retained_feature_identities", "matching-value-count", ["/features/*/identity_disposition/kind"], "features retaining their scientific identity", "Count explicit retained dispositions.", values=["retained"]),
                _c("/counts/successor_feature_identities", "matching-value-count", ["/features/*/identity_disposition/kind"], "features requiring successor scientific identities", "Count explicit successor dispositions.", values=["successor"]),
            ),
            schema_reference="schemas/json/regex-semantic-corpus-v2.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/researched-feature-semantics-2026-09-07.v1.json",
            "audit-or-reconciliation-report",
            "historical-immutable",
            ("tools/semantics/compile_researched_semantics.py",),
            (
                _b("/", "reconciliation-calculation", "audit", "Deterministic research-completeness and compatibility report over the ledger and successor snapshot."),
                _b("/evidence/derivation_id", "researched-feature-semantics", "scientific", "Exact research method binding for the successor semantic assertions."),
                _b("/derivation_id", "researched-feature-semantics", "scientific", "Exact research method binding for the report's semantic conclusions."),
                _b("/legacy_artifact_compatibility/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests of the immutable pre-redesign snapshot, projection, requirement ledger, and denominator."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/regex-semantic-research-completeness.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/research/semantic-architecture-identities-2026-09-07.v1.json",
            "identity-lock",
            "current-generated",
            ("tools/semantics/compile_semantic_architecture.py",),
            (
                _b("/", "manual-registry-decision", "governance", "One-time typed assigned identity allocation for accepted entities and reviewed candidates."),
            ),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/regex-semantic-architecture-identity-allocation.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/research/regex-semantic-architecture-candidates-2026-09-07.v1.json",
            "governed-registry",
            "current-generated",
            ("tools/semantics/compile_semantic_architecture.py",),
            (
                _b("/", "semantic-architecture-disposition", "scientific", "Primary-source candidate evidence, distinctness analysis, disposition and downstream consequence."),
                _b("/counts", "reconciliation-calculation", "reconciliation", "Counts calculated from the exact candidate population."),
                _b("/predecessor_snapshot", "artifact-measurement", "measurement", "Measured predecessor snapshot identity and digest."),
            ),
            coverage_selectors=("/candidates", "/counts", "/predecessor_snapshot"),
            count_contracts=(
                _c("/counts/total", "collection-length", ["/candidates"], "semantic architecture candidates", "Exact candidate collection length."),
                _c("/counts/blocking_unresolved", "matching-value-count", ["/candidates/*/blocking"], "blocking candidate dispositions", "Count explicit blocking flags.", values=[True]),
            ),
            schema_reference="schemas/json/regex-semantic-candidate-disposition-ledger.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v3.json",
            "semantic-snapshot",
            "current-generated",
            ("tools/semantics/compile_semantic_architecture.py",),
            (
                _b("/", "semantic-architecture-disposition", "scientific", "Researched successor semantics and source-bound accepted architecture additions."),
                _b("/authority", "manual-registry-decision", "governance", "Repository authority and explicit denominator boundary."),
                _b("/predecessor", "artifact-measurement", "measurement", "Measured predecessor snapshot identity and digest."),
                _b("/candidate_ledger", "artifact-measurement", "measurement", "Exact candidate-ledger identity and digest."),
                _b("/counts", "reconciliation-calculation", "reconciliation", "Counts calculated from exact successor collections."),
            ),
            coverage_selectors=("/",),
            count_contracts=(
                _c("/counts/canonical_features", "collection-length", ["/features"], "canonical semantic features", "Exact feature collection length."),
                _c("/counts/semantic_variants", "sum-collection-lengths", ["/features/*/semantic_variants"], "semantic variants", "Sum every feature's variant collection."),
                _c("/counts/syntax_manifestations", "collection-length", ["/manifestations"], "syntax and API manifestations", "Exact manifestation collection length."),
                _c("/counts/modifiers", "collection-length", ["/modifiers"], "modifier records", "Exact modifier collection length."),
                _c("/counts/operations", "collection-length", ["/operations"], "canonical host operations", "Exact operation collection length."),
                _c("/counts/semantic_facets", "collection-length", ["/semantic_facets"], "semantic dimensions", "Exact facet collection length."),
                _c("/counts/source_identities", "collection-length", ["/sources"], "source authority records", "Exact source collection length."),
            ),
            schema_reference="schemas/json/regex-semantic-corpus-v3.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/semantic-architecture-disposition-2026-09-07.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/semantics/compile_semantic_architecture.py",),
            (
                _b("/", "reconciliation-calculation", "audit", "Deterministic reconciliation of the candidate ledger, successor semantic snapshot and denominator boundary."),
                _b("/derivation_id", "semantic-architecture-disposition", "scientific", "Exact research method underlying the semantic architecture conclusions."),
                _b("/source_coverage", "semantic-architecture-disposition", "scientific", "Proposition-scoped primary-source coverage finding."),
                _b("/denominator_boundary/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests for immutable predecessor denominator artifacts."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/regex-semantic-architecture-disposition-report.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/research/semantic-universe-freeze-identities-2026-09-08.v1.json",
            "identity-lock",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (_b("/allocations", "manual-registry-decision", "governance", "One-time typed identity allocation for the declared-cutoff audit and accepted additions."),),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/regex-semantic-universe-freeze-allocation.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/research/regex-semantic-universe-adversarial-plan-2026-09-08.v1.json",
            "audit-plan",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (
                _b("/", "semantic-universe-freeze", "scientific", "Source-, ontology-, operation-, test-corpus-, and terminology-first audit method with an exact cutoff and bounded claim."),
                _b("/audit_populations", "reconciliation-calculation", "reconciliation", "Exact declared populations audited by the plan."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/regex-semantic-universe-audit-plan.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/research/regex-semantic-universe-candidates-2026-09-08.v1.json",
            "governed-registry",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (
                _b("/candidates", "semantic-universe-freeze", "scientific", "Every predecessor and newly encountered semantic candidate with renewed evidence and one terminal disposition."),
                _b("/counts", "reconciliation-calculation", "reconciliation", "Counts calculated from the exact final candidate population."),
            ),
            coverage_selectors=("/candidates", "/counts"),
            count_contracts=(
                _c("/counts/total", "collection-length", ["/candidates"], "all audited semantic candidates", "Exact final candidate collection length."),
                _c("/counts/blocking_unresolved", "matching-value-count", ["/candidates/*/blocking"], "blocking candidate dispositions", "Count explicit blocking flags.", values=[True]),
            ),
            schema_reference="schemas/json/regex-semantic-universe-candidate-ledger.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json",
            "semantic-snapshot",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (
                _b("/", "semantic-universe-freeze", "scientific", "Declared-cutoff researched semantic universe and its accepted residual additions."),
                _b("/counts", "reconciliation-calculation", "reconciliation", "Counts calculated from exact frozen collections."),
                _b("/authority", "manual-registry-decision", "governance", "Bounded freeze claim and explicit denominator non-supersession rule."),
            ),
            coverage_selectors=("/",),
            count_contracts=(
                _c("/counts/canonical_features", "collection-length", ["/features"], "canonical frozen features", "Exact feature collection length."),
                _c("/counts/syntax_manifestations", "collection-length", ["/manifestations"], "frozen manifestations", "Exact manifestation collection length."),
                _c("/counts/modifiers", "collection-length", ["/modifiers"], "frozen modifiers", "Exact modifier collection length."),
                _c("/counts/operations", "collection-length", ["/operations"], "frozen operations", "Exact operation collection length."),
                _c("/counts/semantic_facets", "collection-length", ["/semantic_facets"], "frozen facets", "Exact facet collection length."),
                _c("/counts/source_identities", "collection-length", ["/sources"], "frozen source identities", "Exact source collection length."),
            ),
            schema_reference="schemas/json/regex-semantic-corpus-v4.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/regex-semantic-source-coverage-2026-09-08.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (
                _b("/features", "semantic-universe-freeze", "scientific", "Per-feature primary-authority and corroboration audit."),
                _b("/summary", "reconciliation-calculation", "reconciliation", "Counts calculated from feature-level authority coverage."),
            ),
            coverage_selectors=("/features", "/summary"),
            count_contracts=(
                _c("/summary/feature_count", "collection-length", ["/features"], "source-audited features", "Exact feature coverage row count."),
                _c("/summary/source_orphan_count", "matching-value-count", ["/features/*/source_orphan"], "source-orphaned features", "Count true source-orphan flags.", values=[True]),
            ),
            schema_reference="schemas/json/regex-semantic-source-coverage.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/regex-semantic-universe-adversarial-audit-2026-09-08.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (
                _b("/", "semantic-universe-freeze", "scientific", "Bounded adversarial completeness conclusion over exact audit inputs."),
                _b("/audit_units", "reconciliation-calculation", "reconciliation", "Counts calculated from declared structured review populations."),
                _b("/denominator_boundary/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests of predecessor denominator artifacts."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/regex-semantic-universe-audit-report.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/freeze/regex-semantic-universe-2026-09-08.v1.json",
            "artifact-set-manifest",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (
                _b("/", "reconciliation-calculation", "reconciliation", "Deterministic closure and exact artifact binding for the declared-cutoff freeze."),
                _b("/claim", "semantic-universe-freeze", "scientific", "Exact declared-cutoff completeness claim."),
                _b("/bound_artifacts", "artifact-measurement", "measurement", "Content identities and digests of the exact freeze inputs and reports."),
                _b("/closure", "reconciliation-calculation", "reconciliation", "Closure calculated from blockers, source orphans, and freeze invariants."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/regex-semantic-universe-freeze-manifest.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/authority/current.v1.json",
            "authority-index",
            "current-generated",
            ("tools/semantics/freeze_semantic_universe.py",),
            (
                _b("/current_snapshot", "manual-registry-decision", "governance", "Current semantic authority pointer selected by the governed publication workflow."),
                _b("/freeze_manifest", "artifact-measurement", "measurement", "Exact freeze-manifest identity and digest."),
                _b("/denominator_authority", "manual-registry-decision", "governance", "Explicitly retains the predecessor denominator until dedicated rederivation."),
            ),
            coverage_selectors=("/current_snapshot", "/freeze_manifest", "/denominator_authority"),
            schema_reference="schemas/json/regex-semantic-authority-index.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/research/semantic-knowledge-foundation-identities-2026-09-08.v1.json",
            "identity-lock",
            "current-generated",
            ("tools/semantics/certify_semantic_knowledge.py",),
            (
                _b("/allocations", "manual-registry-decision", "governance", "One-time typed schema-family allocation for the semantic foundation manifest and acceptance report."),
            ),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/semantic-knowledge-foundation-allocation.schema.json",
        ),
        ArtifactSpec(
            "semantic-corpus/foundation/semantic-knowledge-architecture.v1.json",
            "artifact-set-manifest",
            "current-generated",
            ("tools/semantics/certify_semantic_knowledge.py",),
            (
                _b("/", "reconciliation-calculation", "audit", "Deterministic integration closure over the exact frozen semantic and scientific-foundation inputs."),
                _b("/semantic_authority", "artifact-measurement", "measurement", "Exact content identities and byte digests of the frozen snapshot, freeze manifest, authority index, and predecessor."),
                _b("/research_evidence", "semantic-universe-freeze", "scientific", "The bounded researched and adversarial evidence set accepted by the semantic gate."),
                _b("/authority_matrix", "manual-registry-decision", "governance", "Non-overlapping semantic decision ownership selected by repository governance."),
                _b("/denominator_input_contract", "manual-registry-decision", "governance", "The inspection boundary delivered to later obligation derivation; it does not emit obligations."),
                _b("/denominator_baseline/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests of the unchanged predecessor denominator artifacts."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/semantic-knowledge-foundation-manifest.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/semantic-knowledge-architecture-acceptance-2026-09-08.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/semantics/certify_semantic_knowledge.py",),
            (
                _b("/", "reconciliation-calculation", "audit", "Deterministic semantic-architecture acceptance conjunction over exact bound inputs and adversarial checks."),
                _b("/candidate_source_closure", "semantic-universe-freeze", "scientific", "Declared-cutoff candidate and primary-source closure inherited without evidence-strength escalation."),
                _b("/denominator_baseline/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests proving predecessor denominator immutability."),
                _b("/current_scientific_certification", "certification-predicate-calculation", "certification", "Current C1-C7 state remains independently evaluated and non-passing."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/semantic-knowledge-foundation-acceptance.schema.json",
        ),
        ArtifactSpec(
            "ontology/derivations/obligation-derivation-identities-2026-09-08.v1.json",
            "identity-lock",
            "current-generated",
            ("tools/semantics/define_obligation_derivation.py",),
            (
                _b("/allocations", "manual-registry-decision", "governance", "One-time typed allocation for the obligation-derivation method and artifact schema families."),
            ),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/obligation-derivation-allocation.schema.json",
        ),
        ArtifactSpec(
            "ontology/derivations/regex-obligation-derivation-rules-2026-09-08.v1.json",
            "governed-registry",
            "current-generated",
            ("tools/semantics/define_obligation_derivation.py",),
            (
                _b("/", "manual-registry-decision", "governance", "Accepted obligation question, state, facet, operation, interaction, and identity rules."),
                _b("/semantic_authority", "artifact-measurement", "measurement", "Exact frozen semantic authority identity, digest, and populations."),
                _b("/semantic_foundation", "artifact-measurement", "measurement", "Measured byte binding to the accepted semantic knowledge foundation."),
                _b("/denominator_boundary/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests proving predecessor denominator immutability."),
                _b("/contract_digest_sha256", "obligation-derivation", "validation", "Canonical digest of the rule contract content."),
                _b("/contract_id", "obligation-derivation", "validation", "Content-derived rule-contract identity."),
                _b("/facet_rules/*/rule_revision_id", "obligation-derivation", "validation", "Content-derived identity of each facet-rule revision."),
                _b("/operation_rules/*/rule_revision_id", "obligation-derivation", "validation", "Content-derived identity of each operation-rule revision."),
            ),
            coverage_selectors=("/",),
            schema_reference="schemas/json/obligation-derivation-contract.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/legacy-obligation-derivation-analysis-2026-09-08.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/semantics/define_obligation_derivation.py",),
            (
                _b("/", "obligation-derivation", "audit", "Deterministic per-obligation reconstruction of the predecessor fixed-grid rationale against frozen feature semantics."),
                _b("/source_projection/file_sha256", "artifact-measurement", "measurement", "Measured byte digest of the immutable predecessor projection."),
                _b("/denominator_boundary/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests proving predecessor denominator immutability."),
                _b("/classification", "classification-guard", "structural", "Protective historical-analysis and non-authority declarations."),
            ),
            coverage_selectors=("/",),
            count_contracts=(
                _c("/summary/obligations_audited", "collection-length", ["/obligation_cases"], "legacy obligation cases", "Every predecessor obligation receives one analysis row."),
                _c("/summary/underrepresented_current_feature_facet_pairs", "collection-length", ["/underrepresented_current_semantics"], "current feature/facet pairs absent from the predecessor grid", "Exact underrepresented collection length."),
            ),
            schema_reference="schemas/json/legacy-obligation-derivation-report.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/obligation-derivation-dry-run-2026-09-08.v1.json",
            "forecast",
            "current-generated",
            ("tools/semantics/define_obligation_derivation.py",),
            (
                _b("/", "obligation-derivation", "forecast", "Deterministic non-authoritative evaluation of every frozen feature/facet pair."),
                _b("/semantic_authority", "artifact-measurement", "measurement", "Exact frozen semantic authority identity, digest, and feature population."),
                _b("/denominator_boundary/artifact_sha256", "artifact-measurement", "measurement", "Measured byte digests proving predecessor denominator immutability."),
                _b("/classification", "classification-guard", "structural", "Protective dry-run, non-authority, and non-execution declarations."),
            ),
            coverage_selectors=("/",),
            count_contracts=(
                _c("/summary/feature_count", "collection-length", ["/feature_results"], "frozen semantic features", "Every feature receives one summary row."),
                _c("/summary/facet_decisions", "collection-length", ["/decisions"], "feature/facet decisions", "Every feature/facet pair receives exactly one decision."),
            ),
            schema_reference="schemas/json/obligation-derivation-dry-run.schema.json",
        ),
        ArtifactSpec(
            "tests/fixtures/semantics/obligation-derivation-cases.v1.json",
            "governed-registry",
            "governed-registry",
            ("governed-manual-entry",),
            (
                _b("/cases", "manual-registry-decision", "validation", "Hand-enumerated expected derivation decisions for representative real and adversarial semantic states."),
            ),
            coverage_selectors=("/cases",),
            schema_reference="schemas/json/obligation-derivation-fixtures.schema.json",
        ),
        ArtifactSpec(
            "ontology/projections/regex-semantic-projection-2026-08-22.v1.json",
            "semantic-projection",
            "historical-immutable",
            semantic_generator,
            (
                _b("/counts", "semantic-counts", "coverage", "Counts calculated from exact generated projection collections."),
                _b("/facet_taxonomy", "facet-template-construction", "structural", "Declared facet/case template copied into the projection."),
                _b("/semantic_obligation_templates", "facet-template-construction", "scientific", "Uniform obligation expansion constructed from the declared facet/case table.", ambiguity="overstated-evidence-strength"),
                _b("/projection_rule", "manual-registry-decision", "governance", "Human-selected projection rule."),
            ),
            coverage_selectors=("/counts", "/facet_taxonomy", "/semantic_obligation_templates", "/projection_rule"),
            count_contracts=PROJECTION_COUNTS,
            schema_reference="schemas/json/regex-semantic-projection.schema.json",
        ),
        ArtifactSpec(
            "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json",
            "vector-requirement-ledger",
            "historical-immutable",
            semantic_generator,
            (
                _b("/counts", "vector-coverage-calculation", "coverage", "Counts calculated from the generated requirements collection."),
                _b("/requirements", "vector-coverage-calculation", "coverage", "Requirements and missing/reuse status generated from executable obligation templates and exact vector references."),
                _b("/reuse_audit", "vector-coverage-calculation", "audit", "Deterministic scan of tracked vector definitions for exact semantic references."),
                _b("/minimum_rule", "manual-registry-decision", "governance", "Human-selected minimum vector-attribution rule."),
            ),
            coverage_selectors=("/counts", "/requirements", "/reuse_audit", "/minimum_rule"),
            count_contracts=VECTOR_COUNTS,
            schema_reference="schemas/json/regex-semantic-vector-requirements.schema.json",
        ),
        ArtifactSpec(
            "reports/scale/regex-semantic-denominator-forecast.json",
            "forecast",
            "current-generated",
            semantic_generator,
            (
                _b("/", "forecast-calculation", "forecast", "Deterministic denominator and retained-byte forecast arithmetic."),
                _b("/classification", "classification-guard", "structural", "Protective design-only classification constants."),
                _b("/source_bindings", "external-restatement", "scientific", "Exact source artifact identities and digests."),
                _b("/profile_bounds_and_allocations", "planning-assumption", "forecast", "Planning profile bounds and archetype allocations retained from governed planning inputs."),
                _b("/obligation_denominator_bounds", "planning-assumption", "forecast", "Planning obligation bounds retained unchanged pending scientific derivation."),
                _b("/compact_evidence_pack_v3/measurement", "artifact-measurement", "measurement", "Measured retained-byte inputs copied from the capacity certification."),
                _b("/compact_evidence_pack_v3/restored_baseline/measurement", "artifact-measurement", "measurement", "Measured restored-contract inputs copied from the capacity certification."),
                _b("/compact_evidence_pack_v3/soft_stop_bytes", "storage-policy", "governance", "Governed soft stop copied from the storage contract."),
                _b("/compact_evidence_pack_v3/hard_cap_bytes", "storage-policy", "governance", "Governed hard ceiling copied from the storage contract."),
                _b("/public_product_readiness", "sparsity-inference", "completeness", "Planning inference about downstream readiness; not empirical or certification evidence.", ambiguity="overstated-evidence-strength"),
            ),
            coverage_selectors=("/profile_bounds_and_allocations", "/obligation_denominator_bounds", "/compact_evidence_pack_v3", "/public_product_readiness"),
            schema_reference="schemas/json/regex-semantic-denominator.schema.json",
        ),
        ArtifactSpec(
            "registries/universe/full-known-universe-2026-08-15.v1.json",
            "governed-registry",
            "governed-registry",
            ("governed-manual-entry",),
            (
                _b("/", "manual-registry-decision", "governance", "Governed registry entries and planning dispositions."),
                _b("/classification", "classification-guard", "structural", "Protective non-authority and non-execution declarations."),
                _b("/discovery_coverage", "semantic-research", "discovery", "Documented discovery method, source classes, and limitations."),
                _b("/other_candidates", "semantic-research", "disposition", "Reviewed non-facility candidate dispositions."),
                _b("/facilities", "planning-assumption", "forecast", "Planning facilities, profile counts, historical bounds, and representatives."),
                _b("/obligation_archetypes", "planning-assumption", "forecast", "Planning obligation-archetype lower, expected, and upper bounds."),
                _b("/forecast_policy/soft_limit_bytes", "storage-policy", "governance", "Governed retained-storage soft stop."),
                _b("/forecast_policy/hard_limit_bytes", "storage-policy", "governance", "Governed retained-storage hard ceiling."),
                _b("/forecast_policy", "planning-assumption", "forecast", "Planning multipliers, rates, allowances, reserve, and packing parameters."),
            ),
            coverage_selectors=("/discovery_coverage", "/facilities", "/obligation_archetypes", "/forecast_policy"),
            schema_reference="schemas/json/full-known-universe-index.schema.json",
        ),
        ArtifactSpec(
            "registries/profiles/vertical-slice-archetypes.v1.json",
            "governed-registry",
            "governed-registry",
            ("governed-manual-entry",),
            (
                _b("/", "manual-registry-decision", "governance", "Governed selection and candidate dispositions."),
                _b("/classification", "classification-guard", "structural", "Protective non-authority declarations."),
                _b("/seed_accounting", "semantic-counts", "reconciliation", "Counts calculated from selected and deferred seed records."),
                _b("/coverage_claims", "sparsity-inference", "coverage", "Reasoned architecture-diversity claims from the governed selection, not empirical behavior evidence."),
            ),
            coverage_selectors=("/coverage_claims", "/selection_policy"),
            count_contracts=(
                _c("/seed_accounting/candidate_count", "sum-integer-values", ["/seed_accounting/selected_count", "/seed_accounting/deferred_count"], "selected and deferred design-seed candidates", "The candidate count is the sum of the disjoint selected and deferred counts."),
                _c("/seed_accounting/selected_count", "collection-length", ["/selected_archetypes"], "selected archetype records", "Exact selected collection length."),
                _c("/seed_accounting/deferred_count", "collection-length", ["/deferred_candidates"], "deferred candidate records", "Exact deferred collection length."),
            ),
            schema_reference="schemas/json/vertical-slice-selection.schema.json",
        ),
        ArtifactSpec(
            "registries/profiles/vertical-slice-coordinates.v1.json",
            "governed-registry",
            "governed-registry",
            ("governed-manual-entry",),
            (
                _b("/", "manual-registry-decision", "governance", "Governed exact profile and environment coordinate selection."),
                _b("/releases/*/evidence", "external-restatement", "scientific", "Exact upstream release evidence references."),
            ),
            schema_reference="schemas/json/vertical-slice-coordinates.schema.json",
        ),
        ArtifactSpec(
            "registries/profiles/small-scale-qualification.v1.json",
            "governed-registry",
            "governed-registry",
            ("governed-manual-entry",),
            (
                _b("/", "manual-registry-decision", "governance", "Governed qualification profile and environment bindings."),
                _b("/classification", "classification-guard", "structural", "Protective non-authority declarations."),
            ),
            schema_reference="schemas/json/qualification-profile-overlay.schema.json",
        ),
        ArtifactSpec(
            "ontology/derivations/semantic-denominator-identities-2026-09-08.v1.json",
            "identity-lock",
            "governed-registry",
            ("tools/semantics/generate_obligation_snapshots.py",),
            (_b("/", "manual-registry-decision", "governance", "Reviewed one-time typed identity allocations; stable labels are not identity inputs."),),
            coverage_selectors=("/fixed_allocations", "/entity_allocations"),
            schema_reference="schemas/json/semantic-denominator-identity-allocation.schema.json",
        ),
        ArtifactSpec(
            "ontology/obligations/regex-semantic-obligations-2026-09-08.v1.json",
            "semantic-snapshot",
            "current-generated",
            ("tools/semantics/generate_obligation_snapshots.py",),
            (_b("/", "denominator-materialization", "scientific", "Feature-specific rule evaluation, cardinality contract, stable allocation, and predecessor reconciliation."),),
            coverage_selectors=("/counts", "/obligations"),
            count_contracts=(
                _c("/counts/total", "collection-length", ["/obligations"], "current semantic obligations", "Exact canonical obligation collection length."),
                _c("/counts/required", "matching-value-count", ["/obligations/*/requirement_state"], "unconditional semantic obligations", "Count obligations whose derivation state is required.", values=["required"]),
                _c("/counts/conditional", "matching-value-count", ["/obligations/*/requirement_state"], "conditional semantic obligations", "Count obligations retaining a capability predicate.", values=["conditionally-required"]),
                _c("/counts/characterization", "matching-value-count", ["/obligations/*/evidence_mode"], "characterization semantic obligations", "Count obligations whose scientific question is non-normative characterization.", values=["characterization-only"]),
            ),
            schema_reference="schemas/json/semantic-obligation-snapshot.schema.json",
        ),
        ArtifactSpec(
            "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json",
            "vector-requirement-ledger",
            "current-generated",
            ("tools/semantics/generate_obligation_snapshots.py",),
            (_b("/", "denominator-materialization", "scientific", "Minimum attributable evidence requirements calculated from obligation archetype roles without creating concrete vectors."),),
            coverage_selectors=("/counts", "/requirements"),
            count_contracts=(
                _c("/counts/total", "collection-length", ["/requirements"], "current semantic requirements", "Exact canonical requirement collection length."),
                _c("/counts/required", "matching-value-count", ["/requirements/*/requirement_state"], "unconditional semantic requirements", "Count requirements whose obligation is required.", values=["required"]),
                _c("/counts/conditional", "matching-value-count", ["/requirements/*/requirement_state"], "conditional semantic requirements", "Count requirements retaining a capability predicate.", values=["conditionally-required"]),
                _c("/counts/characterization", "matching-value-count", ["/requirements/*/requirement_type"], "characterization-only semantic requirements", "Count explicitly non-normative requirements.", values=["characterization-only"]),
                _c("/counts/missing_vector_definitions", "matching-value-count", ["/requirements/*/status"], "requirements without authored vectors", "Count requirements whose vector status remains missing.", values=["missing"]),
            ),
            schema_reference="schemas/json/semantic-requirement-snapshot.schema.json",
        ),
        ArtifactSpec(
            "ontology/migrations/regex-semantic-denominator-2026-09-08.v1.json",
            "audit-or-reconciliation-report",
            "historical-immutable",
            ("tools/semantics/generate_obligation_snapshots.py",),
            (_b("/", "denominator-materialization", "reconciliation", "Total predecessor-to-successor reconciliation calculated from feature, facet, archetype, operation, and evidence-role correspondences."),),
            coverage_selectors=("/counts", "/obligation_migrations", "/requirement_migrations", "/new_obligation_origins", "/new_requirement_origins"),
            count_contracts=(
                _c("/counts/obligation_migrations", "collection-length", ["/obligation_migrations"], "historical obligation migrations", "Every predecessor obligation receives exactly one migration row."),
                _c("/counts/requirement_migrations", "collection-length", ["/requirement_migrations"], "historical requirement migrations", "Every predecessor requirement receives exactly one migration row."),
                _c("/counts/new_obligation_objects", "collection-length", ["/new_obligation_origins"], "current obligation origins", "Every current obligation records its predecessor origin set."),
                _c("/counts/new_requirement_objects", "collection-length", ["/new_requirement_origins"], "current requirement origins", "Every current requirement records its predecessor origin set."),
            ),
            schema_reference="schemas/json/semantic-denominator-migration.schema.json",
        ),
        ArtifactSpec(
            "ontology/projections/regex-semantic-projection-2026-09-08.v2.json",
            "semantic-projection",
            "current-generated",
            ("tools/semantics/generate_obligation_snapshots.py",),
            (_b("/", "denominator-materialization", "scientific", "Deterministic compact projection of current obligation and requirement authority for vector, applicability, and profile consumers."),),
            coverage_selectors=("/counts", "/features"),
            count_contracts=(
                _c("/counts/features", "collection-length", ["/features"], "projected features", "Exact feature projection length."),
            ),
            schema_reference="schemas/json/semantic-requirement-projection-v2.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/semantic-denominator-materialization-2026-09-08.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/semantics/generate_obligation_snapshots.py",),
            (_b("/", "denominator-materialization", "reconciliation", "Deterministic counts, distributions, migration deltas, anomaly dispositions, and dry-run comparison."),),
            coverage_selectors=("/summary", "/distribution", "/migration", "/dry_run_comparison", "/anomaly_checks", "/historical_immutability"),
            schema_reference="schemas/json/semantic-denominator-materialization-report.schema.json",
        ),
        ArtifactSpec(
            "ontology/authority/current-semantic-denominator.v1.json",
            "authority-index",
            "governed-registry",
            ("tools/semantics/generate_obligation_snapshots.py",),
            (
                _b("/", "denominator-materialization", "reconciliation", "Digest-bound current obligation, requirement, projection, migration, report, and certification input references."),
                _b("/governance", "manual-registry-decision", "governance", "Governed authority advancement after validation and explicit deferral of profile expansion."),
            ),
            coverage_selectors=("/current_authority", "/historical_predecessor", "/profile_expanded_denominator", "/governance"),
            schema_reference="schemas/json/semantic-denominator-authority-index.schema.json",
        ),
        ArtifactSpec(
            "ontology/denominator/regex-semantic-denominator-accounting-2026-09-10.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/semantics/audit_scientific_denominator.py",),
            (
                _b("/", "manual-registry-decision", "governance", "Accepted denominator vocabulary, orthogonal accounting axes, scenario meanings, and profile-deferral boundary."),
                _b("/contract_digest_sha256", "denominator-audit", "validation", "JCS/SHA-256 digest of the complete accounting contract body."),
                _b("/contract_id", "denominator-audit", "validation", "Content-derived typed identity of the exact accounting contract."),
            ),
            coverage_selectors=("/population_definitions", "/orthogonal_axes", "/scenario_rules", "/predicate_contract"),
            schema_reference="schemas/json/semantic-denominator-accounting-contract.schema.json",
        ),
        ArtifactSpec(
            "ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json",
            "semantic-projection",
            "current-generated",
            ("tools/semantics/audit_scientific_denominator.py",),
            (_b("/", "denominator-audit", "reconciliation", "Closed capability predicates and exact stable-ID requirement bindings for later empirical profile expansion."),),
            coverage_selectors=("/profile_fact_contract", "/predicate_definitions", "/requirement_predicate_bindings", "/evaluation_contract", "/counts", "/deferral"),
            count_contracts=(
                _c("/counts/semantic_requirements", "collection-length", ["/requirement_predicate_bindings"], "canonical semantic requirement predicate bindings", "Exact binding collection length."),
                _c("/counts/required_requirements", "matching-value-count", ["/requirement_predicate_bindings/*/semantic_applicability"], "unconditional requirement predicate bindings", "Count exact required bindings.", values=["required"]),
                _c("/counts/conditional_requirements", "matching-value-count", ["/requirement_predicate_bindings/*/semantic_applicability"], "conditional requirement predicate bindings", "Count exact conditional bindings.", values=["conditional"]),
                _c("/counts/distinct_predicates", "collection-length", ["/predicate_definitions"], "normalized distinct capability predicates", "Exact predicate definition collection length."),
            ),
            schema_reference="schemas/json/semantic-profile-expansion-handoff.schema.json",
        ),
        ArtifactSpec(
            "reports/semantics/regex-semantic-denominator-audit-2026-09-10.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/semantics/audit_scientific_denominator.py",),
            (_b("/", "denominator-audit", "audit", "Independent stable-ID accounting, predicate validation, cardinality reconstruction, migration closure, stratified reconstruction, and hidden-multiplier audit."),),
            coverage_selectors=("/independent_recomputation", "/current_certification", "/profile_expansion", "/anomaly_dispositions", "/result"),
            schema_reference="schemas/json/semantic-denominator-audit-report.schema.json",
        ),
        ArtifactSpec(
            "ontology/authority/current-semantic-denominator-audit.v1.json",
            "authority-index",
            "governed-registry",
            ("tools/semantics/audit_scientific_denominator.py",),
            (
                _b("/", "denominator-audit", "reconciliation", "Digest-bound current denominator audit, accounting contract, and future profile-expansion handoff."),
                _b("/governance", "manual-registry-decision", "governance", "Local authoritative certification and hosted integrity-verification requirements."),
            ),
            coverage_selectors=("/denominator_authority", "/accounting_contract", "/audit_report", "/profile_expansion_handoff", "/authority_scope", "/governance"),
            schema_reference="schemas/json/semantic-denominator-audit-authority.schema.json",
        ),
        ArtifactSpec(
            "oracle/oracle-foundation-identities-2026-09-10.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/oracle/compile_oracle_foundation.py",),
            (_b("/", "oracle-foundation-governance", "governance", "Reviewed one-time typed identity allocation for the oracle schema family and governance derivation."),),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/oracle-foundation-allocation.schema.json",
        ),
        ArtifactSpec(
            "oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/oracle/compile_oracle_foundation.py",),
            (_b("/", "oracle-foundation-governance", "governance", "Accepted epistemic functions, class-specific judgment boundaries, dependency contract, circularity guards, conflict semantics, and historical expectation-freeze policy."),),
            coverage_selectors=("/oracle_classes", "/resolution_states", "/circularity_guards", "/selection_and_conflict", "/promotion_contract", "/campaign_freeze_contract"),
            schema_reference="schemas/json/oracle-foundation-contract.schema.json",
        ),
        ArtifactSpec(
            "tests/fixtures/oracle/oracle-validation-cases.v1.json",
            "certification-fixture-set",
            "current-generated",
            ("tools/oracle/compile_oracle_foundation.py",),
            (_b("/", "oracle-foundation-governance", "validation", "Reviewed valid O1-O8 examples, prohibited circularity mutations, conflict interface, and immutable campaign-binding canary."),),
            coverage_selectors=("/valid_oracles", "/invalid_cases", "/frozen_vector_binding", "/authority_conflicts"),
            schema_reference="schemas/json/oracle-validation-fixtures.schema.json",
        ),
        ArtifactSpec(
            "reports/oracle/oracle-foundation-2026-09-10.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/oracle/compile_oracle_foundation.py",),
            (
                _b("/", "reconciliation-calculation", "validation", "Deterministic validation of exact oracle classes, guards, class fixtures, prohibited cases, and frozen denominator boundary."),
                _b("/claim_scope", "oracle-foundation-governance", "governance", "Governed boundary excluding applicability, adjudication, waivers, production vectors, and repository-wide certification."),
                _b("/denominator_boundary", "reconciliation-calculation", "reconciliation", "Exact read-only reconciliation with the authoritative 2,390-obligation and 3,378-requirement denominator."),
            ),
            coverage_selectors=("/claim_scope", "/implementation_bindings", "/counts", "/checks", "/denominator_boundary", "/result"),
            schema_reference="schemas/json/oracle-foundation-report.schema.json",
        ),
        ArtifactSpec(
            "oracle/current-authority.v1.json",
            "authority-index",
            "governed-registry",
            ("tools/oracle/compile_oracle_foundation.py",),
            (
                _b("/", "reconciliation-calculation", "reconciliation", "Exact digest-bound current oracle contract, fixture, report, and semantic-requirement references."),
                _b("/historical_compatibility", "oracle-foundation-governance", "governance", "Prospective versioning and no-rewrite history policy."),
                _b("/next_interfaces", "oracle-foundation-governance", "governance", "Explicit deferral of later applicability, adjudication, waiver, and production-vector work."),
                _b("/governance", "oracle-foundation-governance", "governance", "Non-overlapping source, observation, oracle, and future-adjudication authority boundary."),
            ),
            coverage_selectors=("/current_contract", "/validation_fixture", "/foundation_report", "/semantic_requirement_authority", "/historical_compatibility", "/next_interfaces", "/governance"),
            schema_reference="schemas/json/oracle-authority-index.schema.json",
        ),
        ArtifactSpec(
            "oracle/evidence/evidence-admissibility-identities-2026-09-10.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/oracle/compile_evidence_admissibility.py",),
            (_b("/", "evidence-admissibility-governance", "governance", "Reviewed one-time typed allocation for the evidence-admissibility schema family and governance derivation."),),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/evidence-admissibility-allocation.schema.json",
        ),
        ArtifactSpec(
            "oracle/contracts/regex-conformance-evidence-admissibility-2026-09-10.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/oracle/compile_evidence_admissibility.py",),
            (_b("/", "evidence-admissibility-governance", "governance", "Accepted evidence roles, epistemic uses, source-language strengths, immutable provenance requirements, authority-domain rules, and fail-closed prohibitions."),),
            coverage_selectors=("/evidence_roles", "/epistemic_uses", "/normative_strengths", "/quality_axes", "/admissibility_decision_contract", "/immutable_provenance_contract", "/authority_domain_contract", "/prohibitions"),
            schema_reference="schemas/json/evidence-admissibility-contract.schema.json",
        ),
        ArtifactSpec(
            "tests/fixtures/oracle/evidence-admissibility-cases.v1.json",
            "certification-fixture-set",
            "current-generated",
            ("tools/oracle/compile_evidence_admissibility.py",),
            (_b("/", "evidence-admissibility-governance", "validation", "Reviewed O1-O8 evidence-role examples, use-specific acceptance, immutable expectation binding, and prohibited authority escalation cases."),),
            coverage_selectors=("/valid_evidence", "/valid_cases", "/invalid_cases", "/same_material_boundary_cases", "/valid_expectation_basis"),
            schema_reference="schemas/json/evidence-admissibility-fixtures.schema.json",
        ),
        ArtifactSpec(
            "reports/oracle/evidence-admissibility-2026-09-10.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/oracle/compile_evidence_admissibility.py",),
            (
                _b("/", "reconciliation-calculation", "validation", "Deterministic validation of evidence roles, epistemic uses, source-language boundaries, authority-domain independence, adversarial fixtures, and frozen denominator compatibility."),
                _b("/claim_scope", "evidence-admissibility-governance", "governance", "Governed boundary excluding profile applicability, adjudication, waivers, public claims, production vectors, and full scientific certification."),
                _b("/denominator_boundary", "reconciliation-calculation", "reconciliation", "Exact read-only reconciliation with the authoritative 2,390-obligation and 3,378-requirement denominator."),
            ),
            coverage_selectors=("/claim_scope", "/implementation_bindings", "/counts", "/checks", "/denominator_boundary", "/result"),
            schema_reference="schemas/json/evidence-admissibility-report.schema.json",
        ),
        ArtifactSpec(
            "oracle/evidence/current-authority.v1.json",
            "authority-index",
            "governed-registry",
            ("tools/oracle/compile_evidence_admissibility.py",),
            (
                _b("/", "reconciliation-calculation", "reconciliation", "Exact digest-bound current evidence contract, fixed oracle foundation, fixtures, report, and semantic requirement authority."),
                _b("/historical_compatibility", "evidence-admissibility-governance", "governance", "Prospective versioning with no observation, campaign-expectation, or denominator rewrite."),
                _b("/next_interfaces", "evidence-admissibility-governance", "governance", "Explicit deferral of later applicability, adjudication, waiver, and production-vector systems."),
                _b("/governance", "evidence-admissibility-governance", "governance", "Non-overlapping Knowledge, evidence, oracle, observation, and later reconciliation authority boundary."),
            ),
            coverage_selectors=("/current_contract", "/oracle_foundation", "/validation_fixture", "/acceptance_report", "/semantic_requirement_authority", "/historical_compatibility", "/next_interfaces", "/governance"),
            schema_reference="schemas/json/evidence-admissibility-authority.schema.json",
        ),
        ArtifactSpec(
            "applicability/conditional-applicability-identities-2026-09-10.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/applicability/compile_conditional_applicability.py",),
            (_b("/", "conditional-applicability-governance", "governance", "Reviewed one-time typed allocation for the applicability schema family and governing derivation."),),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/conditional-applicability-allocation.schema.json",
        ),
        ArtifactSpec(
            "applicability/contracts/regex-conformance-conditional-applicability-2026-09-10.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/applicability/compile_conditional_applicability.py",),
            (_b("/", "conditional-applicability-governance", "governance", "Accepted total-state algebra, typed predicate language, open-world facts, trace semantics, exclusion boundary, and profile-expansion deferral."),),
            coverage_selectors=("/state_algebra", "/predicate_language", "/field_registry", "/world_semantics", "/capability_fact_contract", "/evaluation_contract", "/dependency_contract", "/exclusion_boundary"),
            schema_reference="schemas/json/conditional-applicability-contract.schema.json",
        ),
        ArtifactSpec(
            "tests/fixtures/applicability/conditional-requirement-applicability.v1.json",
            "certification-fixture-set",
            "current-generated",
            ("tools/applicability/compile_conditional_applicability.py",),
            (_b("/", "conditional-applicability-governance", "validation", "Synthetic valid and prohibited applicability cases covering open-world truth, explicit absence, conflict, type safety, cycles, self-reference, and skip exclusion."),),
            coverage_selectors=("/profile_fact_snapshots", "/valid_cases", "/invalid_cases", "/synthetic_denominator_example"),
            schema_reference="schemas/json/conditional-applicability-fixtures.schema.json",
        ),
        ArtifactSpec(
            "reports/applicability/conditional-requirement-applicability-2026-09-10.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/applicability/compile_conditional_applicability.py",),
            (_b("/", "reconciliation-calculation", "validation", "Deterministic audit of every requirement binding, predicate identity, stable-ID reference, structured fixture outcome, and denominator boundary."),),
            coverage_selectors=("/coverage", "/predicate_audit", "/fixture_results", "/checks", "/denominator_boundary", "/result"),
            schema_reference="schemas/json/conditional-applicability-report.schema.json",
        ),
        ArtifactSpec(
            "applicability/current-authority.v1.json",
            "authority-index",
            "governed-registry",
            ("tools/applicability/compile_conditional_applicability.py",),
            (
                _b("/", "reconciliation-calculation", "reconciliation", "Digest-bound current applicability contract, fixtures, report, requirement authority, and predecessor profile-expansion handoff."),
                _b("/governance", "conditional-applicability-governance", "governance", "Non-overlapping requirement-existence, applicability, oracle, observation, and exclusion authority boundary."),
            ),
            coverage_selectors=("/current_contract", "/validation_fixture", "/acceptance_report", "/requirement_authority", "/profile_expansion_handoff", "/historical_compatibility", "/next_interfaces", "/governance"),
            schema_reference="schemas/json/conditional-applicability-authority.schema.json",
        ),
        ArtifactSpec(
            "adjudication/adjudication-identities-2026-09-11.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/adjudication/compile_adjudication.py",),
            (_b("/", "observation-to-claim-adjudication", "governance", "Reviewed one-time typed allocation for the adjudication schema family and governance derivation."),),
            coverage_selectors=("/allocations",),
            schema_reference="schemas/json/adjudication-allocation.schema.json",
        ),
        ArtifactSpec(
            "adjudication/contracts/regex-conformance-adjudication-2026-09-11.v1.json",
            "governed-registry",
            "governed-registry",
            ("tools/adjudication/compile_adjudication.py",),
            (_b("/", "observation-to-claim-adjudication", "governance", "Accepted coordinate-state algebra, typed claim and discrepancy semantics, positive permitted divergence, gate-only waivers, operational quarantine, and circularity guards."),),
            coverage_selectors=("/authority_model", "/predecessor_contracts", "/coordinate_states", "/state_dimensions", "/claim_kinds", "/discrepancy_relations", "/discrepancy_classifications", "/permitted_divergence", "/waivers", "/quarantine", "/expected_outcomes", "/attempt_derivation", "/circularity_guards"),
            schema_reference="schemas/json/adjudication-contract.schema.json",
        ),
        ArtifactSpec(
            "tests/fixtures/adjudication/adjudication-cases.v1.json",
            "certification-fixture-set",
            "current-generated",
            ("tools/adjudication/compile_adjudication.py",),
            (_b("/", "observation-to-claim-adjudication", "validation", "Synthetic O1-O8, applicability, claim, discrepancy, divergence, waiver, quarantine, lineage, history, and adversarial adjudication cases with no production credit."),),
            coverage_selectors=("/classification", "/evidence_records", "/expected_outcomes", "/applicability_results", "/discrepancy_records", "/discrepancy_history", "/waiver_records", "/quarantine_records", "/execution_lineage_set", "/valid_cases", "/adversarial_cases"),
            schema_reference="schemas/json/adjudication-fixtures.schema.json",
        ),
        ArtifactSpec(
            "reports/adjudication/adjudication-acceptance-2026-09-11.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/adjudication/compile_adjudication.py",),
            (
                _b("/", "reconciliation-calculation", "validation", "Deterministic validation of all adjudication paths, histories, overlays, circularity guards, and immutable-input reconstruction."),
                _b("/claim_scope", "observation-to-claim-adjudication", "governance", "Synthetic acceptance only; no production coordinates, evidence, coverage, public projection, or final certification."),
                _b("/denominator_boundary", "reconciliation-calculation", "reconciliation", "Exact read-only reconciliation with 2,390 obligations and 3,378 requirements while profile expansion remains deferred."),
            ),
            coverage_selectors=("/claim_scope", "/implementation_bindings", "/coverage", "/checks", "/denominator_boundary", "/certification_state", "/result"),
            schema_reference="schemas/json/adjudication-report.schema.json",
        ),
        ArtifactSpec(
            "adjudication/current-authority.v1.json",
            "authority-index",
            "governed-registry",
            ("tools/adjudication/compile_adjudication.py",),
            (
                _b("/", "reconciliation-calculation", "reconciliation", "Digest-bound current adjudication contract, unchanged predecessors, synthetic fixtures, and acceptance report."),
                _b("/historical_compatibility", "observation-to-claim-adjudication", "governance", "Claims remain regenerable while immutable upstream records and discrepancy history remain preserved."),
                _b("/production_boundary", "observation-to-claim-adjudication", "governance", "No real coordinate, production evidence, coverage credit, publication, promotion, or successor activation."),
                _b("/governance", "observation-to-claim-adjudication", "governance", "Waivers are gate-only and quarantine is operational rather than epistemic."),
            ),
            coverage_selectors=("/current_contract", "/predecessors", "/validation_fixture", "/acceptance_report", "/historical_compatibility", "/production_boundary", "/governance"),
            schema_reference="schemas/json/adjudication-authority.schema.json",
        ),
        ArtifactSpec(
            "certification/reports/evidence-adjudication-architecture-closure-2026-09-11.v1.json",
            "audit-or-reconciliation-report",
            "current-generated",
            ("tools/certification/compile_evidence_adjudication_closure.py",),
            (
                _b("/reconstruction", "reconciliation-calculation", "reconciliation", "Exact original-to-linear commit mapping and byte-identical implementation-tree comparison."),
                _b("/authority_bindings", "reconciliation-calculation", "reconciliation", "Digest-bound oracle, evidence, applicability, adjudication, denominator, and certification authorities."),
                _b("/promotion", "artifact-measurement", "measurement", "Observed local certification, hosted verification, and promoted repository revision identifiers."),
                _b("/denominator", "reconciliation-calculation", "reconciliation", "Exact preservation of the accepted obligation and requirement denominator with no profile expansion or coverage credit."),
                _b("/certification", "certification-predicate-calculation", "validation", "Reconciled non-passing C1-C7 state, including C4 at zero of 3,378."),
                _b("/gate_checks", "reconciliation-calculation", "validation", "Mechanical closure of the complete requirement-to-claim and gate-effect questions."),
                _b("/boundary", "reconciliation-calculation", "validation", "Architecture closure creates no profile expansion, production evidence, empirical coverage, or successor implementation."),
                _b("/result", "reconciliation-calculation", "validation", "PASS means the architecture and reconstruction gate closes; it is not scientific conformance certification."),
            ),
            coverage_selectors=("/reconstruction", "/authority_bindings", "/promotion", "/denominator", "/certification", "/gate_checks", "/boundary", "/result"),
            schema_reference="schemas/json/evidence-adjudication-architecture-closure.schema.json",
        ),
        ArtifactSpec(
            "certification/contracts/regex-conformance-certification.v1.json",
            "certification-contract",
            "governed-registry",
            ("schemas/tooling/python/regex_conformance_schema/certification.py",),
            (
                _b("/", "manual-registry-decision", "governance", "Accepted completeness and certification rules encoded by the versioned contract builder."),
                _b("/contract_digest_sha256", "certification-predicate-calculation", "validation", "Canonical digest of the contract content excluding its content identity and digest fields."),
                _b("/contract_id", "certification-predicate-calculation", "validation", "Content-derived certification-definition identity calculated from the contract digest."),
            ),
            coverage_selectors=("/criteria", "/final_composition", "/result_states", "/supersession_and_revocation"),
            schema_reference="schemas/json/certification-contract.schema.json",
        ),
        ArtifactSpec(
            "certification/inputs/current-repository.v1.json",
            "certification-input-set",
            "historical-immutable",
            ("tools/certification/evaluate.py",),
            (
                _b("/", "certification-predicate-calculation", "reconciliation", "Deterministic classification and digest binding of the repository's current canonical certification inputs."),
                _b("/source_artifacts/*/sha256", "artifact-measurement", "measurement", "Measured byte digest of the exact referenced repository artifact."),
            ),
            coverage_selectors=("/criteria", "/source_artifacts"),
            schema_reference="schemas/json/certification-input-set.schema.json",
        ),
        ArtifactSpec(
            "certification/reports/current-repository.v1.json",
            "certification-report",
            "historical-immutable",
            ("tools/certification/evaluate.py",),
            (
                _b("/", "certification-predicate-calculation", "certification", "Deterministic per-criterion evaluation and final required-criterion conjunction over the bound input set."),
            ),
            coverage_selectors=("/authority_status", "/certification_eligible", "/criteria", "/final_state"),
            schema_reference="schemas/json/certification-report.schema.json",
        ),
        ArtifactSpec(
            "certification/contracts/regex-conformance-certification.v1.1.json",
            "certification-contract",
            "governed-registry",
            ("schemas/tooling/python/regex_conformance_schema/certification.py",),
            (
                _b("/", "manual-registry-decision", "governance", "Accepted predicate contract revision supporting the semantic-derived requirement snapshot input mode."),
                _b("/contract_digest_sha256", "certification-predicate-calculation", "validation", "Canonical digest of the contract content excluding identity and digest fields."),
                _b("/contract_id", "certification-predicate-calculation", "validation", "Content-derived certification-definition identity calculated from the contract digest."),
            ),
            coverage_selectors=("/criteria", "/final_composition", "/result_states", "/supersession_and_revocation"),
            schema_reference="schemas/json/certification-contract.schema.json",
        ),
        ArtifactSpec(
            "certification/inputs/current-repository-2026-09-08.v2.json",
            "certification-input-set",
            "current-generated",
            ("tools/certification/evaluate.py",),
            (
                _b("/", "certification-predicate-calculation", "reconciliation", "Deterministic classification and digest binding of the repository's current canonical certification inputs."),
                _b("/source_artifacts/*/sha256", "artifact-measurement", "measurement", "Measured byte digest of the exact referenced repository artifact."),
            ),
            coverage_selectors=("/criteria", "/source_artifacts"),
            schema_reference="schemas/json/certification-input-set.schema.json",
        ),
        ArtifactSpec(
            "certification/reports/current-repository-2026-09-08.v2.json",
            "certification-report",
            "current-generated",
            ("tools/certification/evaluate.py",),
            (_b("/", "certification-predicate-calculation", "certification", "Deterministic evaluation with C4 bound to the semantic-derived requirement snapshot."),),
            coverage_selectors=("/authority_status", "/certification_eligible", "/criteria", "/final_state"),
            schema_reference="schemas/json/certification-report.schema.json",
        ),
        ArtifactSpec(
            "certification/current-authority.v1.json",
            "certification-authority-index",
            "governed-registry",
            ("tools/certification/evaluate.py",),
            (
                _b("/", "manual-registry-decision", "governance", "Append-only certification issuance, supersession, and revocation authority state."),
                _b("/authority_index_sha256", "certification-predicate-calculation", "validation", "Canonical digest over the authority index excluding its digest field."),
                _b("/current_contract", "certification-predicate-calculation", "reconciliation", "Deterministic pointer to the current versioned predicate contract."),
                _b("/current_evaluation", "certification-predicate-calculation", "reconciliation", "Deterministic pointer to the freshly evaluated current-repository report."),
            ),
            coverage_selectors=("/actions", "/certifications", "/current_certification_id", "/current_contract", "/current_evaluation"),
            schema_reference="schemas/json/certification-authority-index.schema.json",
        ),
        ArtifactSpec(
            "tests/fixtures/certification/certification-predicates.v1.json",
            "certification-fixture-set",
            "current-generated",
            ("tools/certification/evaluate.py",),
            (
                _b("/", "certification-predicate-calculation", "validation", "Deterministic expected states obtained by evaluating adversarial fixture input sets with the versioned contract."),
                _b("/supersession_fixture", "classification-guard", "structural", "Synthetic immutable-history fixture used only to validate authority-state routing."),
            ),
            coverage_selectors=("/cases", "/supersession_fixture"),
            schema_reference="schemas/json/certification-predicate-fixtures.schema.json",
        ),
        *_report_specs(),
        *_campaign_specs(),
    )


def _report_specs() -> tuple[ArtifactSpec, ...]:
    forecast_paths = (
        ("reports/scale/known-universe-census-forecast.json", "tools/campaigns/verify_known_universe_census.py", "schemas/json/known-universe-census-forecast.schema.json"),
        ("reports/scale/full-known-universe-corpus-forecast.json", "tools/campaigns/compile_full_known_universe_forecast.py", "schemas/json/full-known-universe-forecast.schema.json"),
        ("reports/scale/factorized-raw-evidence-forecast.json", "tools/campaigns/compile_factorized_evidence_forecast.py", "schemas/json/factorized-evidence-forecast.schema.json"),
        ("reports/scale/evidence-pack-v2-certification.json", "tools/campaigns/compile_evidence_pack_v2.py", "schemas/json/evidence-pack-v2-certification.schema.json"),
        ("reports/scale/evidence-pack-v3-capacity-certification.json", "tools/campaigns/certify_compact_evidence.py", "schemas/json/evidence-pack-v3-capacity-certification.schema.json"),
        ("reports/scale/million-scale-capacity-plan.json", "tools/campaigns/compile_million_scale_capacity_plan.py", "schemas/json/million-scale-capacity-plan.schema.json"),
    )
    result: list[ArtifactSpec] = []
    for path, generator, schema in forecast_paths:
        result.append(
            ArtifactSpec(
                path,
                "forecast" if "certification" not in path else "certification-or-qualification-report",
                "historical-immutable",
                (generator,),
                (
                    _b("/", "forecast-calculation", "forecast", "Deterministic arithmetic over source-bound measurements and planning parameters."),
                    _b("/classification", "classification-guard", "structural", "Protective non-authority, non-execution, and non-mutation declarations."),
                    _b("/certification", "certification-measurement", "certification", "Procedure-backed verification results over exact artifacts or evidence."),
                    _b("/source_binding", "external-restatement", "scientific", "Exact source artifact identities, counts, and digests."),
                    _b("/source_bindings", "external-restatement", "scientific", "Exact source artifact identities, counts, and digests."),
                    _b("/repository_source_bindings", "external-restatement", "scientific", "Exact repository source identities and digests."),
                    _b("/research_sources", "external-restatement", "scientific", "Claims restated from explicit external source URLs."),
                    _b("/decision_gate", "manual-registry-decision", "governance", "Governed decision state; not an empirical result."),
                    _b("/acceptance_gates", "manual-registry-decision", "governance", "Governed stop and authorization requirements."),
                    _b("/p19_measured_basis", "artifact-measurement", "measurement", "Measured operating-envelope and campaign basis copied with exact source binding."),
                    _b("/measured_basis", "artifact-measurement", "measurement", "Measured evidence or execution basis copied with exact source binding."),
                    _b("/pack_measurement", "artifact-measurement", "measurement", "Measured pack bytes, objects, and evidence-class attribution."),
                    _b("/factoring_measurements", "artifact-measurement", "measurement", "Measured factorization and evidence-corpus statistics."),
                    _b("/future_contract_measurement", "artifact-measurement", "measurement", "Measured future-contract encoding statistics."),
                    _b("/lossless_redesign_checkpoint", "artifact-measurement", "measurement", "Measured lossless-redesign checkpoint statistics."),
                    _b("/retention_analysis", "artifact-measurement", "measurement", "Measured counterfactual retention results."),
                    _b("/adversarial_audit", "sparsity-inference", "audit", "Reasoned audit conclusion from ledger and forecast inputs; not an empirical measurement."),
                    _b("/forecast_policy", "planning-assumption", "forecast", "Governed planning assumptions retained without empirical upgrade."),
                    _b("/workload_plan/attempt_policy", "planning-assumption", "forecast", "Planning retry and attempt assumptions."),
                    _b("/execution_capacity", "planning-assumption", "forecast", "Host capacity and deployment planning assumptions."),
                    _b("/publication_plan", "manual-registry-decision", "governance", "Governed publication design and stop conditions."),
                ),
                coverage_selectors=("/research_sources", "/p19_measured_basis", "/measured_basis", "/pack_measurement", "/factoring_measurements", "/future_contract_measurement", "/lossless_redesign_checkpoint", "/retention_analysis", "/workload_plan", "/execution_capacity", "/publication_plan"),
                schema_reference=schema,
            )
        )
    result.extend(
        [
            ArtifactSpec(
                "reports/scale/100k-qualification-design.json",
                "forecast",
                "historical-immutable",
                ("tools/campaigns/compile_100k_qualification.py",),
                (
                    _b("/", "campaign-calculation", "forecast", "Deterministic design-plan aggregation."),
                    _b("/classification", "classification-guard", "structural", "Protective operational-only declarations."),
                    _b("/safety_contract", "manual-registry-decision", "governance", "Governed safety contract."),
                ),
                count_contracts=(
                    _c("/base_logical_template_count", "collection-length", ["/workload_distribution/base_logical_templates"], "base logical templates", "Exact collection length."),
                    _c("/profile_coordinate_count", "collection-length", ["/workload_distribution/profiles"], "profile workload rows", "Exact collection length."),
                    _c("/logical_execution_count", "sum-integer-values", ["/workload_distribution/base_logical_templates/*/logical_execution_count"], "logical executions distributed across unique base logical templates", "Sum the non-overlapping base-template workload counts; category memberships may overlap and are not used as the denominator."),
                ),
                schema_reference="schemas/json/scale-qualification-design-report.schema.json",
            ),
            ArtifactSpec(
                "reports/scale/100k-execution.json",
                "certification-or-qualification-report",
                "historical-immutable",
                ("tools/campaigns/run_100k_qualification.py",),
                (
                    _b("/", "artifact-measurement", "measurement", "Measured execution, attempt, interruption, observation, and shard state."),
                    _b("/reconciliation", "reconciliation-calculation", "reconciliation", "Deterministic reconciliation of measured execution records."),
                    _b("/session_summary", "reconciliation-calculation", "reconciliation", "Calculated session completion summary."),
                ),
                schema_reference="schemas/json/scale-execution-report.schema.json",
            ),
            ArtifactSpec(
                "reports/scale/100k-warehouse-reconciliation.json",
                "audit-or-reconciliation-report",
                "historical-immutable",
                ("tools/campaigns/reconcile_100k_warehouse.py",),
                (
                    _b("/", "reconciliation-calculation", "reconciliation", "Deterministic reconciliation over immutable evidence and derived warehouse rows."),
                    _b("/classification", "classification-guard", "structural", "Protective non-authority and non-mutation declarations."),
                    _b("/evidence", "artifact-measurement", "measurement", "Measured evidence-manifest identity, size, and root digest."),
                    _b("/source_digests", "artifact-measurement", "measurement", "Measured source-file digests."),
                ),
                schema_reference="schemas/json/scale-warehouse-reconciliation.schema.json",
            ),
            ArtifactSpec(
                "reports/scale/cache-disk-pressure-qualification.json",
                "certification-or-qualification-report",
                "historical-immutable",
                ("tools/control_plane/compile_cache_disk_pressure_qualification.py",),
                (
                    _b("/", "certification-measurement", "certification", "Procedure-backed simulated qualification cases and checks."),
                    _b("/classification", "classification-guard", "structural", "Protective operational-only declarations."),
                    _b("/summary", "reconciliation-calculation", "reconciliation", "Calculated case and invariant summary."),
                    _b("/cache_churn", "reconciliation-calculation", "reconciliation", "Calculated cache-cleanup case aggregation."),
                ),
                count_contracts=(
                    _c("/summary/case_count", "collection-length", ["/cases"], "qualification cases", "Exact case collection length."),
                    _c("/summary/passed_case_count", "matching-value-count", ["/cases/*/status"], "cases with passed status", "Filter case status.", values=["passed"]),
                    _c("/summary/failed_case_count", "matching-value-count", ["/cases/*/status"], "cases with failed status", "Filter the explicit failing status.", values=["failed"]),
                    _c("/summary/invariant_count", "collection-length", ["/invariants"], "qualification invariants", "Exact invariant collection length."),
                ),
                schema_reference="schemas/json/cache-disk-pressure-qualification.schema.json",
            ),
        ]
    )
    qualification_reports = (
        ("reports/small-scale/qualification-coverage.json", "tools/campaigns/compile_small_scale.py", "schemas/json/qualification-coverage-report.schema.json"),
        ("reports/small-scale/fault-classification.json", "tools/campaigns/compile_fault_classification.py", "schemas/json/fault-classification-report.schema.json"),
        ("reports/small-scale/evidence-verification-qualification.json", "tools/campaigns/compile_evidence_verification_qualification.py", "schemas/json/evidence-verification-qualification.schema.json"),
        ("reports/small-scale/restart-resume-qualification.json", "tools/campaigns/compile_restart_resume_qualification.py", "schemas/json/restart-resume-qualification.schema.json"),
        ("reports/vertical-slice/minimal-environment-certification.json", "tools/environments/certify_minimal.py", "schemas/json/minimal-environment-certification.schema.json"),
        ("reports/vertical-slice/minimal-adapter-certification.json", "tools/adapters/certify_minimal.py", "schemas/json/minimal-adapter-certification.schema.json"),
        ("reports/vertical-slice/first-campaign.json", "tools/campaigns/run_vertical_slice.py", "schemas/json/first-campaign-report.schema.json"),
    )
    for path, generator, schema in qualification_reports:
        result.append(
            ArtifactSpec(
                path,
                "certification-or-qualification-report",
                "historical-immutable",
                (generator,),
                (
                    _b("/", "certification-measurement", "certification", "Procedure-backed case, observation, environment, or adapter result."),
                    _b("/classification", "classification-guard", "structural", "Protective non-authority declarations."),
                    _b("/summary", "reconciliation-calculation", "reconciliation", "Calculated summary over the report's cases."),
                    _b("/reconciliation", "reconciliation-calculation", "reconciliation", "Calculated agreement between plan, evidence, and observations."),
                    _b("/evidence_filename", "external-restatement", "scientific", "Reference to the external immutable evidence file."),
                    _b("/evidence_sha256", "artifact-measurement", "measurement", "Measured digest of the external immutable evidence file."),
                ),
                schema_reference=schema,
            )
        )
    return tuple(result)


def _campaign_specs() -> tuple[ArtifactSpec, ...]:
    items = (
        ("campaigns/compiled/first-vertical-slice.v1.json", "tools/campaigns/compile_vertical_slice.py", "schemas/json/compiled-campaign.schema.json"),
        ("campaigns/compiled/small-scale-qualification.v1.json", "tools/campaigns/compile_small_scale.py", "schemas/json/compiled-campaign.schema.json"),
        ("campaigns/compiled/100k-qualification.v1.json", "tools/campaigns/compile_100k_qualification.py", "schemas/json/scale-campaign-plan.schema.json"),
        ("campaigns/million/compiled/million-qualification.v1.json", "tools/campaigns/compile_million_qualification.py", "schemas/json/million-scale-campaign-plan.schema.json"),
    )
    return tuple(
        ArtifactSpec(
            path,
            "campaign-plan",
            "historical-immutable",
            (generator,),
            (
                _b("/", "campaign-calculation", "coverage", "Deterministic campaign compilation, denominator, logical-execution, shard, and partition aggregation."),
                _b("/classification", "classification-guard", "structural", "Protective non-authority and qualification-only declarations."),
                _b("/source_digests", "artifact-measurement", "measurement", "Measured digests of exact compiler inputs."),
                _b("/campaign_manifest/classification", "classification-guard", "structural", "Protective classification copied into the manifest."),
                _b("/campaign_manifest/source_digests", "artifact-measurement", "measurement", "Measured digests copied into the manifest."),
            ),
            schema_reference=schema,
        )
        for path, generator, schema in items
    )


def _parse_selector(selector: str) -> tuple[str, ...]:
    if selector == "/":
        return ()
    if not selector.startswith("/"):
        fail("invalid-assertion-selector", "selector must begin with /", selector)
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in selector[1:].split("/"))


def _matches(path: tuple[str, ...], selector: str) -> bool:
    parts = _parse_selector(selector)
    if len(parts) > len(path):
        return False
    return all(expected == "*" or expected == actual for expected, actual in zip(parts, path))


def _specificity(selector: str) -> tuple[int, int]:
    parts = _parse_selector(selector)
    return (len(parts), sum(part != "*" for part in parts))


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, path + (str(index),))
    else:
        yield path, value


def _resolve(value: Any, selector: str) -> list[tuple[tuple[str, ...], Any]]:
    parts = _parse_selector(selector)
    current: list[tuple[tuple[str, ...], Any]] = [((), value)]
    for part in parts:
        next_values: list[tuple[tuple[str, ...], Any]] = []
        for path, node in current:
            if isinstance(node, dict):
                if part == "*":
                    next_values.extend((path + (key,), child) for key, child in node.items())
                elif part in node:
                    next_values.append((path + (part,), node[part]))
            elif isinstance(node, list):
                if part == "*":
                    next_values.extend((path + (str(index),), child) for index, child in enumerate(node))
                elif part.isdigit() and int(part) < len(node):
                    next_values.append((path + (part,), node[int(part)]))
        current = next_values
    return current


def _candidate_paths(value: Any, coverage_selectors: Iterable[str]) -> list[tuple[str, ...]]:
    paths: list[tuple[str, ...]] = []
    for path, _ in _walk(value):
        if not path:
            continue
        final = path[-1].lower()
        named = any(fragment in final for fragment in ASSERTION_KEY_FRAGMENTS)
        contained = any(part in ASSERTION_CONTAINER_NAMES for part in path[:-1])
        explicit = any(_matches(path, selector) for selector in coverage_selectors)
        if named or contained or explicit:
            paths.append(path)
    return paths


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _catalog_digest(value: dict[str, Any]) -> str:
    body = deepcopy(value)
    body.pop("catalog_digest_sha256", None)
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _revision_basis(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "allowed_gate_kinds": record["allowed_gate_kinds"],
        "authority_references": record["authority_references"],
        "derivation_class": record["derivation_class"],
        "derivation_id": record["derivation_id"],
        "independent_evidence": record["independent_evidence"],
        "input_references": record["input_references"],
        "method_key": record["method_key"],
        "method_version": record["method_version"],
    }


def derivation_revision_id(root: Path, record: dict[str, Any]) -> str:
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / PROFILE_PATH)),
        namespace="assertion-derivation-revision",
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity=_revision_basis(record),
    )
    return str(result["content_id"])


def _build_derivations(root: Path) -> list[dict[str, Any]]:
    built: list[dict[str, Any]] = []
    for spec in _derivation_specs(root):
        record = {key: value for key, value in spec.items() if key != "key"}
        record["derivation_id"] = DERIVATION_IDS[spec["key"]]
        record["derivation_revision_id"] = derivation_revision_id(root, record)
        built.append(record)
    return sorted(built, key=lambda item: item["derivation_id"])


def _count_value(record: dict[str, Any], spec: CountSpec) -> int:
    inputs: list[tuple[tuple[str, ...], Any]] = []
    for selector in spec.inputs:
        inputs.extend(_resolve(record, selector))
    declared_nodes = _resolve(record, spec.declared)
    if len(declared_nodes) != 1 or isinstance(declared_nodes[0][1], bool) or not isinstance(declared_nodes[0][1], int):
        fail("invalid-declared-count", "declared count selector must resolve to exactly one integer", spec.declared)
    declared_path = declared_nodes[0][0]
    if any(path == declared_path for path, _ in inputs):
        fail("self-validating-count", "a declared count cannot be one of its own inputs", spec.declared)
    if spec.rule == "collection-length":
        if len(inputs) != 1 or not isinstance(inputs[0][1], (list, dict)):
            fail("invalid-count-input", "collection-length requires exactly one collection", spec.declared)
        calculated = len(inputs[0][1])
    elif spec.rule == "sum-collection-lengths":
        if not inputs or any(not isinstance(value, (list, dict)) for _, value in inputs):
            fail("invalid-count-input", "sum-collection-lengths requires collections", spec.declared)
        calculated = sum(len(value) for _, value in inputs)
    elif spec.rule == "matching-value-count":
        if not spec.match_values:
            fail("invalid-count-input", "matching-value-count requires match values", spec.declared)
        calculated = sum(value in spec.match_values for _, value in inputs)
    elif spec.rule == "sum-integer-values":
        if not inputs or any(isinstance(value, bool) or not isinstance(value, int) for _, value in inputs):
            fail("invalid-count-input", "sum-integer-values requires integers", spec.declared)
        calculated = sum(value for _, value in inputs)
    else:
        fail("unsupported-count-rule", f"unknown count rule {spec.rule!r}", spec.declared)
    declared = declared_nodes[0][1]
    if declared != calculated:
        fail("generated-count-mismatch", f"declared {declared} but calculated {calculated} for {spec.population}", spec.declared)
    return calculated


def validate_count_contract(record: dict[str, Any], spec: CountSpec) -> int:
    """Validate one declared count against its named population and return it."""
    return _count_value(record, spec)


def _build_artifact(root: Path, spec: ArtifactSpec, derivations: dict[str, dict[str, Any]]) -> dict[str, Any]:
    source = root / spec.path
    if not source.is_file():
        fail("missing-assertion-artifact", "inventoried artifact is missing", spec.path)
    record = load_strict(source)
    candidates = _candidate_paths(record, spec.coverage_selectors)
    matched_counts: Counter[BindingSpec] = Counter()
    for path in candidates:
        matches = [binding for binding in spec.bindings if _matches(path, binding.selector)]
        if not matches:
            fail("unbound-generated-assertion", "generated assertion has no derivation binding", f"{spec.path}#/{'/'.join(path)}")
        best = max(_specificity(item.selector) for item in matches)
        strongest = [item for item in matches if _specificity(item.selector) == best]
        derivation_keys = {item.derivation for item in strongest}
        if len(derivation_keys) != 1:
            fail("incompatible-derivation-bindings", "equally specific bindings assign different derivations", f"{spec.path}#/{'/'.join(path)}")
        winner = strongest[0]
        matched_counts[winner] += 1
    bindings = []
    for binding in spec.bindings:
        if matched_counts[binding] == 0:
            continue
        derivation = derivations[binding.derivation]
        bindings.append(
            {
                "selector": binding.selector,
                "derivation_id": derivation["derivation_id"],
                "derivation_revision_id": derivation["derivation_revision_id"],
                "assertion_kind": binding.assertion_kind,
                "evidence_role": ROLE_BY_CLASS[derivation["derivation_class"]],
                "current_value_source": binding.current_value_source,
                "reproducible": binding.reproducible,
                "legacy_ambiguity": binding.legacy_ambiguity,
                "matched_assertion_count": matched_counts[binding],
            }
        )
    contracts = []
    for count_spec in spec.count_contracts:
        _count_value(record, count_spec)
        item = {
            "declared_count_selector": count_spec.declared,
            "calculation_rule": count_spec.rule,
            "input_selectors": list(count_spec.inputs),
            "counted_population": count_spec.population,
            "legacy_name_ambiguous": count_spec.ambiguous,
            "resolution": count_spec.resolution,
        }
        if count_spec.match_values:
            item["match_values"] = list(count_spec.match_values)
        contracts.append(item)
    built = {
        "path": spec.path,
        "artifact_sha256": _raw_sha256(source),
        "artifact_class": spec.artifact_class,
        "lifecycle": spec.lifecycle,
        "generators": list(spec.generators),
        "coverage_selectors": list(spec.coverage_selectors),
        "assertion_bindings": bindings,
        "count_contracts": contracts,
    }
    if spec.schema_reference is not None:
        built["schema_reference"] = spec.schema_reference
    return built


def build_catalog(root: Path) -> dict[str, Any]:
    derivation_records = _build_derivations(root)
    by_key = {key: next(item for item in derivation_records if item["derivation_id"] == identifier) for key, identifier in DERIVATION_IDS.items()}
    artifacts = [_build_artifact(root, spec, by_key) for spec in _artifact_specs()]
    by_class: Counter[str] = Counter()
    ambiguous = 0
    groups = 0
    occurrences = 0
    count_contracts = 0
    derivation_by_id = {item["derivation_id"]: item for item in derivation_records}
    for artifact in artifacts:
        count_contracts += len(artifact["count_contracts"])
        for binding in artifact["assertion_bindings"]:
            count = binding["matched_assertion_count"]
            groups += 1
            occurrences += count
            by_class[derivation_by_id[binding["derivation_id"]]["derivation_class"]] += count
            if binding["legacy_ambiguity"] != "none":
                ambiguous += count
    catalog: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "schema_family_id": SCHEMA_FAMILY_ID,
        "namespace_registry": NAMESPACE_PATH.as_posix(),
        "derivation_identity_profile": PROFILE_PATH.as_posix(),
        "coverage_policy": {
            "assertion_key_fragments": list(ASSERTION_KEY_FRAGMENTS),
            "assertion_container_names": list(ASSERTION_CONTAINER_NAMES),
            "rule": "Every scalar whose key is assertion-like, whose ancestor is an assertion container, or whose path is selected explicitly must resolve to exactly one most-specific derivation binding.",
        },
        "derivations": derivation_records,
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
        "coverage_summary": {
            "derivation_id": by_key["semantic-counts"]["derivation_id"],
            "derivation_revision_id": by_key["semantic-counts"]["derivation_revision_id"],
            "evidence_role": ROLE_BY_CLASS["calculation"],
            "inventoried_artifacts": len(artifacts),
            "historical_immutable_artifacts": sum(item["lifecycle"] == "historical-immutable" for item in artifacts),
            "assertion_groups": groups,
            "assertion_occurrences": occurrences,
            "previously_ambiguous_occurrences": ambiguous,
            "count_contracts": count_contracts,
            "by_derivation_class": dict(sorted(by_class.items())),
        },
    }
    catalog["catalog_digest_sha256"] = _catalog_digest(catalog)
    return catalog


def _validate_derivation(record: dict[str, Any], root: Path, registry: NamespaceRegistry) -> None:
    registry.validate(record["derivation_id"])
    registry.validate(record["derivation_revision_id"])
    if not record["derivation_id"].startswith("rcid:v1:assertion-derivation:u7:"):
        fail("wrong-derivation-namespace", "derivation handle must use the assigned assertion-derivation namespace", record["derivation_id"])
    if not record["derivation_revision_id"].startswith("rcid:v1:assertion-derivation-revision:h:"):
        fail("wrong-derivation-revision-namespace", "derivation revision must be content-derived", record["derivation_revision_id"])
    if record["metadata"]["kind"] != record["derivation_class"]:
        fail("contradictory-derivation-class", "metadata kind differs from derivation class", record["derivation_id"])
    allowed = set(record["allowed_gate_kinds"])
    if not allowed or not allowed.issubset(ALLOWED_GATES_BY_CLASS[record["derivation_class"]]):
        fail("inappropriate-evidence-strength", "derivation declares an unsupported gate kind", record["derivation_id"])
    expected_independent = record["derivation_class"] in {"measurement", "research-derived", "external-evidence"}
    if record["independent_evidence"] != expected_independent:
        fail("inappropriate-evidence-strength", "independent-evidence flag contradicts derivation class", record["derivation_id"])
    expected_revision = derivation_revision_id(root, record)
    if record["derivation_revision_id"] != expected_revision:
        fail("derivation-revision-mismatch", "derivation revision does not match its identity basis", record["derivation_id"])


def validate_catalog_integrity(root: Path, actual: dict[str, Any]) -> None:
    """Validate derivation identities, references, and bound revisions."""
    registry = NamespaceRegistry.load(root / NAMESPACE_PATH)
    registry.validate(SCHEMA_FAMILY_ID)
    identifiers: set[str] = set()
    revisions: set[str] = set()
    revision_by_id: dict[str, str] = {}
    for record in actual["derivations"]:
        _validate_derivation(record, root, registry)
        if record["derivation_id"] in identifiers or record["derivation_revision_id"] in revisions:
            fail("duplicate-derivation-id", "derivation handles and revisions must be unique", record["derivation_id"])
        identifiers.add(record["derivation_id"])
        revisions.add(record["derivation_revision_id"])
        revision_by_id[record["derivation_id"]] = record["derivation_revision_id"]
    referenced = [
        (binding["derivation_id"], binding["derivation_revision_id"])
        for artifact in actual["artifacts"]
        for binding in artifact["assertion_bindings"]
    ]
    referenced.append(
        (
            actual["coverage_summary"]["derivation_id"],
            actual["coverage_summary"]["derivation_revision_id"],
        )
    )
    dangling = sorted(identifier for identifier, _ in referenced if identifier not in identifiers)
    if dangling:
        fail("dangling-derivation-reference", "artifact binding references an unknown derivation", str(dangling))
    stale = sorted(
        identifier
        for identifier, revision in referenced
        if revision_by_id[identifier] != revision
    )
    if stale:
        fail("stale-derivation-revision", "artifact binding does not reference the current derivation revision", str(stale))


def verify_catalog(root: Path, catalog: dict[str, Any] | None = None) -> dict[str, int]:
    actual = load_strict(root / CATALOG_PATH) if catalog is None else catalog
    expected = build_catalog(root)
    validate_catalog_integrity(root, actual)
    if actual != expected:
        fail("generated-assertion-catalog-drift", "tracked catalog differs from deterministic inventory rebuild", CATALOG_PATH.as_posix())
    if actual["catalog_digest_sha256"] != _catalog_digest(actual):
        fail("generated-assertion-catalog-digest", "catalog digest differs from canonical content", CATALOG_PATH.as_posix())
    return {
        "generated_assertion_artifacts": actual["coverage_summary"]["inventoried_artifacts"],
        "generated_assertion_groups": actual["coverage_summary"]["assertion_groups"],
        "generated_assertion_occurrences": actual["coverage_summary"]["assertion_occurrences"],
        "generated_count_contracts": actual["coverage_summary"]["count_contracts"],
    }


def require_gate(catalog: dict[str, Any], derivation_id: str, gate_kind: str) -> None:
    by_id = {item["derivation_id"]: item for item in catalog["derivations"]}
    if derivation_id not in by_id:
        fail("dangling-derivation-reference", "gate references an unknown derivation", derivation_id)
    record = by_id[derivation_id]
    if gate_kind not in record["allowed_gate_kinds"]:
        fail(
            "inappropriate-evidence-strength",
            f"{record['derivation_class']} derivation cannot satisfy {gate_kind}",
            derivation_id,
        )


def find_binding(catalog: dict[str, Any], artifact_path: str, assertion_path: str) -> dict[str, Any]:
    artifact = next((item for item in catalog["artifacts"] if item["path"] == artifact_path), None)
    if artifact is None:
        fail("missing-assertion-artifact", "artifact is not inventoried", artifact_path)
    path = _parse_selector(assertion_path)
    matches = [item for item in artifact["assertion_bindings"] if _matches(path, item["selector"])]
    if not matches:
        fail("unbound-generated-assertion", "assertion has no derivation binding", f"{artifact_path}#{assertion_path}")
    best = max(_specificity(item["selector"]) for item in matches)
    strongest = [item for item in matches if _specificity(item["selector"]) == best]
    if len({item["derivation_id"] for item in strongest}) != 1:
        fail("incompatible-derivation-bindings", "equally specific bindings disagree", f"{artifact_path}#{assertion_path}")
    return strongest[0]


def require_assertion_gate(
    catalog: dict[str, Any], artifact_path: str, assertion_path: str, gate_kind: str
) -> None:
    require_gate(catalog, find_binding(catalog, artifact_path, assertion_path)["derivation_id"], gate_kind)
