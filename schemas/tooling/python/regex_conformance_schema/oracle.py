"""Versioned oracle taxonomy, provenance traversal, and circularity guards.

This module defines prospective expectation authority.  It does not execute a
target, adjudicate a discrepancy, issue a waiver, or create production vectors.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from typing import Any, Iterable

from .derivation import CATALOG_PATH as DERIVATION_CATALOG_PATH, DERIVATION_IDS, verify_catalog as verify_derivation_catalog
from .errors import ConformanceDataError, fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .obligation_snapshots import REQUIREMENT_PATH
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import verify_catalog as verify_identity_catalog


PUBLISHED_ON = "2026-09-10"
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a08d07-ef56-7b11-bf43-47af7271e6a5"
ORACLE_DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a08d07-ef56-7cf6-a0ec-bba01aa82e7c"

ALLOCATION_PATH = Path("oracle/oracle-foundation-identities-2026-09-10.v1.json")
CONTRACT_PATH = Path("oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json")
FIXTURE_PATH = Path("tests/fixtures/oracle/oracle-validation-cases.v1.json")
REPORT_PATH = Path("reports/oracle/oracle-foundation-2026-09-10.v1.json")
AUTHORITY_PATH = Path("oracle/current-authority.v1.json")

ALLOCATION_SCHEMA_PATH = Path("schemas/json/oracle-foundation-allocation.schema.json")
CONTRACT_SCHEMA_PATH = Path("schemas/json/oracle-foundation-contract.schema.json")
RECORD_SCHEMA_PATH = Path("schemas/json/oracle-record.schema.json")
FIXTURE_SCHEMA_PATH = Path("schemas/json/oracle-validation-fixtures.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/oracle-foundation-report.schema.json")
AUTHORITY_SCHEMA_PATH = Path("schemas/json/oracle-authority-index.schema.json")
VECTOR_BINDING_SCHEMA_PATH = Path("schemas/json/oracle-vector-binding.schema.json")
SEMANTIC_SNAPSHOT_PATH = Path("semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
CONTENT_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")
IMPLEMENTATION_PATHS = (
    Path("schemas/tooling/python/regex_conformance_schema/oracle.py"),
    Path("tools/oracle/compile_oracle_foundation.py"),
    ALLOCATION_SCHEMA_PATH,
    CONTRACT_SCHEMA_PATH,
    RECORD_SCHEMA_PATH,
    FIXTURE_SCHEMA_PATH,
    REPORT_SCHEMA_PATH,
    AUTHORITY_SCHEMA_PATH,
    VECTOR_BINDING_SCHEMA_PATH,
)

ORACLE_CLASSES = {
    "O1": {
        "name": "normative-source",
        "epistemic_function": "A versioned normative source directly establishes the scoped expected behavior.",
        "scope_kind": "external-normative",
        "required_provenance_fields": ["claim_revision_id", "derivation_revision_id", "locator", "scope_statement", "source_identity", "source_version"],
        "permitted_judgments": ["normative-conformant", "normative-nonconformant", "normative-expectation-established"],
        "may_establish_conventional_expected_result": True,
        "conclusion_boundary": "Only the exact normative source, edition, anchor, claim revision, and satisfied applicability scope are authoritative.",
    },
    "O2": {
        "name": "formal-derivation",
        "epistemic_function": "An independently checked mathematical or mechanical construction establishes a result within its declared model.",
        "scope_kind": "formal-model",
        "required_provenance_fields": ["assumptions", "construction_identity", "construction_version", "domain_restrictions", "independent_checker_identity", "witness_digest_sha256"],
        "permitted_judgments": ["formal-expectation-established", "formal-model-satisfied", "formal-model-violated"],
        "may_establish_conventional_expected_result": True,
        "conclusion_boundary": "The conclusion is limited to the recorded construction, assumptions, and domain; using a regex implementation as calculator is not formal independence.",
    },
    "O3": {
        "name": "data-derived",
        "epistemic_function": "An independently versioned authoritative dataset and deterministic algorithm establish a data-scoped result.",
        "scope_kind": "data-version-scoped",
        "required_provenance_fields": ["algorithm_identity", "algorithm_version", "data_digest_sha256", "data_source_identity", "data_version", "scope_statement"],
        "permitted_judgments": ["data-expectation-established", "data-scoped-agreement", "data-scoped-disagreement"],
        "may_establish_conventional_expected_result": True,
        "conclusion_boundary": "The conclusion is valid only for the pinned data version, algorithm, and semantic rules governing use of that data.",
    },
    "O4": {
        "name": "metamorphic-relational",
        "epistemic_function": "A necessary relation among executions of the same applicable profile establishes relational satisfaction or violation.",
        "scope_kind": "same-profile-relation",
        "required_provenance_fields": ["applicability_gates", "follow_up_construction_ids", "permitted_conclusion", "relation_identity", "relation_version", "source_construction_ids"],
        "permitted_judgments": ["relational-discrepancy", "relation-satisfied", "relation-violated"],
        "may_establish_conventional_expected_result": False,
        "conclusion_boundary": "Violation of a valid necessary invariant may establish a discrepancy; satisfaction never proves full correctness.",
    },
    "O5": {
        "name": "designated-intra-family-reference",
        "epistemic_function": "A designated profile supports an explicitly family-relative comparison.",
        "scope_kind": "family-relative",
        "required_provenance_fields": ["carve_outs", "comparison_scope", "designation_source_id", "reason_designated", "reference_profile_id"],
        "permitted_judgments": ["family-relative-change", "family-relative-divergence", "family-relative-equivalence", "family-relative-regression"],
        "may_establish_conventional_expected_result": False,
        "conclusion_boundary": "The reference is not independent correctness authority and cannot produce universal normative conformance.",
    },
    "O6": {
        "name": "implementation-documentation",
        "epistemic_function": "Versioned implementation documentation establishes what that exact implementation claims to do.",
        "scope_kind": "implementation-self-documentation",
        "required_provenance_fields": ["claim_revision_id", "documentation_identity", "documentation_version", "implementation_scope_id", "locator", "scope_statement"],
        "permitted_judgments": ["documentation-ambiguous", "implementation-documentation-conformant", "implementation-documentation-nonconformant"],
        "may_establish_conventional_expected_result": True,
        "conclusion_boundary": "Agreement is conformance only to the implementation's own documentation, never silently to an external normative source.",
    },
    "O7": {
        "name": "historical-characterization",
        "epistemic_function": "A preserved historical observation is itself the scoped object of study.",
        "scope_kind": "historical-characterization",
        "required_provenance_fields": ["evidence_manifest_id", "historical_claim_revision_id", "observed_on", "reproduction_scope", "source_observation_id"],
        "permitted_judgments": ["historical-behavior-diverged", "historical-behavior-reproduced", "historical-fact-recorded"],
        "may_establish_conventional_expected_result": False,
        "conclusion_boundary": "The result is an empirical historical fact and cannot bootstrap itself into normative truth.",
    },
    "O8": {
        "name": "characterization-only",
        "epistemic_function": "No admissible correctness oracle exists, so only observation, differential description, or a research gap may be recorded.",
        "scope_kind": "characterization",
        "required_provenance_fields": ["reason_no_correctness_oracle", "research_gap_id", "scope_statement", "searched_source_ids"],
        "permitted_judgments": ["characterization-recorded", "descriptive-differential", "research-gap-recorded"],
        "may_establish_conventional_expected_result": False,
        "conclusion_boundary": "No conformance verdict or expected result is permitted.",
    },
}

RESOLUTION_STATES = {
    "oracle-established": "An admissible oracle establishes the scoped expectation or relation.",
    "oracle-inapplicable": "The oracle is legitimate but its declared scope or applicability condition is false.",
    "expectation-ambiguous": "The authority does not select one unambiguous expected result.",
    "expectation-under-specified": "Applicable authority intentionally leaves the relevant behavior open.",
    "conflicting-authoritative-expectations": "Two or more legitimate authorities establish incompatible scoped expectations; every claim is preserved.",
    "oracle-inputs-unavailable": "Required pinned source, data, construction, or reference inputs are unavailable.",
    "characterization-only": "No admissible correctness oracle exists; execution may produce characterization but no conformance verdict.",
}

DEPENDENCY_KINDS = [
    "absence-of-authority",
    "authoritative-dataset",
    "designated-reference-profile",
    "empirical-consensus",
    "empirical-observation",
    "expectation-projection",
    "formal-construction",
    "generator",
    "historical-observation",
    "implementation-documentation",
    "normative-source-proposition",
    "relation-definition",
    "research-claim",
    "target-implementation-output",
]

DEPENDENCY_ROLES = [
    "comparison-input",
    "context-only",
    "descriptive-statistic",
    "expected-basis",
    "historical-subject",
    "promotion-source",
    "stimulus-only",
]

GUARDS = [
    ("G1", "observation-not-expectation", "An observation cannot be an expectation basis; promotion requires a separately independent oracle basis and an explicit reviewed event."),
    ("G2", "no-consensus-oracle", "Consensus and majority statistics are descriptive only and cannot establish an expectation or conformance judgment."),
    ("G3", "generator-cannot-self-oracle", "A stimulus generator and any evaluator in its semantic authority domain cannot supply the expected answer."),
    ("G4", "no-negative-inference-from-silence", "Missing documentation or standardization cannot imply rejection or unsupported behavior."),
    ("G5", "conflicting-authorities-survive", "Conflicting legitimate claims remain separate and require an explicit unresolved conflict record."),
    ("G6", "no-transitive-laundering", "Dependency traversal rejects indirect observation or target-output paths hidden behind claims or projections."),
    ("G7", "reference-profile-not-universal", "A designated profile is limited to declared intra-family comparison scope."),
    ("G8", "frozen-expectations-stable", "A campaign binds exact immutable oracle and expectation revisions; later authority changes cannot mutate that binding."),
]

CLASS_COMPATIBILITY = {
    "normative-expected-outcome": {"O1", "O2", "O3", "O8"},
    "profile-documentation-outcome": {"O1", "O2", "O3", "O6", "O8"},
    "relational-comparison": {"O4", "O5", "O7", "O8"},
    "characterization-record": {"O7", "O8"},
}

REQUIRED_CLASS_DEPENDENCY_KIND = {
    "O1": "normative-source-proposition",
    "O2": "formal-construction",
    "O3": "authoritative-dataset",
    "O4": "relation-definition",
    "O5": "designated-reference-profile",
    "O6": "implementation-documentation",
    "O7": "historical-observation",
}

PROMOTION_FIELDS = {
    "independent_oracle_basis_dependency_ids",
    "justification",
    "promoted_at",
    "promoter_id",
    "reviewer_id",
    "source_observation_id",
    "target_expectation_revision_id",
}

MUTABLE_VERSION_ALIASES = {"current", "head", "latest", "main", "master", "tip"}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _record_digest(record: dict[str, Any], *excluded: str) -> str:
    return _digest({key: value for key, value in record.items() if key not in set(excluded)})


def _content_id(root: Path, namespace: str, artifact_kind: str, body: dict[str, Any]) -> str:
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / CONTENT_PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": artifact_kind, "content_sha256": _digest(body)},
    )
    return str(result["content_id"])


def _finalize(root: Path, body: dict[str, Any], *, namespace: str, artifact_kind: str, id_field: str, digest_field: str) -> dict[str, Any]:
    return {**body, id_field: _content_id(root, namespace, artifact_kind, body), digest_field: _digest(body)}


def build_allocation() -> dict[str, Any]:
    return {
        "schema_version": "oracle-foundation-allocation.v1",
        "allocated_on": PUBLISHED_ON,
        "allocations": [
            {"entity_class": "assertion-derivation", "canonical_key": "derivation.oracle-foundation-governance", "assigned_id": ORACLE_DERIVATION_ID},
            {"entity_class": "schema-family", "canonical_key": "schema.oracle-foundation", "assigned_id": SCHEMA_FAMILY_ID},
        ],
    }


@lru_cache(maxsize=4)
def _contract_derivation_cached(root_text: str) -> dict[str, str]:
    catalog = load_strict(Path(root_text) / DERIVATION_CATALOG_PATH)
    item = next((entry for entry in catalog["derivations"] if entry["derivation_id"] == ORACLE_DERIVATION_ID), None)
    if item is None:
        fail("missing-oracle-derivation", "oracle foundation derivation is absent from the canonical derivation catalog")
    return {
        "derivation_id": item["derivation_id"],
        "derivation_revision_id": item["derivation_revision_id"],
        "derivation_class": item["derivation_class"],
    }


def _contract_derivation(root: Path) -> dict[str, str]:
    return deepcopy(_contract_derivation_cached(str(root.resolve())))


def build_contract(root: Path) -> dict[str, Any]:
    requirement = load_strict(root / REQUIREMENT_PATH)
    body = {
        "schema_version": "oracle-foundation-contract.v1",
        "contract_version": "1.0.0",
        "effective_on": PUBLISHED_ON,
        "authority_scope": "Prospective expected-result and scoped-comparison authority for canonical semantic requirements; no applicability decision, observation rewrite, discrepancy adjudication, waiver, claim issuance, or production vector is created here.",
        "semantic_requirement_authority": {
            "path": REQUIREMENT_PATH.as_posix(),
            "artifact_id": requirement["snapshot_id"],
            "digest_sha256": requirement["snapshot_digest_sha256"],
            "requirement_count": len(requirement["requirements"]),
        },
        "oracle_classes": [
            {"oracle_class": code, **deepcopy(spec)} for code, spec in ORACLE_CLASSES.items()
        ],
        "resolution_states": [
            {"state": state, "meaning": meaning} for state, meaning in RESOLUTION_STATES.items()
        ],
        "dependency_contract": {
            "dependency_kinds": DEPENDENCY_KINDS,
            "semantic_roles": DEPENDENCY_ROLES,
            "authority_domain_rule": "Tools, modules, aliases, wrappers, and processes backed by the same semantic implementation must share one authority_domain_id.",
            "traversal_rule": "Validate the complete directed dependency graph from every root, reject cycles, and propagate prohibited source kinds and authority-domain taint through every intermediate claim or projection.",
        },
        "circularity_guards": [
            {"guard_id": guard_id, "machine_rule": rule, "statement": statement, "mandatory": True}
            for guard_id, rule, statement in GUARDS
        ],
        "selection_and_conflict": {
            "class_precedence": "none",
            "numeric_rank_forbidden": True,
            "selection_rule": "Evaluate each applicable oracle independently for its declared epistemic purpose. Never select an oracle merely from its O-number.",
            "compatible_composition_rule": "Compatible claims may be jointly bound only through an explicit immutable projection naming every oracle revision.",
            "conflict_rule": "Incompatible legitimate expectations remain separate and create conflicting-authoritative-expectations with no automatically selected winner.",
            "future_adjudication_required": True,
        },
        "promotion_contract": {
            "observation_alone_sufficient": False,
            "required_fields": sorted(PROMOTION_FIELDS),
            "independence_rule": "Every independent basis is traversed and must establish the expectation without depending on the promoted observation, evaluated target output, consensus, or generator evaluator.",
        },
        "campaign_freeze_contract": {
            "exact_oracle_ids_and_digests_required": True,
            "exact_contract_id_and_digest_required": True,
            "mutable_latest_alias_forbidden": True,
            "later_revision_mutates_historical_binding": False,
        },
        "requirement_capability_compatibility": [
            {"expected_oracle_capability": capability, "admissible_oracle_classes": sorted(classes)}
            for capability, classes in sorted(CLASS_COMPATIBILITY.items())
        ],
        "derivation": _contract_derivation(root),
    }
    return _finalize(root, body, namespace="trust-policy-revision", artifact_kind="oracle-foundation-contract-v1", id_field="contract_id", digest_field="contract_digest_sha256")


def validate_contract(root: Path, contract: dict[str, Any]) -> None:
    validate_instance(contract, load_strict(root / CONTRACT_SCHEMA_PATH), source=CONTRACT_PATH.as_posix())
    body = {key: value for key, value in contract.items() if key not in {"contract_id", "contract_digest_sha256"}}
    if contract["contract_digest_sha256"] != _digest(body):
        fail("oracle-contract-digest", "oracle contract digest differs")
    if contract["contract_id"] != _content_id(root, "trust-policy-revision", "oracle-foundation-contract-v1", body):
        fail("oracle-contract-identity", "oracle contract content identity differs")
    classes = contract["oracle_classes"]
    if [item["oracle_class"] for item in classes] != list(ORACLE_CLASSES):
        fail("oracle-class-set", "oracle classes must be exactly O1 through O8 in canonical order")
    if any("rank" in key.lower() or "confidence" in key.lower() for item in classes for key in item):
        fail("oracle-confidence-ladder", "oracle classes are epistemic functions, not a confidence ranking")
    if any(item["name"] in {"consensus", "majority-vote"} for item in classes):
        fail("consensus-oracle-class", "consensus is forbidden as an oracle class")
    for item in classes:
        expected = ORACLE_CLASSES[item["oracle_class"]]
        if any(item[key] != value for key, value in expected.items()):
            fail("oracle-class-contract-drift", f"{item['oracle_class']} differs from its governed semantics")
    if [item["guard_id"] for item in contract["circularity_guards"]] != [item[0] for item in GUARDS]:
        fail("oracle-guard-set", "all eight circularity guards are mandatory")
    if contract["selection_and_conflict"]["class_precedence"] != "none" or not contract["selection_and_conflict"]["numeric_rank_forbidden"]:
        fail("oracle-precedence", "numeric class precedence is forbidden")
    if contract["semantic_requirement_authority"]["path"] != REQUIREMENT_PATH.as_posix():
        fail("stale-requirement-authority", "oracle contract binds a non-current requirement snapshot")
    if contract != build_contract(root):
        fail("oracle-contract-drift", "tracked oracle contract differs from its exact current inputs and implementation")


def oracle_record_digest(record: dict[str, Any]) -> str:
    return _record_digest(record, "oracle_id", "oracle_digest_sha256")


def finalize_oracle_record(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    body = {key: value for key, value in record.items() if key not in {"oracle_id", "oracle_digest_sha256"}}
    return {
        **body,
        "oracle_id": _content_id(root, "expectation-projection", "oracle-record-v1", body),
        "oracle_digest_sha256": _digest(body),
    }


@lru_cache(maxsize=4)
def _requirements_cached(root_text: str) -> dict[str, dict[str, Any]]:
    return {item["scientific_id"]: item for item in load_strict(Path(root_text) / REQUIREMENT_PATH)["requirements"]}


def _requirements(root: Path) -> dict[str, dict[str, Any]]:
    return _requirements_cached(str(root.resolve()))


@lru_cache(maxsize=4)
def _semantic_sources_cached(root_text: str) -> dict[str, dict[str, Any]]:
    snapshot = load_strict(Path(root_text) / SEMANTIC_SNAPSHOT_PATH)
    return {item["source_id"]: item for item in snapshot["sources"]}


def _semantic_sources(root: Path) -> dict[str, dict[str, Any]]:
    return _semantic_sources_cached(str(root.resolve()))


def _class_spec(contract: dict[str, Any], oracle_class: str) -> dict[str, Any]:
    item = next((entry for entry in contract["oracle_classes"] if entry["oracle_class"] == oracle_class), None)
    if item is None:
        fail("unknown-oracle-class", f"unsupported oracle class {oracle_class!r}")
    return item


def _traverse_dependencies(record: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str], set[str]]:
    nodes = record["dependency_graph"]["nodes"]
    by_id = {item["dependency_id"]: item for item in nodes}
    if len(by_id) != len(nodes):
        fail("duplicate-oracle-dependency", "oracle dependency IDs must be unique")
    roots = record["dependency_graph"]["root_dependency_ids"]
    if len(roots) != len(set(roots)) or any(item not in by_id for item in roots):
        fail("dangling-oracle-root", "oracle roots must be unique existing dependencies")
    for node in nodes:
        upstream = node["upstream_dependency_ids"]
        if len(upstream) != len(set(upstream)) or any(item not in by_id for item in upstream):
            fail("dangling-oracle-dependency", f"{node['dependency_id']} has a missing or duplicate upstream dependency")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            fail("oracle-dependency-cycle", f"dependency cycle reaches {identifier}")
        if identifier in visited:
            return
        visiting.add(identifier)
        for upstream in by_id[identifier]["upstream_dependency_ids"]:
            visit(upstream)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in by_id:
        visit(identifier)

    reachable: set[str] = set()

    def collect(identifier: str) -> None:
        if identifier in reachable:
            return
        reachable.add(identifier)
        for upstream in by_id[identifier]["upstream_dependency_ids"]:
            collect(upstream)

    expected_roots = {identifier for identifier in roots if by_id[identifier]["semantic_role"] == "expected-basis"}
    for identifier in expected_roots:
        collect(identifier)
    return by_id, expected_roots, reachable


def _validate_promotion(record: dict[str, Any], by_id: dict[str, dict[str, Any]], expected_reachable: set[str]) -> None:
    promotion = record["promotion_event"]
    observations = [node for node in by_id.values() if node["semantic_role"] == "promotion-source"]
    if promotion is None:
        if observations:
            fail("unreviewed-observation-promotion", "promotion-source dependency requires an explicit reviewed promotion event")
        return
    if record["oracle_class"] not in {"O1", "O2", "O3", "O6"}:
        fail("invalid-observation-promotion", "only a conventional expectation class may record an observation-promotion event")
    required = PROMOTION_FIELDS
    if set(promotion) != required or any(promotion[field] is None or promotion[field] == "" or promotion[field] == [] for field in required):
        fail("invalid-observation-promotion", "promotion event is incomplete")
    if not observations or promotion["source_observation_id"] not in {node["dependency_id"] for node in observations}:
        fail("invalid-observation-promotion", "promotion does not reference its preserved source observation dependency")
    basis = promotion["independent_oracle_basis_dependency_ids"]
    if not basis or any(identifier not in expected_reachable for identifier in basis):
        fail("observation-promotion-without-independent-authority", "promotion requires a reachable independent expected-basis dependency")
    forbidden = {"empirical-observation", "historical-observation", "target-implementation-output", "empirical-consensus", "generator", "absence-of-authority"}
    if any(by_id[identifier]["kind"] in forbidden for identifier in basis):
        fail("observation-promotion-without-independent-authority", "an observation or circular input cannot be the independent basis")


def validate_oracle_record(root: Path, contract: dict[str, Any], record: dict[str, Any]) -> None:
    validate_instance(record, load_strict(root / RECORD_SCHEMA_PATH), source="oracle record")
    body = {key: value for key, value in record.items() if key not in {"oracle_id", "oracle_digest_sha256"}}
    if record["oracle_digest_sha256"] != _digest(body) or record["oracle_id"] != _content_id(root, "expectation-projection", "oracle-record-v1", body):
        fail("oracle-record-identity", "oracle record ID or digest differs from its exact content")
    if record["contract_ref"] != {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]}:
        fail("oracle-contract-binding", "oracle record does not bind the exact current contract")
    if record["derivation"] != _contract_derivation(root):
        fail("oracle-derivation-binding", "oracle record does not bind the governed oracle derivation revision")

    requirement = _requirements(root).get(record["requirement_scientific_id"])
    if requirement is None:
        fail("unknown-oracle-requirement", "oracle record references no canonical semantic requirement")
    spec = _class_spec(contract, record["oracle_class"])
    if record["scope"]["kind"] != spec["scope_kind"]:
        fail("oracle-scope-class-mismatch", "oracle scope does not match its epistemic class")
    if record["oracle_class"] not in CLASS_COMPATIBILITY[requirement["expected_oracle_capability"]]:
        fail("oracle-requirement-incompatible", "oracle class cannot answer this requirement's declared oracle capability")
    provenance = record["provenance"]
    if set(provenance) != set(spec["required_provenance_fields"]):
        fail("oracle-provenance-fields", f"{record['oracle_class']} requires exactly its class-specific provenance fields")
    if any(value is None or value == "" or value == [] for value in provenance.values()):
        fail("oracle-provenance-empty", "oracle provenance fields must be populated")
    version_fields = {
        "O1": ("source_version",),
        "O2": ("construction_version",),
        "O3": ("algorithm_version", "data_version"),
        "O4": ("relation_version",),
        "O6": ("documentation_version",),
    }.get(record["oracle_class"], ())
    if any(str(provenance[field]).strip().lower() in MUTABLE_VERSION_ALIASES for field in version_fields):
        fail("mutable-oracle-version", "oracle provenance must pin an exact version rather than a mutable alias")
    sources = _semantic_sources(root)
    if record["oracle_class"] == "O1":
        source = sources.get(provenance["source_identity"])
        if source is None or source.get("normative") is not True:
            fail("oracle-source-authority", "O1 must reference a canonical normative source identity")
    if record["oracle_class"] == "O3" and provenance["data_source_identity"] not in sources:
        fail("oracle-source-authority", "O3 must reference a canonical authoritative data-source identity")
    if record["oracle_class"] == "O6":
        source = sources.get(provenance["documentation_identity"])
        if source is None or source.get("source_class") != "official-implementation-documentation":
            fail("oracle-source-authority", "O6 must reference canonical official implementation documentation")
    if record["oracle_class"] == "O8" and any(identifier not in sources for identifier in provenance["searched_source_ids"]):
        fail("oracle-source-authority", "O8 searched sources must resolve in the canonical semantic source registry")
    permitted = record["permitted_judgments"]
    if not permitted or len(permitted) != len(set(permitted)) or not set(permitted).issubset(spec["permitted_judgments"]):
        fail("oracle-judgment-escalation", "oracle record requests a conclusion outside its class boundary")

    state = record["resolution_state"]
    expected = record["expected_result"]
    if state == "oracle-established":
        if spec["may_establish_conventional_expected_result"] and (expected is None or expected["result_type"] != "conventional"):
            fail("missing-oracle-expected-result", "established conventional oracle requires an exact expected result")
        if record["oracle_class"] == "O4" and (expected is None or expected["result_type"] != "relation"):
            fail("missing-relational-condition", "metamorphic oracle requires an exact necessary relation")
        if record["oracle_class"] in {"O5", "O7", "O8"} and expected is not None:
            fail("noncorrectness-oracle-expected-result", "reference, historical, and characterization classes cannot create expected results")
    elif expected is not None:
        fail("invalid-unestablished-expectation", "non-established oracle state cannot carry an expected result")
    if record["oracle_class"] == "O8" and state != "characterization-only":
        fail("characterization-only-state", "O8 must remain characterization-only")
    if record["oracle_class"] == "O5":
        if record["scope"]["kind"] != "family-relative" or record["scope"]["profile_family_id"] is None:
            fail("reference-profile-universalized", "designated reference requires an explicit family-relative scope")
        if any(item.startswith("normative-") for item in permitted):
            fail("reference-profile-universalized", "designated reference cannot issue a normative judgment")
        if provenance["reference_profile_id"] not in record["scope"]["profile_ids"]:
            fail("reference-profile-scope-mismatch", "designated reference profile must appear in the exact family-relative scope")
    if record["oracle_class"] == "O4" and not record["scope"]["profile_ids"]:
        fail("relational-profile-scope", "metamorphic relations require one exact same-profile evaluation scope")
    if record["oracle_class"] == "O6" and provenance["implementation_scope_id"] not in record["scope"]["profile_ids"]:
        fail("implementation-documentation-scope", "implementation documentation must bind the exact documented evaluation profile")
    if record["oracle_class"] == "O7" and any("conform" in item or item.startswith("normative-") for item in permitted):
        fail("historical-observation-normative", "historical characterization cannot issue a normative verdict")

    by_id, expected_roots, expected_reachable = _traverse_dependencies(record)
    if any(node["version"].strip().lower() in MUTABLE_VERSION_ALIASES for node in by_id.values()):
        fail("mutable-oracle-version", "oracle dependency nodes must bind exact versions rather than mutable aliases")
    root_nodes = [by_id[identifier] for identifier in record["dependency_graph"]["root_dependency_ids"]]
    if state == "oracle-established" and record["oracle_class"] not in {"O5", "O7", "O8"} and not expected_roots:
        fail("missing-independent-oracle-basis", "established oracle has no expected-basis root")
    expected_nodes = [by_id[identifier] for identifier in expected_reachable]
    if expected is not None and any(node["kind"] == "empirical-consensus" for node in expected_nodes):
        fail("consensus-oracle-forbidden", "consensus cannot establish expected output or correctness")
    if expected is not None and any(node["kind"] == "absence-of-authority" for node in expected_nodes):
        fail("negative-inference-from-silence", "absence of authority cannot imply rejection or unsupported behavior")
    if record["oracle_class"] in {"O1", "O2", "O3", "O6"} and any(node["kind"] in {"empirical-observation", "historical-observation"} for node in expected_nodes):
        fail("observation-as-expectation", "observation-tainted dependency path cannot establish an expected result")

    evaluated_profiles = set(record["independence"]["evaluated_profile_ids"])
    generator_domains = set(record["independence"]["stimulus_generator_authority_domain_ids"])
    for node in expected_nodes:
        if node["kind"] == "target-implementation-output" and (record["oracle_class"] in {"O1", "O2", "O3", "O6"} or evaluated_profiles.intersection(node["subject_profile_ids"])):
            fail("target-self-oracle", "target output is in its own expected-result dependency path")
        if node["authority_domain_id"] in generator_domains:
            fail("generator-self-oracle", "stimulus generator authority domain also supplies the expected answer")
    _validate_promotion(record, by_id, expected_reachable)
    required_kind = REQUIRED_CLASS_DEPENDENCY_KIND.get(record["oracle_class"])
    if required_kind is not None and not any(node["kind"] == required_kind for node in root_nodes):
        fail("oracle-class-authority-root", f"{record['oracle_class']} lacks its required {required_kind} root")


def validate_oracle_collection(root: Path, contract: dict[str, Any], records: list[dict[str, Any]], conflicts: list[dict[str, Any]]) -> None:
    for record in records:
        validate_oracle_record(root, contract, record)
    by_id = {record["oracle_id"]: record for record in records}
    if len(by_id) != len(records):
        fail("duplicate-oracle-record", "oracle record identities must be unique")
    groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["resolution_state"] == "oracle-established" and record["expected_result"] is not None and record["expected_result"]["result_type"] == "conventional":
            groups[record["requirement_scientific_id"]].append(record)
    required_pairs: set[frozenset[str]] = set()
    for requirement_id, group in groups.items():
        for left_index, left in enumerate(group):
            for right in group[left_index + 1:]:
                left_profiles = set(left["scope"]["profile_ids"])
                right_profiles = set(right["scope"]["profile_ids"])
                left_operations = set(left["scope"]["operation_scientific_ids"])
                right_operations = set(right["scope"]["operation_scientific_ids"])
                disjoint_profiles = left_profiles and right_profiles and left_profiles.isdisjoint(right_profiles)
                disjoint_operations = left_operations and right_operations and left_operations.isdisjoint(right_operations)
                same_value = canonical_bytes(left["expected_result"]["value"]) == canonical_bytes(right["expected_result"]["value"])
                if not same_value and not disjoint_profiles and not disjoint_operations:
                    required_pairs.add(frozenset((left["oracle_id"], right["oracle_id"])))
    conflict_sets: list[set[str]] = []
    for conflict in conflicts:
        if set(conflict) != {"conflict_id", "requirement_scientific_id", "oracle_ids", "resolution_state", "selected_oracle_id", "scope_overlap_basis"}:
            fail("invalid-authority-conflict", "authority conflict record has missing or unknown fields")
        identifiers = set(conflict["oracle_ids"])
        if len(identifiers) < 2 or not identifiers.issubset(by_id):
            fail("authority-conflict-closure", "conflict record must reference at least two existing oracle records")
        if {by_id[identifier]["requirement_scientific_id"] for identifier in identifiers} != {conflict["requirement_scientific_id"]}:
            fail("authority-conflict-requirement", "conflicting oracle records must answer the same semantic requirement")
        if conflict["resolution_state"] != "conflicting-authoritative-expectations" or conflict["selected_oracle_id"] is not None:
            fail("authority-conflict-overwritten", "authority conflict cannot have an automatic winner")
        if not conflict["scope_overlap_basis"]:
            fail("authority-conflict-scope", "conflict record must explain the overlapping applicability scope")
        if not any(pair.issubset(identifiers) for pair in required_pairs):
            fail("spurious-authority-conflict", "conflict record does not contain an overlapping incompatible expectation pair")
        conflict_sets.append(identifiers)
    for pair in required_pairs:
        if not any(set(pair).issubset(identifiers) for identifiers in conflict_sets):
            fail("unrepresented-authority-conflict", "overlapping incompatible legitimate expectations must survive in an explicit conflict record")


def validate_vector_binding(root: Path, contract: dict[str, Any], binding: dict[str, Any], records: Iterable[dict[str, Any]]) -> None:
    validate_instance(binding, load_strict(root / VECTOR_BINDING_SCHEMA_PATH), source="oracle vector binding")
    if binding["contract_ref"] != {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]}:
        fail("frozen-binding-contract", "vector binding does not freeze the exact oracle contract")
    if binding["mutable_latest_alias_used"]:
        fail("mutable-oracle-alias", "mutable latest aliases cannot be frozen campaign inputs")
    by_id = {item["oracle_id"]: item for item in records}
    for reference in binding["oracle_refs"]:
        record = by_id.get(reference["oracle_id"])
        if record is None or reference["oracle_digest_sha256"] != record["oracle_digest_sha256"]:
            fail("frozen-oracle-drift", "frozen vector binding references a missing or changed oracle revision")
    body = {key: value for key, value in binding.items() if key not in {"binding_id", "binding_digest_sha256"}}
    if binding["binding_digest_sha256"] != _digest(body) or binding["binding_id"] != _content_id(root, "expectation-projection", "oracle-vector-binding-v1", body):
        fail("oracle-binding-identity", "vector binding identity or digest differs")


def _dependency(label: str, kind: str, role: str, *, upstream: list[str] | None = None, authority: str | None = None, profiles: list[str] | None = None, evaluator: bool = False) -> dict[str, Any]:
    return {
        "dependency_id": f"urn:strling:oracle-fixture:{label}",
        "kind": kind,
        "semantic_role": role,
        "authority_domain_id": authority or f"urn:strling:authority:{label}",
        "version": "fixture-v1",
        "content_digest_sha256": _digest({"fixture": label, "kind": kind}),
        "upstream_dependency_ids": upstream or [],
        "subject_profile_ids": profiles or [],
        "semantic_evaluator": evaluator,
    }


def _base_record(root: Path, contract: dict[str, Any], requirement_id: str, oracle_class: str, provenance: dict[str, Any], dependency: dict[str, Any], *, scope_profiles: list[str] | None = None, family_id: str | None = None, expected: dict[str, Any] | None = None, state: str = "oracle-established") -> dict[str, Any]:
    spec = ORACLE_CLASSES[oracle_class]
    body = {
        "schema_version": "oracle-record.v1",
        "oracle_record_version": "1.0.0",
        "contract_ref": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "requirement_scientific_id": requirement_id,
        "oracle_class": oracle_class,
        "resolution_state": state,
        "scope": {
            "kind": spec["scope_kind"],
            "operation_scientific_ids": [],
            "profile_ids": scope_profiles or [],
            "profile_family_id": family_id,
            "semantic_assertion_revision_ids": ["rcid:v1:finding-revision:h:jcs-sha256-v1:" + "1" * 64],
        },
        "applicability_conditions": {"operator": "all", "clauses": [{"field": "requirement.scientific-id", "operator": "equals", "value": requirement_id}]},
        "provenance": provenance,
        "dependency_graph": {"nodes": [dependency], "root_dependency_ids": [dependency["dependency_id"]]},
        "independence": {"evaluated_profile_ids": scope_profiles or [], "stimulus_generator_authority_domain_ids": ["urn:strling:authority:fixture-generator"], "requires_independent_basis": oracle_class in {"O1", "O2", "O3", "O6"}},
        "permitted_judgments": spec["permitted_judgments"],
        "expected_result": expected,
        "promotion_event": None,
        "derivation": _contract_derivation(root),
    }
    return finalize_oracle_record(root, body)


def build_fixtures(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    requirements = load_strict(root / REQUIREMENT_PATH)["requirements"]
    by_capability = {}
    for capability in CLASS_COMPATIBILITY:
        by_capability[capability] = min((item for item in requirements if item["expected_oracle_capability"] == capability), key=lambda item: item["scientific_id"])["scientific_id"]
    profile = "rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7"
    family = "rcid:v1:profile-family:u7:019ff982-e97c-7a8b-a8bb-a28cfe33bcce"
    digest = "2" * 64
    records = [
        _base_record(root, contract, by_capability["normative-expected-outcome"], "O1", {"source_identity": "unicode-tr18", "source_version": "Revision 25", "locator": "RL1.2", "claim_revision_id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "2" * 64, "scope_statement": "Pinned normative fixture scope.", "derivation_revision_id": _contract_derivation(root)["derivation_revision_id"]}, _dependency("o1-source", "normative-source-proposition", "expected-basis"), expected={"result_type": "conventional", "value": {"match": True}, "scope_statement": "Normative fixture expectation."}),
        _base_record(root, contract, by_capability["normative-expected-outcome"], "O2", {"construction_identity": "urn:strling:formal:dfa-membership", "construction_version": "1.0.0", "assumptions": ["regular-language subset"], "domain_restrictions": ["finite Unicode scalar alphabet fixture"], "witness_digest_sha256": digest, "independent_checker_identity": "urn:strling:formal:checker-b"}, _dependency("o2-construction", "formal-construction", "expected-basis"), expected={"result_type": "conventional", "value": {"match": True}, "scope_statement": "Formal fixture expectation."}),
        _base_record(root, contract, by_capability["normative-expected-outcome"], "O3", {"data_source_identity": "unicode-uax44", "data_version": "17.0.0", "data_digest_sha256": digest, "algorithm_identity": "urn:strling:algorithm:property-membership", "algorithm_version": "1.0.0", "scope_statement": "Pinned Unicode property membership fixture."}, _dependency("o3-data", "authoritative-dataset", "expected-basis"), expected={"result_type": "conventional", "value": {"match": True}, "scope_statement": "Data-derived fixture expectation."}),
        _base_record(root, contract, by_capability["relational-comparison"], "O4", {"relation_identity": "urn:strling:relation:quoting-round-trip", "relation_version": "1.0.0", "source_construction_ids": ["urn:strling:construction:source"], "follow_up_construction_ids": ["urn:strling:construction:follow-up"], "applicability_gates": ["same applicable profile and operation"], "permitted_conclusion": "Violation establishes a discrepancy; satisfaction establishes only this relation."}, _dependency("o4-relation", "relation-definition", "expected-basis"), scope_profiles=[profile], expected={"result_type": "relation", "value": {"operator": "equal-observations"}, "scope_statement": "Same-profile necessary relation."}),
        _base_record(root, contract, by_capability["relational-comparison"], "O5", {"reference_profile_id": profile, "designation_source_id": "urn:strling:decision:reference-fixture", "reason_designated": "Fixture reference for one family-relative comparison.", "comparison_scope": "One implementation family and declared backend transition.", "carve_outs": ["No external normative conclusion"]}, _dependency("o5-reference", "designated-reference-profile", "comparison-input", profiles=[profile]), scope_profiles=[profile], family_id=family, expected=None),
        _base_record(root, contract, by_capability["profile-documentation-outcome"], "O6", {"documentation_identity": "python-re", "documentation_version": "3.14", "locator": "re.Pattern.search", "implementation_scope_id": profile, "claim_revision_id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "3" * 64, "scope_statement": "Exact documented profile fixture."}, _dependency("o6-doc", "implementation-documentation", "expected-basis", profiles=[profile]), scope_profiles=[profile], expected={"result_type": "conventional", "value": {"match": False}, "scope_statement": "Implementation-documentation fixture expectation."}),
        _base_record(root, contract, by_capability["characterization-record"], "O7", {"source_observation_id": "rcid:v1:observation:u7:019fffff-ffff-7fff-bfff-fffffffffff1", "evidence_manifest_id": "rcid:v1:evidence-manifest:h:jcs-sha256-v1:" + "4" * 64, "observed_on": "2025-01-01", "reproduction_scope": "Exact preserved historical profile fixture.", "historical_claim_revision_id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "5" * 64}, _dependency("o7-history", "historical-observation", "historical-subject", profiles=[profile]), scope_profiles=[profile], expected=None),
        _base_record(root, contract, by_capability["characterization-record"], "O8", {"research_gap_id": "urn:strling:research-gap:fixture", "searched_source_ids": ["unicode-tr18"], "reason_no_correctness_oracle": "The fixture intentionally has no authority that selects one expected result.", "scope_statement": "Characterization-only fixture."}, _dependency("o8-gap", "research-claim", "context-only"), expected=None, state="characterization-only"),
    ]
    first = records[0]
    binding_body = {
        "schema_version": "oracle-vector-binding.v1",
        "vector_revision_id": "rcid:v1:vector-revision:h:jcs-sha256-v1:" + "6" * 64,
        "semantic_requirement_id": first["requirement_scientific_id"],
        "contract_ref": first["contract_ref"],
        "oracle_refs": [{"oracle_id": first["oracle_id"], "oracle_digest_sha256": first["oracle_digest_sha256"]}],
        "resolution_state": "oracle-established",
        "frozen_at": "2026-09-10T12:00:00Z",
        "campaign_definition_revision_id": "rcid:v1:campaign-definition-revision:h:jcs-sha256-v1:" + "7" * 64,
        "mutable_latest_alias_used": False,
    }
    binding = _finalize(root, binding_body, namespace="expectation-projection", artifact_kind="oracle-vector-binding-v1", id_field="binding_id", digest_field="binding_digest_sha256")
    invalid = [
        {"case_id": "majority-vote-expected", "base_class": "O1", "expected_error": "consensus-oracle-forbidden"},
        {"case_id": "target-output-self-oracle", "base_class": "O1", "expected_error": "target-self-oracle"},
        {"case_id": "generator-evaluator-self-oracle", "base_class": "O2", "expected_error": "generator-self-oracle"},
        {"case_id": "observation-promotion-without-basis", "base_class": "O1", "expected_error": "observation-promotion-without-independent-authority"},
        {"case_id": "indirect-observation-claim-expectation", "base_class": "O1", "expected_error": "observation-as-expectation"},
        {"case_id": "reference-profile-universalized", "base_class": "O5", "expected_error": "oracle-scope-class-mismatch"},
        {"case_id": "unspecified-means-unsupported", "base_class": "O1", "expected_error": "negative-inference-from-silence"},
        {"case_id": "historical-observation-normative", "base_class": "O7", "expected_error": "oracle-judgment-escalation"},
        {"case_id": "missing-version-provenance", "base_class": "O3", "expected_error": "oracle-provenance-fields"},
        {"case_id": "dependency-cycle", "base_class": "O2", "expected_error": "oracle-dependency-cycle"},
    ]
    body = {
        "schema_version": "oracle-validation-fixtures.v1",
        "published_on": PUBLISHED_ON,
        "contract_ref": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "valid_oracles": records,
        "frozen_vector_binding": binding,
        "invalid_cases": invalid,
        "authority_conflicts": [],
        "derivation": _contract_derivation(root),
    }
    return _finalize(root, body, namespace="expectation-projection", artifact_kind="oracle-validation-fixtures-v1", id_field="fixture_set_id", digest_field="fixture_set_digest_sha256")


def _invalid_record(root: Path, contract: dict[str, Any], fixture: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    base = deepcopy(next(item for item in fixture["valid_oracles"] if item["oracle_class"] == case["base_class"]))
    code = case["case_id"]
    nodes = base["dependency_graph"]["nodes"]
    root_node = nodes[0]
    if code == "majority-vote-expected":
        root_node["kind"] = "empirical-consensus"
    elif code == "target-output-self-oracle":
        profile = "rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7"
        base["independence"]["evaluated_profile_ids"] = [profile]
        root_node["kind"] = "target-implementation-output"
        root_node["subject_profile_ids"] = [profile]
    elif code == "generator-evaluator-self-oracle":
        root_node["kind"] = "generator"
        root_node["semantic_evaluator"] = True
        root_node["authority_domain_id"] = base["independence"]["stimulus_generator_authority_domain_ids"][0]
    elif code == "observation-promotion-without-basis":
        observation = _dependency("invalid-promotion-observation", "empirical-observation", "promotion-source")
        nodes.append(observation)
        base["dependency_graph"]["root_dependency_ids"].append(observation["dependency_id"])
        base["promotion_event"] = {"source_observation_id": observation["dependency_id"], "promoter_id": "reviewer-a", "reviewer_id": "reviewer-b", "promoted_at": "2026-09-10", "justification": "Invalid fixture lacks independent basis.", "independent_oracle_basis_dependency_ids": [observation["dependency_id"]], "target_expectation_revision_id": "rcid:v1:expectation-projection:h:jcs-sha256-v1:" + "8" * 64}
    elif code == "indirect-observation-claim-expectation":
        observation = _dependency("indirect-observation", "empirical-observation", "context-only")
        root_node["kind"] = "research-claim"
        root_node["upstream_dependency_ids"] = [observation["dependency_id"]]
        nodes.append(observation)
    elif code == "reference-profile-universalized":
        base["scope"]["kind"] = "external-normative"
        base["scope"]["profile_family_id"] = None
    elif code == "unspecified-means-unsupported":
        root_node["kind"] = "absence-of-authority"
        base["expected_result"]["value"] = {"unsupported": True}
    elif code == "historical-observation-normative":
        base["permitted_judgments"] = ["normative-conformant"]
    elif code == "missing-version-provenance":
        base["provenance"].pop("data_version")
    elif code == "dependency-cycle":
        root_node["upstream_dependency_ids"] = [root_node["dependency_id"]]
    return finalize_oracle_record(root, base)


def validate_fixtures(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> dict[str, int]:
    validate_instance(fixture, load_strict(root / FIXTURE_SCHEMA_PATH), source=FIXTURE_PATH.as_posix())
    body = {key: value for key, value in fixture.items() if key not in {"fixture_set_id", "fixture_set_digest_sha256"}}
    if fixture["fixture_set_digest_sha256"] != _digest(body) or fixture["fixture_set_id"] != _content_id(root, "expectation-projection", "oracle-validation-fixtures-v1", body):
        fail("oracle-fixture-identity", "oracle fixture identity or digest differs")
    if fixture["derivation"] != _contract_derivation(root):
        fail("oracle-fixture-derivation", "oracle fixture set does not bind the governed derivation revision")
    validate_oracle_collection(root, contract, fixture["valid_oracles"], fixture["authority_conflicts"])
    if {item["oracle_class"] for item in fixture["valid_oracles"]} != set(ORACLE_CLASSES):
        fail("oracle-fixture-class-coverage", "valid fixtures must cover O1 through O8")
    validate_vector_binding(root, contract, fixture["frozen_vector_binding"], fixture["valid_oracles"])
    rejected = 0
    for case in fixture["invalid_cases"]:
        try:
            validate_oracle_record(root, contract, _invalid_record(root, contract, fixture, case))
        except ConformanceDataError as error:
            if error.code != case["expected_error"]:
                fail("oracle-fixture-wrong-error", f"{case['case_id']} expected {case['expected_error']} but got {error.code}")
            rejected += 1
        else:
            fail("oracle-fixture-not-rejected", f"prohibited case {case['case_id']} unexpectedly validated")
    return {"valid_oracle_classes": len(fixture["valid_oracles"]), "prohibited_cases_rejected": rejected}


def build_report(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    result = validate_fixtures(root, contract, fixture)
    body = {
        "schema_version": "oracle-foundation-report.v1",
        "published_on": PUBLISHED_ON,
        "claim_scope": "Machine validation of the oracle taxonomy, class-specific provenance, judgment boundaries, dependency traversal, circularity guards, conflict preservation, and immutable vector binding; not applicability, adjudication, waiver, production-vector, or scientific certification authority.",
        "contract": {"path": CONTRACT_PATH.as_posix(), "artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"]},
        "fixtures": {"path": FIXTURE_PATH.as_posix(), "artifact_id": fixture["fixture_set_id"], "digest_sha256": fixture["fixture_set_digest_sha256"]},
        "implementation_bindings": [
            {"path": path.as_posix(), "file_sha256": _sha(root / path)}
            for path in IMPLEMENTATION_PATHS
        ],
        "counts": {
            "oracle_classes": len(contract["oracle_classes"]),
            "resolution_states": len(contract["resolution_states"]),
            "circularity_guards": len(contract["circularity_guards"]),
            "valid_class_fixtures": result["valid_oracle_classes"],
            "prohibited_cases_rejected": result["prohibited_cases_rejected"],
        },
        "checks": [
            {"check_id": "class-functions-not-ranking", "status": "PASS"},
            {"check_id": "class-specific-provenance", "status": "PASS"},
            {"check_id": "permitted-judgment-boundaries", "status": "PASS"},
            {"check_id": "transitive-dependency-circularity", "status": "PASS"},
            {"check_id": "consensus-generator-target-guards", "status": "PASS"},
            {"check_id": "under-specification-and-conflict-survival", "status": "PASS"},
            {"check_id": "historical-expectation-freeze", "status": "PASS"},
            {"check_id": "semantic-requirement-compatibility", "status": "PASS"},
        ],
        "denominator_boundary": {"obligations": 2390, "requirements": 3378, "modified": False, "profile_expanded_execution_denominator": "deferred"},
        "result": "PASS",
        "derivation": _contract_derivation(root),
    }
    return _finalize(root, body, namespace="trust-assessment", artifact_kind="oracle-foundation-report-v1", id_field="report_id", digest_field="report_digest_sha256")


def build_authority(root: Path, contract: dict[str, Any], fixture: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    requirement = load_strict(root / REQUIREMENT_PATH)
    body = {
        "schema_version": "oracle-authority-index.v1",
        "current_contract": {"path": CONTRACT_PATH.as_posix(), "artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"], "file_sha256": _sha(root / CONTRACT_PATH)},
        "validation_fixture": {"path": FIXTURE_PATH.as_posix(), "artifact_id": fixture["fixture_set_id"], "digest_sha256": fixture["fixture_set_digest_sha256"], "file_sha256": _sha(root / FIXTURE_PATH)},
        "foundation_report": {"path": REPORT_PATH.as_posix(), "artifact_id": report["report_id"], "digest_sha256": report["report_digest_sha256"], "file_sha256": _sha(root / REPORT_PATH)},
        "semantic_requirement_authority": {"path": REQUIREMENT_PATH.as_posix(), "artifact_id": requirement["snapshot_id"], "digest_sha256": requirement["snapshot_digest_sha256"], "file_sha256": _sha(root / REQUIREMENT_PATH)},
        "historical_compatibility": {"existing_observations_rewritten": False, "existing_campaigns_reinterpreted": False, "mutable_latest_alias_is_certified_input": False, "migration_rule": "prospective-versioned-no-rewrite"},
        "next_interfaces": {"applicability": "deferred", "claims_and_adjudication": "deferred", "waivers": "deferred", "production_vectors": "deferred"},
        "governance": "Repository oracle records and frozen bindings own machine-operational expectation authority; sources remain authoritative for their own propositions, observations remain empirical, and later adjudication must preserve conflicts.",
        "derivation": _contract_derivation(root),
    }
    return _finalize(root, body, namespace="artifact-set-manifest", artifact_kind="oracle-authority-index-v1", id_field="index_id", digest_field="index_digest_sha256")


def _validate_finalized(root: Path, record: dict[str, Any], schema_path: Path, *, namespace: str, artifact_kind: str, id_field: str, digest_field: str, source: str) -> None:
    validate_instance(record, load_strict(root / schema_path), source=source)
    body = {key: value for key, value in record.items() if key not in {id_field, digest_field}}
    if record[digest_field] != _digest(body) or record[id_field] != _content_id(root, namespace, artifact_kind, body):
        fail("oracle-artifact-identity", f"{source} ID or digest differs from exact content")


def verify_current(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    allocation = load_strict(root / ALLOCATION_PATH)
    validate_instance(allocation, load_strict(root / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_PATH.as_posix())
    if allocation != build_allocation():
        fail("oracle-allocation-drift", "oracle identity allocation differs")
    contract = load_strict(root / CONTRACT_PATH)
    validate_contract(root, contract)
    fixture = load_strict(root / FIXTURE_PATH)
    fixture_counts = validate_fixtures(root, contract, fixture)
    if fixture != build_fixtures(root, contract):
        fail("oracle-fixture-drift", "tracked oracle fixtures differ from deterministic construction")
    report = load_strict(root / REPORT_PATH)
    _validate_finalized(root, report, REPORT_SCHEMA_PATH, namespace="trust-assessment", artifact_kind="oracle-foundation-report-v1", id_field="report_id", digest_field="report_digest_sha256", source=REPORT_PATH.as_posix())
    if report != build_report(root, contract, fixture) or report["result"] != "PASS":
        fail("oracle-report-drift", "tracked oracle report differs from fresh validation")
    authority = load_strict(root / AUTHORITY_PATH)
    _validate_finalized(root, authority, AUTHORITY_SCHEMA_PATH, namespace="artifact-set-manifest", artifact_kind="oracle-authority-index-v1", id_field="index_id", digest_field="index_digest_sha256", source=AUTHORITY_PATH.as_posix())
    if authority != build_authority(root, contract, fixture, report):
        fail("oracle-authority-drift", "oracle authority index differs from exact current artifacts")
    if broad_foundations:
        identity = verify_identity_catalog(root)
        derivation = verify_derivation_catalog(root)
        identity_count = identity["scientific_identities"]
        derivation_groups = derivation["generated_assertion_groups"]
    else:
        identity_count = len(load_strict(root / "registries/identity/scientific-identities.v1.json")["bindings"])
        derivation_groups = load_strict(root / DERIVATION_CATALOG_PATH)["coverage_summary"]["assertion_groups"]
    requirement = load_strict(root / REQUIREMENT_PATH)
    if len(requirement["requirements"]) != 3378:
        fail("oracle-denominator-mutation", "oracle work must not change the canonical requirement denominator")
    return {
        "result": report["result"],
        "contract_id": contract["contract_id"],
        "report_id": report["report_id"],
        "oracle_classes": fixture_counts["valid_oracle_classes"],
        "guards": len(contract["circularity_guards"]),
        "prohibited_cases_rejected": fixture_counts["prohibited_cases_rejected"],
        "requirements": len(requirement["requirements"]),
        "scientific_identities": identity_count,
        "derivation_groups": derivation_groups,
    }


def _write(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        fail("oracle-artifact-write", "oracle artifact failed read-after-write", path.as_posix())


def materialize(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    _write(root / ALLOCATION_PATH, build_allocation())
    contract = build_contract(root)
    _write(root / CONTRACT_PATH, contract)
    fixture = build_fixtures(root, contract)
    _write(root / FIXTURE_PATH, fixture)
    report = build_report(root, contract, fixture)
    _write(root / REPORT_PATH, report)
    authority = build_authority(root, contract, fixture, report)
    _write(root / AUTHORITY_PATH, authority)
    return verify_current(root, broad_foundations=broad_foundations)
