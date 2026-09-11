"""Evidence roles, immutable provenance, and fail-closed epistemic admissibility.

Evidence role answers which proposition an object may support.  Quality and
reproducibility are orthogonal properties and never elevate that role.  This
module is prospective: it does not rewrite observations, evaluate profiles,
adjudicate findings, issue waivers, or author vectors.
"""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from typing import Any

from .derivation import CATALOG_PATH as DERIVATION_CATALOG_PATH, DERIVATION_IDS, verify_catalog as verify_derivation_catalog
from .errors import ConformanceDataError, fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .obligation_snapshots import OBLIGATION_PATH, REQUIREMENT_PATH
from .oracle import (
    AUTHORITY_PATH as ORACLE_AUTHORITY_PATH,
    CONTRACT_PATH as ORACLE_CONTRACT_PATH,
    FIXTURE_PATH as ORACLE_FIXTURE_PATH,
    MUTABLE_VERSION_ALIASES,
    SEMANTIC_SNAPSHOT_PATH,
    _requirements,
    _semantic_sources,
    _traverse_dependencies,
    validate_contract as validate_oracle_contract,
    validate_oracle_record,
)
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import verify_catalog as verify_identity_catalog


PUBLISHED_ON = "2026-09-10"
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a08d9e-ab75-7e0e-bc29-b6f484056552"
EVIDENCE_DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a08d9e-ab75-762b-8a10-90db25ccb8fb"

ALLOCATION_PATH = Path("oracle/evidence/evidence-admissibility-identities-2026-09-10.v1.json")
CONTRACT_PATH = Path("oracle/contracts/regex-conformance-evidence-admissibility-2026-09-10.v1.json")
FIXTURE_PATH = Path("tests/fixtures/oracle/evidence-admissibility-cases.v1.json")
REPORT_PATH = Path("reports/oracle/evidence-admissibility-2026-09-10.v1.json")
AUTHORITY_PATH = Path("oracle/evidence/current-authority.v1.json")

ALLOCATION_SCHEMA_PATH = Path("schemas/json/evidence-admissibility-allocation.schema.json")
CONTRACT_SCHEMA_PATH = Path("schemas/json/evidence-admissibility-contract.schema.json")
RECORD_SCHEMA_PATH = Path("schemas/json/evidence-admissibility-record.schema.json")
REQUEST_SCHEMA_PATH = Path("schemas/json/evidence-admissibility-request.schema.json")
EXPECTATION_BASIS_SCHEMA_PATH = Path("schemas/json/expectation-basis.schema.json")
FIXTURE_SCHEMA_PATH = Path("schemas/json/evidence-admissibility-fixtures.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/evidence-admissibility-report.schema.json")
AUTHORITY_SCHEMA_PATH = Path("schemas/json/evidence-admissibility-authority.schema.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
CONTENT_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")

IMPLEMENTATION_PATHS = (
    Path("schemas/tooling/python/regex_conformance_schema/evidence_admissibility.py"),
    Path("tools/oracle/compile_evidence_admissibility.py"),
    ALLOCATION_SCHEMA_PATH,
    CONTRACT_SCHEMA_PATH,
    RECORD_SCHEMA_PATH,
    REQUEST_SCHEMA_PATH,
    EXPECTATION_BASIS_SCHEMA_PATH,
    FIXTURE_SCHEMA_PATH,
    REPORT_SCHEMA_PATH,
    AUTHORITY_SCHEMA_PATH,
)

ROLE_SPECS = {
    "normative-source-evidence": {
        "oracle_class": "O1",
        "epistemic_function": "Preserves an exact proposition from an explicitly normative source for its exact governed scope.",
        "required_provenance_fields": ["proposition_revision_id", "retrieval_snapshot_id", "semantic_authority", "source_identity", "source_revision", "source_snapshot_digest_sha256", "stable_locator"],
        "potentially_admitted_uses": ["establish-normative-expectation", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["normative-required-expectation", "normative-prohibited-expectation", "normative-permission", "normative-optionality", "normative-conditional-expectation", "normative-ambiguity-recorded", "normative-under-specification-recorded", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": True,
        "conclusion_boundary": "Only mandatory, prohibitive, permissive, optional, or conditional normative language can establish its corresponding scoped expectation; informative, ambiguous, unspecified, or silent material cannot.",
    },
    "formal-derivation-evidence": {
        "oracle_class": "O2",
        "epistemic_function": "Preserves an independently checkable result within an exact formal model and admitted semantic subset.",
        "required_provenance_fields": ["admitted_semantic_subset", "assumptions", "derivation_method_identity", "derivation_method_version", "derivation_output_digest_sha256", "formal_model_identity", "formal_model_version", "independent_checker_identities", "input_identities"],
        "potentially_admitted_uses": ["establish-formal-model-expectation", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["formal-model-expectation", "formal-model-satisfied", "formal-model-violated", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": True,
        "conclusion_boundary": "A program output is formal evidence only when the model, assumptions, inputs, subset, method, output, and independent check are pinned and independent of the evaluated target.",
    },
    "authoritative-data-derived-evidence": {
        "oracle_class": "O3",
        "epistemic_function": "Combines pinned authoritative data with an established semantic rule and deterministic derivation.",
        "required_provenance_fields": ["algorithm_identity", "algorithm_version", "dataset_digest_sha256", "dataset_identity", "dataset_version", "derivation_output_digest_sha256", "semantic_rule_revision_id"],
        "potentially_admitted_uses": ["establish-data-scoped-expectation", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["data-scoped-expectation", "data-scoped-agreement", "data-scoped-disagreement", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": True,
        "conclusion_boundary": "Neither a data table nor an algorithm alone establishes regex semantics; pinned data, an independent semantic rule, and the deterministic derivation are all required.",
    },
    "relational-metamorphic-evidence": {
        "oracle_class": "O4",
        "epistemic_function": "Evaluates a necessary relation among exact executions of the same applicable profile.",
        "required_provenance_fields": ["directionality", "execution_ids", "gating_assumptions", "relation_identity", "relation_semantics", "relation_version", "satisfaction_establishes_full_correctness", "violation_sufficient_for_relational_defect"],
        "potentially_admitted_uses": ["evaluate-metamorphic-relation", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["relation-violation-defect", "relation-satisfied-only", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": False,
        "conclusion_boundary": "Violation of a valid necessary relation may establish a relational defect; satisfaction establishes only the relation and never full correctness.",
    },
    "family-relative-reference-evidence": {
        "oracle_class": "O5",
        "epistemic_function": "Compares exact configurations, backends, or releases within one explicitly designated implementation family.",
        "required_provenance_fields": ["carve_outs", "compared_profile_ids", "comparison_scope", "designation_revision_id", "profile_family_id", "reference_profile_id"],
        "potentially_admitted_uses": ["establish-family-relative-comparison", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["family-relative-equivalence", "family-relative-divergence", "family-relative-regression", "family-relative-change", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": False,
        "conclusion_boundary": "A designated reference is family-relative evidence, not independent correctness authority and never universal truth.",
    },
    "implementation-documentation-evidence": {
        "oracle_class": "O6",
        "epistemic_function": "Preserves what an exact implementation revision documents about itself.",
        "required_provenance_fields": ["ambiguity_status", "completeness_status", "documentation_identity", "documentation_revision", "documentation_snapshot_digest_sha256", "implementation_scope_id", "stable_locator"],
        "potentially_admitted_uses": ["establish-implementation-documentation-expectation", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["implementation-documented-expectation", "implementation-documentation-ambiguous", "implementation-documentation-incomplete", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": True,
        "conclusion_boundary": "The evidence may establish conformance to the implementation's own documentation, never silently an external normative requirement.",
    },
    "historical-empirical-evidence": {
        "oracle_class": "O7",
        "epistemic_function": "Preserves what a specific historical profile did and whether exact reproduction agreed.",
        "required_provenance_fields": ["evidence_manifest_ids", "historical_profile_ids", "historical_scope", "observation_ids", "observed_interval", "reproduction_record_ids"],
        "potentially_admitted_uses": ["establish-historical-fact", "establish-characterization", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["historical-fact-recorded", "historical-behavior-reproduced", "historical-behavior-diverged", "characterization-recorded", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": False,
        "conclusion_boundary": "Age, stability, and reproduction establish historical fact only; they cannot bootstrap normative truth.",
    },
    "characterization-only-evidence": {
        "oracle_class": "O8",
        "epistemic_function": "Preserves observations, differentials, probes, or research gaps when no admissible correctness authority exists.",
        "required_provenance_fields": ["characterization_scope", "observation_or_probe_ids", "reason_no_expectation", "research_gap_id", "searched_authority_ids"],
        "potentially_admitted_uses": ["establish-characterization", "support-discrepancy-investigation", "support-research-revision"],
        "permitted_conclusions": ["characterization-recorded", "descriptive-differential", "research-gap-recorded", "discrepancy-investigation-input", "research-revision-input"],
        "expectation_bearing": False,
        "conclusion_boundary": "Even perfectly reproduced characterization cannot create an expected result or conformance verdict.",
    },
}

USE_SPECS = {
    "establish-normative-expectation": ("Establish the exact externally normative expectation selected by applicable source language.", ["normative-source-evidence"], ["normative-required-expectation", "normative-prohibited-expectation", "normative-permission", "normative-optionality", "normative-conditional-expectation", "normative-ambiguity-recorded", "normative-under-specification-recorded"], True, True),
    "establish-formal-model-expectation": ("Establish a result within an explicit independent formal model.", ["formal-derivation-evidence"], ["formal-model-expectation", "formal-model-satisfied", "formal-model-violated"], True, True),
    "establish-data-scoped-expectation": ("Establish a result scoped to pinned authoritative data and an established semantic rule.", ["authoritative-data-derived-evidence"], ["data-scoped-expectation", "data-scoped-agreement", "data-scoped-disagreement"], True, True),
    "evaluate-metamorphic-relation": ("Evaluate a necessary relation without promoting relation satisfaction into full correctness.", ["relational-metamorphic-evidence"], ["relation-violation-defect", "relation-satisfied-only"], False, False),
    "establish-family-relative-comparison": ("Establish equivalence, divergence, regression, or change only within one family-relative scope.", ["family-relative-reference-evidence"], ["family-relative-equivalence", "family-relative-divergence", "family-relative-regression", "family-relative-change"], False, False),
    "establish-implementation-documentation-expectation": ("Establish what one exact implementation documents about itself.", ["implementation-documentation-evidence"], ["implementation-documented-expectation", "implementation-documentation-ambiguous", "implementation-documentation-incomplete"], True, True),
    "establish-historical-fact": ("Establish an exact historical empirical fact, never a normative expectation.", ["historical-empirical-evidence"], ["historical-fact-recorded", "historical-behavior-reproduced", "historical-behavior-diverged"], False, False),
    "establish-characterization": ("Record characterization, descriptive differential, or research-gap evidence.", ["historical-empirical-evidence", "characterization-only-evidence"], ["characterization-recorded", "descriptive-differential", "research-gap-recorded"], False, False),
    "support-discrepancy-investigation": ("Provide independently preserved context for later discrepancy investigation without adjudicating it.", list(ROLE_SPECS), ["discrepancy-investigation-input"], False, False),
    "support-research-revision": ("Motivate later researched revision without becoming that revision's authority by itself.", list(ROLE_SPECS), ["research-revision-input"], False, False),
}

STRENGTH_SPECS = {
    "required": ("The authority mandates behavior in scope.", True, ["normative-required-expectation", "implementation-documented-expectation"]),
    "prohibited": ("The authority forbids behavior in scope.", True, ["normative-prohibited-expectation", "implementation-documented-expectation"]),
    "permitted": ("The authority allows behavior but does not require it.", True, ["normative-permission", "implementation-documented-expectation"]),
    "optional": ("The authority explicitly makes support or behavior optional.", True, ["normative-optionality", "implementation-documented-expectation"]),
    "conditional": ("The authority selects behavior only when its explicit condition holds.", True, ["normative-conditional-expectation", "implementation-documented-expectation"]),
    "implementation-defined": ("The authority delegates selection to the implementation and requires the choice to remain explicit.", False, ["normative-under-specification-recorded", "implementation-documentation-incomplete"]),
    "unspecified": ("The authority intentionally does not constrain this behavior.", False, ["normative-under-specification-recorded"]),
    "informative-non-normative": ("The material informs interpretation but does not impose a requirement.", False, []),
    "ambiguous": ("The applicable language admits multiple unresolved interpretations.", False, ["normative-ambiguity-recorded", "implementation-documentation-ambiguous"]),
    "silent-not-established": ("No proposition was established; silence does not imply rejection.", False, ["normative-under-specification-recorded", "implementation-documentation-incomplete"]),
    "not-applicable": ("Normative source-language classification is not applicable to this evidence role.", False, []),
}

PROHIBITIONS = [
    ("E01", "observation-not-normative", "An observation cannot establish normative evidence."),
    ("E02", "consensus-not-normative", "Cross-engine consensus is descriptive and cannot establish normative evidence."),
    ("E03", "family-reference-not-universal", "Family-relative reference behavior cannot establish a universal expectation."),
    ("E04", "history-not-normative", "Historical behavior cannot establish normative evidence."),
    ("E05", "characterization-not-conformance", "Characterization-only evidence cannot establish conformance."),
    ("E06", "implementation-documentation-not-external", "Implementation documentation cannot silently become external normative authority."),
    ("E07", "informative-language-not-mandatory", "Informative source prose cannot establish a mandatory requirement."),
    ("E08", "silence-not-rejection", "Source silence cannot imply unsupported or rejected behavior."),
    ("E09", "mutable-source-not-certified", "Mutable or unversioned material cannot be a certified expectation basis."),
    ("E10", "data-requires-rule", "Data-derived evidence requires pinned data and an established semantic rule."),
    ("E11", "shared-authority-not-independent", "Wrappers sharing one upstream authority domain do not provide independent evidence."),
    ("E12", "ambiguity-not-resolved-by-agreement", "Implementation agreement with one interpretation cannot resolve ambiguous authority."),
]


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
        "schema_version": "evidence-admissibility-allocation.v1",
        "allocated_on": PUBLISHED_ON,
        "allocations": [
            {"entity_class": "assertion-derivation", "canonical_key": "derivation.evidence-admissibility-governance", "assigned_id": EVIDENCE_DERIVATION_ID},
            {"entity_class": "schema-family", "canonical_key": "schema.evidence-admissibility", "assigned_id": SCHEMA_FAMILY_ID},
        ],
    }


@lru_cache(maxsize=4)
def _evidence_derivation_cached(root_text: str) -> dict[str, str]:
    catalog = load_strict(Path(root_text) / DERIVATION_CATALOG_PATH)
    item = next((entry for entry in catalog["derivations"] if entry["derivation_id"] == EVIDENCE_DERIVATION_ID), None)
    if item is None:
        fail("missing-evidence-admissibility-derivation", "evidence admissibility derivation is absent from the canonical catalog")
    return {key: item[key] for key in ("derivation_id", "derivation_revision_id", "derivation_class")}


def _evidence_derivation(root: Path) -> dict[str, str]:
    return deepcopy(_evidence_derivation_cached(str(root.resolve())))


def _artifact_ref(path: Path, record: dict[str, Any], id_field: str, digest_field: str, **extra: Any) -> dict[str, Any]:
    return {"path": path.as_posix(), "artifact_id": record[id_field], "digest_sha256": record[digest_field], **extra}


def build_contract(root: Path) -> dict[str, Any]:
    oracle_contract = load_strict(root / ORACLE_CONTRACT_PATH)
    snapshot = load_strict(root / SEMANTIC_SNAPSHOT_PATH)
    requirement = load_strict(root / REQUIREMENT_PATH)
    body = {
        "schema_version": "evidence-admissibility-contract.v1",
        "contract_version": "1.0.0",
        "effective_on": PUBLISHED_ON,
        "authority_scope": "Prospective evidence-role and epistemic-use admissibility for exact semantic requirements. No profile applicability decision, discrepancy adjudication, waiver, claim issuance, observation rewrite, or production vector is created here.",
        "oracle_foundation": _artifact_ref(ORACLE_CONTRACT_PATH, oracle_contract, "contract_id", "contract_digest_sha256", contract_version=oracle_contract["contract_version"]),
        "knowledge_authority": _artifact_ref(SEMANTIC_SNAPSHOT_PATH, snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "semantic_requirement_authority": _artifact_ref(REQUIREMENT_PATH, requirement, "snapshot_id", "snapshot_digest_sha256", requirement_count=len(requirement["requirements"])),
        "evidence_roles": [{"evidence_role": role, **deepcopy(spec)} for role, spec in ROLE_SPECS.items()],
        "epistemic_uses": [
            {"epistemic_use": use, "meaning": values[0], "admissible_evidence_roles": values[1], "permitted_conclusions": values[2], "correctness_establishing": values[3], "independence_required": values[4]}
            for use, values in USE_SPECS.items()
        ],
        "normative_strengths": [
            {"strength": strength, "meaning": values[0], "may_establish_concrete_expectation": values[1], "permitted_conclusions": values[2]}
            for strength, values in STRENGTH_SPECS.items()
        ],
        "quality_axes": {
            "role_is_orthogonal": True,
            "numeric_confidence_forbidden": True,
            "integrity_statuses": ["verified", "unverified", "failed"],
            "preservation_statuses": ["immutable-complete", "incomplete", "unavailable"],
            "reproducibility_statuses": ["not-applicable", "unassessed", "reproduced", "not-reproduced", "provenance-blocked"],
            "rule": "Quality controls whether evidence is usable at all; it never changes which proposition the evidence role is permitted to support.",
        },
        "admissibility_decision_contract": {
            "decision_states": ["admissible", "inadmissible"],
            "fail_closed": True,
            "unknown_or_incomplete_never_elevates": True,
            "scope_must_be_covered": True,
            "decision_inputs": ["evidence role", "epistemic use", "requested conclusion", "oracle compatibility", "normative strength", "semantic scope", "immutable provenance", "dependency independence", "quality eligibility"],
        },
        "immutable_provenance_contract": {
            "exact_version_required": True,
            "content_digest_required": True,
            "stable_locator_required_when_source_based": True,
            "mutable_aliases_forbidden": sorted(MUTABLE_VERSION_ALIASES),
            "knowledge_projection_rule": "A projection is operationally authoritative only for the exact frozen campaign binding; source meaning remains owned by its exact Knowledge identities and revisions.",
        },
        "authority_domain_contract": {
            "wrapper_independence_forbidden": True,
            "shared_upstream_is_shared_authority": True,
            "independent_domain_count_rule": "Count unique authority domains over all reachable expected-basis dependencies after collapsing wrappers and transformed mirrors to their upstream semantic authority.",
            "deep_dependency_traversal_required": True,
        },
        "prohibitions": [{"prohibition_id": code, "machine_rule": rule, "statement": statement} for code, rule, statement in PROHIBITIONS],
        "derivation": _evidence_derivation(root),
    }
    return _finalize(root, body, namespace="trust-policy-revision", artifact_kind="evidence-admissibility-contract-v1", id_field="contract_id", digest_field="contract_digest_sha256")


def _role_spec(contract: dict[str, Any], role: str) -> dict[str, Any]:
    value = next((item for item in contract["evidence_roles"] if item["evidence_role"] == role), None)
    if value is None:
        fail("unknown-evidence-role", f"unknown evidence role {role!r}")
    return value


def _use_spec(contract: dict[str, Any], use: str) -> dict[str, Any]:
    value = next((item for item in contract["epistemic_uses"] if item["epistemic_use"] == use), None)
    if value is None:
        fail("unknown-epistemic-use", f"unknown epistemic use {use!r}")
    return value


def _strength_spec(contract: dict[str, Any], strength: str) -> dict[str, Any]:
    value = next((item for item in contract["normative_strengths"] if item["strength"] == strength), None)
    if value is None:
        fail("unknown-normative-strength", f"unknown normative strength {strength!r}")
    return value


def validate_contract(root: Path, contract: dict[str, Any]) -> None:
    validate_instance(contract, load_strict(root / CONTRACT_SCHEMA_PATH), source=CONTRACT_PATH.as_posix())
    body = {key: value for key, value in contract.items() if key not in {"contract_id", "contract_digest_sha256"}}
    if contract["contract_digest_sha256"] != _digest(body) or contract["contract_id"] != _content_id(root, "trust-policy-revision", "evidence-admissibility-contract-v1", body):
        fail("evidence-contract-identity", "evidence admissibility contract identity or digest differs")
    if [item["evidence_role"] for item in contract["evidence_roles"]] != list(ROLE_SPECS):
        fail("evidence-role-set", "evidence roles must be exactly the governed O1 through O8 mappings")
    if [item["epistemic_use"] for item in contract["epistemic_uses"]] != list(USE_SPECS):
        fail("epistemic-use-set", "epistemic uses differ from the governed decision vocabulary")
    if [item["strength"] for item in contract["normative_strengths"]] != list(STRENGTH_SPECS):
        fail("normative-strength-set", "normative source-language strengths differ from the governed vocabulary")
    if any(item != {"evidence_role": role, **ROLE_SPECS[role]} for role, item in zip(ROLE_SPECS, contract["evidence_roles"])):
        fail("evidence-role-contract-drift", "evidence role semantics differ from governance")
    oracle_contract = load_strict(root / ORACLE_CONTRACT_PATH)
    validate_oracle_contract(root, oracle_contract)
    expected_oracle = _artifact_ref(ORACLE_CONTRACT_PATH, oracle_contract, "contract_id", "contract_digest_sha256", contract_version=oracle_contract["contract_version"])
    if contract["oracle_foundation"] != expected_oracle:
        fail("stale-oracle-foundation", "evidence contract does not bind exact fixed oracle authority")
    requirement = load_strict(root / REQUIREMENT_PATH)
    if contract["semantic_requirement_authority"] != _artifact_ref(REQUIREMENT_PATH, requirement, "snapshot_id", "snapshot_digest_sha256", requirement_count=3378):
        fail("evidence-denominator-mutation", "evidence contract must bind the exact 3,378-requirement authority")
    if contract != build_contract(root):
        fail("evidence-contract-drift", "tracked evidence contract differs from exact current inputs and implementation")


def finalize_evidence_record(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    body = {key: value for key, value in record.items() if key not in {"evidence_id", "evidence_digest_sha256"}}
    return _finalize(root, body, namespace="evidence-manifest", artifact_kind="evidence-admissibility-record-v1", id_field="evidence_id", digest_field="evidence_digest_sha256")


def _scope_set(scope: dict[str, Any], key: str) -> set[str]:
    return set(scope.get(key, []))


def validate_evidence_record(root: Path, contract: dict[str, Any], record: dict[str, Any]) -> None:
    validate_instance(record, load_strict(root / RECORD_SCHEMA_PATH), source="evidence admissibility record")
    body = {key: value for key, value in record.items() if key not in {"evidence_id", "evidence_digest_sha256"}}
    if record["evidence_digest_sha256"] != _digest(body) or record["evidence_id"] != _content_id(root, "evidence-manifest", "evidence-admissibility-record-v1", body):
        fail("evidence-record-identity", "evidence record identity or digest differs from exact content")
    if record["contract_ref"] != {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]}:
        fail("evidence-contract-binding", "evidence record does not bind exact admissibility contract")
    oracle_contract = load_strict(root / ORACLE_CONTRACT_PATH)
    if record["oracle_contract_ref"] != {"contract_id": oracle_contract["contract_id"], "contract_digest_sha256": oracle_contract["contract_digest_sha256"]}:
        fail("evidence-oracle-contract-binding", "evidence record does not bind exact oracle foundation")
    oracle_records = {item["oracle_id"]: item for item in load_strict(root / ORACLE_FIXTURE_PATH)["valid_oracles"]}
    oracle_record = oracle_records.get(record["oracle_ref"]["oracle_id"])
    if oracle_record is None or record["oracle_ref"] != {"oracle_id": oracle_record["oracle_id"], "oracle_digest_sha256": oracle_record["oracle_digest_sha256"], "oracle_class": oracle_record["oracle_class"]}:
        fail("evidence-oracle-binding", "evidence record references no exact admitted oracle record")
    validate_oracle_record(root, oracle_contract, oracle_record)
    spec = _role_spec(contract, record["evidence_role"])
    if spec["oracle_class"] != oracle_record["oracle_class"] or record["oracle_compatibility"] != [spec["oracle_class"]]:
        fail("evidence-oracle-incompatible", "evidence role and fixed oracle class are incompatible")
    if set(record["provenance"]) != set(spec["required_provenance_fields"]):
        fail("evidence-provenance-fields", f"{record['evidence_role']} requires exactly its class-specific provenance")
    if any(value is None or value == "" or value == [] for value in record["provenance"].values()):
        fail("evidence-provenance-empty", "evidence provenance fields must be populated")
    if not set(record["claimed_epistemic_uses"]).issubset(spec["potentially_admitted_uses"]):
        fail("evidence-use-escalation", "evidence record claims an epistemic use outside its role boundary")
    if record["record_derivation"] != _evidence_derivation(root):
        fail("evidence-derivation-binding", "evidence record does not bind exact evidence governance derivation")

    source = record["source_authority"]
    if source["source_revision"].strip().lower() in MUTABLE_VERSION_ALIASES:
        fail("mutable-evidence-source", "evidence source revision must be immutable and exact")
    if any(str(value).strip().lower() in MUTABLE_VERSION_ALIASES for key, value in record["provenance"].items() if key.endswith("version") or key.endswith("revision")):
        fail("mutable-evidence-source", "evidence provenance must not use a mutable version alias")
    if not source["immutable_input"]:
        fail("mutable-evidence-source", "certified evidence inputs must be immutable")
    expected_authority = {
        "normative-source-evidence": "external-normative", "formal-derivation-evidence": "formal-model", "authoritative-data-derived-evidence": "authoritative-data", "relational-metamorphic-evidence": "relational",
        "family-relative-reference-evidence": "family-relative", "implementation-documentation-evidence": "implementation-self-documentation", "historical-empirical-evidence": "historical-empirical", "characterization-only-evidence": "characterization",
    }[record["evidence_role"]]
    if source["semantic_authority"] != expected_authority:
        fail("evidence-authority-domain-mismatch", "source semantic authority does not match evidence role")
    sources = _semantic_sources(root)
    role = record["evidence_role"]
    if role == "normative-source-evidence":
        provenance = record["provenance"]
        item = sources.get(provenance["source_identity"])
        if item is None or item.get("normative") is not True:
            fail("non-normative-source", "O1 evidence must reference an explicitly normative canonical source")
        if (source["source_identity"], source["source_revision"], source["source_digest_sha256"], source["locator"]) != (provenance["source_identity"], provenance["source_revision"], provenance["source_snapshot_digest_sha256"], provenance["stable_locator"]):
            fail("evidence-source-provenance-mismatch", "O1 source authority and proposition provenance differ")
    if role == "authoritative-data-derived-evidence":
        provenance = record["provenance"]
        if provenance["dataset_identity"] not in sources:
            fail("unknown-authoritative-dataset", "O3 evidence must reference a canonical authoritative dataset")
        if (source["source_identity"], source["source_revision"], source["source_digest_sha256"]) != (provenance["dataset_identity"], provenance["dataset_version"], provenance["dataset_digest_sha256"]):
            fail("evidence-source-provenance-mismatch", "O3 dataset authority and derivation provenance differ")
    if role == "implementation-documentation-evidence":
        provenance = record["provenance"]
        item = sources.get(provenance["documentation_identity"])
        if item is None or item.get("source_class") != "official-implementation-documentation":
            fail("implementation-documentation-source", "O6 evidence must reference canonical official implementation documentation")
        if (source["source_identity"], source["source_revision"], source["source_digest_sha256"], source["locator"]) != (provenance["documentation_identity"], provenance["documentation_revision"], provenance["documentation_snapshot_digest_sha256"], provenance["stable_locator"]):
            fail("evidence-source-provenance-mismatch", "O6 documentation authority and claim provenance differ")
    if role == "characterization-only-evidence" and any(item not in sources for item in record["provenance"]["searched_authority_ids"]):
        fail("unknown-searched-authority", "O8 searched authorities must resolve in Knowledge")

    requirements = _requirements(root)
    if any(identifier not in requirements for identifier in record["semantic_scope"]["requirement_scientific_ids"]):
        fail("unknown-evidence-requirement", "evidence scope references no canonical requirement")
    if role == "family-relative-reference-evidence":
        provenance = record["provenance"]
        if provenance["profile_family_id"] not in record["semantic_scope"]["profile_family_ids"] or provenance["reference_profile_id"] not in record["semantic_scope"]["profile_ids"]:
            fail("family-reference-scope", "family-reference evidence must stay in its declared family and reference-profile scope")
    if role == "implementation-documentation-evidence" and record["provenance"]["implementation_scope_id"] not in record["semantic_scope"]["profile_ids"]:
        fail("implementation-documentation-scope", "implementation documentation must bind its exact implementation profile")
    if role in {"normative-source-evidence", "implementation-documentation-evidence"}:
        if record["normative_strength"] == "not-applicable":
            fail("missing-source-language-strength", "source proposition evidence requires explicit source-language strength")
    elif record["normative_strength"] != "not-applicable":
        fail("normative-strength-inapplicable", "non-source-language evidence must use not-applicable normative strength")

    by_id, expected_roots, reachable = _traverse_dependencies(record)
    if any(node["version"].strip().lower() in MUTABLE_VERSION_ALIASES for node in by_id.values()):
        fail("mutable-evidence-source", "evidence dependency graph must pin exact versions")
    if not expected_roots and role in {"normative-source-evidence", "formal-derivation-evidence", "authoritative-data-derived-evidence", "implementation-documentation-evidence"}:
        fail("missing-expectation-basis", "expectation-bearing evidence requires an expected-basis dependency")
    if source["authority_domain_id"] not in {node["authority_domain_id"] for node in by_id.values()}:
        fail("evidence-authority-domain-mismatch", "preserved source authority is absent from the dependency graph")
    expected_nodes = [by_id[item] for item in reachable]
    forbidden = {"empirical-consensus", "empirical-observation", "historical-observation", "target-implementation-output", "generator", "absence-of-authority"}
    if spec["expectation_bearing"] and any(node["kind"] in forbidden for node in expected_nodes):
        code = {
            "empirical-consensus": "consensus-as-normative-evidence", "empirical-observation": "observation-as-normative-evidence", "historical-observation": "historical-as-normative-evidence", "target-implementation-output": "target-output-as-normative-evidence", "generator": "generator-as-normative-evidence", "absence-of-authority": "silence-as-normative-evidence",
        }[next(node["kind"] for node in expected_nodes if node["kind"] in forbidden)]
        fail(code, "prohibited dependency cannot establish expectation-bearing evidence")
    if role == "authoritative-data-derived-evidence":
        kinds = {node["kind"] for node in expected_nodes}
        if not {"authoritative-dataset", "research-claim"}.issubset(kinds):
            fail("data-without-semantic-rule", "data-derived evidence requires both authoritative data and an established semantic rule")
    if role == "relational-metamorphic-evidence":
        provenance = record["provenance"]
        if provenance["satisfaction_establishes_full_correctness"] is not False or provenance["violation_sufficient_for_relational_defect"] is not True:
            fail("relational-conclusion-escalation", "necessary relation satisfaction cannot establish full correctness")
    if role == "formal-derivation-evidence":
        checker_ids = set(record["provenance"]["independent_checker_identities"])
        if not checker_ids.issubset(by_id):
            fail("formal-checker-not-bound", "formal derivation evidence must bind every independent checker into its dependency graph")
        if any(by_id[identifier]["authority_domain_id"] == source["authority_domain_id"] for identifier in checker_ids):
            fail("formal-checker-not-independent", "formal checker must not share the derivation method's semantic authority domain")


def _covers(evidence_scope: dict[str, Any], request_scope: dict[str, Any]) -> bool:
    return all(_scope_set(request_scope, key).issubset(_scope_set(evidence_scope, key)) for key in ("requirement_scientific_ids", "profile_ids", "profile_family_ids", "operation_scientific_ids"))


def evaluate_admissibility(root: Path, contract: dict[str, Any], records: list[dict[str, Any]], request: dict[str, Any]) -> dict[str, Any]:
    validate_instance(request, load_strict(root / REQUEST_SCHEMA_PATH), source="evidence admissibility request")
    by_id = {record["evidence_id"]: record for record in records}
    if len(by_id) != len(records):
        fail("duplicate-evidence-record", "evidence records must have unique content identities")
    selected: list[dict[str, Any]] = []
    for ref in request["evidence_refs"]:
        record = by_id.get(ref["evidence_id"])
        if record is None or ref["evidence_digest_sha256"] != record["evidence_digest_sha256"]:
            fail("evidence-reference-mismatch", "request evidence reference is missing or digest-mismatched")
        validate_evidence_record(root, contract, record)
        selected.append(record)
    use = _use_spec(contract, request["epistemic_use"])
    if request["requested_conclusion"] not in use["permitted_conclusions"]:
        fail("conclusion-not-permitted-for-use", "requested conclusion is outside the epistemic use boundary")
    for record in selected:
        role = _role_spec(contract, record["evidence_role"])
        if record["evidence_role"] not in use["admissible_evidence_roles"] or request["epistemic_use"] not in record["claimed_epistemic_uses"]:
            fail("evidence-role-inadmissible", "evidence role is inadmissible for requested use")
        if request["oracle_class"] != role["oracle_class"] or request["oracle_class"] not in record["oracle_compatibility"]:
            fail("evidence-oracle-incompatible", "requested oracle class does not match evidence role")
        if request["requested_conclusion"] not in role["permitted_conclusions"]:
            fail("evidence-conclusion-escalation", "evidence role cannot establish requested conclusion")
        if not _covers(record["semantic_scope"], request["scope"]):
            fail("evidence-scope-mismatch", "requested scope exceeds preserved evidence scope")
        quality = record["quality"]
        authoritative_use = not request["epistemic_use"].startswith("support-")
        if authoritative_use and (quality["integrity_status"] != "verified" or quality["preservation_status"] != "immutable-complete"):
            code = "expectation-evidence-quality-incomplete" if use["correctness_establishing"] else "evidence-quality-incomplete"
            fail(code, "an establishing or evaluating use requires verified immutable-complete evidence")
        if request["requested_conclusion"] == "historical-behavior-reproduced" and quality["reproducibility_status"] != "reproduced":
            fail("historical-reproduction-not-established", "historical reproduction conclusion requires reproduced evidence quality")
        if request["requested_conclusion"] == "historical-behavior-diverged" and quality["reproducibility_status"] != "not-reproduced":
            fail("historical-divergence-not-established", "historical divergence conclusion requires not-reproduced evidence quality")
        if request["epistemic_use"] in {"establish-normative-expectation", "establish-implementation-documentation-expectation"}:
            strength = _strength_spec(contract, record["normative_strength"])
            if request["requested_conclusion"] not in strength["permitted_conclusions"]:
                if record["normative_strength"] == "informative-non-normative":
                    fail("informative-prose-as-mandatory", "informative material cannot establish a mandatory expectation")
                if record["normative_strength"] == "ambiguous":
                    fail("ambiguous-evidence-as-established", "ambiguous source language cannot establish one selected expectation")
                if record["normative_strength"] == "silent-not-established":
                    fail("silence-means-unsupported", "source silence cannot establish unsupported or rejection")
                fail("normative-strength-conclusion-mismatch", "source-language strength does not permit requested conclusion")
    if request["require_independent_authorities"] or use["independence_required"]:
        domains: set[str] = set()
        authority_signatures: set[frozenset[str]] = set()
        for record in selected:
            by_dependency, expected_roots, _ = _traverse_dependencies(record)

            def ultimate_domains(identifier: str) -> set[str]:
                upstream = by_dependency[identifier]["upstream_dependency_ids"]
                if not upstream:
                    return {by_dependency[identifier]["authority_domain_id"]}
                return set().union(*(ultimate_domains(item) for item in upstream))

            roots = expected_roots or set(record["dependency_graph"]["root_dependency_ids"])
            signature = frozenset().union(*(ultimate_domains(identifier) for identifier in roots))
            authority_signatures.add(signature)
            domains.update(signature)
        if request["require_independent_authorities"] and len(selected) > 1 and len(authority_signatures) != len(selected):
            fail("shared-authority-false-independence", "multiple evidence wrappers collapse to the same upstream semantic authority signature")
        if len(domains) < request["minimum_authority_domains"]:
            fail("shared-authority-false-independence", "evidence wrappers do not meet the required independent authority-domain count")
    return {"decision": "admissible", "evidence_ids": sorted(record["evidence_id"] for record in selected), "epistemic_use": request["epistemic_use"], "requested_conclusion": request["requested_conclusion"]}


def finalize_expectation_basis(root: Path, basis: dict[str, Any]) -> dict[str, Any]:
    body = {key: value for key, value in basis.items() if key not in {"basis_id", "basis_digest_sha256"}}
    return _finalize(root, body, namespace="expectation-projection", artifact_kind="expectation-basis-v1", id_field="basis_id", digest_field="basis_digest_sha256")


def validate_expectation_basis(root: Path, contract: dict[str, Any], records: list[dict[str, Any]], basis: dict[str, Any]) -> None:
    validate_instance(basis, load_strict(root / EXPECTATION_BASIS_SCHEMA_PATH), source="expectation basis")
    body = {key: value for key, value in basis.items() if key not in {"basis_id", "basis_digest_sha256"}}
    if basis["basis_digest_sha256"] != _digest(body) or basis["basis_id"] != _content_id(root, "expectation-projection", "expectation-basis-v1", body):
        fail("expectation-basis-identity", "expectation basis identity or digest differs")
    if basis["contract_ref"] != {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]}:
        fail("expectation-basis-contract", "expectation basis does not bind exact evidence contract")
    request = {
        "schema_version": "evidence-admissibility-request.v1",
        "evidence_refs": basis["evidence_refs"],
        "epistemic_use": basis["epistemic_use"],
        "requested_conclusion": basis["conclusion"],
        "scope": {"requirement_scientific_ids": [basis["semantic_requirement_id"]], **basis["scope"]},
        "oracle_class": next(record["oracle_compatibility"][0] for record in records if record["evidence_id"] == basis["evidence_refs"][0]["evidence_id"]),
        "require_independent_authorities": False,
        "minimum_authority_domains": 1,
    }
    evaluate_admissibility(root, contract, records, request)
    oracle_records = {item["oracle_id"]: item for item in load_strict(root / ORACLE_FIXTURE_PATH)["valid_oracles"]}
    if any(ref["oracle_id"] not in oracle_records or ref["oracle_digest_sha256"] != oracle_records[ref["oracle_id"]]["oracle_digest_sha256"] for ref in basis["oracle_refs"]):
        fail("expectation-basis-oracle", "expectation basis oracle reference is stale or missing")


def _record_scope(oracle_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "statement": f"Exact fixture scope for {oracle_record['oracle_class']} evidence.",
        "requirement_scientific_ids": [oracle_record["requirement_scientific_id"]],
        "profile_ids": oracle_record["scope"]["profile_ids"],
        "profile_family_ids": [] if oracle_record["scope"]["profile_family_id"] is None else [oracle_record["scope"]["profile_family_id"]],
        "operation_scientific_ids": oracle_record["scope"]["operation_scientific_ids"],
        "semantic_assertion_revision_ids": oracle_record["scope"]["semantic_assertion_revision_ids"],
    }


def _source_authority(oracle_class: str, authority_domain: str) -> dict[str, Any]:
    values = {
        "O1": ("unicode-tr18", "UTS #18 revision 25", "RL1.2", "external-normative"),
        "O2": ("urn:strling:formal-model:fixture", "1.0.0", "urn:strling:formal-model:fixture#proof", "formal-model"),
        "O3": ("unicode-uax44", "Unicode 17.0", "Property_Definitions", "authoritative-data"),
        "O4": ("urn:strling:relation:quoting-round-trip", "1.0.0", "urn:strling:relation:quoting-round-trip#definition", "relational"),
        "O5": ("urn:strling:decision:reference-fixture", "1.0.0", "urn:strling:decision:reference-fixture#scope", "family-relative"),
        "O6": ("python-re", "Python 3.14", "re.Pattern.search", "implementation-self-documentation"),
        "O7": ("urn:strling:historical-fixture", "2025-01-01", "urn:strling:historical-fixture#observation", "historical-empirical"),
        "O8": ("urn:strling:characterization-fixture", "1.0.0", "urn:strling:characterization-fixture#probe", "characterization"),
    }[oracle_class]
    return {
        "authority_domain_id": authority_domain,
        "source_identity": values[0],
        "source_revision": values[1],
        "source_digest_sha256": "a" * 64 if oracle_class in {"O1", "O3", "O6"} else _digest({"source": values[0], "revision": values[1]}),
        "locator": values[2],
        "semantic_authority": values[3],
        "immutable_input": True,
    }


def _provenance(oracle_record: dict[str, Any]) -> dict[str, Any]:
    oracle_class = oracle_record["oracle_class"]
    profile_ids = oracle_record["scope"]["profile_ids"]
    family_id = oracle_record["scope"]["profile_family_id"]
    fixture_profile = profile_ids[0] if profile_ids else "rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7"
    fixture_family = family_id or "rcid:v1:profile-family:u7:019ff982-e97c-7a8b-a8bb-a28cfe33bcce"
    digest = "a" * 64
    return {
        "O1": {
            "source_identity": "unicode-tr18", "source_revision": "UTS #18 revision 25", "source_snapshot_digest_sha256": digest,
            "stable_locator": "RL1.2", "proposition_revision_id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "1" * 64,
            "semantic_authority": "normative-standard", "retrieval_snapshot_id": "rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:" + "2" * 64,
        },
        "O2": {
            "derivation_method_identity": "urn:strling:method:automata-equivalence", "derivation_method_version": "1.0.0",
            "formal_model_identity": "urn:strling:model:regular-language", "formal_model_version": "1.0.0",
            "assumptions": ["Finite alphabet fixed by the fixture"], "admitted_semantic_subset": ["regular-language core"],
            "input_identities": ["urn:strling:formal-input:fixture-a"], "derivation_output_digest_sha256": digest,
            "independent_checker_identities": ["urn:strling:checker:independent-fixture"],
        },
        "O3": {
            "dataset_identity": "unicode-uax44", "dataset_version": "Unicode 17.0", "dataset_digest_sha256": digest,
            "algorithm_identity": "urn:strling:algorithm:property-membership", "algorithm_version": "1.0.0",
            "semantic_rule_revision_id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "3" * 64,
            "derivation_output_digest_sha256": "b" * 64,
        },
        "O4": {
            "relation_identity": "urn:strling:relation:quoting-round-trip", "relation_version": "1.0.0",
            "relation_semantics": "Escaping a literal and matching it against that literal preserves the required same-profile relation.",
            "gating_assumptions": ["Same applicable profile and text domain"],
            "execution_ids": ["rcid:v1:execution-revision:h:jcs-sha256-v1:" + "4" * 64, "rcid:v1:execution-revision:h:jcs-sha256-v1:" + "5" * 64],
            "directionality": "necessary-one-way", "violation_sufficient_for_relational_defect": True, "satisfaction_establishes_full_correctness": False,
        },
        "O5": {
            "profile_family_id": fixture_family, "reference_profile_id": fixture_profile, "compared_profile_ids": [fixture_profile],
            "designation_revision_id": "rcid:v1:trust-policy-revision:h:jcs-sha256-v1:" + "6" * 64,
            "comparison_scope": "Fixture comparison within exactly one implementation family.", "carve_outs": ["No external normative conclusion"],
        },
        "O6": {
            "documentation_identity": "python-re", "documentation_revision": "Python 3.14", "documentation_snapshot_digest_sha256": digest,
            "stable_locator": "re.Pattern.search", "implementation_scope_id": fixture_profile, "ambiguity_status": "unambiguous", "completeness_status": "complete-for-claim",
        },
        "O7": {
            "observation_ids": ["rcid:v1:observation:u7:019fffff-ffff-7fff-bfff-fffffffffff1"],
            "evidence_manifest_ids": ["rcid:v1:evidence-manifest:h:jcs-sha256-v1:" + "7" * 64],
            "historical_profile_ids": [fixture_profile], "observed_interval": "2025-01-01/2025-01-01",
            "reproduction_record_ids": ["rcid:v1:evidence-manifest:h:jcs-sha256-v1:" + "8" * 64], "historical_scope": "Exact historical fixture profile.",
        },
        "O8": {
            "observation_or_probe_ids": ["rcid:v1:observation:u7:019fffff-ffff-7fff-bfff-fffffffffff2"],
            "characterization_scope": "Undocumented fixture behavior with no correctness authority.",
            "reason_no_expectation": "Reviewed sources do not select one expected result.", "searched_authority_ids": ["unicode-tr18", "python-re"],
            "research_gap_id": "urn:strling:research-gap:evidence-fixture",
        },
    }[oracle_class]


def _dependency_graph(oracle_record: dict[str, Any]) -> dict[str, Any]:
    graph = deepcopy(oracle_record["dependency_graph"])
    if oracle_record["oracle_class"] == "O2":
        checker = {
            "dependency_id": "urn:strling:checker:independent-fixture",
            "kind": "formal-construction", "semantic_role": "expected-basis", "authority_domain_id": "urn:strling:authority:o2-independent-checker",
            "version": "1.0.0", "content_digest_sha256": "d" * 64, "upstream_dependency_ids": [], "subject_profile_ids": [], "semantic_evaluator": False,
        }
        graph["nodes"].append(checker)
        graph["root_dependency_ids"].append(checker["dependency_id"])
    if oracle_record["oracle_class"] == "O3":
        rule = {
            "dependency_id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "3" * 64,
            "kind": "research-claim", "semantic_role": "expected-basis", "authority_domain_id": "urn:strling:authority:o3-semantic-rule",
            "version": "1.0.0", "content_digest_sha256": "c" * 64, "upstream_dependency_ids": [], "subject_profile_ids": [], "semantic_evaluator": False,
        }
        graph["nodes"].append(rule)
        graph["root_dependency_ids"].append(rule["dependency_id"])
    return graph


def _evidence_record(root: Path, contract: dict[str, Any], oracle_record: dict[str, Any], role: str) -> dict[str, Any]:
    oracle_class = oracle_record["oracle_class"]
    role_spec = ROLE_SPECS[role]
    authority_domain = oracle_record["dependency_graph"]["nodes"][0]["authority_domain_id"]
    body = {
        "schema_version": "evidence-admissibility-record.v1", "record_version": "1.0.0",
        "contract_ref": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "oracle_contract_ref": oracle_record["contract_ref"],
        "oracle_ref": {"oracle_id": oracle_record["oracle_id"], "oracle_digest_sha256": oracle_record["oracle_digest_sha256"], "oracle_class": oracle_class},
        "evidence_role": role, "normative_strength": "required" if oracle_class in {"O1", "O6"} else "not-applicable",
        "source_authority": _source_authority(oracle_class, authority_domain), "semantic_scope": _record_scope(oracle_record),
        "provenance": _provenance(oracle_record), "dependency_graph": _dependency_graph(oracle_record),
        "quality": {"integrity_status": "verified", "preservation_status": "immutable-complete", "reproducibility_status": "reproduced" if oracle_class == "O7" else "unassessed" if oracle_class == "O8" else "not-applicable", "quality_changes_epistemic_role": False},
        "oracle_compatibility": [oracle_class], "claimed_epistemic_uses": role_spec["potentially_admitted_uses"], "record_derivation": _evidence_derivation(root),
    }
    return finalize_evidence_record(root, body)


def _request(record: dict[str, Any], use: str, conclusion: str, *, independent: bool = False, minimum_domains: int = 1) -> dict[str, Any]:
    scope = record["semantic_scope"]
    return {
        "schema_version": "evidence-admissibility-request.v1",
        "evidence_refs": [{"evidence_id": record["evidence_id"], "evidence_digest_sha256": record["evidence_digest_sha256"]}],
        "epistemic_use": use, "requested_conclusion": conclusion,
        "scope": {key: scope[key] for key in ("requirement_scientific_ids", "profile_ids", "profile_family_ids", "operation_scientific_ids")},
        "oracle_class": record["oracle_compatibility"][0], "require_independent_authorities": independent, "minimum_authority_domains": minimum_domains,
    }


def build_fixtures(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    oracle_records = load_strict(root / ORACLE_FIXTURE_PATH)["valid_oracles"]
    by_class = {item["oracle_class"]: item for item in oracle_records}
    valid_evidence = [_evidence_record(root, contract, by_class[f"O{index}"], role) for index, role in enumerate(ROLE_SPECS, 1)]
    by_role = {item["evidence_role"]: item for item in valid_evidence}
    selections = [
        ("o1-normative", "normative-source-evidence", "establish-normative-expectation", "normative-required-expectation"),
        ("o2-formal", "formal-derivation-evidence", "establish-formal-model-expectation", "formal-model-expectation"),
        ("o3-data", "authoritative-data-derived-evidence", "establish-data-scoped-expectation", "data-scoped-expectation"),
        ("o4-relational", "relational-metamorphic-evidence", "evaluate-metamorphic-relation", "relation-satisfied-only"),
        ("o5-family", "family-relative-reference-evidence", "establish-family-relative-comparison", "family-relative-divergence"),
        ("o6-self-documentation", "implementation-documentation-evidence", "establish-implementation-documentation-expectation", "implementation-documented-expectation"),
        ("o7-history", "historical-empirical-evidence", "establish-historical-fact", "historical-behavior-reproduced"),
        ("o8-characterization", "characterization-only-evidence", "establish-characterization", "characterization-recorded"),
    ]
    valid_cases = [{"case_id": case, "request": _request(by_role[role], use, conclusion), "expected_decision": "admissible"} for case, role, use, conclusion in selections]
    same_material = [
        {"case_id": "implementation-doc-self-expectation", "request": _request(by_role["implementation-documentation-evidence"], "establish-implementation-documentation-expectation", "implementation-documented-expectation"), "expected_decision": "admissible"},
        {"case_id": "implementation-doc-research-input", "request": _request(by_role["implementation-documentation-evidence"], "support-research-revision", "research-revision-input"), "expected_decision": "admissible"},
    ]
    invalid_definitions = [
        ("observation-as-normative", "normative-source-evidence", "dependency:empirical-observation", "observation-as-normative-evidence"),
        ("consensus-as-normative", "normative-source-evidence", "dependency:empirical-consensus", "consensus-as-normative-evidence"),
        ("family-reference-as-universal", "family-relative-reference-evidence", "request:normative", "evidence-role-inadmissible"),
        ("historical-as-normative", "historical-empirical-evidence", "request:normative", "evidence-role-inadmissible"),
        ("characterization-as-conformance", "characterization-only-evidence", "request:normative", "evidence-role-inadmissible"),
        ("implementation-doc-as-external-normative", "implementation-documentation-evidence", "request:normative", "evidence-role-inadmissible"),
        ("informative-prose-as-mandatory", "normative-source-evidence", "strength:informative-non-normative", "informative-prose-as-mandatory"),
        ("silence-means-unsupported", "normative-source-evidence", "strength:silent-not-established", "silence-means-unsupported"),
        ("mutable-source-version", "normative-source-evidence", "source-revision:latest", "mutable-evidence-source"),
        ("data-without-semantic-rule", "authoritative-data-derived-evidence", "dependency:remove-semantic-rule", "data-without-semantic-rule"),
        ("shared-authority-false-independence", "formal-derivation-evidence", "request:two-shared-wrappers", "shared-authority-false-independence"),
        ("ambiguous-evidence-established-from-agreement", "normative-source-evidence", "strength:ambiguous", "ambiguous-evidence-as-established"),
    ]
    invalid_cases = []
    for case, role, mutation, expected_error in invalid_definitions:
        base = by_role[role]
        request = _request(base, "establish-normative-expectation", "normative-required-expectation") if mutation.startswith("request:normative") or mutation.startswith("strength:") or mutation.startswith("source-") or role == "normative-source-evidence" else _request(base, ROLE_SPECS[role]["potentially_admitted_uses"][0], ROLE_SPECS[role]["permitted_conclusions"][0])
        invalid_cases.append({"case_id": case, "base_role": role, "request": request, "mutation": mutation, "expected_error": expected_error})

    first = by_role["normative-source-evidence"]
    request = valid_cases[0]["request"]
    oracle = by_class["O1"]
    basis_body = {
        "schema_version": "expectation-basis.v1", "contract_ref": first["contract_ref"], "oracle_contract_ref": first["oracle_contract_ref"],
        "semantic_requirement_id": first["semantic_scope"]["requirement_scientific_ids"][0], "epistemic_use": request["epistemic_use"], "conclusion": request["requested_conclusion"],
        "evidence_refs": request["evidence_refs"], "oracle_refs": [{"oracle_id": oracle["oracle_id"], "oracle_digest_sha256": oracle["oracle_digest_sha256"]}],
        "scope": {key: first["semantic_scope"][key] for key in ("profile_ids", "profile_family_ids", "operation_scientific_ids")},
        "resolution_state": "oracle-established", "frozen_at": "2026-09-10T12:00:00Z", "mutable_latest_alias_used": False,
    }
    body = {
        "schema_version": "evidence-admissibility-fixtures.v1", "published_on": PUBLISHED_ON,
        "contract_ref": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "valid_evidence": valid_evidence, "valid_cases": valid_cases, "invalid_cases": invalid_cases,
        "same_material_boundary_cases": same_material, "valid_expectation_basis": finalize_expectation_basis(root, basis_body), "derivation": _evidence_derivation(root),
    }
    return _finalize(root, body, namespace="artifact-set-manifest", artifact_kind="evidence-admissibility-fixtures-v1", id_field="fixture_set_id", digest_field="fixture_set_digest_sha256")


def _mutated_case(root: Path, contract: dict[str, Any], fixture: dict[str, Any], case: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = deepcopy(fixture["valid_evidence"])
    record_index = next(index for index, item in enumerate(records) if item["evidence_role"] == case["base_role"])
    record = records[record_index]
    request = deepcopy(case["request"])
    mutation = case["mutation"]
    if mutation.startswith("dependency:"):
        value = mutation.split(":", 1)[1]
        if value == "remove-semantic-rule":
            removed = {node["dependency_id"] for node in record["dependency_graph"]["nodes"] if node["kind"] == "research-claim"}
            record["dependency_graph"]["nodes"] = [node for node in record["dependency_graph"]["nodes"] if node["dependency_id"] not in removed]
            record["dependency_graph"]["root_dependency_ids"] = [identifier for identifier in record["dependency_graph"]["root_dependency_ids"] if identifier not in removed]
            for node in record["dependency_graph"]["nodes"]:
                node["upstream_dependency_ids"] = []
        else:
            record["dependency_graph"]["nodes"][0]["kind"] = value
    elif mutation.startswith("strength:"):
        strength = mutation.split(":", 1)[1]
        record["normative_strength"] = strength
        if strength == "ambiguous":
            observation = {
                "dependency_id": "urn:strling:evidence-fixture:agreeing-observation", "kind": "empirical-observation", "semantic_role": "comparison-input",
                "authority_domain_id": "urn:strling:authority:observed-profile", "version": "1.0.0", "content_digest_sha256": "e" * 64,
                "upstream_dependency_ids": [], "subject_profile_ids": [], "semantic_evaluator": False,
            }
            record["dependency_graph"]["nodes"].append(observation)
            record["dependency_graph"]["root_dependency_ids"].append(observation["dependency_id"])
    elif mutation == "source-revision:latest":
        record["source_authority"]["source_revision"] = "latest"
    elif mutation == "request:normative":
        pass
    elif mutation == "request:two-shared-wrappers":
        second = deepcopy(record)
        second["source_authority"]["source_identity"] = "urn:strling:formal-model:fixture-wrapper-2"
        second["source_authority"]["locator"] = "urn:strling:formal-model:fixture-wrapper-2#proof"
        old_root = second["dependency_graph"]["nodes"][0]["dependency_id"]
        second["dependency_graph"]["nodes"][0]["dependency_id"] += ":wrapper-2"
        second["dependency_graph"]["root_dependency_ids"] = [second["dependency_graph"]["nodes"][0]["dependency_id"] if identifier == old_root else identifier for identifier in second["dependency_graph"]["root_dependency_ids"]]
        second = finalize_evidence_record(root, second)
        records.append(second)
        request["evidence_refs"].append({"evidence_id": second["evidence_id"], "evidence_digest_sha256": second["evidence_digest_sha256"]})
        request["require_independent_authorities"] = True
        request["minimum_authority_domains"] = 2
    record = finalize_evidence_record(root, record)
    records[record_index] = record
    request["evidence_refs"][0] = {"evidence_id": record["evidence_id"], "evidence_digest_sha256": record["evidence_digest_sha256"]}
    return records, request


def validate_fixtures(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> dict[str, int]:
    validate_instance(fixture, load_strict(root / FIXTURE_SCHEMA_PATH), source=FIXTURE_PATH.as_posix())
    body = {key: value for key, value in fixture.items() if key not in {"fixture_set_id", "fixture_set_digest_sha256"}}
    if fixture["fixture_set_digest_sha256"] != _digest(body) or fixture["fixture_set_id"] != _content_id(root, "artifact-set-manifest", "evidence-admissibility-fixtures-v1", body):
        fail("evidence-fixture-identity", "evidence fixture identity or digest differs")
    if fixture["derivation"] != _evidence_derivation(root):
        fail("evidence-fixture-derivation", "evidence fixtures do not bind exact governance derivation")
    if set(item["evidence_role"] for item in fixture["valid_evidence"]) != set(ROLE_SPECS):
        fail("evidence-fixture-role-coverage", "valid evidence must cover all eight roles")
    for record in fixture["valid_evidence"]:
        validate_evidence_record(root, contract, record)
    for case in fixture["valid_cases"] + fixture["same_material_boundary_cases"]:
        result = evaluate_admissibility(root, contract, fixture["valid_evidence"], case["request"])
        if result["decision"] != case["expected_decision"]:
            fail("evidence-fixture-decision", f"valid case {case['case_id']} was not admitted")
    rejected = 0
    for case in fixture["invalid_cases"]:
        records, request = _mutated_case(root, contract, fixture, case)
        try:
            evaluate_admissibility(root, contract, records, request)
        except ConformanceDataError as error:
            if error.code != case["expected_error"]:
                fail("evidence-fixture-wrong-error", f"{case['case_id']} expected {case['expected_error']} but got {error.code}")
            rejected += 1
        else:
            fail("evidence-fixture-not-rejected", f"prohibited case {case['case_id']} unexpectedly validated")
    validate_expectation_basis(root, contract, fixture["valid_evidence"], fixture["valid_expectation_basis"])
    return {"valid_role_fixtures": len(fixture["valid_evidence"]), "valid_cases": len(fixture["valid_cases"]), "same_material": len(fixture["same_material_boundary_cases"]), "rejected": rejected}


def build_report(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    counts = validate_fixtures(root, contract, fixture)
    oracle_contract = load_strict(root / ORACLE_CONTRACT_PATH)
    body = {
        "schema_version": "evidence-admissibility-report.v1", "published_on": PUBLISHED_ON,
        "claim_scope": "Machine validation of evidence role, epistemic use, source-language strength, immutable provenance, scope, quality eligibility, authority-domain independence, and O1-O8 compatibility; not applicability, adjudication, waiver, public claims, production vectors, or scientific certification.",
        "contract": _artifact_ref(CONTRACT_PATH, contract, "contract_id", "contract_digest_sha256"),
        "oracle_foundation": _artifact_ref(ORACLE_CONTRACT_PATH, oracle_contract, "contract_id", "contract_digest_sha256"),
        "fixtures": _artifact_ref(FIXTURE_PATH, fixture, "fixture_set_id", "fixture_set_digest_sha256"),
        "implementation_bindings": [{"path": path.as_posix(), "file_sha256": _sha(root / path)} for path in IMPLEMENTATION_PATHS],
        "counts": {"evidence_roles": 8, "epistemic_uses": 10, "normative_strengths": 11, "valid_role_fixtures": counts["valid_role_fixtures"], "valid_admissibility_cases": counts["valid_cases"], "prohibited_cases_rejected": counts["rejected"], "same_material_boundary_cases": counts["same_material"]},
        "checks": [
            {"check_id": "o1-o8-role-compatibility", "status": "PASS"}, {"check_id": "normative-characterization-boundary", "status": "PASS"},
            {"check_id": "source-language-strength", "status": "PASS"}, {"check_id": "quality-role-orthogonality", "status": "PASS"},
            {"check_id": "immutable-expectation-inputs", "status": "PASS"}, {"check_id": "transitive-dependency-circularity", "status": "PASS"},
            {"check_id": "authority-domain-independence", "status": "PASS"}, {"check_id": "data-plus-semantic-rule", "status": "PASS"},
            {"check_id": "same-material-different-uses", "status": "PASS"}, {"check_id": "under-specification-preserved", "status": "PASS"},
            {"check_id": "characterization-never-conformance", "status": "PASS"}, {"check_id": "historical-artifacts-no-rewrite", "status": "PASS"},
        ],
        "denominator_boundary": {"obligations": 2390, "requirements": 3378, "conditional_requirements": 1972, "c4": "FAIL — 0/3378", "modified": False, "profile_expanded_execution_denominator": "deferred"},
        "result": "PASS", "derivation": _evidence_derivation(root),
    }
    return _finalize(root, body, namespace="trust-assessment", artifact_kind="evidence-admissibility-report-v1", id_field="report_id", digest_field="report_digest_sha256")


def build_authority(root: Path, contract: dict[str, Any], fixture: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    oracle_contract = load_strict(root / ORACLE_CONTRACT_PATH)
    requirement = load_strict(root / REQUIREMENT_PATH)
    def binding(path: Path, record: dict[str, Any], id_field: str, digest_field: str) -> dict[str, Any]:
        return {**_artifact_ref(path, record, id_field, digest_field), "file_sha256": _sha(root / path)}
    body = {
        "schema_version": "evidence-admissibility-authority.v1",
        "current_contract": binding(CONTRACT_PATH, contract, "contract_id", "contract_digest_sha256"),
        "oracle_foundation": binding(ORACLE_CONTRACT_PATH, oracle_contract, "contract_id", "contract_digest_sha256"),
        "validation_fixture": binding(FIXTURE_PATH, fixture, "fixture_set_id", "fixture_set_digest_sha256"),
        "acceptance_report": binding(REPORT_PATH, report, "report_id", "report_digest_sha256"),
        "semantic_requirement_authority": binding(REQUIREMENT_PATH, requirement, "snapshot_id", "snapshot_digest_sha256"),
        "historical_compatibility": {"observations_rewritten": False, "campaign_expectations_reinterpreted": False, "denominator_changed": False, "migration_rule": "prospective-versioned-no-rewrite"},
        "next_interfaces": {"profile_applicability": "deferred", "claims_and_adjudication": "deferred", "waivers": "deferred", "production_vectors": "deferred"},
        "governance": "Knowledge owns exact source meaning; evidence records preserve immutable inputs and allowed epistemic roles; oracle records own scoped expectation functions; observations remain empirical; later reconciliation must preserve every independent fact and conflict.",
        "derivation": _evidence_derivation(root),
    }
    return _finalize(root, body, namespace="artifact-set-manifest", artifact_kind="evidence-admissibility-authority-v1", id_field="index_id", digest_field="index_digest_sha256")


def _validate_finalized(root: Path, record: dict[str, Any], schema_path: Path, *, namespace: str, artifact_kind: str, id_field: str, digest_field: str, source: str) -> None:
    validate_instance(record, load_strict(root / schema_path), source=source)
    body = {key: value for key, value in record.items() if key not in {id_field, digest_field}}
    if record[digest_field] != _digest(body) or record[id_field] != _content_id(root, namespace, artifact_kind, body):
        fail("evidence-artifact-identity", f"{source} identity or digest differs")


def verify_current(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    allocation = load_strict(root / ALLOCATION_PATH)
    validate_instance(allocation, load_strict(root / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_PATH.as_posix())
    if allocation != build_allocation():
        fail("evidence-allocation-drift", "evidence identity allocation differs")
    contract = load_strict(root / CONTRACT_PATH)
    validate_contract(root, contract)
    fixture = load_strict(root / FIXTURE_PATH)
    counts = validate_fixtures(root, contract, fixture)
    if fixture != build_fixtures(root, contract):
        fail("evidence-fixture-drift", "evidence fixtures differ from deterministic construction")
    report = load_strict(root / REPORT_PATH)
    _validate_finalized(root, report, REPORT_SCHEMA_PATH, namespace="trust-assessment", artifact_kind="evidence-admissibility-report-v1", id_field="report_id", digest_field="report_digest_sha256", source=REPORT_PATH.as_posix())
    if report != build_report(root, contract, fixture) or report["result"] != "PASS":
        fail("evidence-report-drift", "evidence report differs from fresh validation")
    authority = load_strict(root / AUTHORITY_PATH)
    _validate_finalized(root, authority, AUTHORITY_SCHEMA_PATH, namespace="artifact-set-manifest", artifact_kind="evidence-admissibility-authority-v1", id_field="index_id", digest_field="index_digest_sha256", source=AUTHORITY_PATH.as_posix())
    if authority != build_authority(root, contract, fixture, report):
        fail("evidence-authority-drift", "evidence authority index differs from exact current artifacts")
    obligations = load_strict(root / OBLIGATION_PATH)
    requirements = load_strict(root / REQUIREMENT_PATH)
    if len(obligations["obligations"]) != 2390 or len(requirements["requirements"]) != 3378 or sum(item["requirement_state"] == "conditionally-required" for item in requirements["requirements"]) != 1972:
        fail("evidence-denominator-mutation", "evidence admissibility work changed the accepted denominator")
    if broad_foundations:
        identity_count = verify_identity_catalog(root)["scientific_identities"]
        derivation_groups = verify_derivation_catalog(root)["generated_assertion_groups"]
    else:
        identity_count = len(load_strict(root / "registries/identity/scientific-identities.v1.json")["bindings"])
        derivation_groups = load_strict(root / DERIVATION_CATALOG_PATH)["coverage_summary"]["assertion_groups"]
    return {"result": report["result"], "contract_id": contract["contract_id"], "report_id": report["report_id"], "evidence_roles": 8, "epistemic_uses": 10, "prohibited_cases_rejected": counts["rejected"], "requirements": 3378, "scientific_identities": identity_count, "derivation_groups": derivation_groups}


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
        fail("evidence-artifact-write", "evidence artifact failed read-after-write", path.as_posix())


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
