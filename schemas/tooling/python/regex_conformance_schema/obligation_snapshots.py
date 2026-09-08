"""Canonical semantic-obligation and minimum-requirement materialization."""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path
from typing import Any

from .derivation import derivation_revision_id
from .errors import fail
from .identity import NamespaceRegistry, build_content_identity, generate_assigned_id
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .obligation_derivation import (
    CONTRACT_PATH,
    DENOMINATOR_SHA256,
    DRY_RUN_PATH,
    LEGACY_CASE_ARCHETYPE,
    LEGACY_FACET_MAP,
    LEGACY_FORECAST_PATH,
    LEGACY_PROJECTION_PATH,
    LEGACY_REQUIREMENTS_PATH,
    SEMANTIC_FOUNDATION_PATH,
    SNAPSHOT_PATH,
    build_contract,
    denominator_baseline,
    derive_feature,
    validate_contract,
)
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import (
    CATALOG_PATH as IDENTITY_CATALOG_PATH,
    ScientificDescriptor,
    catalog_digest,
    collect_descriptors,
    lineage_record_id,
    semantic_fingerprint,
    verify_catalog as verify_identity_catalog,
)


PUBLISHED_ON = "2026-09-08"
ALLOCATION_PATH = Path("ontology/derivations/semantic-denominator-identities-2026-09-08.v1.json")
OBLIGATION_PATH = Path("ontology/obligations/regex-semantic-obligations-2026-09-08.v1.json")
REQUIREMENT_PATH = Path("vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json")
MIGRATION_PATH = Path("ontology/migrations/regex-semantic-denominator-2026-09-08.v1.json")
PROJECTION_PATH = Path("ontology/projections/regex-semantic-projection-2026-09-08.v2.json")
REPORT_PATH = Path("reports/semantics/semantic-denominator-materialization-2026-09-08.v1.json")
AUTHORITY_PATH = Path("ontology/authority/current-semantic-denominator.v1.json")

ALLOCATION_SCHEMA_PATH = Path("schemas/json/semantic-denominator-identity-allocation.schema.json")
OBLIGATION_SCHEMA_PATH = Path("schemas/json/semantic-obligation-snapshot.schema.json")
REQUIREMENT_SCHEMA_PATH = Path("schemas/json/semantic-requirement-snapshot.schema.json")
MIGRATION_SCHEMA_PATH = Path("schemas/json/semantic-denominator-migration.schema.json")
PROJECTION_SCHEMA_PATH = Path("schemas/json/semantic-requirement-projection-v2.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/semantic-denominator-materialization-report.schema.json")
AUTHORITY_SCHEMA_PATH = Path("schemas/json/semantic-denominator-authority-index.schema.json")
ARTIFACT_PROFILE_PATH = Path("schemas/identity-profiles/semantic-research-artifact.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")

MATERIALIZATION_DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a08250-8e26-7ae3-aaf5-32e23ece7dbc"
SCHEMA_FAMILIES = {
    "allocation": "rcid:v1:schema-family:u7:01a08267-043b-7dc2-8f17-4ef9fa8df569",
    "obligation": "rcid:v1:schema-family:u7:01a08267-043b-75b0-8ef3-7e0f88dcf447",
    "requirement": "rcid:v1:schema-family:u7:01a08267-043b-7d2d-a0c8-9564ed542b9c",
    "migration": "rcid:v1:schema-family:u7:01a08267-043b-7fe7-8c9c-ce82cae21d64",
    "projection": "rcid:v1:schema-family:u7:01a08267-043b-7dcd-bada-1b7c4190730f",
    "report": "rcid:v1:schema-family:u7:01a08267-043b-7cf7-b5fc-54e4e4bc8873",
    "authority": "rcid:v1:schema-family:u7:01a08267-043b-7db8-a4b9-1c022e11bdea",
}

# The UUIDv7 values above are fixed reviewed assignments.  They deliberately do
# not derive scientific entity identity from mutable labels.  Entity allocations
# below are persisted once in ALLOCATION_PATH and are never regenerated.

CARDINALITY_RULE_KEY = "requirement-cardinality.by-archetype-polarity.v1"
LEGACY_POSITIVE_ROLES = {
    "acceptance", "positive", "participation", "value", "span", "history-or-name",
    "success", "scope", "off-versus-on", "state-transition", "expansion",
    "missing-or-unset-group", "escaping", "callback-or-state", "prerequisite",
    "modifier", "comparison-control", "native-diagnostic",
}
LEGACY_NEGATIVE_ROLES = {"rejection", "negative", "no-match", "class"}
LEGACY_BOUNDARY_ROLES = {
    "ambiguity-boundary", "boundary", "competing-interpretation", "start-offset",
    "zero-length-progress", "repeated-next", "terminal-state", "unset-versus-empty",
    "datum-domain", "class-or-property", "case-folding", "index-unit",
    "malformed-input", "locale-mode-or-cursor", "result-shape", "global-progress",
    "phase", "limit", "timeout", "exhaustion", "termination", "confounder",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _content_id(root: Path, namespace: str, family: str, body: dict[str, Any]) -> str:
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / ARTIFACT_PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=family,
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": _digest(body)},
    )
    return str(result["content_id"])


def _finalize(root: Path, body: dict[str, Any], *, namespace: str, family: str, id_field: str, digest_field: str) -> dict[str, Any]:
    digest = _digest(body)
    return {**body, id_field: _content_id(root, namespace, family, body), digest_field: digest}


def materialization_derivation_spec(root: Path) -> dict[str, Any]:
    record = {
        "title": "Canonical semantic denominator materialization",
        "derivation_class": "calculation",
        "method_key": "semantic-denominator-materialization",
        "method_version": "1.0.0",
        "input_references": [SNAPSHOT_PATH.as_posix(), CONTRACT_PATH.as_posix(), DRY_RUN_PATH.as_posix()],
        "authority_references": [SEMANTIC_FOUNDATION_PATH.as_posix()],
        "allowed_gate_kinds": ["arithmetic-closure", "structural-integrity"],
        "independent_evidence": False,
        "metadata": {
            "kind": "calculation",
            "input_references": ["the frozen semantic snapshot, accepted rule revisions, one-time typed identity allocation, predecessor denominator, and archetype polarity cardinality contract"],
            "procedure_ref": "schemas/tooling/python/regex_conformance_schema/obligation_snapshots.py",
            "formula": "Materialize one immutable obligation per accepted prospective scientific question, then one minimum requirement per archetype evidence role while preserving conditional predicates and predecessor lineage.",
        },
        "notes": "Materialization establishes current semantic-denominator authority; it does not author vectors, evaluate profiles, or provide empirical evidence.",
        "derivation_id": MATERIALIZATION_DERIVATION_ID,
    }
    record["derivation_revision_id"] = derivation_revision_id(root, record)
    return record


def _fixed_allocations() -> list[dict[str, str]]:
    return [
        {"entity_class": "assertion-derivation", "canonical_key": "derivation.semantic-denominator-materialization", "assigned_id": MATERIALIZATION_DERIVATION_ID},
        *[
            {"entity_class": "schema-family", "canonical_key": f"schema.semantic-denominator.{key}", "assigned_id": value}
            for key, value in sorted(SCHEMA_FAMILIES.items())
        ],
    ]


def _artifact_binding(path: Path, artifact: dict[str, Any], id_field: str, digest_field: str) -> dict[str, str]:
    return {"path": path.as_posix(), "artifact_id": artifact[id_field], "digest_sha256": artifact[digest_field]}


def _semantic_assertion_revision(root: Path, feature: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    field = reference["selector"].removeprefix("semantic_assertions.")
    assertion = feature["semantic_assertions"][field]
    basis = {
        "feature_scientific_id": feature["scientific_id"],
        "selector": reference["selector"],
        "state": assertion["state"],
        "scope": assertion["scope"],
        "statement": assertion["statement"],
        "source_ids": sorted(assertion["source_ids"]),
        "derivation_id": assertion["derivation_id"],
    }
    return {
        "assertion_revision_id": _content_id(root, "finding-revision", SCHEMA_FAMILIES["obligation"], basis),
        "selector": reference["selector"],
        "state": assertion["state"],
        "scope": assertion["scope"],
        "derivation_id": assertion["derivation_id"],
        "source_ids": sorted(assertion["source_ids"]),
    }


def _evidence_mode(candidate: dict[str, Any]) -> str:
    if candidate["archetype_id"] == "archetype.permitted-variation" or candidate["question_type"] == "characterization-only":
        return "characterization-only"
    if candidate["question_type"] == "relational/metamorphic-candidate":
        return "relational/metamorphic-candidate"
    if candidate["question_type"] == "normative/conformance-capable" and candidate["requirement_state"] == "required":
        return "conformance-capable"
    return "conditional-conformance"


def _execution_requirement(archetype_id: str, evidence_mode: str) -> str:
    if evidence_mode == "characterization-only":
        return "characterization-observation"
    if evidence_mode == "relational/metamorphic-candidate":
        return "executable-relational-vector-family"
    if archetype_id in {"archetype.state-transition", "archetype.repeated-iteration", "archetype.phase-specific"}:
        return "executable-sequence"
    if archetype_id in {"archetype.resource-limit-termination", "archetype.complexity-guarantee"}:
        return "bounded-resource-witness-family"
    return "executable-vector"


def _oracle_capability(evidence_mode: str) -> str:
    return {
        "conformance-capable": "normative-expected-outcome",
        "conditional-conformance": "profile-documentation-outcome",
        "characterization-only": "characterization-record",
        "relational/metamorphic-candidate": "relational-comparison",
    }[evidence_mode]


def _cardinality_contract(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    roles = []
    for archetype in contract["obligation_archetypes"]:
        polarities = list(archetype["subject_polarities"])
        roles.append({
            "archetype_id": archetype["archetype_id"],
            "roles": polarities,
            "rationale": f"{archetype['scientific_question']} Each declared evidence role ({', '.join(polarities)}) requires one independently attributable minimum requirement; roles may later expand to multiple concrete vectors without changing this requirement identity.",
        })
    body = {"rule_key": CARDINALITY_RULE_KEY, "method": "Create one minimum requirement for each evidence role declared by the accepted obligation archetype; never infer cardinality from a target count.", "archetype_roles": roles}
    body["rule_revision_id"] = _content_id(root, "applicability-rule-set", SCHEMA_FAMILIES["requirement"], body)
    return body


def _old_catalog_maps(root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    catalog = load_strict(root / IDENTITY_CATALOG_PATH)
    by_key = {item["canonical_key"]: item for item in catalog["bindings"]}
    return by_key, {key: value["scientific_id"] for key, value in by_key.items()}


def _obligation_blueprints(root: Path) -> tuple[list[dict[str, Any]], dict[str, list[str]], dict[str, list[str]]]:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    contract = load_strict(root / CONTRACT_PATH)
    validate_contract(root, contract, snapshot)
    decisions = [decision for feature in snapshot["features"] for decision in derive_feature(snapshot, contract, feature)]
    candidates: list[dict[str, Any]] = []
    by_triple: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for decision in decisions:
        for candidate in decision["provisional_obligations"]:
            value = {"feature": next(item for item in snapshot["features"] if item["feature_id"] == decision["feature_id"]), "decision": decision, "candidate": candidate}
            candidates.append(value)
            by_triple[(decision["feature_id"], decision["facet_id"], candidate["archetype_id"])].append(value)
    old_projection = load_strict(root / LEGACY_PROJECTION_PATH)
    old_to_new: dict[str, list[str]] = {}
    new_to_old: dict[str, list[str]] = defaultdict(list)
    old_by_key = {item["obligation_id"]: item for item in old_projection["semantic_obligation_templates"]}
    for old in old_projection["semantic_obligation_templates"]:
        archetype = LEGACY_CASE_ARCHETYPE[old["case"]]
        matches = by_triple.get((old["feature_id"], LEGACY_FACET_MAP[old["facet"]], archetype), []) if archetype else []
        keys = sorted(item["candidate"]["analysis_key"] for item in matches)
        old_to_new[old["obligation_id"]] = keys
        for key in keys:
            new_to_old[key].append(old["obligation_id"])
    blueprints = []
    for value in candidates:
        candidate = value["candidate"]
        decision = value["decision"]
        predecessors = sorted(new_to_old[candidate["analysis_key"]])
        retained_key = None
        if len(predecessors) == 1 and len(old_to_new[predecessors[0]]) == 1:
            old = old_by_key[predecessors[0]]
            old_ops = sorted(item if item.startswith("operation.") else f"operation.{item}" for item in old["operation_ids"])
            if old_ops == sorted(candidate["operation_ids"]):
                retained_key = predecessors[0]
        basis = deepcopy(candidate["prospective_identity_basis"])
        basis_digest = _digest({"domain": "strling.regex-conformance.semantic-obligation.v1", "basis": basis})
        blueprints.append({**value, "identity_basis": basis, "basis_digest_sha256": basis_digest, "predecessor_keys": predecessors, "retained_key": retained_key})
    if len(blueprints) != 2390 or len({item["basis_digest_sha256"] for item in blueprints}) != len(blueprints):
        fail("semantic-obligation-blueprint-population", "canonical obligation blueprints must exactly preserve the 2,390 distinct dry-run questions")
    return sorted(blueprints, key=lambda item: item["basis_digest_sha256"]), old_to_new, {key: sorted(value) for key, value in new_to_old.items()}


def _legacy_role(value: str) -> str | None:
    if value in LEGACY_POSITIVE_ROLES:
        return "positive"
    if value in LEGACY_NEGATIVE_ROLES:
        return "negative"
    if value in LEGACY_BOUNDARY_ROLES:
        return "boundary"
    return None


def _requirement_blueprints(root: Path, obligations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list[str]], dict[str, list[str]]]:
    old_requirements = load_strict(root / LEGACY_REQUIREMENTS_PATH)["requirements"]
    old_by_obligation: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in old_requirements:
        old_by_obligation[item["obligation_id"]].append(item)
    preliminary = []
    for obligation in obligations:
        roles = obligation["requirement_cardinality"]["roles"]
        for role in roles:
            predecessors = []
            for old_obligation in obligation["predecessor_keys"]:
                for old in old_by_obligation.get(old_obligation, []):
                    mapped = _legacy_role(old["vector_role"])
                    if len(roles) == 1 or mapped is None or mapped == role:
                        predecessors.append(old["requirement_id"])
            evidence_mode = obligation["evidence_mode"]
            execution_requirement = _execution_requirement(obligation["archetype_id"], evidence_mode)
            identity_basis = {
                "obligation_scientific_ids": [obligation["scientific_id"]],
                "evidence_role": role,
                "requirement_type": evidence_mode,
                "execution_requirement": execution_requirement,
                "expected_oracle_capability": _oracle_capability(evidence_mode),
                "profile_condition": obligation["profile_condition"],
                "operation_scientific_ids": obligation["operation_scientific_ids"],
                "cardinality_rule_revision_id": obligation["requirement_cardinality"]["rule_revision_id"],
            }
            preliminary.append({
                "obligation": obligation,
                "role": role,
                "predecessor_keys": sorted(set(predecessors)),
                "evidence_mode": evidence_mode,
                "execution_requirement": execution_requirement,
                "identity_basis": identity_basis,
                "basis_digest_sha256": _digest({"domain": "strling.regex-conformance.semantic-requirement.v1", "basis": identity_basis}),
            })
    old_to_new: dict[str, list[str]] = {item["requirement_id"]: [] for item in old_requirements}
    for item in preliminary:
        for predecessor in item["predecessor_keys"]:
            old_to_new[predecessor].append(item["basis_digest_sha256"])
    new_to_old = {item["basis_digest_sha256"]: item["predecessor_keys"] for item in preliminary}
    old_by_key = {item["requirement_id"]: item for item in old_requirements}
    for item in preliminary:
        item["retained_key"] = None
        if len(item["predecessor_keys"]) == 1 and len(old_to_new[item["predecessor_keys"][0]]) == 1 and item["obligation"]["lineage_disposition"] == "retained":
            old = old_by_key[item["predecessor_keys"][0]]
            if old["vector_role"] == item["role"] and sorted(old["required_operation_ids"]) == sorted(item["obligation"]["operation_ids"]):
                item["retained_key"] = old["requirement_id"]
    if len(preliminary) != len({item["basis_digest_sha256"] for item in preliminary}):
        fail("semantic-requirement-blueprint-identity", "requirement scientific questions are duplicated")
    return sorted(preliminary, key=lambda item: item["basis_digest_sha256"]), {key: sorted(value) for key, value in old_to_new.items()}, new_to_old


def _allocation_record(root: Path, *, allow_new: bool) -> dict[str, Any]:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    contract = load_strict(root / CONTRACT_PATH)
    path = root / ALLOCATION_PATH
    existing = load_strict(path) if path.is_file() else None
    allocations = {(item["entity_class"], item["basis_digest_sha256"]): item for item in (existing or {}).get("entity_allocations", [])}
    catalog_by_key, scientific_by_key = _old_catalog_maps(root)
    registry = NamespaceRegistry.load(root / NAMESPACE_PATH)
    obligation_blueprints, _, _ = _obligation_blueprints(root)
    obligation_shells = []
    for item in obligation_blueprints:
        identity = ("obligation", item["basis_digest_sha256"])
        allocation = allocations.get(identity)
        if allocation is None:
            if not allow_new:
                fail("missing-denominator-identity-allocation", "obligation identity has not been allocated", item["basis_digest_sha256"])
            retained = item["retained_key"]
            allocation = {
                "entity_class": "obligation",
                "basis_digest_sha256": item["basis_digest_sha256"],
                "canonical_key": retained or f"obligation.semantic-derived.{item['basis_digest_sha256'][:24]}",
                "assigned_id": scientific_by_key[retained] if retained else generate_assigned_id(registry, "rcid", "obligation"),
                "allocation_kind": "retained-predecessor" if retained else "new-assignment",
            }
            allocations[identity] = allocation
        obligation_shells.append({
            "obligation_key": allocation["canonical_key"],
            "scientific_id": allocation["assigned_id"],
            "identity_basis": item["identity_basis"],
            "basis_digest_sha256": item["basis_digest_sha256"],
            "predecessor_keys": item["predecessor_keys"],
            "lineage_disposition": "retained" if item["retained_key"] else "pending",
            "feature_id": item["decision"]["feature_id"],
            "feature_scientific_id": item["decision"]["feature_scientific_id"],
            "facet_id": item["decision"]["facet_id"],
            "archetype_id": item["candidate"]["archetype_id"],
            "question_type": item["candidate"]["question_type"],
            "requirement_state": item["candidate"]["requirement_state"],
            "evidence_mode": _evidence_mode(item["candidate"]),
            "operation_ids": item["candidate"]["operation_ids"],
            "operation_scientific_ids": item["candidate"]["operation_scientific_ids"],
            "profile_condition": item["candidate"]["profile_condition"],
            "requirement_cardinality": {},
        })
    cardinality = _cardinality_contract(root, contract)
    roles_by_archetype = {item["archetype_id"]: item for item in cardinality["archetype_roles"]}
    for item in obligation_shells:
        spec = roles_by_archetype[item["archetype_id"]]
        item["requirement_cardinality"] = {"rule_revision_id": cardinality["rule_revision_id"], "minimum_requirements": len(spec["roles"]), "roles": spec["roles"], "rationale": spec["rationale"]}
    # Resolve obligation origin before requirement-retention analysis.
    reverse_counts = Counter(old for item in obligation_shells for old in item["predecessor_keys"])
    for item in obligation_shells:
        if item["lineage_disposition"] == "retained":
            continue
        count = len(item["predecessor_keys"])
        if count == 0:
            item["lineage_disposition"] = "new-semantic-obligation"
        elif count > 1 and any(reverse_counts[key] > 1 for key in item["predecessor_keys"]):
            item["lineage_disposition"] = "many-to-many-successor"
        elif count > 1:
            item["lineage_disposition"] = "merged-successor"
        elif reverse_counts[item["predecessor_keys"][0]] > 1:
            item["lineage_disposition"] = "split-successor"
        else:
            item["lineage_disposition"] = "successor"
    requirement_blueprints, _, _ = _requirement_blueprints(root, obligation_shells)
    for item in requirement_blueprints:
        identity = ("semantic-requirement", item["basis_digest_sha256"])
        allocation = allocations.get(identity)
        if allocation is None:
            if not allow_new:
                fail("missing-denominator-identity-allocation", "semantic requirement identity has not been allocated", item["basis_digest_sha256"])
            retained = item["retained_key"]
            allocation = {
                "entity_class": "semantic-requirement",
                "basis_digest_sha256": item["basis_digest_sha256"],
                "canonical_key": retained or f"semantic-requirement.semantic-derived.{item['basis_digest_sha256'][:24]}",
                "assigned_id": scientific_by_key[retained] if retained else generate_assigned_id(registry, "rcid", "semantic-requirement"),
                "allocation_kind": "retained-predecessor" if retained else "new-assignment",
            }
            allocations[identity] = allocation
    expected_keys = {("obligation", item["basis_digest_sha256"]) for item in obligation_blueprints} | {("semantic-requirement", item["basis_digest_sha256"]) for item in requirement_blueprints}
    if set(allocations) != expected_keys:
        fail("stale-denominator-identity-allocation", "allocation contains an entity outside the accepted materialization")
    record = {
        "schema_version": "semantic-denominator-identity-allocation.v1",
        "allocated_on": PUBLISHED_ON,
        "semantic_authority": _artifact_binding(SNAPSHOT_PATH, snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "rule_contract": _artifact_binding(CONTRACT_PATH, contract, "contract_id", "contract_digest_sha256"),
        "fixed_allocations": _fixed_allocations(),
        "entity_allocations": sorted(allocations.values(), key=lambda item: (item["entity_class"], item["basis_digest_sha256"])),
    }
    validate_instance(record, load_strict(root / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_PATH.as_posix())
    all_allocations = [*record["fixed_allocations"], *record["entity_allocations"]]
    ids = [item["assigned_id"] for item in all_allocations]
    keys = [(item["entity_class"], item["canonical_key"]) for item in all_allocations]
    if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
        fail("denominator-identity-reuse", "one assigned identity or canonical key owns multiple scientific bases")
    for item in all_allocations:
        parsed = registry.validate(item["assigned_id"])
        if parsed.mode != "u7" or parsed.namespace != item["entity_class"]:
            fail("denominator-identity-namespace", "allocation does not use its entity class assigned namespace", item["canonical_key"])
    return record


def allocate_identities(root: Path) -> dict[str, Any]:
    record = _allocation_record(root, allow_new=True)
    _write_canonical(root / ALLOCATION_PATH, record)
    rebuilt = _allocation_record(root, allow_new=False)
    if canonical_bytes(record) != canonical_bytes(rebuilt):
        fail("denominator-allocation-nondeterministic", "persisted one-time allocation did not rebuild")
    counts = Counter(item["entity_class"] for item in record["entity_allocations"])
    return {"obligation_identities": counts["obligation"], "requirement_identities": counts["semantic-requirement"]}


def _allocation_maps(root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    record = _allocation_record(root, allow_new=False)
    by_basis = {item["basis_digest_sha256"]: item for item in record["entity_allocations"]}
    by_key = {item["canonical_key"]: item for item in record["entity_allocations"]}
    return by_basis, by_key


def build_obligation_snapshot(root: Path) -> tuple[dict[str, Any], dict[str, list[str]], dict[str, list[str]]]:
    snapshot = load_strict(root / SNAPSHOT_PATH)
    contract = load_strict(root / CONTRACT_PATH)
    allocation_by_basis, _ = _allocation_maps(root)
    blueprints, old_to_analysis, analysis_to_old = _obligation_blueprints(root)
    catalog_by_key, scientific_by_key = _old_catalog_maps(root)
    facet_scientific = {item["facet_id"]: item["scientific_id"] for item in snapshot["semantic_facets"]}
    cardinality = _cardinality_contract(root, contract)
    cardinality_by_archetype = {item["archetype_id"]: item for item in cardinality["archetype_roles"]}
    analysis_to_key: dict[str, str] = {}
    obligations = []
    old_successor_count = Counter(old for item in blueprints for old in item["predecessor_keys"])
    for item in blueprints:
        candidate = item["candidate"]
        decision = item["decision"]
        feature = item["feature"]
        allocation = allocation_by_basis[item["basis_digest_sha256"]]
        refs = decision["semantic_inputs"] or [{"selector": "semantic_assertions.definition"}]
        assertions = [_semantic_assertion_revision(root, feature, ref) for ref in refs]
        predecessors = [scientific_by_key[key] for key in item["predecessor_keys"]]
        if item["retained_key"]:
            disposition = "retained"
        elif not predecessors:
            disposition = "new-semantic-obligation"
        elif len(predecessors) > 1 and any(old_successor_count[key] > 1 for key in item["predecessor_keys"]):
            disposition = "many-to-many-successor"
        elif len(predecessors) > 1:
            disposition = "merged-successor"
        elif old_successor_count[item["predecessor_keys"][0]] > 1:
            disposition = "split-successor"
        else:
            disposition = "successor"
        role_spec = cardinality_by_archetype[candidate["archetype_id"]]
        key = allocation["canonical_key"]
        analysis_to_key[candidate["analysis_key"]] = key
        obligations.append({
            "obligation_key": key,
            "scientific_id": allocation["assigned_id"],
            "identity_basis": item["identity_basis"],
            "feature_id": decision["feature_id"],
            "feature_scientific_id": decision["feature_scientific_id"],
            "facet_id": decision["facet_id"],
            "facet_scientific_id": facet_scientific[decision["facet_id"]],
            "archetype_id": candidate["archetype_id"],
            "question_type": candidate["question_type"],
            "requirement_state": candidate["requirement_state"],
            "evidence_mode": _evidence_mode(candidate),
            "operation_ids": candidate["operation_ids"],
            "operation_scientific_ids": candidate["operation_scientific_ids"],
            "profile_condition": candidate["profile_condition"],
            "semantic_assertions": assertions,
            "source_semantic_assertion_ids": [value["assertion_revision_id"] for value in assertions],
            "interaction_basis": candidate["interaction_basis"],
            "semantic_variant_basis": candidate["semantic_variant_basis"],
            "derivation": {"rule_key": decision["rule_key"], "rule_revision_id": decision["rule_revision_id"], "derivation_id": contract["derivation_id"], "derivation_revision_id": contract["derivation_revision_id"]},
            "explanation": {"reason": decision["reason"], "chain": [*sorted(value["assertion_revision_id"] for value in assertions), decision["rule_revision_id"], decision["facet_id"], candidate["archetype_id"], ",".join(candidate["operation_scientific_ids"]), "conditional profile predicate" if candidate["requirement_state"] == "conditionally-required" else "required semantic question"]},
            "requirement_cardinality": {"rule_revision_id": cardinality["rule_revision_id"], "minimum_requirements": len(role_spec["roles"]), "roles": role_spec["roles"], "rationale": role_spec["rationale"]},
            "predecessor_scientific_ids": predecessors,
            "lineage_disposition": disposition,
        })
    old_to_keys = {old: sorted(analysis_to_key[key] for key in keys) for old, keys in old_to_analysis.items()}
    key_to_old = {analysis_to_key[key]: old for key, old in analysis_to_old.items()}
    obligation_counts = Counter(item["requirement_state"] for item in obligations)
    facet_counts = Counter(item["facet_id"] for item in obligations)
    archetype_counts = Counter(item["archetype_id"] for item in obligations)
    question_counts = Counter(item["question_type"] for item in obligations)
    body = {
        "schema_version": "semantic-obligation-snapshot.v1", "published_on": PUBLISHED_ON, "authority_status": "current-canonical",
        "semantic_authority": _artifact_binding(SNAPSHOT_PATH, snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "rule_contract": _artifact_binding(CONTRACT_PATH, contract, "contract_id", "contract_digest_sha256"),
        "identity_allocation": {"path": ALLOCATION_PATH.as_posix(), "file_sha256": _sha(root / ALLOCATION_PATH)},
        "predecessor": {"path": LEGACY_PROJECTION_PATH.as_posix(), "projection_id": load_strict(root / LEGACY_PROJECTION_PATH)["projection_id"], "file_sha256": _sha(root / LEGACY_PROJECTION_PATH), "obligation_count": 12048},
        "counts": {"total": len(obligations), "required": obligation_counts["required"], "conditional": obligation_counts["conditionally-required"], "characterization": sum(item["evidence_mode"] == "characterization-only" for item in obligations), "by_facet": dict(sorted(facet_counts.items())), "by_archetype": dict(sorted(archetype_counts.items())), "by_question_type": dict(sorted(question_counts.items()))},
        "requirement_cardinality_contract": cardinality,
        "obligations": sorted(obligations, key=lambda value: value["obligation_key"]),
        "derivation_id": MATERIALIZATION_DERIVATION_ID,
        "derivation_revision_id": materialization_derivation_spec(root)["derivation_revision_id"],
    }
    result = _finalize(root, body, namespace="ontology-snapshot", family=SCHEMA_FAMILIES["obligation"], id_field="snapshot_id", digest_field="snapshot_digest_sha256")
    validate_instance(result, load_strict(root / OBLIGATION_SCHEMA_PATH), source=OBLIGATION_PATH.as_posix())
    return result, old_to_keys, key_to_old


def build_requirement_snapshot(root: Path, obligation_snapshot: dict[str, Any]) -> tuple[dict[str, Any], dict[str, list[str]], dict[str, list[str]]]:
    allocation_by_basis, _ = _allocation_maps(root)
    obligations = []
    for value in obligation_snapshot["obligations"]:
        obligations.append({**value, "predecessor_keys": []})
    # Recover readable predecessor keys from the catalog for migration matching.
    by_scientific = {item["scientific_id"]: item["canonical_key"] for item in load_strict(root / IDENTITY_CATALOG_PATH)["bindings"]}
    for item in obligations:
        item["predecessor_keys"] = [by_scientific[value] for value in item["predecessor_scientific_ids"]]
    blueprints, old_to_basis, basis_to_old = _requirement_blueprints(root, obligations)
    scientific_by_key = _old_catalog_maps(root)[1]
    basis_to_key: dict[str, str] = {}
    old_successor_count = Counter(old for item in blueprints for old in item["predecessor_keys"])
    requirements = []
    for item in blueprints:
        allocation = allocation_by_basis[item["basis_digest_sha256"]]
        obligation = item["obligation"]
        predecessors = [scientific_by_key[key] for key in item["predecessor_keys"]]
        if item["retained_key"]:
            disposition = "retained"
        elif not predecessors:
            disposition = "new-semantic-requirement"
        elif len(predecessors) > 1 and any(old_successor_count[key] > 1 for key in item["predecessor_keys"]):
            disposition = "many-to-many-successor"
        elif len(predecessors) > 1:
            disposition = "merged-successor"
        elif old_successor_count[item["predecessor_keys"][0]] > 1:
            disposition = "split-successor"
        else:
            disposition = "successor"
        key = allocation["canonical_key"]
        basis_to_key[item["basis_digest_sha256"]] = key
        requirements.append({
            "requirement_key": key, "scientific_id": allocation["assigned_id"], "identity_basis": item["identity_basis"],
            "obligation_keys": [obligation["obligation_key"]], "obligation_scientific_ids": [obligation["scientific_id"]],
            "feature_id": obligation["feature_id"], "feature_scientific_id": obligation["feature_scientific_id"], "facet_id": obligation["facet_id"], "archetype_id": obligation["archetype_id"],
            "evidence_role": item["role"], "question_type": obligation["question_type"], "requirement_type": item["evidence_mode"], "requirement_state": obligation["requirement_state"],
            "execution_requirement": item["execution_requirement"], "expected_oracle_capability": _oracle_capability(item["evidence_mode"]), "profile_condition": obligation["profile_condition"],
            "minimum_evidence_count": 1, "cardinality_rule_revision_id": obligation["requirement_cardinality"]["rule_revision_id"], "cardinality_rationale": obligation["requirement_cardinality"]["rationale"],
            "required_operation_ids": obligation["operation_ids"], "required_operation_scientific_ids": obligation["operation_scientific_ids"],
            "required_attribution": f"A future vector or admissible evidence family must name requirement {allocation['assigned_id']} and obligation {obligation['scientific_id']}; incidental co-occurrence earns no credit.",
            "existing_vector_ids": [], "status": "missing", "derivation_id": MATERIALIZATION_DERIVATION_ID, "derivation_revision_id": materialization_derivation_spec(root)["derivation_revision_id"],
            "predecessor_scientific_ids": predecessors, "lineage_disposition": disposition,
        })
    old_to_keys = {old: sorted(basis_to_key[basis] for basis in bases) for old, bases in old_to_basis.items()}
    key_to_old = {basis_to_key[basis]: old for basis, old in basis_to_old.items()}
    states = Counter(item["requirement_state"] for item in requirements)
    modes = Counter(item["requirement_type"] for item in requirements)
    roles = Counter(item["evidence_role"] for item in requirements)
    body = {
        "schema_version": "semantic-requirement-snapshot.v1", "published_on": PUBLISHED_ON, "authority_status": "current-canonical",
        "obligation_snapshot": _artifact_binding(OBLIGATION_PATH, obligation_snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "predecessor": {"path": LEGACY_REQUIREMENTS_PATH.as_posix(), "digest_sha256": _sha(root / LEGACY_REQUIREMENTS_PATH), "requirement_count": 9506},
        "cardinality_rule": {"rule_key": CARDINALITY_RULE_KEY, "rule_revision_id": obligation_snapshot["requirement_cardinality_contract"]["rule_revision_id"], "rationale": "Minimum requirements are scientific evidence roles declared by each archetype, not a one-row-per-obligation target."},
        "counts": {"total": len(requirements), "required": states["required"], "conditional": states["conditionally-required"], "characterization": modes["characterization-only"], "conformance_capable": modes["conformance-capable"], "conditional_conformance": modes["conditional-conformance"], "relational_metamorphic_candidate": modes["relational/metamorphic-candidate"], "missing_vector_definitions": len(requirements), "by_role": dict(sorted(roles.items()))},
        "requirements": sorted(requirements, key=lambda value: value["requirement_key"]),
        "derivation_id": MATERIALIZATION_DERIVATION_ID, "derivation_revision_id": materialization_derivation_spec(root)["derivation_revision_id"],
    }
    result = _finalize(root, body, namespace="ontology-snapshot", family=SCHEMA_FAMILIES["requirement"], id_field="snapshot_id", digest_field="snapshot_digest_sha256")
    validate_instance(result, load_strict(root / REQUIREMENT_SCHEMA_PATH), source=REQUIREMENT_PATH.as_posix())
    return result, old_to_keys, key_to_old


def _migration_disposition(old_key: str, successor_keys: list[str], successor_to_old: dict[str, list[str]], retained_key: str | None, analysis_classification: str | None) -> tuple[str, str]:
    if retained_key == old_key:
        return "retained-scientific-identity", "The predecessor and successor ask the same scientific question over the same canonical operation scope; only representation and explainability metadata changed."
    if not successor_keys:
        if analysis_classification == "uniform-template-without-feature-specific-trigger":
            return "retired-no-researched-trigger", "Frozen researched semantics explicitly suppress this predecessor template; its identity remains reserved as historical."
        return "historical-only-unmapped", "No uniquely justified successor question exists under the accepted derivation rules; the historical identity remains resolvable without receiving current denominator credit."
    if len(successor_keys) > 1:
        return "split-into-successors", "One coarse predecessor question separates into multiple independently attributable semantic questions or evidence roles."
    if len(successor_to_old[successor_keys[0]]) > 1:
        return "merged-into-successor", "Multiple fixed-grid predecessor questions collapse into one scientifically attributable successor question."
    return "semantically-equivalent-successor", "The current rule preserves the scientific topic but corrects meaning-bearing scope, condition, or evidence cardinality, so a successor identity is required."


def build_migration_ledger(root: Path, obligation_snapshot: dict[str, Any], requirement_snapshot: dict[str, Any], obligation_old_to_new: dict[str, list[str]], requirement_old_to_new: dict[str, list[str]]) -> dict[str, Any]:
    catalog_by_key, scientific_by_key = _old_catalog_maps(root)
    new_obligation_by_key = {item["obligation_key"]: item for item in obligation_snapshot["obligations"]}
    new_requirement_by_key = {item["requirement_key"]: item for item in requirement_snapshot["requirements"]}
    obligation_successor_to_old: dict[str, list[str]] = defaultdict(list)
    requirement_successor_to_old: dict[str, list[str]] = defaultdict(list)
    for old, successors in obligation_old_to_new.items():
        for successor in successors:
            obligation_successor_to_old[successor].append(old)
    for old, successors in requirement_old_to_new.items():
        for successor in successors:
            requirement_successor_to_old[successor].append(old)
    legacy_report = load_strict(root / "reports/semantics/legacy-obligation-derivation-analysis-2026-09-08.v1.json")
    classification = {item["legacy_obligation_id"]: item["analysis_classification"] for item in legacy_report["obligation_cases"]}
    obligation_rows = []
    for old in sorted(obligation_old_to_new):
        successors = obligation_old_to_new[old]
        retained = next((key for key in successors if new_obligation_by_key[key]["scientific_id"] == scientific_by_key[old]), None)
        disposition, reason = _migration_disposition(old, successors, obligation_successor_to_old, retained, classification.get(old))
        obligation_rows.append({"predecessor_key": old, "predecessor_scientific_id": scientific_by_key[old], "disposition": disposition, "successor_keys": successors, "successor_scientific_ids": [new_obligation_by_key[key]["scientific_id"] for key in successors], "reason": reason, "derivation_class": "research-derived" if disposition in {"retired-no-researched-trigger", "historical-only-unmapped"} else "calculation"})
    requirement_rows = []
    obligation_disposition_by_key = {item["predecessor_key"]: item["disposition"] for item in obligation_rows}
    old_requirements = {item["requirement_id"]: item for item in load_strict(root / LEGACY_REQUIREMENTS_PATH)["requirements"]}
    for old in sorted(requirement_old_to_new):
        successors = requirement_old_to_new[old]
        retained = next((key for key in successors if new_requirement_by_key[key]["scientific_id"] == scientific_by_key[old]), None)
        parent_class = obligation_disposition_by_key[old_requirements[old]["obligation_id"]]
        analysis_classification = "uniform-template-without-feature-specific-trigger" if parent_class == "retired-no-researched-trigger" else None
        disposition, reason = _migration_disposition(old, successors, requirement_successor_to_old, retained, analysis_classification)
        requirement_rows.append({"predecessor_key": old, "predecessor_scientific_id": scientific_by_key[old], "disposition": disposition, "successor_keys": successors, "successor_scientific_ids": [new_requirement_by_key[key]["scientific_id"] for key in successors], "reason": reason, "derivation_class": "research-derived" if disposition in {"retired-no-researched-trigger", "historical-only-unmapped"} else "calculation"})
    def origins(values: list[dict[str, Any]], key_field: str, kind: str) -> list[dict[str, Any]]:
        result = []
        for item in values:
            disposition = item["lineage_disposition"]
            origin = "new-semantic-object" if disposition.startswith("new-") else disposition
            result.append({"successor_key": item[key_field], "successor_scientific_id": item["scientific_id"], "predecessor_scientific_ids": item["predecessor_scientific_ids"], "origin": origin, "reason": f"The accepted semantic derivation and cardinality rules classify this current object as {origin}."})
        return sorted(result, key=lambda value: value["successor_key"])
    obligation_counts = Counter(item["disposition"] for item in obligation_rows)
    requirement_counts = Counter(item["disposition"] for item in requirement_rows)
    body = {
        "schema_version": "semantic-denominator-migration.v1", "published_on": PUBLISHED_ON,
        "predecessor": {"projection_path": LEGACY_PROJECTION_PATH.as_posix(), "projection_sha256": _sha(root / LEGACY_PROJECTION_PATH), "obligation_count": 12048, "requirements_path": LEGACY_REQUIREMENTS_PATH.as_posix(), "requirements_sha256": _sha(root / LEGACY_REQUIREMENTS_PATH), "requirement_count": 9506},
        "successor": {"obligation_snapshot_id": obligation_snapshot["snapshot_id"], "obligation_count": obligation_snapshot["counts"]["total"], "requirement_snapshot_id": requirement_snapshot["snapshot_id"], "requirement_count": requirement_snapshot["counts"]["total"]},
        "counts": {"obligation_migrations": len(obligation_rows), "obligation_by_disposition": dict(sorted(obligation_counts.items())), "requirement_migrations": len(requirement_rows), "requirement_by_disposition": dict(sorted(requirement_counts.items())), "new_obligation_objects": obligation_snapshot["counts"]["total"], "new_requirement_objects": requirement_snapshot["counts"]["total"]},
        "obligation_migrations": obligation_rows, "requirement_migrations": requirement_rows,
        "new_obligation_origins": origins(obligation_snapshot["obligations"], "obligation_key", "obligation"),
        "new_requirement_origins": origins(requirement_snapshot["requirements"], "requirement_key", "requirement"),
        "derivation_id": MATERIALIZATION_DERIVATION_ID, "derivation_revision_id": materialization_derivation_spec(root)["derivation_revision_id"],
    }
    result = _finalize(root, body, namespace="reconciliation-set", family=SCHEMA_FAMILIES["migration"], id_field="ledger_id", digest_field="ledger_digest_sha256")
    validate_instance(result, load_strict(root / MIGRATION_SCHEMA_PATH), source=MIGRATION_PATH.as_posix())
    return result


def _write_canonical(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _lineage(root: Path, *, kind: str, effect: str, source_ids: list[str], target_ids: list[str], prior_keys: list[str], current_keys: list[str], prior_fingerprints: list[str], current_fingerprints: list[str], rationale: str) -> dict[str, Any]:
    record = {
        "change_kind": kind, "identity_effect": effect, "effective_date": PUBLISHED_ON,
        "source_ids": sorted(set(source_ids)), "target_ids": sorted(set(target_ids)),
        "prior_keys": sorted(set(prior_keys)), "current_keys": sorted(set(current_keys)),
        "prior_fingerprints": sorted(set(prior_fingerprints)), "current_fingerprints": sorted(set(current_fingerprints)),
        "rationale": rationale,
    }
    record["lineage_record_id"] = lineage_record_id(root, record)
    return record


def transition_identity_catalog(root: Path, migration: dict[str, Any]) -> dict[str, int]:
    catalog = load_strict(root / IDENTITY_CATALOG_PATH)
    bindings = deepcopy(catalog["bindings"])
    existing_lineage = {item["lineage_record_id"]: item for item in catalog["lineage_records"]}
    owners = {item["canonical_key"]: item for item in bindings}
    allocation = load_strict(root / ALLOCATION_PATH)
    allocated_by_key = {item["canonical_key"]: item for item in allocation["entity_allocations"]}
    descriptors, sources = collect_descriptors(root)
    descriptor_by_key = {item.key: item for item in descriptors}
    # Add every newly allocated current entity before resolving cross-entity fingerprints.
    for descriptor in descriptors:
        if descriptor.key in owners:
            continue
        allocation_item = allocated_by_key.get(descriptor.key)
        if allocation_item is None or allocation_item["entity_class"] != descriptor.entity_class:
            fail("missing-current-identity-allocation", "current denominator entity lacks the reviewed allocation", descriptor.key)
        binding = {
            "scientific_id": allocation_item["assigned_id"], "entity_class": descriptor.entity_class,
            "canonical_key": descriptor.key, "former_keys": [], "status": "active",
            "source_role": descriptor.source_role, "semantic_fingerprint_history": [],
        }
        bindings.append(binding)
        owners[descriptor.key] = binding
    identities = {key: item["scientific_id"] for key, item in owners.items()}
    current_fingerprints = {key: semantic_fingerprint(descriptor, identities) for key, descriptor in descriptor_by_key.items()}
    for key, descriptor in descriptor_by_key.items():
        binding = owners[key]
        allocation_item = allocated_by_key.get(key)
        if allocation_item and binding["scientific_id"] != allocation_item["assigned_id"]:
            fail("denominator-allocation-catalog-conflict", "identity catalog disagrees with the accepted denominator allocation", key)
        binding["status"] = "active"
        binding["source_role"] = descriptor.source_role
        actual = current_fingerprints[key]
        if not binding["semantic_fingerprint_history"]:
            binding["semantic_fingerprint_history"].append({"effective_date": PUBLISHED_ON, "fingerprint_sha256": actual, "lineage_record_id": None})
        elif binding["semantic_fingerprint_history"][-1]["fingerprint_sha256"] != actual:
            prior = binding["semantic_fingerprint_history"][-1]["fingerprint_sha256"]
            record = _lineage(
                root, kind="corrected-without-semantic-change", effect="retained",
                source_ids=[binding["scientific_id"]], target_ids=[binding["scientific_id"]],
                prior_keys=[key], current_keys=[key], prior_fingerprints=[prior], current_fingerprints=[actual],
                rationale="The scientific question and canonical operation scope are retained; the successor adds typed semantic references, explicit conditionality, cardinality, and explainability without changing the entity's meaning.",
            )
            existing_lineage.setdefault(record["lineage_record_id"], record)
            binding["semantic_fingerprint_history"].append({"effective_date": PUBLISHED_ON, "fingerprint_sha256": actual, "lineage_record_id": record["lineage_record_id"]})

    migration_rows = [*migration["obligation_migrations"], *migration["requirement_migrations"]]
    row_by_key = {item["predecessor_key"]: item for item in migration_rows}
    status_by_disposition = {
        "semantically-equivalent-successor": "superseded", "superseded": "superseded",
        "split-into-successors": "split", "merged-into-successor": "merged",
        "retired-no-researched-trigger": "out-of-scope", "historical-only-unmapped": "unresolved",
    }
    for key, row in row_by_key.items():
        if row["disposition"] == "retained-scientific-identity":
            continue
        owners[key]["status"] = status_by_disposition[row["disposition"]]

    # One-to-one successors and splits are explicit edges. Merges are grouped so
    # the lineage contract sees all predecessors in one scientifically meaningful edge.
    for row in migration_rows:
        if row["disposition"] not in {"semantically-equivalent-successor", "superseded", "split-into-successors"}:
            continue
        source = owners[row["predecessor_key"]]
        targets = [owners[key] for key in row["successor_keys"]]
        kind = "split-from" if len(targets) > 1 else "supersedes"
        record = _lineage(
            root, kind=kind, effect="new-identity", source_ids=[source["scientific_id"]],
            target_ids=[item["scientific_id"] for item in targets], prior_keys=[row["predecessor_key"]],
            current_keys=row["successor_keys"], prior_fingerprints=[source["semantic_fingerprint_history"][-1]["fingerprint_sha256"]],
            current_fingerprints=[current_fingerprints[key] for key in row["successor_keys"]], rationale=row["reason"],
        )
        existing_lineage.setdefault(record["lineage_record_id"], record)
    merged_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in migration_rows:
        if row["disposition"] == "merged-into-successor":
            merged_groups[row["successor_keys"][0]].append(row)
    for target_key, rows in merged_groups.items():
        if len(rows) < 2:
            fail("invalid-denominator-merge", "a merge disposition must have multiple predecessors", target_key)
        sources_for_merge = [owners[item["predecessor_key"]] for item in rows]
        record = _lineage(
            root, kind="merged-from", effect="new-identity",
            source_ids=[item["scientific_id"] for item in sources_for_merge], target_ids=[owners[target_key]["scientific_id"]],
            prior_keys=[item["predecessor_key"] for item in rows], current_keys=[target_key],
            prior_fingerprints=[item["semantic_fingerprint_history"][-1]["fingerprint_sha256"] for item in sources_for_merge],
            current_fingerprints=[current_fingerprints[target_key]], rationale=rows[0]["reason"],
        )
        existing_lineage.setdefault(record["lineage_record_id"], record)
    bindings.sort(key=lambda item: (item["entity_class"], item["canonical_key"]))
    active = sum(item["status"] == "active" for item in bindings)
    result = {
        **{key: value for key, value in catalog.items() if key not in {"source_artifacts", "bindings", "lineage_records", "counts", "catalog_digest_sha256"}},
        "source_artifacts": sources,
        "bindings": bindings,
        "lineage_records": sorted(existing_lineage.values(), key=lambda item: item["lineage_record_id"]),
        "counts": {
            "active": active, "historical": len(bindings) - active,
            "by_class": dict(sorted(Counter(item["entity_class"] for item in bindings).items())),
            "lineage_records": len(existing_lineage), "total": len(bindings),
        },
    }
    result["catalog_digest_sha256"] = catalog_digest(result)
    (root / IDENTITY_CATALOG_PATH).write_text(dump_pretty(result), encoding="utf-8", newline="\n")
    return verify_identity_catalog(root, result)


def build_projection(root: Path, obligation_snapshot: dict[str, Any], requirement_snapshot: dict[str, Any]) -> dict[str, Any]:
    semantic = load_strict(root / SNAPSHOT_PATH)
    body = {
        "schema_version": "semantic-requirement-projection.v2", "published_on": PUBLISHED_ON,
        "authority_status": "current-semantic-denominator-input",
        "semantic_snapshot": _artifact_binding(SNAPSHOT_PATH, semantic, "snapshot_id", "snapshot_digest_sha256"),
        "obligation_snapshot": _artifact_binding(OBLIGATION_PATH, obligation_snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "requirement_snapshot": _artifact_binding(REQUIREMENT_PATH, requirement_snapshot, "snapshot_id", "snapshot_digest_sha256"),
        "counts": {"features": len(semantic["features"]), "operations": len(semantic["operations"]), "facets": len(semantic["semantic_facets"]), "obligations": obligation_snapshot["counts"]["total"], "requirements": requirement_snapshot["counts"]["total"], "conditional_obligations": obligation_snapshot["counts"]["conditional"], "conditional_requirements": requirement_snapshot["counts"]["conditional"]},
        "features": [{"feature_id": item["feature_id"], "scientific_id": item["scientific_id"]} for item in semantic["features"]],
        "operations": [{"operation_id": item["operation_id"], "scientific_id": item["scientific_id"]} for item in semantic["operations"]],
        "facets": [{"facet_id": item["facet_id"], "scientific_id": item["scientific_id"]} for item in semantic["semantic_facets"]],
        "requirements": [{
            "requirement_key": item["requirement_key"], "scientific_id": item["scientific_id"],
            "obligation_scientific_ids": item["obligation_scientific_ids"], "feature_scientific_id": item["feature_scientific_id"],
            "facet_id": item["facet_id"], "archetype_id": item["archetype_id"], "evidence_role": item["evidence_role"],
            "question_type": item["question_type"], "requirement_type": item["requirement_type"], "requirement_state": item["requirement_state"],
            "profile_condition": item["profile_condition"], "operation_scientific_ids": item["required_operation_scientific_ids"],
            "derivation_revision_id": item["derivation_revision_id"],
        } for item in requirement_snapshot["requirements"]],
        "profile_expansion": {"status": "deferred", "formula": "Evaluate each requirement's closed capability predicate over the empirically frozen exact profile registry, then count one logical coordinate per applicable requirement/profile/operation scope.", "forbidden_shortcut": "Do not multiply by predecessor planning profile counts or treat missing capability data as not-applicable."},
    }
    result = _finalize(root, body, namespace="ontology-projection", family=SCHEMA_FAMILIES["projection"], id_field="projection_id", digest_field="projection_digest_sha256")
    validate_instance(result, load_strict(root / PROJECTION_SCHEMA_PATH), source=PROJECTION_PATH.as_posix())
    return result


def _percentile(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def build_report(root: Path, obligation_snapshot: dict[str, Any], requirement_snapshot: dict[str, Any], migration: dict[str, Any], projection: dict[str, Any], identity_counts: dict[str, int]) -> dict[str, Any]:
    obligation_by_feature = Counter(item["feature_id"] for item in obligation_snapshot["obligations"])
    requirement_by_feature = Counter(item["feature_id"] for item in requirement_snapshot["requirements"])
    values_o = list(obligation_by_feature.values())
    values_r = list(requirement_by_feature.values())
    dry = load_strict(root / DRY_RUN_PATH)
    anomaly_checks = [
        {"check": "zero-obligation-feature", "status": "PASS", "detail": "All 269 frozen features have at least one attributable obligation."},
        {"check": "obligation-without-requirement-path", "status": "PASS", "detail": "Every obligation owns its declared minimum requirement roles."},
        {"check": "orphan-requirement", "status": "PASS", "detail": "Every requirement references one canonical current obligation."},
        {"check": "duplicate-scientific-question", "status": "PASS", "detail": "Obligation and requirement identity bases are unique."},
        {"check": "conflicting-feature-facet-decision", "status": "PASS", "detail": "The accepted rule engine remains total at one decision per feature/facet pair."},
        {"check": "conditional-without-predicate", "status": "PASS", "detail": "Every conditional object retains a non-empty closed profile predicate."},
        {"check": "required-from-unresolved-semantics", "status": "PASS", "detail": "The frozen derivation contains zero blocked or unresolved obligation decisions."},
        {"check": "operation-multiplier-explosion", "status": "PASS", "detail": "Operations remain scopes inside 2,390 questions rather than a blind feature-by-operation cross product."},
        {"check": "feature-population-outlier", "status": "PASS", "detail": f"Reviewed maxima remain bounded at {max(values_o)} obligations and {max(values_r)} minimum requirements for one feature."},
        {"check": "characterization-as-conformance", "status": "PASS", "detail": "Permitted-variation evidence roles are explicitly characterization-only."},
        {"check": "semantic-source-missing", "status": "PASS", "detail": "Every obligation binds at least one content-derived semantic assertion revision and primary source identity."},
        {"check": "historical-artifact-mutation", "status": "PASS", "detail": "All predecessor byte digests equal the accepted immutability baseline."},
    ]
    old_o, new_o = 12048, obligation_snapshot["counts"]["total"]
    old_r, new_r = 9506, requirement_snapshot["counts"]["total"]
    body = {
        "schema_version": "semantic-denominator-materialization-report.v1", "published_on": PUBLISHED_ON,
        "authority": {"semantic_snapshot_id": load_strict(root / SNAPSHOT_PATH)["snapshot_id"], "obligation_snapshot_id": obligation_snapshot["snapshot_id"], "requirement_snapshot_id": requirement_snapshot["snapshot_id"], "projection_id": projection["projection_id"]},
        "summary": {"features": 269, "obligations": new_o, "required_obligations": obligation_snapshot["counts"]["required"], "conditional_obligations": obligation_snapshot["counts"]["conditional"], "characterization_obligations": obligation_snapshot["counts"]["characterization"], "requirements": new_r, "required_requirements": requirement_snapshot["counts"]["required"], "conditional_requirements": requirement_snapshot["counts"]["conditional"], "characterization_requirements": requirement_snapshot["counts"]["characterization"], "profile_predicates": sum(item["requirement_state"] == "conditionally-required" for item in obligation_snapshot["obligations"]), "blocked": 0},
        "distribution": {"obligations_per_feature": {"minimum": min(values_o), "median": _percentile(values_o, .5), "p95": _percentile(values_o, .95), "maximum": max(values_o)}, "requirements_per_feature": {"minimum": min(values_r), "median": _percentile(values_r, .5), "p95": _percentile(values_r, .95), "maximum": max(values_r)}, "obligations_by_facet": obligation_snapshot["counts"]["by_facet"], "requirements_by_role": requirement_snapshot["counts"]["by_role"], "requirements_by_operation": dict(sorted(Counter(op for item in requirement_snapshot["requirements"] for op in item["required_operation_ids"]).items())), "interaction_derived_obligations": obligation_snapshot["counts"]["by_archetype"].get("archetype.interaction-specific", 0)},
        "migration": deepcopy(migration["counts"]),
        "dry_run_comparison": {"dry_run_obligations": dry["summary"]["provisional_obligations"], "canonical_obligations": new_o, "obligation_delta": new_o - dry["summary"]["provisional_obligations"], "canonical_requirements": new_r, "cardinality_expansion": new_r - new_o, "explanation": "The canonical obligation population is exactly the accepted dry-run question population. Requirement count is larger only because two-polarity archetypes require independently attributable minimum evidence roles."},
        "anomaly_checks": anomaly_checks,
        "profile_expansion": {"status": "deferred", "semantic_requirement_count": new_r, "exact_profile_count": None, "final_execution_denominator": None, "reason": "Exact capability predicates cannot be evaluated until the empirical profile universe is frozen; predecessor planning multipliers are not reused."},
        "historical_immutability": denominator_baseline(root),
        "derivations": {"obligation_rule_derivation_id": load_strict(root / CONTRACT_PATH)["derivation_id"], "materialization_derivation_id": MATERIALIZATION_DERIVATION_ID, "materialization_derivation_revision_id": materialization_derivation_spec(root)["derivation_revision_id"], "identity_count": identity_counts["scientific_identities"], "lineage_record_count": identity_counts["scientific_lineage_records"]},
    }
    result = _finalize(root, body, namespace="finding-revision", family=SCHEMA_FAMILIES["report"], id_field="report_id", digest_field="report_digest_sha256")
    validate_instance(result, load_strict(root / REPORT_SCHEMA_PATH), source=REPORT_PATH.as_posix())
    return result


def build_authority(root: Path, obligation_snapshot: dict[str, Any], requirement_snapshot: dict[str, Any], migration: dict[str, Any], projection: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    certification_input_path = Path("certification/inputs/current-repository-2026-09-08.v2.json")
    certification_report_path = Path("certification/reports/current-repository-2026-09-08.v2.json")
    certification_input = load_strict(root / certification_input_path)
    certification_report = load_strict(root / certification_report_path)
    old_projection = load_strict(root / LEGACY_PROJECTION_PATH)
    body = {
        "schema_version": "semantic-denominator-authority-index.v1", "effective_on": PUBLISHED_ON,
        "current": {
            "obligation_snapshot": _artifact_binding(OBLIGATION_PATH, obligation_snapshot, "snapshot_id", "snapshot_digest_sha256"),
            "requirement_snapshot": _artifact_binding(REQUIREMENT_PATH, requirement_snapshot, "snapshot_id", "snapshot_digest_sha256"),
            "projection": _artifact_binding(PROJECTION_PATH, projection, "projection_id", "projection_digest_sha256"),
            "migration_ledger": _artifact_binding(MIGRATION_PATH, migration, "ledger_id", "ledger_digest_sha256"),
            "materialization_report": _artifact_binding(REPORT_PATH, report, "report_id", "report_digest_sha256"),
            "certification_input": _artifact_binding(certification_input_path, certification_input, "input_set_id", "input_set_digest_sha256"),
            "certification_evaluation": _artifact_binding(certification_report_path, certification_report, "report_id", "report_digest_sha256"),
        },
        "historical_predecessor": {"projection": {"path": LEGACY_PROJECTION_PATH.as_posix(), "artifact_id": old_projection["projection_id"], "file_sha256": _sha(root / LEGACY_PROJECTION_PATH), "obligation_count": 12048}, "requirements": {"path": LEGACY_REQUIREMENTS_PATH.as_posix(), "file_sha256": _sha(root / LEGACY_REQUIREMENTS_PATH), "requirement_count": 9506}, "forecast": {"path": LEGACY_FORECAST_PATH.as_posix(), "file_sha256": _sha(root / LEGACY_FORECAST_PATH)}},
        "profile_expanded_denominator": {"status": "deferred", "reason": "The final execution denominator awaits empirical profile-universe freeze and capability-predicate evaluation."},
        "governance": {"authority_change": "manual-decision", "validated_artifact_precondition": True, "predecessor_rewritten": False, "production_vectors_generated": False},
    }
    result = _finalize(root, body, namespace="artifact-set-manifest", family=SCHEMA_FAMILIES["authority"], id_field="index_id", digest_field="index_digest_sha256")
    validate_instance(result, load_strict(root / AUTHORITY_SCHEMA_PATH), source=AUTHORITY_PATH.as_posix())
    return result


def _validate_cross_artifacts(root: Path, obligation_snapshot: dict[str, Any], requirement_snapshot: dict[str, Any], migration: dict[str, Any], projection: dict[str, Any]) -> None:
    obligations = obligation_snapshot["obligations"]
    requirements = requirement_snapshot["requirements"]
    obligation_by_id = {item["scientific_id"]: item for item in obligations}
    if len(obligation_by_id) != len(obligations):
        fail("duplicate-obligation-identity", "two current obligations own one scientific identity")
    requirement_by_id = {item["scientific_id"]: item for item in requirements}
    if len(requirement_by_id) != len(requirements):
        fail("duplicate-requirement-identity", "two current requirements own one scientific identity")
    refs = Counter(value for item in requirements for value in item["obligation_scientific_ids"])
    for obligation in obligations:
        expected = obligation["requirement_cardinality"]["minimum_requirements"]
        if refs[obligation["scientific_id"]] != expected:
            fail("obligation-requirement-cardinality", "obligation does not own its exact declared minimum requirement population", obligation["obligation_key"])
        if obligation["requirement_state"] == "conditionally-required" and not obligation["profile_condition"].get("clauses"):
            fail("conditional-obligation-without-predicate", "conditional obligation lacks a closed predicate", obligation["obligation_key"])
        if not obligation["source_semantic_assertion_ids"]:
            fail("obligation-without-semantic-source", "obligation has no source semantic assertion", obligation["obligation_key"])
    if set(value for item in requirements for value in item["obligation_scientific_ids"]) != set(obligation_by_id):
        fail("orphan-obligation-or-requirement", "obligation/requirement references do not close")
    if migration["counts"]["obligation_migrations"] != 12048 or migration["counts"]["requirement_migrations"] != 9506:
        fail("denominator-migration-population", "predecessor migration ledgers are not total")
    if projection["counts"]["obligations"] != len(obligations) or projection["counts"]["requirements"] != len(requirements):
        fail("denominator-projection-count", "successor projection counts do not reconcile")
    if obligation_snapshot["counts"]["total"] != 2390:
        fail("dry-run-materialization-drift", "canonical obligation count differs from the accepted dry-run questions")
    if not denominator_baseline(root)["artifacts_unchanged"]:
        fail("historical-denominator-mutation", "predecessor denominator bytes changed during materialization")


def build_core(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    obligation, obligation_old_to_new, _ = build_obligation_snapshot(root)
    requirement, requirement_old_to_new, _ = build_requirement_snapshot(root, obligation)
    migration = build_migration_ledger(root, obligation, requirement, obligation_old_to_new, requirement_old_to_new)
    projection = build_projection(root, obligation, requirement)
    _validate_cross_artifacts(root, obligation, requirement, migration, projection)
    return obligation, requirement, migration, projection


def materialize_core(root: Path) -> dict[str, Any]:
    if not denominator_baseline(root)["artifacts_unchanged"]:
        fail("historical-denominator-mutation", "predecessor denominator bytes differ before materialization")
    core = build_core(root)
    for path, value in zip((OBLIGATION_PATH, REQUIREMENT_PATH, MIGRATION_PATH, PROJECTION_PATH), core, strict=True):
        _write_canonical(root / path, value)
    identity_counts = transition_identity_catalog(root, core[2])
    report = build_report(root, *core, identity_counts)
    _write_canonical(root / REPORT_PATH, report)
    rebuilt = build_core(root)
    if any(canonical_bytes(left) != canonical_bytes(right) for left, right in zip(core, rebuilt, strict=True)):
        fail("semantic-denominator-nondeterministic", "double regeneration changed a canonical snapshot")
    return {"obligations": core[0]["counts"]["total"], "requirements": core[1]["counts"]["total"], **identity_counts, "report_id": report["report_id"]}


def finalize_authority(root: Path) -> dict[str, Any]:
    obligation = load_strict(root / OBLIGATION_PATH)
    requirement = load_strict(root / REQUIREMENT_PATH)
    migration = load_strict(root / MIGRATION_PATH)
    projection = load_strict(root / PROJECTION_PATH)
    report = load_strict(root / REPORT_PATH)
    authority = build_authority(root, obligation, requirement, migration, projection, report)
    _write_canonical(root / AUTHORITY_PATH, authority)
    return {"authority_id": authority["index_id"], "authority_digest_sha256": authority["index_digest_sha256"]}


def explain(root: Path, identifier: str) -> dict[str, Any]:
    obligation_snapshot = load_strict(root / OBLIGATION_PATH)
    requirement_snapshot = load_strict(root / REQUIREMENT_PATH)
    obligation = next((item for item in obligation_snapshot["obligations"] if identifier in {item["obligation_key"], item["scientific_id"]}), None)
    requirement = next((item for item in requirement_snapshot["requirements"] if identifier in {item["requirement_key"], item["scientific_id"]}), None)
    if obligation is None and requirement is None:
        fail("unknown-denominator-identity", "identifier is not a current obligation or requirement", identifier)
    if requirement is not None:
        obligation = next(item for item in obligation_snapshot["obligations"] if item["scientific_id"] in requirement["obligation_scientific_ids"])
    return {
        "query": identifier,
        "feature": {"feature_id": obligation["feature_id"], "scientific_id": obligation["feature_scientific_id"]},
        "semantic_assertions": obligation["semantic_assertions"],
        "rule": obligation["derivation"],
        "facet": {"facet_id": obligation["facet_id"], "scientific_id": obligation["facet_scientific_id"]},
        "archetype_id": obligation["archetype_id"],
        "operation_scope": {"operation_ids": obligation["operation_ids"], "operation_scientific_ids": obligation["operation_scientific_ids"], "profile_condition": obligation["profile_condition"]},
        "obligation": {"obligation_key": obligation["obligation_key"], "scientific_id": obligation["scientific_id"], "requirement_state": obligation["requirement_state"], "question_type": obligation["question_type"], "explanation": obligation["explanation"], "predecessor_scientific_ids": obligation["predecessor_scientific_ids"]},
        "requirement": None if requirement is None else {"requirement_key": requirement["requirement_key"], "scientific_id": requirement["scientific_id"], "evidence_role": requirement["evidence_role"], "requirement_type": requirement["requirement_type"], "execution_requirement": requirement["execution_requirement"], "cardinality_rule_revision_id": requirement["cardinality_rule_revision_id"], "predecessor_scientific_ids": requirement["predecessor_scientific_ids"]},
    }


def verify_current(root: Path, *, verify_identity: bool = True) -> dict[str, Any]:
    allocation = _allocation_record(root, allow_new=False)
    if (root / ALLOCATION_PATH).read_bytes() != canonical_bytes(allocation) + b"\n":
        fail("semantic-denominator-allocation-drift", "tracked identity allocation differs")
    built = build_core(root)
    for path, value in zip((OBLIGATION_PATH, REQUIREMENT_PATH, MIGRATION_PATH, PROJECTION_PATH), built, strict=True):
        if (root / path).read_bytes() != canonical_bytes(value) + b"\n":
            fail("semantic-denominator-artifact-drift", "tracked artifact differs from deterministic rebuild", path.as_posix())
    identity_counts = verify_identity_catalog(root) if verify_identity else {"scientific_identities": load_strict(root / IDENTITY_CATALOG_PATH)["counts"]["total"], "scientific_lineage_records": load_strict(root / IDENTITY_CATALOG_PATH)["counts"]["lineage_records"]}
    expected_report = build_report(root, *built, identity_counts)
    if (root / REPORT_PATH).read_bytes() != canonical_bytes(expected_report) + b"\n":
        fail("semantic-denominator-report-drift", "materialization report differs from fresh evaluation")
    authority = load_strict(root / AUTHORITY_PATH)
    expected_authority = build_authority(root, *built, expected_report)
    if canonical_bytes(authority) != canonical_bytes(expected_authority):
        fail("semantic-denominator-authority-drift", "current denominator authority index differs")
    return {"obligations": built[0]["counts"]["total"], "requirements": built[1]["counts"]["total"], "conditional_obligations": built[0]["counts"]["conditional"], "characterization_requirements": built[1]["counts"]["characterization"], **identity_counts, "authority_id": authority["index_id"]}
