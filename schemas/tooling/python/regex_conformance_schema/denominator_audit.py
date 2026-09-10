"""Independent accounting and audit of the canonical semantic denominator."""

from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import math
import os
from pathlib import Path
from typing import Any, Iterable

from .derivation import derivation_revision_id
from .errors import fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .obligation_derivation import CONTRACT_PATH as RULE_CONTRACT_PATH, DRY_RUN_PATH, SNAPSHOT_PATH
from .obligation_snapshots import (
    ARTIFACT_PROFILE_PATH,
    AUTHORITY_PATH as DENOMINATOR_AUTHORITY_PATH,
    MIGRATION_PATH,
    NAMESPACE_PATH,
    OBLIGATION_PATH,
    PROJECTION_PATH,
    REQUIREMENT_PATH,
    SCHEMA_FAMILIES,
)
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import normalize_predicate


PUBLISHED_ON = "2026-09-10"
CONTRACT_PATH = Path("ontology/denominator/regex-semantic-denominator-accounting-2026-09-10.v1.json")
HANDOFF_PATH = Path("ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json")
REPORT_PATH = Path("reports/semantics/regex-semantic-denominator-audit-2026-09-10.v1.json")
AUDIT_AUTHORITY_PATH = Path("ontology/authority/current-semantic-denominator-audit.v1.json")

CONTRACT_SCHEMA_PATH = Path("schemas/json/semantic-denominator-accounting-contract.schema.json")
HANDOFF_SCHEMA_PATH = Path("schemas/json/semantic-profile-expansion-handoff.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/semantic-denominator-audit-report.schema.json")
AUDIT_AUTHORITY_SCHEMA_PATH = Path("schemas/json/semantic-denominator-audit-authority.schema.json")

IDENTITY_CATALOG_PATH = Path("registries/identity/scientific-identities.v1.json")
DERIVATION_CATALOG_PATH = Path("registries/provenance/generated-assertion-derivations.v1.json")
CERTIFICATION_REPORT_PATH = Path("certification/reports/current-repository-2026-09-08.v2.json")
LEGACY_PROJECTION_PATH = Path("ontology/projections/regex-semantic-projection-2026-08-22.v1.json")
LEGACY_REQUIREMENTS_PATH = Path("vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json")
LEGACY_FORECAST_PATH = Path("reports/scale/regex-semantic-denominator-forecast.json")

AUDIT_DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a08bfe-f086-7b3f-bc06-0ed1f691f052"

CAPABILITY_FIELDS = {
    "profile.feature_scientific_ids": "rcid:v1:feature:",
    "profile.operation_scientific_ids": "rcid:v1:operation:",
    "profile.manifestation_scientific_ids": "rcid:v1:manifestation:",
    "profile.semantic_variant_scientific_ids": "rcid:v1:semantic-variant:",
    "profile.modifier_scientific_ids": "rcid:v1:modifier:",
}
PREDICATE_OPERATORS = {"contains", "intersects", "not-contains", "disjoint"}
VALUE_FROM = {"feature.scientific_id", "derived.operation_scientific_ids"}
POSITIVE_OPERATORS = {"contains", "intersects"}
NEGATIVE_OPERATORS = {"not-contains", "disjoint"}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _content_id(root: Path, namespace: str, family: str, body: dict[str, Any]) -> str:
    identity = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / ARTIFACT_PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=family,
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": _digest(body)},
    )
    return str(identity["content_id"])


def _finalize(
    root: Path,
    body: dict[str, Any],
    *,
    namespace: str,
    family: str,
    id_field: str,
    digest_field: str,
) -> dict[str, Any]:
    digest = _digest(body)
    return {
        **body,
        id_field: _content_id(root, namespace, family, body),
        digest_field: digest,
    }


def _artifact_binding(path: Path, artifact: dict[str, Any], id_field: str, digest_field: str) -> dict[str, str]:
    return {
        "path": path.as_posix(),
        "artifact_id": artifact[id_field],
        "digest_sha256": artifact[digest_field],
        "file_sha256": _sha(path) if path.is_absolute() else "",
    }


def _bound(root: Path, path: Path, artifact: dict[str, Any], id_field: str, digest_field: str) -> dict[str, str]:
    value = _artifact_binding(path, artifact, id_field, digest_field)
    value["file_sha256"] = _sha(root / path)
    return value


def _id_commitment(values: Iterable[str]) -> dict[str, Any]:
    ordered = sorted(values)
    if len(ordered) != len(set(ordered)):
        fail("duplicate-commitment-member", "stable-ID commitment population contains a duplicate")
    return {"member_count": len(ordered), "jcs_sha256": _digest(ordered)}


def audit_derivation_spec(root: Path) -> dict[str, Any]:
    record = {
        "title": "Independent semantic denominator accounting audit",
        "derivation_class": "calculation",
        "method_key": "semantic-denominator-independent-audit",
        "method_version": "1.0.0",
        "input_references": [
            OBLIGATION_PATH.as_posix(),
            REQUIREMENT_PATH.as_posix(),
            MIGRATION_PATH.as_posix(),
            DRY_RUN_PATH.as_posix(),
            RULE_CONTRACT_PATH.as_posix(),
        ],
        "authority_references": [DENOMINATOR_AUTHORITY_PATH.as_posix()],
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
        "derivation_id": AUDIT_DERIVATION_ID,
    }
    record["derivation_revision_id"] = derivation_revision_id(root, record)
    return record


def build_contract(root: Path) -> dict[str, Any]:
    semantic = load_strict(root / SNAPSHOT_PATH)
    obligations = load_strict(root / OBLIGATION_PATH)
    requirements = load_strict(root / REQUIREMENT_PATH)
    authority = load_strict(root / DENOMINATOR_AUTHORITY_PATH)
    body: dict[str, Any] = {
        "schema_version": "semantic-denominator-accounting-contract.v1",
        "contract_version": "1.0.0",
        "effective_on": PUBLISHED_ON,
        "authority": {
            "semantic_snapshot": _bound(root, SNAPSHOT_PATH, semantic, "snapshot_id", "snapshot_digest_sha256"),
            "obligation_snapshot": _bound(root, OBLIGATION_PATH, obligations, "snapshot_id", "snapshot_digest_sha256"),
            "requirement_snapshot": _bound(root, REQUIREMENT_PATH, requirements, "snapshot_id", "snapshot_digest_sha256"),
            "denominator_authority": _bound(root, DENOMINATOR_AUTHORITY_PATH, authority, "index_id", "index_digest_sha256"),
        },
        "population_definitions": [
            {"term": "scientific-obligation", "definition": "One canonical scientific behavior or question that must be known.", "population": "canonical obligations", "axis": "object-kind", "partition_behavior": "separate-population", "contributes_to_c4": False, "future_execution_contribution": "Through its minimum attributable requirements."},
            {"term": "minimum-requirement", "definition": "One independently attributable minimum evidence role needed to answer a scientific obligation.", "population": "canonical requirements", "axis": "object-kind", "partition_behavior": "separate-population", "contributes_to_c4": True, "future_execution_contribution": "One or more exact profile/operation applicability coordinates after profile freeze."},
            {"term": "required", "definition": "Unconditional under the frozen semantic model; profile feature and operation exposure are still evaluated later.", "population": "canonical requirements", "axis": "semantic-applicability", "partition_behavior": "partition-member", "contributes_to_c4": True, "future_execution_contribution": "Eligible wherever the exact profile predicate resolves true."},
            {"term": "conditional", "definition": "Requires an implementation, variant, manifestation, modifier, feature, or operation capability fact before profile applicability can be decided.", "population": "canonical requirements", "axis": "semantic-applicability", "partition_behavior": "partition-member", "contributes_to_c4": True, "future_execution_contribution": "Only coordinates whose closed predicate resolves true."},
            {"term": "characterization-only", "definition": "Requires observation without asserting one normative cross-profile outcome.", "population": "canonical requirements", "axis": "scientific-purpose", "partition_behavior": "partition-member", "contributes_to_c4": True, "future_execution_contribution": "Characterization coverage, never silent normative credit."},
            {"term": "executable", "definition": "Can be answered through a target-attributable vector, sequence, relation, bounded resource witness, or characterization observation under the current model.", "population": "canonical requirements", "axis": "execution-disposition", "partition_behavior": "overlapping-rollup", "contributes_to_c4": True, "future_execution_contribution": "Subject to exact profile applicability."},
            {"term": "informative", "definition": "Produces scientific knowledge without necessarily carrying a direct normative expected outcome; includes relational and characterization questions.", "population": "canonical requirements", "axis": "scientific-purpose", "partition_behavior": "overlapping-rollup", "contributes_to_c4": True, "future_execution_contribution": "Relational or characterization evidence under its declared question type."},
            {"term": "prohibited", "definition": "Must not be executed or credited under an explicit safety, semantic, authority, or applicability rule; it is not synonymous with not-applicable.", "population": "candidate requirements before admission", "axis": "execution-disposition", "partition_behavior": "partition-member", "contributes_to_c4": False, "future_execution_contribution": "None unless a successor contract removes the prohibition."},
            {"term": "unresolved", "definition": "Cannot be assigned authoritatively because a required upstream semantic or applicability fact is unresolved.", "population": "candidate requirements before admission", "axis": "execution-disposition", "partition_behavior": "partition-member", "contributes_to_c4": False, "future_execution_contribution": "Blocked until the missing authority is resolved."},
            {"term": "unperformable-dispositioned-evidence", "definition": "A future applicable coordinate that cannot be executed but remains explicitly dispositioned with admissible evidence or an absence reason instead of disappearing from accounting.", "population": "future profile-expanded coordinates", "axis": "coordinate-disposition", "partition_behavior": "partition-member", "contributes_to_c4": False, "future_execution_contribution": "Retained as an explicit disposition; never fabricated as an observation."},
            {"term": "semantic-side-denominator", "definition": "The canonical obligation and minimum-requirement populations before exact profile capability evaluation.", "population": "canonical obligations and requirements", "axis": "scope", "partition_behavior": "separate-population", "contributes_to_c4": True, "future_execution_contribution": "Input to exact profile-specific applicability."},
            {"term": "profile-expanded-denominator", "definition": "The future exact applicable coordinate population after empirical profile facts evaluate every requirement predicate and operation scope.", "population": "future profile-specific coordinates", "axis": "scope", "partition_behavior": "separate-population", "contributes_to_c4": True, "future_execution_contribution": "Deferred; no numeric population is asserted by this contract."},
            {"term": "logical-execution", "definition": "One applicable scientific coordinate requiring one terminal disposition regardless of retry or repeat count.", "population": "future profile-specific coordinates", "axis": "execution-unit", "partition_behavior": "separate-population", "contributes_to_c4": True, "future_execution_contribution": "One completion credit after admissible target-attributable terminal evidence."},
            {"term": "physical-attempt", "definition": "One append-only physical realization of a logical execution; retries and repeats never multiply denominator credit.", "population": "future execution evidence", "axis": "execution-unit", "partition_behavior": "separate-population", "contributes_to_c4": False, "future_execution_contribution": "Provenance only; inconclusive attempts cannot satisfy a logical execution."},
            {"term": "lower", "definition": "The unconditional semantic minimum known without evaluating future profile capability facts.", "population": "canonical obligations and requirements", "axis": "scenario", "partition_behavior": "scenario", "contributes_to_c4": True, "future_execution_contribution": "Lower semantic-side bound only; not a profile-expanded count."},
            {"term": "expected", "definition": "The unconditional minimum plus conditional members weighted only by an accepted empirical profile-applicability model.", "population": "canonical obligations and requirements", "axis": "scenario", "partition_behavior": "scenario", "contributes_to_c4": True, "future_execution_contribution": "Symbolic and deferred until empirical profile applicability supplies the expectation model."},
            {"term": "conservative", "definition": "The provisioned semantic ceiling containing every current required and conditional member without claiming every condition holds for every profile.", "population": "canonical obligations and requirements", "axis": "scenario", "partition_behavior": "scenario", "contributes_to_c4": True, "future_execution_contribution": "Capacity bound only; not the final execution denominator."},
        ],
        "orthogonal_axes": {
            "semantic_applicability": {"partition": ["required", "conditional"], "cross_sum_permitted": True},
            "scientific_purpose": {"partition": ["conformance-capable", "relational/metamorphic-candidate", "characterization-only"], "cross_sum_permitted": True},
            "execution_disposition": {"partition": ["executable-conformance", "executable-relational", "executable-characterization", "non-executable-informative", "prohibited", "unresolved"], "cross_sum_permitted": True},
            "evidence_role": {"partition": ["positive", "negative", "boundary", "characterization"], "cross_sum_permitted": True},
            "operation_membership": {"partition": [], "cross_sum_permitted": False, "reason": "One requirement may name multiple operation scopes; operation totals overlap and must never be added."},
        },
        "scenario_rules": {
            "lower": {"formula": "required", "numeric_policy": "exact"},
            "expected": {"formula": "required + sum(P(profile facts satisfy conditional predicate_i))", "numeric_policy": "deferred-symbolic-with-exact-bounds", "reason": "No accepted empirical profile-applicability expectation model exists at this cutoff."},
            "conservative": {"formula": "required + conditional", "numeric_policy": "exact-provisioned-ceiling", "qualification": "Does not assert that all conditions apply to any one profile."},
        },
        "predicate_contract": {
            "root_operator": "all",
            "fields": sorted(CAPABILITY_FIELDS),
            "operators": sorted(PREDICATE_OPERATORS),
            "value_from": sorted(VALUE_FROM),
            "unknown_fact_result": "unresolved",
            "missing_capability_is_not": ["unsupported", "not-applicable", "false-without-evidence"],
        },
        "authority_references": [
            "GOVERNANCE.md#review-classes",
            "certification/contracts/regex-conformance-certification.v1.1.json",
            "docs/architecture/semantic-obligation-snapshots.md",
        ],
        "derivation": {"derivation_class": "manual-decision", "scope": "Accepted denominator vocabulary and accounting semantics encoded for deterministic repository evaluation."},
    }
    result = _finalize(root, body, namespace="applicability-rule-set", family=SCHEMA_FAMILIES["requirement"], id_field="contract_id", digest_field="contract_digest_sha256")
    validate_instance(result, load_strict(root / CONTRACT_SCHEMA_PATH), source=CONTRACT_PATH.as_posix())
    return result


def _condition_key(value: dict[str, Any]) -> bytes:
    return canonical_bytes(normalize_predicate(value))


def validate_profile_condition(condition: dict[str, Any], known_ids: set[str]) -> dict[str, Any]:
    errors: list[str] = []
    if condition.get("operator") != "all":
        errors.append("root-operator")
    clauses = condition.get("clauses")
    if not isinstance(clauses, list) or not clauses:
        return {"valid": False, "tautology": True, "contradiction": False, "errors": [*errors, "empty-clauses"]}
    normalized_clauses = [normalize_predicate(item) for item in clauses if isinstance(item, dict)]
    if len(normalized_clauses) != len(clauses):
        errors.append("non-object-clause")
    if len({_digest(item) for item in normalized_clauses}) != len(normalized_clauses):
        errors.append("duplicate-clause")
    positive: set[tuple[str, str]] = set()
    negative: set[tuple[str, str]] = set()
    for clause in normalized_clauses:
        field = clause.get("field")
        operator = clause.get("operator")
        if field not in CAPABILITY_FIELDS:
            errors.append("unknown-field")
        if operator not in PREDICATE_OPERATORS:
            errors.append("unknown-operator")
        target_keys = [key for key in ("value", "values", "value_from") if key in clause]
        if len(target_keys) != 1:
            errors.append("ambiguous-target")
            continue
        target_key = target_keys[0]
        target = clause[target_key]
        if target_key == "value_from":
            if target not in VALUE_FROM:
                errors.append("unknown-value-from")
            tokens = [f"from:{target}"]
        elif target_key == "values":
            if not isinstance(target, list) or not target or len(target) != len(set(target)):
                errors.append("invalid-values")
                tokens = []
            else:
                tokens = list(target)
        else:
            tokens = [target]
        if operator in {"contains", "not-contains"} and target_key == "values":
            errors.append("operator-target-mismatch")
        if operator in {"intersects", "disjoint"} and target_key == "value":
            errors.append("operator-target-mismatch")
        for token in tokens:
            if isinstance(token, str) and not token.startswith("from:"):
                if token not in known_ids or (field in CAPABILITY_FIELDS and not token.startswith(CAPABILITY_FIELDS[field])):
                    errors.append("invalid-scientific-reference")
            pair = (str(field), str(token))
            if operator in POSITIVE_OPERATORS:
                positive.add(pair)
            elif operator in NEGATIVE_OPERATORS:
                negative.add(pair)
    return {
        "valid": not errors,
        "tautology": False,
        "contradiction": bool(positive & negative),
        "errors": sorted(set(errors)),
    }


def classify_requirement(requirement: dict[str, Any]) -> str:
    requirement_type = requirement.get("requirement_type")
    execution = requirement.get("execution_requirement")
    if requirement_type in {"conformance-capable", "conditional-conformance"}:
        return "executable-conformance" if execution else "unresolved"
    if requirement_type == "relational/metamorphic-candidate":
        return "executable-relational" if execution else "unresolved"
    if requirement_type == "characterization-only":
        return "executable-characterization" if execution else "non-executable-informative"
    return "unresolved"


def _percentile(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _distribution(values: Iterable[int]) -> dict[str, int]:
    members = list(values)
    return {
        "minimum": min(members),
        "median": _percentile(members, 0.5),
        "p95": _percentile(members, 0.95),
        "maximum": max(members),
    }


def _predicate_id(
    registry: NamespaceRegistry,
    profile: IdentityProfile,
    predicate: dict[str, Any],
) -> str:
    body = {"domain": "strling.regex-conformance.profile-capability-predicate.v1", "predicate": normalize_predicate(predicate)}
    identity = build_content_identity(
        registry=registry,
        profile=profile,
        namespace="applicability-rule-set",
        identity_schema_family_id=SCHEMA_FAMILIES["projection"],
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": _digest(body)},
    )
    return str(identity["content_id"])


def build_handoff(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    obligations = load_strict(root / OBLIGATION_PATH)
    requirements = load_strict(root / REQUIREMENT_PATH)
    registry = NamespaceRegistry.load(root / NAMESPACE_PATH)
    profile = IdentityProfile.from_record(load_strict(root / ARTIFACT_PROFILE_PATH))
    predicates: dict[str, dict[str, Any]] = {}
    bindings = []
    for requirement in sorted(requirements["requirements"], key=lambda item: item["scientific_id"]):
        predicate = normalize_predicate(requirement["profile_condition"])
        predicate_id = _predicate_id(registry, profile, predicate)
        predicates.setdefault(predicate_id, {"predicate_id": predicate_id, "predicate": predicate})
        bindings.append({
            "requirement_scientific_id": requirement["scientific_id"],
            "obligation_scientific_id": requirement["obligation_scientific_ids"][0],
            "feature_scientific_id": requirement["feature_scientific_id"],
            "semantic_applicability": "required" if requirement["requirement_state"] == "required" else "conditional",
            "predicate_id": predicate_id,
            "operation_scientific_ids": sorted(requirement["required_operation_scientific_ids"]),
        })
    conditional_predicates = {
        item["predicate_id"] for item in bindings if item["semantic_applicability"] == "conditional"
    }
    body: dict[str, Any] = {
        "schema_version": "semantic-profile-expansion-handoff.v1",
        "published_on": PUBLISHED_ON,
        "authority": {
            "accounting_contract": {"path": CONTRACT_PATH.as_posix(), "artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"]},
            "obligation_snapshot": _bound(root, OBLIGATION_PATH, obligations, "snapshot_id", "snapshot_digest_sha256"),
            "requirement_snapshot": _bound(root, REQUIREMENT_PATH, requirements, "snapshot_id", "snapshot_digest_sha256"),
        },
        "profile_fact_contract": {
            "required_fields": sorted(CAPABILITY_FIELDS),
            "field_identity_prefixes": CAPABILITY_FIELDS,
            "predicate_operators": sorted(PREDICATE_OPERATORS),
            "value_from": sorted(VALUE_FROM),
            "unknown_fact_result": "unresolved",
        },
        "predicate_definitions": sorted(predicates.values(), key=lambda item: item["predicate_id"]),
        "requirement_predicate_bindings": bindings,
        "evaluation_contract": {
            "formula": "For each exact profile and semantic requirement, resolve feature and operation variables, evaluate the closed predicate, preserve unknown as unresolved, and emit one exact profile × feature × obligation × operation applicability result for each eligible operation.",
            "true_result": "applicable-coordinate-candidate",
            "false_result": "not-applicable-with-evaluated-reason",
            "unknown_result": "unresolved-not-unsupported",
            "operation_rule": "Eligible operations are the exact intersection of the profile operation identities and the requirement operation scope; operation counts are never inferred by a multiplier.",
        },
        "counts": {
            "semantic_requirements": len(bindings),
            "required_requirements": sum(item["semantic_applicability"] == "required" for item in bindings),
            "conditional_requirements": sum(item["semantic_applicability"] == "conditional" for item in bindings),
            "distinct_predicates": len(predicates),
            "distinct_conditional_predicates": len(conditional_predicates),
            "exact_profiles": None,
            "final_logical_execution_denominator": None,
        },
        "deferral": {
            "status": "deferred",
            "reason": "The exact profile registry and empirical capability facts are not frozen.",
            "historical_multiplier_substituted": False,
        },
        "derivation_id": AUDIT_DERIVATION_ID,
        "derivation_revision_id": audit_derivation_spec(root)["derivation_revision_id"],
    }
    result = _finalize(root, body, namespace="ontology-projection", family=SCHEMA_FAMILIES["projection"], id_field="projection_id", digest_field="projection_digest_sha256")
    validate_instance(result, load_strict(root / HANDOFF_SCHEMA_PATH), source=HANDOFF_PATH.as_posix())
    return result


def _compare_counts(declared: dict[str, Any], recomputed: dict[str, Any], keys: Iterable[str], population: str) -> None:
    for key in keys:
        if declared.get(key) != recomputed.get(key):
            fail("independent-denominator-disagreement", f"{population} {key} differs: declared {declared.get(key)!r}, recomputed {recomputed.get(key)!r}")


def _prospective_obligation_bases(dry_run: dict[str, Any]) -> dict[bytes, tuple[dict[str, Any], dict[str, Any]]]:
    result: dict[bytes, tuple[dict[str, Any], dict[str, Any]]] = {}
    for decision in dry_run["decisions"]:
        for candidate in decision["provisional_obligations"]:
            key = canonical_bytes(candidate["prospective_identity_basis"])
            if key in result:
                fail("duplicate-prospective-obligation", "dry-run emitted a duplicate scientific question")
            result[key] = (decision, candidate)
    return result


def _migration_audit(migration: dict[str, Any], obligations: list[dict[str, Any]], requirements: list[dict[str, Any]]) -> dict[str, Any]:
    current_obligation_keys = {item["obligation_key"] for item in obligations}
    current_requirement_keys = {item["requirement_key"] for item in requirements}
    current_obligation_ids = {item["scientific_id"] for item in obligations}
    current_requirement_ids = {item["scientific_id"] for item in requirements}
    rows = [
        ("obligation", migration["obligation_migrations"], current_obligation_keys, current_obligation_ids),
        ("requirement", migration["requirement_migrations"], current_requirement_keys, current_requirement_ids),
    ]
    summaries: dict[str, Any] = {}
    for label, entries, current_keys, current_ids in rows:
        predecessor_keys = [item["predecessor_key"] for item in entries]
        predecessor_ids = [item["predecessor_scientific_id"] for item in entries]
        if len(predecessor_keys) != len(set(predecessor_keys)) or len(predecessor_ids) != len(set(predecessor_ids)):
            fail("duplicate-migration-predecessor", f"{label} predecessor is dispositioned more than once")
        for item in entries:
            if not set(item["successor_keys"]).issubset(current_keys) or not set(item["successor_scientific_ids"]).issubset(current_ids):
                fail("dangling-migration-successor", f"{label} migration references a non-current successor", item["predecessor_key"])
        summaries[label] = {
            "predecessor_count": len(entries),
            "by_disposition": dict(sorted(Counter(item["disposition"] for item in entries).items())),
            "predecessor_id_commitment": _id_commitment(predecessor_ids),
        }
    origin_sets = [
        ("obligation", migration["new_obligation_origins"], current_obligation_ids),
        ("requirement", migration["new_requirement_origins"], current_requirement_ids),
    ]
    for label, origins, current_ids in origin_sets:
        origin_ids = [item["successor_scientific_id"] for item in origins]
        if len(origin_ids) != len(set(origin_ids)) or set(origin_ids) != current_ids:
            fail("migration-origin-closure", f"{label} current-origin rows do not exactly cover current objects")
        summaries[label]["current_origin_count"] = len(origin_ids)
        summaries[label]["current_origin_id_commitment"] = _id_commitment(origin_ids)
    return summaries


def _sample_reconstruction(
    obligation: dict[str, Any],
    requirement: dict[str, Any] | None,
    decision: dict[str, Any],
    sample_axis: str,
    sample_value: str,
) -> dict[str, Any]:
    return {
        "sample_axis": sample_axis,
        "sample_value": sample_value,
        "feature_scientific_id": obligation["feature_scientific_id"],
        "semantic_assertion_revision_ids": sorted(item["assertion_revision_id"] for item in obligation["semantic_assertions"]),
        "rule_revision_id": decision["rule_revision_id"],
        "obligation_scientific_id": obligation["scientific_id"],
        "cardinality_rule_revision_id": obligation["requirement_cardinality"]["rule_revision_id"],
        "requirement_scientific_id": None if requirement is None else requirement["scientific_id"],
        "denominator_classification": {
            "semantic_applicability": "required" if obligation["requirement_state"] == "required" else "conditional",
            "execution_disposition": None if requirement is None else classify_requirement(requirement),
        },
        "result": "PASS",
    }


def reconcile_obligation_bases(
    obligations: list[dict[str, Any]],
    dry_run: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Independently require exact prospective-question/current-object closure."""
    bases = _prospective_obligation_bases(dry_run)
    obligation_decision: dict[str, dict[str, Any]] = {}
    for obligation in obligations:
        key = canonical_bytes(obligation["identity_basis"])
        if key not in bases:
            fail("over-counted-obligation", "canonical obligation has no independently reconstructed dry-run question", obligation["obligation_key"])
        obligation_decision[obligation["scientific_id"]] = bases[key][0]
    if len(bases) != len(obligations):
        fail("under-counted-obligation", f"{len(bases) - len(obligations)} prospective scientific questions are absent from the canonical obligation snapshot")
    return obligation_decision


def _build_samples(
    root: Path,
    semantic: dict[str, Any],
    obligations: list[dict[str, Any]],
    requirements: list[dict[str, Any]],
    dry_run: dict[str, Any],
) -> dict[str, Any]:
    obligation_decision = reconcile_obligation_bases(obligations, dry_run)
    requirements_by_obligation: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for requirement in requirements:
        requirements_by_obligation[requirement["obligation_scientific_ids"][0]].append(requirement)
    samples: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(axis: str, value: str, obligation: dict[str, Any], requirement: dict[str, Any] | None = None) -> None:
        marker = (axis, value)
        if marker in seen:
            return
        seen.add(marker)
        if requirement is None:
            requirement = sorted(requirements_by_obligation[obligation["scientific_id"]], key=lambda item: item["scientific_id"])[0]
        samples.append(_sample_reconstruction(obligation, requirement, obligation_decision[obligation["scientific_id"]], axis, value))

    obligations_by_facet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for obligation in obligations:
        obligations_by_facet[obligation["facet_id"]].append(obligation)
    suppressed_by_facet: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for decision in dry_run["decisions"]:
        if decision["decision"] in {"not-applicable", "not-required-by-feature-semantics"}:
            suppressed_by_facet[decision["facet_id"]].append(decision)
    excluded_samples = []
    for facet in sorted(item["facet_id"] for item in semantic["semantic_facets"]):
        if obligations_by_facet[facet]:
            add("facet", facet, sorted(obligations_by_facet[facet], key=lambda item: item["scientific_id"])[0])
        else:
            decision = sorted(suppressed_by_facet[facet], key=lambda item: item["feature_scientific_id"])[0]
            excluded_samples.append({"sample_axis": "facet", "sample_value": facet, "feature_scientific_id": decision["feature_scientific_id"], "decision": decision["decision"], "rule_revision_id": decision["rule_revision_id"], "result": "PASS"})
    for operation in sorted(item["scientific_id"] for item in semantic["operations"]):
        requirement = min((item for item in requirements if operation in item["required_operation_scientific_ids"]), key=lambda item: item["scientific_id"])
        obligation = next(item for item in obligations if item["scientific_id"] == requirement["obligation_scientific_ids"][0])
        add("operation", operation, obligation, requirement)
    for state in ("required", "conditionally-required"):
        requirement = min((item for item in requirements if item["requirement_state"] == state), key=lambda item: item["scientific_id"])
        obligation = next(item for item in obligations if item["scientific_id"] == requirement["obligation_scientific_ids"][0])
        add("semantic-applicability", state, obligation, requirement)
    for role in ("positive", "negative", "boundary", "characterization"):
        requirement = min((item for item in requirements if item["evidence_role"] == role), key=lambda item: item["scientific_id"])
        obligation = next(item for item in obligations if item["scientific_id"] == requirement["obligation_scientific_ids"][0])
        add("evidence-role", role, obligation, requirement)
    feature_counts = Counter(item["feature_scientific_id"] for item in requirements)
    ordered_counts = sorted(feature_counts.values())
    targets = {"low": ordered_counts[0], "median": ordered_counts[(len(ordered_counts) - 1) // 2], "high": ordered_counts[-1]}
    for band, count in targets.items():
        feature_id = min(key for key, value in feature_counts.items() if value == count)
        obligation = min((item for item in obligations if item["feature_scientific_id"] == feature_id), key=lambda item: item["scientific_id"])
        add("feature-requirement-band", f"{band}:{count}", obligation)
    original_path = root / "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json"
    original = load_strict(original_path)
    legacy_features = {item["feature_id"] for item in original["features"]}
    for feature in sorted((item for item in semantic["features"] if item["feature_id"] not in legacy_features), key=lambda item: item["scientific_id"])[:5]:
        obligation = min((item for item in obligations if item["feature_scientific_id"] == feature["scientific_id"]), key=lambda item: item["scientific_id"])
        add("semantic-successor-feature", feature["feature_id"], obligation)
    interaction = min((item for item in obligations if item["facet_id"] == "facet.interaction-composition"), key=lambda item: item["scientific_id"])
    add("interaction-derived", interaction["feature_id"], interaction)
    for facet, decisions in sorted(suppressed_by_facet.items()):
        decision = sorted(decisions, key=lambda item: (item["decision"], item["feature_scientific_id"]))[0]
        if any(item["feature_scientific_id"] == decision["feature_scientific_id"] and item["facet_id"] == facet for item in obligations):
            fail("suppressed-decision-generated-obligation", "suppressed feature/facet decision incorrectly appears in denominator", facet)
        excluded_samples.append({"sample_axis": "suppressed-facet", "sample_value": facet, "feature_scientific_id": decision["feature_scientific_id"], "decision": decision["decision"], "rule_revision_id": decision["rule_revision_id"], "result": "PASS"})
    return {
        "included_reconstructions": sorted(samples, key=lambda item: (item["sample_axis"], item["sample_value"])),
        "excluded_reconstructions": sorted(excluded_samples, key=lambda item: (item["sample_axis"], item["sample_value"])),
        "included_count": len(samples),
        "excluded_count": len(excluded_samples),
        "result": "PASS",
    }


def _multiplier_audit(root: Path, dry_run: dict[str, Any], obligations: list[dict[str, Any]], requirements: list[dict[str, Any]]) -> dict[str, Any]:
    feature_shapes = len({item["shape_digest_sha256"] for item in dry_run["feature_results"]})
    checks = [
        {"mechanism": "legacy 48-case feature template", "location": LEGACY_PROJECTION_PATH.as_posix(), "classification": "historical-planning-only", "feeds_current_authority": False, "evidence": "12,048 = 251 × 48 remains immutable historical structure and is fully migration-dispositioned."},
        {"mechanism": "legacy profile/archetype lower-expected-conservative bounds", "location": LEGACY_FORECAST_PATH.as_posix(), "classification": "historical-planning-only", "feeds_current_authority": False, "evidence": "Current authority binds no legacy profile count, platform factor, repetition factor, retry factor, or canary multiplier."},
        {"mechanism": "feature × facet decision grid", "location": DRY_RUN_PATH.as_posix(), "classification": "scientifically-derived-structural-audit", "feeds_current_authority": False, "evidence": "The 4,035 decisions audit every feature/facet relation but 2,470 suppressions produce no obligation; decisions yield 85 distinct feature shapes."},
        {"mechanism": "operation membership", "location": REQUIREMENT_PATH.as_posix(), "classification": "scientifically-derived-overlapping-scope", "feeds_current_authority": True, "evidence": "Operation memberships are explicit scientific-ID sets inside each requirement and are not cross-summed or multiplied."},
        {"mechanism": "archetype evidence-role cardinality", "location": OBLIGATION_PATH.as_posix(), "classification": "scientifically-derived-cardinality", "feeds_current_authority": True, "evidence": "Each obligation expands only through its archetype subject-polarity roles; 988 two-role obligations create exactly 988 additional requirements."},
    ]
    forbidden_keys = {"profile_multiplier", "platform_multiplier", "repetition_factor", "assumed_profile_count", "planning_profile_count"}
    current_values = [load_strict(root / path) for path in (OBLIGATION_PATH, REQUIREMENT_PATH, DENOMINATOR_AUTHORITY_PATH)]

    def keys(value: Any) -> Iterable[str]:
        if isinstance(value, dict):
            for key, child in value.items():
                yield key
                yield from keys(child)
        elif isinstance(value, list):
            for child in value:
                yield from keys(child)

    detected = sorted(forbidden_keys.intersection({key for value in current_values for key in keys(value)}))
    if detected:
        fail("hidden-uniform-multiplier", "current denominator authority contains forbidden planning multiplier fields", ",".join(detected))
    return {
        "mechanisms": checks,
        "authoritative_unexplained_multiplier_count": 0,
        "forbidden_current_fields": detected,
        "feature_shape_count": feature_shapes,
        "uniform_feature_shape": feature_shapes == 1,
        "result": "PASS" if feature_shapes > 1 else "FAIL",
    }


def independent_recompute(root: Path, contract: dict[str, Any], handoff: dict[str, Any]) -> dict[str, Any]:
    semantic = load_strict(root / SNAPSHOT_PATH)
    obligation_snapshot = load_strict(root / OBLIGATION_PATH)
    requirement_snapshot = load_strict(root / REQUIREMENT_PATH)
    migration = load_strict(root / MIGRATION_PATH)
    rule_contract = load_strict(root / RULE_CONTRACT_PATH)
    dry_run = load_strict(root / DRY_RUN_PATH)
    obligations = obligation_snapshot["obligations"]
    requirements = requirement_snapshot["requirements"]
    known_ids = {item["scientific_id"] for item in load_strict(root / IDENTITY_CATALOG_PATH)["bindings"]}

    obligation_counts = {
        "total": len(obligations),
        "required": sum(item["requirement_state"] == "required" for item in obligations),
        "conditional": sum(item["requirement_state"] == "conditionally-required" for item in obligations),
        "characterization": sum(item["evidence_mode"] == "characterization-only" for item in obligations),
    }
    requirement_counts = {
        "total": len(requirements),
        "required": sum(item["requirement_state"] == "required" for item in requirements),
        "conditional": sum(item["requirement_state"] == "conditionally-required" for item in requirements),
        "characterization": sum(item["requirement_type"] == "characterization-only" for item in requirements),
    }
    _compare_counts(obligation_snapshot["counts"], obligation_counts, obligation_counts, "obligation")
    _compare_counts(requirement_snapshot["counts"], requirement_counts, requirement_counts, "requirement")
    if sum(obligation_counts[key] for key in ("required", "conditional")) != obligation_counts["total"]:
        fail("obligation-applicability-cross-sum", "required and conditional obligations do not partition the population")
    if sum(requirement_counts[key] for key in ("required", "conditional")) != requirement_counts["total"]:
        fail("requirement-applicability-cross-sum", "required and conditional requirements do not partition the population")

    purpose = Counter()
    disposition = Counter()
    for requirement in requirements:
        if requirement["requirement_type"] in {"conformance-capable", "conditional-conformance"}:
            purpose["conformance-capable"] += 1
        elif requirement["requirement_type"] == "relational/metamorphic-candidate":
            purpose["relational/metamorphic-candidate"] += 1
        else:
            purpose["characterization-only"] += 1
        disposition[classify_requirement(requirement)] += 1
    for missing in ("non-executable-informative", "prohibited", "unresolved"):
        disposition.setdefault(missing, 0)
    if sum(purpose.values()) != len(requirements) or sum(disposition.values()) != len(requirements):
        fail("overlap-unsafe-accounting", "orthogonal base partitions do not each close exactly")
    roles = Counter(item["evidence_role"] for item in requirements)
    facets = Counter(item["facet_id"] for item in requirements)
    operations = Counter(operation for item in requirements for operation in item["required_operation_scientific_ids"])
    if sum(roles.values()) != len(requirements) or sum(facets.values()) != len(requirements):
        fail("requirement-partition-cross-sum", "role or facet partition does not close")
    if len(operations) != len(semantic["operations"]):
        fail("operation-coverage", "not all canonical operations appear in requirement scopes")

    cardinality_by_archetype = {item["archetype_id"]: sorted(item["subject_polarities"]) for item in rule_contract["obligation_archetypes"]}
    requirements_by_obligation: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for requirement in requirements:
        if len(requirement["obligation_scientific_ids"]) != 1:
            fail("non-minimal-requirement-attribution", "current minimum requirement must reference exactly one obligation", requirement["requirement_key"])
        requirements_by_obligation[requirement["obligation_scientific_ids"][0]].append(requirement)
    expanded_obligations = []
    for obligation in obligations:
        members = requirements_by_obligation.get(obligation["scientific_id"], [])
        expected_roles = cardinality_by_archetype[obligation["archetype_id"]]
        actual_roles = sorted(item["evidence_role"] for item in members)
        if actual_roles != expected_roles or actual_roles != sorted(obligation["requirement_cardinality"]["roles"]):
            fail("cardinality-role-disagreement", "requirement roles do not match independent archetype polarity", obligation["obligation_key"])
        if len(members) > 1:
            expanded_obligations.append(obligation["scientific_id"])
    expansion = sum(len(items) - 1 for items in requirements_by_obligation.values())
    if len(requirements_by_obligation) != len(obligations) or expansion != len(requirements) - len(obligations):
        fail("cardinality-expansion-cross-sum", "obligation to requirement expansion does not close")

    all_conditions: dict[bytes, list[str]] = defaultdict(list)
    conditional_conditions: dict[bytes, list[str]] = defaultdict(list)
    tautologies = contradictions = invalid = 0
    for requirement in requirements:
        outcome = validate_profile_condition(requirement["profile_condition"], known_ids)
        tautologies += outcome["tautology"]
        contradictions += outcome["contradiction"]
        invalid += not outcome["valid"]
        key = _condition_key(requirement["profile_condition"])
        all_conditions[key].append(requirement["scientific_id"])
        if requirement["requirement_state"] == "conditionally-required":
            conditional_conditions[key].append(requirement["scientific_id"])
    if tautologies or contradictions or invalid:
        fail("invalid-profile-predicate", f"predicate audit found tautologies={tautologies}, contradictions={contradictions}, invalid={invalid}")
    if handoff["counts"]["distinct_predicates"] != len(all_conditions) or handoff["counts"]["distinct_conditional_predicates"] != len(conditional_conditions):
        fail("profile-handoff-predicate-count", "handoff predicate counts differ from independent recomputation")

    dry_decisions = Counter(item["decision"] for item in dry_run["decisions"])
    samples = _build_samples(root, semantic, obligations, requirements, dry_run)
    migration_result = _migration_audit(migration, obligations, requirements)
    multiplier = _multiplier_audit(root, dry_run, obligations, requirements)
    if multiplier["result"] != "PASS":
        fail("uniform-feature-shape", "all features retain one obligation shape")

    result = {
        "result": "PASS",
        "obligations": {**obligation_counts, "stable_id_commitment": _id_commitment(item["scientific_id"] for item in obligations)},
        "requirements": {**requirement_counts, "stable_id_commitment": _id_commitment(item["scientific_id"] for item in requirements)},
        "base_partitions": {
            "semantic_applicability": {"counts": {"required": requirement_counts["required"], "conditional": requirement_counts["conditional"]}, "cross_sum": len(requirements)},
            "scientific_purpose": {"counts": dict(sorted(purpose.items())), "cross_sum": sum(purpose.values())},
            "execution_disposition": {"counts": dict(sorted(disposition.items())), "cross_sum": sum(disposition.values())},
            "evidence_role": {"counts": dict(sorted(roles.items())), "cross_sum": sum(roles.values())},
        },
        "overlapping_rollups": {
            "executable": sum(disposition[key] for key in ("executable-conformance", "executable-relational", "executable-characterization")),
            "informative": purpose["relational/metamorphic-candidate"] + purpose["characterization-only"] + disposition["non-executable-informative"],
            "prohibited": disposition["prohibited"],
            "unresolved": disposition["unresolved"],
            "qualification": "These are named rollups over explicit base-axis members and must not be added to each other or to applicability counts.",
        },
        "scenario_accounting": {
            "obligations": {"lower": obligation_counts["required"], "expected": {"numeric_total": None, "lower_bound": obligation_counts["required"], "upper_bound": obligation_counts["total"], "formula": f"{obligation_counts['required']} + sum(P(profile facts satisfy predicate_o)) for {obligation_counts['conditional']} conditional obligations"}, "conservative": obligation_counts["total"]},
            "requirements": {"lower": requirement_counts["required"], "expected": {"numeric_total": None, "lower_bound": requirement_counts["required"], "upper_bound": requirement_counts["total"], "formula": f"{requirement_counts['required']} + sum(P(profile facts satisfy predicate_r)) for {requirement_counts['conditional']} conditional requirements"}, "conservative": requirement_counts["total"]},
            "expected_status": "deferred-symbolic",
        },
        "predicate_audit": {
            "requirement_predicates": len(requirements),
            "conditional_requirements": requirement_counts["conditional"],
            "distinct_predicates": len(all_conditions),
            "distinct_conditional_predicates": len(conditional_conditions),
            "requirements_per_conditional_predicate": _distribution(len(items) for items in conditional_conditions.values()),
            "capability_dimensions": dict(sorted(Counter(clause["field"] for item in requirements for clause in item["profile_condition"]["clauses"]).items())),
            "tautologies": tautologies,
            "contradictions": contradictions,
            "invalid_or_unresolved_references": invalid,
            "conditional_requirement_id_commitment": _id_commitment(item["scientific_id"] for item in requirements if item["requirement_state"] == "conditionally-required"),
        },
        "cardinality_audit": {
            "obligations": len(obligations),
            "minimum_one_per_obligation": len(obligations),
            "additional_independently_attributable_roles": expansion,
            "requirements": len(requirements),
            "single_role_obligations": len(obligations) - len(expanded_obligations),
            "multi_role_obligations": len(expanded_obligations),
            "expanded_obligation_id_commitment": _id_commitment(expanded_obligations),
            "role_counts": dict(sorted(roles.items())),
            "unjustified_expansions": 0,
        },
        "distributions": {
            "requirements_by_facet_partition": dict(sorted(facets.items())),
            "requirements_by_operation_membership_overlapping": dict(sorted(operations.items())),
            "operation_membership_cross_sum_permitted": False,
            "requirements_per_feature": _distribution(Counter(item["feature_scientific_id"] for item in requirements).values()),
        },
        "excluded_decisions": {
            "not_required_by_feature_semantics": dry_decisions["not-required-by-feature-semantics"],
            "not_applicable": dry_decisions["not-applicable"],
            "prohibited": 0,
            "blocked_unresolved": dry_decisions["blocked-by-unresolved-semantics"],
            "qualification": "Not-applicable and not-required are distinct researched suppressions; neither is relabeled prohibited.",
        },
        "sample_audit": samples,
        "migration_audit": migration_result,
        "multiplier_audit": multiplier,
    }
    return result


def build_report(root: Path, contract: dict[str, Any], handoff: dict[str, Any]) -> dict[str, Any]:
    obligation = load_strict(root / OBLIGATION_PATH)
    requirement = load_strict(root / REQUIREMENT_PATH)
    migration = load_strict(root / MIGRATION_PATH)
    semantic = load_strict(root / SNAPSHOT_PATH)
    authority = load_strict(root / DENOMINATOR_AUTHORITY_PATH)
    certification = load_strict(root / CERTIFICATION_REPORT_PATH)
    recomputed = independent_recompute(root, contract, handoff)
    c4 = next(item for item in certification["criteria"] if item["criterion_id"] == "C4")
    if (c4["status"], c4["numerator_count"], c4["denominator_count"]) != ("FAIL", 0, 3378):
        fail("denominator-c4-drift", "current certification must remain C4 FAIL at 0/3378")
    body: dict[str, Any] = {
        "schema_version": "semantic-denominator-audit-report.v1",
        "published_on": PUBLISHED_ON,
        "claim": "Every canonical semantic obligation and minimum requirement is counted through an explicit derivation, partitioned without overlap ambiguity, and independently reproducible from committed inputs without a profile multiplier.",
        "authority": {
            "semantic_snapshot": _bound(root, SNAPSHOT_PATH, semantic, "snapshot_id", "snapshot_digest_sha256"),
            "obligation_snapshot": _bound(root, OBLIGATION_PATH, obligation, "snapshot_id", "snapshot_digest_sha256"),
            "requirement_snapshot": _bound(root, REQUIREMENT_PATH, requirement, "snapshot_id", "snapshot_digest_sha256"),
            "migration_ledger": _bound(root, MIGRATION_PATH, migration, "ledger_id", "ledger_digest_sha256"),
            "denominator_authority": _bound(root, DENOMINATOR_AUTHORITY_PATH, authority, "index_id", "index_digest_sha256"),
            "accounting_contract": {"path": CONTRACT_PATH.as_posix(), "artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"], "file_sha256": _sha(root / CONTRACT_PATH)},
            "profile_expansion_handoff": {"path": HANDOFF_PATH.as_posix(), "artifact_id": handoff["projection_id"], "digest_sha256": handoff["projection_digest_sha256"], "file_sha256": _sha(root / HANDOFF_PATH)},
        },
        "independent_recomputation": recomputed,
        "current_certification": {"report_id": certification["report_id"], "status": certification["final_state"], "c4": {"status": c4["status"], "completed": c4["numerator_count"], "denominator": c4["denominator_count"]}},
        "profile_expansion": {"status": "deferred", "exact_profile_count": None, "final_logical_execution_denominator": None, "historical_planning_multiplier_substituted": False, "handoff_id": handoff["projection_id"]},
        "anomaly_dispositions": [
            {"anomaly": "unaccounted-obligation", "count": 0, "status": "PASS"},
            {"anomaly": "unaccounted-requirement", "count": 0, "status": "PASS"},
            {"anomaly": "overlapping-axis-cross-sum", "count": 0, "status": "PASS"},
            {"anomaly": "predicate-tautology", "count": recomputed["predicate_audit"]["tautologies"], "status": "PASS"},
            {"anomaly": "predicate-contradiction", "count": recomputed["predicate_audit"]["contradictions"], "status": "PASS"},
            {"anomaly": "invalid-predicate-reference", "count": recomputed["predicate_audit"]["invalid_or_unresolved_references"], "status": "PASS"},
            {"anomaly": "unjustified-cardinality-expansion", "count": recomputed["cardinality_audit"]["unjustified_expansions"], "status": "PASS"},
            {"anomaly": "migration-orphan", "count": 0, "status": "PASS"},
            {"anomaly": "authoritative-unexplained-multiplier", "count": recomputed["multiplier_audit"]["authoritative_unexplained_multiplier_count"], "status": "PASS"},
            {"anomaly": "profile-expansion-overclaim", "count": 0, "status": "PASS"},
        ],
        "derivation_id": AUDIT_DERIVATION_ID,
        "derivation_revision_id": audit_derivation_spec(root)["derivation_revision_id"],
        "result": "PASS",
    }
    result = _finalize(root, body, namespace="finding-revision", family=SCHEMA_FAMILIES["report"], id_field="report_id", digest_field="report_digest_sha256")
    validate_instance(result, load_strict(root / REPORT_SCHEMA_PATH), source=REPORT_PATH.as_posix())
    return result


def build_audit_authority(root: Path, contract: dict[str, Any], handoff: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    denominator_authority = load_strict(root / DENOMINATOR_AUTHORITY_PATH)
    body = {
        "schema_version": "semantic-denominator-audit-authority.v1",
        "effective_on": PUBLISHED_ON,
        "denominator_authority": _bound(root, DENOMINATOR_AUTHORITY_PATH, denominator_authority, "index_id", "index_digest_sha256"),
        "accounting_contract": {"path": CONTRACT_PATH.as_posix(), "artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"]},
        "audit_report": {"path": REPORT_PATH.as_posix(), "artifact_id": report["report_id"], "digest_sha256": report["report_digest_sha256"]},
        "profile_expansion_handoff": {"path": HANDOFF_PATH.as_posix(), "artifact_id": handoff["projection_id"], "digest_sha256": handoff["projection_digest_sha256"]},
        "authority_scope": "Semantic-side denominator accounting only; exact profiles and the final logical-execution denominator remain deferred.",
        "governance": {"local_authoritative_certification_required": True, "hosted_integrity_veto_required": True, "scientific_certification_issued": False},
        "derivation_id": AUDIT_DERIVATION_ID,
        "derivation_revision_id": audit_derivation_spec(root)["derivation_revision_id"],
    }
    result = _finalize(root, body, namespace="artifact-set-manifest", family=SCHEMA_FAMILIES["authority"], id_field="index_id", digest_field="index_digest_sha256")
    validate_instance(result, load_strict(root / AUDIT_AUTHORITY_SCHEMA_PATH), source=AUDIT_AUTHORITY_PATH.as_posix())
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
    if path.read_bytes() != encoded:
        fail("denominator-audit-readback", "generated artifact failed read-after-write", path.as_posix())


def materialize(root: Path) -> dict[str, Any]:
    contract = build_contract(root)
    _write_canonical(root / CONTRACT_PATH, contract)
    handoff = build_handoff(root, contract)
    _write_canonical(root / HANDOFF_PATH, handoff)
    report = build_report(root, contract, handoff)
    _write_canonical(root / REPORT_PATH, report)
    authority = build_audit_authority(root, contract, handoff, report)
    _write_canonical(root / AUDIT_AUTHORITY_PATH, authority)
    verify_current(root, verify_derivation_catalog=False)
    return {
        "result": report["result"],
        "contract_id": contract["contract_id"],
        "report_id": report["report_id"],
        "handoff_id": handoff["projection_id"],
        "requirements": report["independent_recomputation"]["requirements"]["total"],
    }


def verify_current(root: Path, *, verify_derivation_catalog: bool = True) -> dict[str, Any]:
    expected_contract = build_contract(root)
    tracked_contract = load_strict(root / CONTRACT_PATH)
    if canonical_bytes(expected_contract) != canonical_bytes(tracked_contract):
        fail("denominator-accounting-contract-drift", "tracked accounting contract differs from deterministic rebuild")
    expected_handoff = build_handoff(root, expected_contract)
    tracked_handoff = load_strict(root / HANDOFF_PATH)
    if canonical_bytes(expected_handoff) != canonical_bytes(tracked_handoff):
        fail("profile-expansion-handoff-drift", "tracked profile handoff differs from deterministic rebuild")
    expected_report = build_report(root, expected_contract, expected_handoff)
    tracked_report = load_strict(root / REPORT_PATH)
    if canonical_bytes(expected_report) != canonical_bytes(tracked_report):
        fail("semantic-denominator-audit-drift", "tracked denominator audit report differs from independent recomputation")
    expected_authority = build_audit_authority(root, expected_contract, expected_handoff, expected_report)
    tracked_authority = load_strict(root / AUDIT_AUTHORITY_PATH)
    if canonical_bytes(expected_authority) != canonical_bytes(tracked_authority):
        fail("denominator-audit-authority-drift", "tracked denominator audit authority differs")
    if verify_derivation_catalog:
        catalog = load_strict(root / DERIVATION_CATALOG_PATH)
        revision = audit_derivation_spec(root)["derivation_revision_id"]
        if not any(item["derivation_id"] == AUDIT_DERIVATION_ID and item["derivation_revision_id"] == revision for item in catalog["derivations"]):
            fail("denominator-audit-derivation-binding", "audit derivation revision is absent from the canonical catalog")
    return {
        "result": tracked_report["result"],
        "contract_id": tracked_contract["contract_id"],
        "report_id": tracked_report["report_id"],
        "requirements": tracked_report["independent_recomputation"]["requirements"]["total"],
        "lower": tracked_report["independent_recomputation"]["scenario_accounting"]["requirements"]["lower"],
        "conservative": tracked_report["independent_recomputation"]["scenario_accounting"]["requirements"]["conservative"],
    }


def explain(root: Path, identifier: str) -> dict[str, Any]:
    report = load_strict(root / REPORT_PATH)
    requirements = load_strict(root / REQUIREMENT_PATH)["requirements"]
    requirement = next((item for item in requirements if identifier in {item["requirement_key"], item["scientific_id"]}), None)
    if requirement is None:
        fail("unknown-denominator-audit-identity", "identifier is not a current semantic requirement", identifier)
    return {
        "query": identifier,
        "semantic_applicability": "required" if requirement["requirement_state"] == "required" else "conditional",
        "scientific_purpose": "conformance-capable" if requirement["requirement_type"] in {"conformance-capable", "conditional-conformance"} else requirement["requirement_type"],
        "execution_disposition": classify_requirement(requirement),
        "evidence_role": requirement["evidence_role"],
        "profile_condition": requirement["profile_condition"],
        "scenario_membership": {"lower": requirement["requirement_state"] == "required", "expected": "symbolic-until-profile-model", "conservative": True},
        "c4_population": "canonical-semantic-requirement",
        "audit_report_id": report["report_id"],
    }
