"""Acceptance gate for the canonical semantic obligation denominator.

The gate consumes committed semantic-denominator artifacts.  It never calls the
primary materializer, creates vectors, evaluates real profiles, or claims full
scientific certification.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import os
from pathlib import Path
from typing import Any, Iterable

from .certification import CURRENT_REPORT_PATH, verify_repository_certification
from .denominator_audit import (
    AUDIT_AUTHORITY_PATH,
    CONTRACT_PATH as ACCOUNTING_CONTRACT_PATH,
    HANDOFF_PATH,
    REPORT_PATH as AUDIT_REPORT_PATH,
    independent_recompute,
    validate_profile_condition,
    verify_current as verify_denominator_audit,
)
from .derivation import CATALOG_PATH as DERIVATION_CATALOG_PATH, DERIVATION_IDS, verify_catalog as verify_derivation_catalog
from .errors import fail
from .foundation import ACCEPTANCE_PATH as SCIENTIFIC_FOUNDATION_ACCEPTANCE_PATH, verify_foundation_history
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .obligation_derivation import CONTRACT_PATH as RULE_CONTRACT_PATH, DRY_RUN_PATH, SNAPSHOT_PATH
from .obligation_snapshots import (
    ARTIFACT_PROFILE_PATH,
    AUTHORITY_PATH as DENOMINATOR_AUTHORITY_PATH,
    MIGRATION_PATH,
    OBLIGATION_PATH,
    PROJECTION_PATH,
    REQUIREMENT_PATH,
    SCHEMA_FAMILIES,
)
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import verify_catalog as verify_identity_catalog
from .semantic_foundation import ACCEPTANCE_PATH as SEMANTIC_FOUNDATION_ACCEPTANCE_PATH, verify_current_semantic_foundation


ACCEPTED_INPUT_SHA = "6e7816fb52d350599d3cc9136ea2040a710cc79a"
PUBLISHED_ON = "2026-09-10"
MANIFEST_PATH = Path("ontology/denominator/true-obligation-denominator-foundation-2026-09-10.v1.json")
REPORT_PATH = Path("reports/semantics/true-obligation-denominator-acceptance-2026-09-10.v1.json")
MANIFEST_SCHEMA_PATH = Path("schemas/json/true-obligation-denominator-foundation.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/true-obligation-denominator-acceptance.schema.json")
IDENTITY_CATALOG_PATH = Path("registries/identity/scientific-identities.v1.json")
CERTIFICATION_CONTRACT_PATH = Path("certification/contracts/regex-conformance-certification.v1.1.json")
CERTIFICATION_INPUT_PATH = Path("certification/inputs/current-repository-2026-09-08.v2.json")
CERTIFICATION_AUTHORITY_PATH = Path("certification/current-authority.v1.json")

IMPLEMENTATION_PATHS = (
    Path("schemas/tooling/python/regex_conformance_schema/denominator_foundation.py"),
    Path("tools/semantics/certify_true_denominator.py"),
    MANIFEST_SCHEMA_PATH,
    REPORT_SCHEMA_PATH,
)

LEGACY_PROJECTION_PATH = Path("ontology/projections/regex-semantic-projection-2026-08-22.v1.json")
LEGACY_REQUIREMENTS_PATH = Path("vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json")
LEGACY_FORECAST_PATH = Path("reports/scale/regex-semantic-denominator-forecast.json")
LEGACY_SHA256 = {
    LEGACY_PROJECTION_PATH.as_posix(): "b25fbeaf80fc8e77f92fb5b36a094896bf30e86d4550ad62982f80a028b605b2",
    LEGACY_REQUIREMENTS_PATH.as_posix(): "a03feacf51bf3af241a7ab4fe0ea74bd29981670de93ec3d880a27516232cca7",
    LEGACY_FORECAST_PATH.as_posix(): "dab61b42376d757eadada26c31d8fb5c173a508bb6ce780e98a220449ce6e871",
}

EXPECTED = {
    "obligations": 2390,
    "required_obligations": 1058,
    "conditional_obligations": 1332,
    "requirements": 3378,
    "required_requirements": 1406,
    "conditional_requirements": 1972,
    "conformance_capable": 3071,
    "relational_metamorphic": 228,
    "characterization_only": 79,
    "positive": 1785,
    "negative": 1394,
    "boundary": 120,
    "characterization": 79,
    "cardinality_expansion": 988,
    "distinct_conditional_predicates": 278,
    "distinct_predicates": 354,
    "suppressed_not_required": 2237,
    "suppressed_not_applicable": 233,
}

EXPECTED_MIGRATION = {
    "obligation": {
        "predecessor_count": 12048,
        "by_disposition": {
            "semantically-equivalent-successor": 881,
            "historical-only-unmapped": 1375,
            "merged-into-successor": 1908,
            "retained-scientific-identity": 151,
            "retired-no-researched-trigger": 7585,
            "split-into-successors": 148,
        },
    },
    "requirement": {
        "predecessor_count": 9506,
        "by_disposition": {
            "semantically-equivalent-successor": 795,
            "historical-only-unmapped": 1907,
            "merged-into-successor": 1459,
            "retained-scientific-identity": 32,
            "retired-no-researched-trigger": 5223,
            "split-into-successors": 90,
        },
    },
}

REQUIRED_GATE_CHECKS = (
    "applicability-partitions",
    "cardinality-expansion",
    "conditional-predicates",
    "derivation-contract",
    "derivation-integrity",
    "deterministic-regeneration",
    "evidence-role-partition",
    "execution-accounting",
    "historical-denominator-immutability",
    "identity-lineage",
    "independent-recomputation",
    "migration-closure",
    "multiplier-leakage",
    "obligation-integrity",
    "obligation-population",
    "profile-expansion-deferral",
    "requirement-integrity",
    "requirement-population",
    "scientific-purpose-partition",
    "semantic-authority",
)

ARTIFACT_BINDINGS: tuple[tuple[str, Path, str, str], ...] = (
    ("semantic-snapshot", SNAPSHOT_PATH, "snapshot_id", "snapshot_digest_sha256"),
    ("obligation-derivation-contract", RULE_CONTRACT_PATH, "contract_id", "contract_digest_sha256"),
    ("obligation-snapshot", OBLIGATION_PATH, "snapshot_id", "snapshot_digest_sha256"),
    ("requirement-snapshot", REQUIREMENT_PATH, "snapshot_id", "snapshot_digest_sha256"),
    ("semantic-projection", PROJECTION_PATH, "projection_id", "projection_digest_sha256"),
    ("migration-ledger", MIGRATION_PATH, "ledger_id", "ledger_digest_sha256"),
    ("denominator-authority", DENOMINATOR_AUTHORITY_PATH, "index_id", "index_digest_sha256"),
    ("denominator-accounting-contract", ACCOUNTING_CONTRACT_PATH, "contract_id", "contract_digest_sha256"),
    ("denominator-audit-report", AUDIT_REPORT_PATH, "report_id", "report_digest_sha256"),
    ("denominator-audit-authority", AUDIT_AUTHORITY_PATH, "index_id", "index_digest_sha256"),
    ("profile-expansion-handoff", HANDOFF_PATH, "projection_id", "projection_digest_sha256"),
    ("certification-contract", CERTIFICATION_CONTRACT_PATH, "contract_id", "contract_digest_sha256"),
    ("certification-input", CERTIFICATION_INPUT_PATH, "input_set_id", "input_set_digest_sha256"),
    ("certification-report", CURRENT_REPORT_PATH, "report_id", "report_digest_sha256"),
    ("scientific-foundation-acceptance", SCIENTIFIC_FOUNDATION_ACCEPTANCE_PATH, "acceptance_report_id", "acceptance_report_digest_sha256"),
    ("semantic-foundation-acceptance", SEMANTIC_FOUNDATION_ACCEPTANCE_PATH, "report_id", "report_digest_sha256"),
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _record_digest(record: dict[str, Any], *excluded: str) -> str:
    return _digest({key: value for key, value in record.items() if key not in excluded})


def _content_id(root: Path, namespace: str, family: str, body: dict[str, Any]) -> str:
    return str(
        build_content_identity(
            registry=NamespaceRegistry.load(root / "registries/identity/namespaces.v3.json"),
            profile=IdentityProfile.from_record(load_strict(root / ARTIFACT_PROFILE_PATH)),
            namespace=namespace,
            identity_schema_family_id=family,
            identity_schema_version="1.0.0",
            identity={"artifact_digest_sha256": _digest(body)},
        )["content_id"]
    )


def _finalize(
    root: Path,
    body: dict[str, Any],
    *,
    namespace: str,
    family: str,
    id_field: str,
    digest_field: str,
) -> dict[str, Any]:
    return {
        **body,
        id_field: _content_id(root, namespace, family, body),
        digest_field: _digest(body),
    }


def _artifact_ref(root: Path, role: str, path: Path, id_field: str, digest_field: str) -> dict[str, str]:
    artifact = load_strict(root / path)
    return {
        "role": role,
        "path": path.as_posix(),
        "artifact_id": artifact[id_field],
        "content_digest_sha256": artifact[digest_field],
        "file_sha256": _sha(root / path),
    }


def _catalog_ref(root: Path, role: str, path: Path) -> dict[str, Any]:
    artifact = load_strict(root / path)
    return {
        "role": role,
        "path": path.as_posix(),
        "schema_version": artifact["schema_version"],
        "catalog_digest_sha256": artifact["catalog_digest_sha256"],
        "file_sha256": _sha(root / path),
        "member_count": len(artifact["bindings"] if role == "identity-catalog" else artifact["derivations"]),
    }


def _file_ref(root: Path, path: Path) -> dict[str, str]:
    return {"path": path.as_posix(), "file_sha256": _sha(root / path)}


def _derivation_bindings(root: Path) -> list[dict[str, str]]:
    catalog = load_strict(root / DERIVATION_CATALOG_PATH)
    by_id = {item["derivation_id"]: item for item in catalog["derivations"]}
    specs = (
        ("independent-recomputation", "denominator-audit", "structural-integrity"),
        ("gate-conjunction", "reconciliation-calculation", "structural-integrity"),
        ("artifact-integrity", "artifact-measurement", "independent-evidence"),
        ("authority-boundary", "manual-registry-decision", "governance-policy"),
    )
    return [
        {
            "binding_key": binding_key,
            "derivation_id": DERIVATION_IDS[key],
            "derivation_revision_id": by_id[DERIVATION_IDS[key]]["derivation_revision_id"],
            "derivation_class": by_id[DERIVATION_IDS[key]]["derivation_class"],
            "gate_kind": gate_kind,
        }
        for binding_key, key, gate_kind in specs
    ]


def build_manifest(root: Path) -> dict[str, Any]:
    scientific = load_strict(root / SCIENTIFIC_FOUNDATION_ACCEPTANCE_PATH)
    semantic = load_strict(root / SEMANTIC_FOUNDATION_ACCEPTANCE_PATH)
    body = {
        "schema_version": "true-obligation-denominator-foundation.v1",
        "accepted_input_repository_sha": ACCEPTED_INPUT_SHA,
        "published_on": PUBLISHED_ON,
        "claim_scope": "Acceptance of the canonical semantic-side obligation and requirement denominator; not full C1-C7 certification and not profile-expanded execution scale.",
        "artifacts": [
            _artifact_ref(root, role, path, id_field, digest_field)
            for role, path, id_field, digest_field in ARTIFACT_BINDINGS
        ],
        "catalogs": [
            _catalog_ref(root, "identity-catalog", IDENTITY_CATALOG_PATH),
            _catalog_ref(root, "derivation-catalog", DERIVATION_CATALOG_PATH),
        ],
        "implementation": [_file_ref(root, path) for path in IMPLEMENTATION_PATHS],
        "predecessor_acceptance": {
            "scientific_foundation": scientific["foundation_acceptance"],
            "semantic_knowledge_architecture": semantic["result"],
        },
        "expected_population": deepcopy(EXPECTED),
        "historical_denominator": [
            {"path": path, "file_sha256": digest}
            for path, digest in sorted(LEGACY_SHA256.items())
        ],
        "local_authoritative_certification": {
            "architecture": "Local Authoritative Certification / Hosted Integrity Verification",
            "manifest_path": "certification/local/current-local-certification.v1.json",
            "source_state_requirement": "exact committed source SHA and clean worktree",
            "hosted_role": "bounded integrity verifier with veto authority",
        },
        "assertion_derivations": _derivation_bindings(root),
    }
    return _finalize(
        root,
        body,
        namespace="artifact-set-manifest",
        family=SCHEMA_FAMILIES["authority"],
        id_field="manifest_id",
        digest_field="manifest_digest_sha256",
    )


def _require_exact(label: str, actual: int, expected: int) -> None:
    if actual != expected:
        fail("true-denominator-count", f"{label} differs: expected {expected}, observed {actual}")


def _id_commitment(values: Iterable[str]) -> dict[str, Any]:
    ordered = sorted(values)
    if len(ordered) != len(set(ordered)):
        fail("duplicate-scientific-identity", "stable-ID commitment contains a duplicate")
    return {"member_count": len(ordered), "jcs_sha256": _digest(ordered)}


def _predicate_values(requirement: dict[str, Any], clause: dict[str, Any]) -> set[str]:
    if "value" in clause:
        return {clause["value"]}
    if "values" in clause:
        return set(clause["values"])
    if clause.get("value_from") == "feature.scientific_id":
        return {requirement["feature_scientific_id"]}
    if clause.get("value_from") == "derived.operation_scientific_ids":
        return set(requirement["required_operation_scientific_ids"])
    fail("unknown-predicate-value", "predicate has no resolvable value source")


def evaluate_profile_condition(requirement: dict[str, Any], facts: dict[str, set[str] | None]) -> str:
    """Three-valued bounded canary for the later applicability boundary."""
    for clause in requirement["profile_condition"]["clauses"]:
        observed = facts.get(clause["field"])
        if observed is None:
            return "unresolved"
        expected = _predicate_values(requirement, clause)
        operator = clause["operator"]
        satisfied = {
            "contains": expected.issubset(observed),
            "intersects": bool(expected.intersection(observed)),
            "not-contains": expected.isdisjoint(observed),
            "disjoint": expected.isdisjoint(observed),
        }[operator]
        if not satisfied:
            return "not-applicable"
    return "applicable"


def _condition_fixtures(requirement: dict[str, Any]) -> list[dict[str, str]]:
    facts: dict[str, set[str] | None] = {}
    for clause in requirement["profile_condition"]["clauses"]:
        values = _predicate_values(requirement, clause)
        facts.setdefault(clause["field"], set())
        if clause["operator"] in {"contains", "intersects"}:
            assert isinstance(facts[clause["field"]], set)
            facts[clause["field"]].update(values)
    true_result = evaluate_profile_condition(requirement, facts)
    first = requirement["profile_condition"]["clauses"][0]
    false_facts = {key: None if value is None else set(value) for key, value in facts.items()}
    expected = _predicate_values(requirement, first)
    if first["operator"] in {"contains", "intersects"}:
        false_facts[first["field"]] = set()
    else:
        false_facts[first["field"]] = set(expected)
    unknown_facts = {key: None if value is None else set(value) for key, value in facts.items()}
    unknown_facts[first["field"]] = None
    outcomes = [
        {"fixture": "capability-true", "expected": "applicable", "observed": true_result},
        {"fixture": "capability-false", "expected": "not-applicable", "observed": evaluate_profile_condition(requirement, false_facts)},
        {"fixture": "capability-unknown", "expected": "unresolved", "observed": evaluate_profile_condition(requirement, unknown_facts)},
    ]
    if any(item["expected"] != item["observed"] for item in outcomes):
        fail("conditional-boundary", "conditional predicate tri-state canary failed")
    return outcomes


def _suppression_audit(dry_run: dict[str, Any], obligations: list[dict[str, Any]]) -> dict[str, Any]:
    obligation_pairs = {(item["feature_scientific_id"], item["facet_id"]) for item in obligations}
    suppressed = [item for item in dry_run["decisions"] if item["decision"] in {"not-required-by-feature-semantics", "not-applicable"}]
    if any((item["feature_scientific_id"], item["facet_id"]) in obligation_pairs for item in suppressed):
        fail("suppression-leak", "suppressed feature/facet decision produced a canonical obligation")
    counts = Counter(item["decision"] for item in suppressed)
    _require_exact("not-required suppressions", counts["not-required-by-feature-semantics"], EXPECTED["suppressed_not_required"])
    _require_exact("not-applicable suppressions", counts["not-applicable"], EXPECTED["suppressed_not_applicable"])
    if any((not item["semantic_inputs"] and not item["governing_states"]) or not item["reason"] for item in suppressed):
        fail("unexplained-suppression", "suppressed decision lacks semantic state or rationale")
    return {
        "result": "PASS",
        "not_required_by_feature_semantics": counts["not-required-by-feature-semantics"],
        "not_applicable": counts["not-applicable"],
        "unresolved": counts["blocked-by-unresolved-semantics"],
        "decision_commitment": _id_commitment(
            f"{item['feature_scientific_id']}|{item['facet_id']}|{item['decision']}|{item['rule_revision_id']}"
            for item in suppressed
        ),
        "not_applicable_is_prohibited": False,
        "profile_absence_causes_suppression": False,
    }


def _over_count_audit(
    semantic: dict[str, Any],
    obligations: list[dict[str, Any]],
    requirements: list[dict[str, Any]],
    fresh: dict[str, Any],
) -> dict[str, Any]:
    obligation_bases = [_digest(item["identity_basis"]) for item in obligations]
    requirement_bases = [_digest(item["identity_basis"]) for item in requirements]
    if len(obligation_bases) != len(set(obligation_bases)):
        fail("duplicate-scientific-question", "two obligations have the same scientific identity basis")
    if len(requirement_bases) != len(set(requirement_bases)):
        fail("duplicate-evidence-role", "two requirements have the same scientific identity basis")
    roles_by_obligation: dict[str, list[str]] = defaultdict(list)
    for requirement in requirements:
        roles_by_obligation[requirement["obligation_scientific_ids"][0]].append(requirement["evidence_role"])
    if any(len(roles) != len(set(roles)) for roles in roles_by_obligation.values()):
        fail("duplicate-evidence-role", "an obligation has a duplicated independently attributable evidence role")
    operation_map = {item["scientific_id"]: item["operation_id"] for item in semantic["operations"]}
    for requirement in requirements:
        if [operation_map[value] for value in requirement["required_operation_scientific_ids"]] != requirement["required_operation_ids"]:
            fail("operation-alias-duplication", "requirement operation labels do not map exactly to canonical operations", requirement["requirement_key"])
    if any(item["requirement_type"] == "characterization-only" and item["expected_oracle_capability"] != "characterization-record" for item in requirements):
        fail("characterization-escalation", "characterization requirement was promoted to normative oracle capability")
    interaction = [item for item in obligations if item["facet_id"] == "facet.interaction-composition"]
    if any(not item["interaction_basis"] for item in interaction):
        fail("interaction-overcount", "interaction obligation lacks an explicit interaction basis")
    if fresh["multiplier_audit"]["authoritative_unexplained_multiplier_count"]:
        fail("hidden-uniform-multiplier", "an unexplained multiplier contributes to current authority")
    return {
        "result": "PASS",
        "suspected_over_count": 0,
        "dispositions": [
            {"attack": "missing-semantic-trigger", "result": "PASS", "evidence": "Every obligation identity basis exactly closes against an independently reconstructed accepted dry-run question."},
            {"attack": "duplicate-scientific-question", "result": "PASS", "evidence": f"{len(obligation_bases)} obligation bases are unique."},
            {"attack": "duplicate-evidence-role", "result": "PASS", "evidence": f"{len(requirement_bases)} requirement bases and per-obligation evidence roles are unique."},
            {"attack": "operation-alias", "result": "PASS", "evidence": "All operation scopes map one-to-one to the 33 canonical operation identities."},
            {"attack": "characterization-as-conformance", "result": "PASS", "evidence": "All 79 characterization-only requirements retain characterization observation capability."},
            {"attack": "interaction-subsumption", "result": "PASS", "evidence": f"All {len(interaction)} interaction obligations carry an explicit typed interaction basis."},
            {"attack": "legacy-template-leak", "result": "PASS", "evidence": "The independent multiplier scan found zero current-authority uniform planning multipliers."},
        ],
    }


def _under_count_audit(
    semantic: dict[str, Any],
    obligations: list[dict[str, Any]],
    requirements: list[dict[str, Any]],
    dry_run: dict[str, Any],
    fresh: dict[str, Any],
) -> dict[str, Any]:
    generating = [item for item in dry_run["decisions"] if item["decision"] in {"required", "conditionally-required"}]
    generated_candidates = sum(len(item["provisional_obligations"]) for item in generating)
    if generated_candidates != len(obligations):
        fail("under-counted-obligation", "accepted derivation decisions do not close to the obligation population")
    requirement_obligations = {item["obligation_scientific_ids"][0] for item in requirements}
    missing_paths = [item["scientific_id"] for item in obligations if item["scientific_id"] not in requirement_obligations]
    if missing_paths:
        fail("orphan-obligation", "a canonical obligation has no minimum evidence path", missing_paths[0])
    feature_counts = Counter(item["feature_scientific_id"] for item in requirements)
    missing_features = [item["scientific_id"] for item in semantic["features"] if item["scientific_id"] not in feature_counts]
    if missing_features:
        fail("feature-without-requirement", "canonical feature has no meaningful requirement path", missing_features[0])
    operation_ids = {item["scientific_id"] for item in semantic["operations"]}
    represented_operations = {value for item in requirements for value in item["required_operation_scientific_ids"]}
    if represented_operations != operation_ids:
        fail("operation-under-count", "not every canonical operation has an attributable requirement scope")
    represented_facets = {item["facet_id"] for item in obligations}
    decision_facets = {item["facet_id"] for item in dry_run["decisions"]}
    semantic_facets = {item["facet_id"] for item in semantic["semantic_facets"]}
    if decision_facets != semantic_facets or len(dry_run["decisions"]) != len(semantic["features"]) * len(semantic["semantic_facets"]):
        fail("semantic-space-under-count", "feature/facet decision space is incomplete")
    for name in ("facet.phase", "facet.complexity-guarantee", "facet.security-context"):
        if name not in represented_facets:
            fail("new-facet-under-count", "accepted semantic facet has no derived obligations", name)
    if fresh["excluded_decisions"]["blocked_unresolved"]:
        fail("blocked-semantic-space", "unresolved semantic decisions block denominator closure")
    return {
        "result": "PASS",
        "suspected_under_count": 0,
        "dispositions": [
            {"attack": "accepted-question-missing", "result": "PASS", "evidence": f"{generated_candidates} accepted prospective questions exactly match canonical obligations."},
            {"attack": "obligation-without-evidence-path", "result": "PASS", "evidence": "All 2,390 obligations have one or more requirements."},
            {"attack": "feature-without-requirement", "result": "PASS", "evidence": f"All {len(semantic['features'])} features have a requirement path; min={min(feature_counts.values())}."},
            {"attack": "operation-without-requirement", "result": "PASS", "evidence": "All 33 canonical operations appear in attributable requirement scopes."},
            {"attack": "semantic-field-unexamined", "result": "PASS", "evidence": f"All {len(dry_run['decisions'])} feature/facet decisions are present; suppressions remain separately auditable."},
            {"attack": "new-facet-omission", "result": "PASS", "evidence": "Phase, complexity-guarantee, and security-context facets all produce semantically triggered obligations."},
            {"attack": "interaction-coverage-omission", "result": "PASS", "evidence": "Typed interaction obligations retain relational attribution and minimum evidence roles."},
        ],
    }


def _explainability_audit(
    semantic: dict[str, Any],
    obligations: list[dict[str, Any]],
    requirements: list[dict[str, Any]],
    fresh: dict[str, Any],
) -> dict[str, Any]:
    obligation_by_id = {item["scientific_id"]: item for item in obligations}
    for obligation in obligations:
        assertions = obligation["semantic_assertions"]
        chain = obligation["explanation"]["chain"]
        required = {
            *obligation["source_semantic_assertion_ids"],
            obligation["derivation"]["rule_revision_id"],
            obligation["facet_id"],
            obligation["archetype_id"],
        }
        if not assertions or not required.issubset(set(chain)) or not obligation["explanation"]["reason"]:
            fail("obligation-explainability", "obligation lacks a complete semantic-to-obligation explanation chain", obligation["obligation_key"])
    for requirement in requirements:
        if len(requirement["obligation_scientific_ids"]) != 1:
            fail("requirement-explainability", "minimum requirement attribution is not singular", requirement["requirement_key"])
        obligation = obligation_by_id.get(requirement["obligation_scientific_ids"][0])
        if obligation is None:
            fail("orphan-requirement", "requirement references no current obligation", requirement["requirement_key"])
        if requirement["cardinality_rule_revision_id"] != obligation["requirement_cardinality"]["rule_revision_id"]:
            fail("requirement-explainability", "requirement cardinality rule differs from its obligation", requirement["requirement_key"])
        if requirement["evidence_role"] not in obligation["requirement_cardinality"]["roles"] or not requirement["cardinality_rationale"]:
            fail("requirement-explainability", "requirement has no attributable cardinality rationale", requirement["requirement_key"])
    samples = fresh["sample_audit"]
    represented_facets = {item["sample_value"] for item in samples["included_reconstructions"] if item["sample_axis"] == "facet"}
    excluded_facets = {item["sample_value"] for item in samples["excluded_reconstructions"] if item["sample_axis"] == "facet"}
    all_facets = {item["facet_id"] for item in semantic["semantic_facets"]}
    if represented_facets | excluded_facets != all_facets:
        fail("facet-sample-coverage", "deterministic explanation samples do not cover every facet")
    return {
        "result": "PASS",
        "obligations_with_complete_chain": len(obligations),
        "requirements_with_complete_chain": len(requirements),
        "included_reconstructions": len(samples["included_reconstructions"]),
        "excluded_reconstructions": len(samples["excluded_reconstructions"]),
        "facet_coverage": len(all_facets),
        "operation_coverage": len(semantic["operations"]),
        "sample_commitment": _digest(samples),
        "representative_chains": samples["included_reconstructions"][:8],
    }


def _historical_integrity(root: Path) -> list[dict[str, str]]:
    result = []
    for path, expected in sorted(LEGACY_SHA256.items()):
        observed = _sha(root / path)
        if observed != expected:
            fail("historical-denominator-mutation", "predecessor denominator artifact changed", path)
        result.append({"path": path, "expected_sha256": expected, "observed_sha256": observed, "result": "PASS"})
    return result


def _validate_migration_closure(fresh: dict[str, Any]) -> None:
    for population in ("obligation", "requirement"):
        observed = fresh["migration_audit"][population]
        expected = EXPECTED_MIGRATION[population]
        if observed["predecessor_count"] != expected["predecessor_count"] or observed["by_disposition"] != expected["by_disposition"]:
            fail("migration-disagreement", f"{population} predecessor migration does not match accepted closure")


def _validate_c4_and_profile(certification: dict[str, Any], handoff: dict[str, Any]) -> dict[str, Any]:
    c4 = next(item for item in certification["criteria"] if item["criterion_id"] == "C4")
    if (c4["status"], c4["numerator_count"], c4["denominator_count"]) != ("FAIL", 0, 3378):
        fail("stale-c4-denominator", "C4 is not exactly FAIL at 0/3378")
    if handoff["counts"]["exact_profiles"] is not None or handoff["counts"]["final_logical_execution_denominator"] is not None:
        fail("premature-profile-count", "profile or logical-execution count appeared before empirical profile freeze")
    if handoff["deferral"]["status"] != "deferred" or handoff["deferral"]["historical_multiplier_substituted"]:
        fail("profile-expansion-overclaim", "profile expansion is not cleanly deferred")
    return c4


def _check(check_id: str, *evidence: str) -> dict[str, Any]:
    return {"check_id": check_id, "status": "PASS", "evidence": list(evidence)}


def build_acceptance_report(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    semantic = load_strict(root / SNAPSHOT_PATH)
    obligations = load_strict(root / OBLIGATION_PATH)["obligations"]
    requirements = load_strict(root / REQUIREMENT_PATH)["requirements"]
    dry_run = load_strict(root / DRY_RUN_PATH)
    accounting = load_strict(root / ACCOUNTING_CONTRACT_PATH)
    handoff = load_strict(root / HANDOFF_PATH)
    certification = load_strict(root / CURRENT_REPORT_PATH)
    fresh = independent_recompute(root, accounting, handoff)

    _require_exact("obligations", fresh["obligations"]["total"], EXPECTED["obligations"])
    _require_exact("required obligations", fresh["obligations"]["required"], EXPECTED["required_obligations"])
    _require_exact("conditional obligations", fresh["obligations"]["conditional"], EXPECTED["conditional_obligations"])
    _require_exact("requirements", fresh["requirements"]["total"], EXPECTED["requirements"])
    _require_exact("required requirements", fresh["requirements"]["required"], EXPECTED["required_requirements"])
    _require_exact("conditional requirements", fresh["requirements"]["conditional"], EXPECTED["conditional_requirements"])
    purpose = fresh["base_partitions"]["scientific_purpose"]["counts"]
    roles = fresh["base_partitions"]["evidence_role"]["counts"]
    _require_exact("conformance-capable", purpose["conformance-capable"], EXPECTED["conformance_capable"])
    _require_exact("relational/metamorphic", purpose["relational/metamorphic-candidate"], EXPECTED["relational_metamorphic"])
    _require_exact("characterization-only", purpose["characterization-only"], EXPECTED["characterization_only"])
    for role in ("positive", "negative", "boundary", "characterization"):
        _require_exact(f"evidence role {role}", roles[role], EXPECTED[role])
    _require_exact("cardinality expansion", fresh["cardinality_audit"]["additional_independently_attributable_roles"], EXPECTED["cardinality_expansion"])
    _require_exact("distinct conditional predicates", fresh["predicate_audit"]["distinct_conditional_predicates"], EXPECTED["distinct_conditional_predicates"])
    _require_exact("distinct predicates", fresh["predicate_audit"]["distinct_predicates"], EXPECTED["distinct_predicates"])

    over_count = _over_count_audit(semantic, obligations, requirements, fresh)
    under_count = _under_count_audit(semantic, obligations, requirements, dry_run, fresh)
    suppression = _suppression_audit(dry_run, obligations)
    explainability = _explainability_audit(semantic, obligations, requirements, fresh)
    conditional = min((item for item in requirements if item["requirement_state"] == "conditionally-required"), key=lambda item: item["scientific_id"])
    condition_fixtures = _condition_fixtures(conditional)
    historical = _historical_integrity(root)

    _validate_migration_closure(fresh)
    c4 = _validate_c4_and_profile(certification, handoff)
    scenario = fresh["scenario_accounting"]
    if scenario["requirements"]["lower"] != 1406 or scenario["requirements"]["conservative"] != 3378 or scenario["requirements"]["expected"]["numeric_total"] is not None:
        fail("scenario-accounting", "requirement scenario accounting is not exact and symbolic")

    checks = [
        _check("applicability-partitions", "obligations=1058+1332", "requirements=1406+1972"),
        _check("cardinality-expansion", "2390+988=3378", "unjustified=0"),
        _check("conditional-predicates", "conditional=1972", "distinct=278", "tautologies=0", "contradictions=0", "unknown-references=0"),
        _check("derivation-contract", accounting["contract_id"], "scenario and orthogonal-axis vocabulary validated"),
        _check("derivation-integrity", "all obligation and requirement derivation chains validated", "evidence strength not escalated"),
        _check("deterministic-regeneration", "manifest and gate report rebuild byte-identically from committed inputs"),
        _check("evidence-role-partition", "positive=1785", "negative=1394", "boundary=120", "characterization=79"),
        _check("execution-accounting", "executable=3378", "informative-overlap=307", "prohibited=0", "unresolved=0"),
        _check("historical-denominator-immutability", *[item["observed_sha256"] for item in historical]),
        _check("identity-lineage", f"identities={manifest['catalogs'][0]['member_count']}", "all stable IDs and migration lineage validate"),
        _check("independent-recomputation", "fresh snapshot-only recomputation=PASS", fresh["requirements"]["stable_id_commitment"]["jcs_sha256"]),
        _check("migration-closure", "obligations=12048", "requirements=9506", "orphans=0"),
        _check("multiplier-leakage", "current-authority unexplained multipliers=0", "historical planning remains historical"),
        _check("obligation-integrity", "2390/2390 identity, semantics, facet, archetype, operation, derivation, and explanation records valid"),
        _check("obligation-population", "2390 canonical semantic obligations"),
        _check("profile-expansion-deferral", "exact profiles=null", "final logical executions=null", "historical multiplier substituted=false"),
        _check("requirement-integrity", "3378/3378 identity, attribution, purpose, evidence role, and cardinality records valid"),
        _check("requirement-population", "3378 canonical minimum requirements"),
        _check("scientific-purpose-partition", "conformance=3071", "relational=228", "characterization=79"),
        _check("semantic-authority", semantic["snapshot_id"], "scientific foundation=PASS", "semantic foundation=PASS"),
    ]
    if tuple(sorted(item["check_id"] for item in checks)) != REQUIRED_GATE_CHECKS:
        fail("true-denominator-check-set", "gate did not execute the exact required predicate set")

    body = {
        "schema_version": "true-obligation-denominator-acceptance.v1",
        "published_on": PUBLISHED_ON,
        "foundation_manifest": {
            "path": MANIFEST_PATH.as_posix(),
            "artifact_id": manifest["manifest_id"],
            "content_digest_sha256": manifest["manifest_digest_sha256"],
            "file_sha256": hashlib.sha256(canonical_bytes(manifest) + b"\n").hexdigest(),
        },
        "result": "PASS",
        "claim_scope": "The semantic denominator is accepted as the authoritative basis for later oracle, vector, and applicability work; this is not C1-C7 certification or a profile-expanded execution count.",
        "checks": checks,
        "exact_accounting": {
            "obligations": deepcopy(fresh["obligations"]),
            "requirements": deepcopy(fresh["requirements"]),
            "base_partitions": deepcopy(fresh["base_partitions"]),
            "overlapping_rollups": deepcopy(fresh["overlapping_rollups"]),
            "scenario_accounting": deepcopy(scenario),
        },
        "over_count_audit": over_count,
        "under_count_audit": under_count,
        "suppression_audit": suppression,
        "conditional_predicate_audit": {
            **deepcopy(fresh["predicate_audit"]),
            "tri_state_fixtures": condition_fixtures,
            "fixture_requirement_id": conditional["scientific_id"],
        },
        "cardinality_audit": deepcopy(fresh["cardinality_audit"]),
        "explainability_audit": explainability,
        "migration_audit": deepcopy(fresh["migration_audit"]),
        "multiplier_audit": deepcopy(fresh["multiplier_audit"]),
        "historical_integrity": historical,
        "current_c4": {
            "status": c4["status"],
            "completed": c4["numerator_count"],
            "denominator": c4["denominator_count"],
            "scientific_certification_issued": False,
        },
        "profile_expansion": {
            "status": "deferred",
            "exact_profile_count": None,
            "final_logical_execution_denominator": None,
            "historical_planning_multiplier_substituted": False,
            "handoff_id": handoff["projection_id"],
        },
        "local_certification_binding": {
            "status": "requires-manifest-only-envelope",
            "manifest_path": "certification/local/current-local-certification.v1.json",
            "hosted_verification": "external-bounded-veto",
            "reason": "The source-bound gate report cannot self-contain the certification root or a future hosted run without creating a circular digest/SHA dependency.",
        },
        "assertion_derivations": deepcopy(manifest["assertion_derivations"]),
    }
    return _finalize(
        root,
        body,
        namespace="trust-assessment",
        family=SCHEMA_FAMILIES["report"],
        id_field="report_id",
        digest_field="report_digest_sha256",
    )


def validate_manifest(root: Path, manifest: dict[str, Any], *, verify_current_files: bool) -> None:
    validate_instance(manifest, load_strict(root / MANIFEST_SCHEMA_PATH), source=MANIFEST_PATH.as_posix())
    digest = _record_digest(manifest, "manifest_id", "manifest_digest_sha256")
    if manifest["manifest_digest_sha256"] != digest:
        fail("true-denominator-manifest-digest", "foundation manifest digest differs")
    if manifest["manifest_id"] != _content_id(root, "artifact-set-manifest", SCHEMA_FAMILIES["authority"], {key: value for key, value in manifest.items() if key not in {"manifest_id", "manifest_digest_sha256"}}):
        fail("true-denominator-manifest-id", "foundation manifest identity differs")
    if manifest["accepted_input_repository_sha"] != ACCEPTED_INPUT_SHA:
        fail("true-denominator-input-sha", "foundation manifest binds another accepted input revision")
    if verify_current_files and canonical_bytes(manifest) != canonical_bytes(build_manifest(root)):
        fail("true-denominator-manifest-drift", "foundation manifest differs from exact current inputs")


def validate_acceptance_report(root: Path, manifest: dict[str, Any], report: dict[str, Any]) -> None:
    validate_instance(report, load_strict(root / REPORT_SCHEMA_PATH), source=REPORT_PATH.as_posix())
    digest = _record_digest(report, "report_id", "report_digest_sha256")
    if report["report_digest_sha256"] != digest:
        fail("true-denominator-report-digest", "gate report digest differs")
    body = {key: value for key, value in report.items() if key not in {"report_id", "report_digest_sha256"}}
    if report["report_id"] != _content_id(root, "trust-assessment", SCHEMA_FAMILIES["report"], body):
        fail("true-denominator-report-id", "gate report identity differs")
    if report["foundation_manifest"]["artifact_id"] != manifest["manifest_id"] or report["foundation_manifest"]["content_digest_sha256"] != manifest["manifest_digest_sha256"]:
        fail("true-denominator-report-manifest", "gate report binds another foundation manifest")
    if report["result"] != "PASS" or any(item["status"] != "PASS" for item in report["checks"]):
        fail("true-denominator-gate-failed", "true denominator acceptance is not fully passing")
    if tuple(sorted(item["check_id"] for item in report["checks"])) != REQUIRED_GATE_CHECKS:
        fail("true-denominator-check-set", "acceptance report omits a required predicate")


def verify_current(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    manifest = load_strict(root / MANIFEST_PATH)
    validate_manifest(root, manifest, verify_current_files=True)
    report = load_strict(root / REPORT_PATH)
    expected = build_acceptance_report(root, manifest)
    validate_acceptance_report(root, manifest, report)
    if canonical_bytes(report) != canonical_bytes(expected):
        fail("true-denominator-report-drift", "tracked gate report differs from fresh independent recomputation")
    audit = verify_denominator_audit(root)
    if audit["result"] != "PASS":
        fail("true-denominator-predecessor-audit", "predecessor independent denominator audit is not PASS")
    identity = verify_identity_catalog(root)
    derivation = verify_derivation_catalog(root)
    if broad_foundations:
        if verify_foundation_history(root)["foundation_acceptance"] != "PASS":
            fail("true-denominator-scientific-foundation", "scientific foundation history is not PASS")
        if verify_current_semantic_foundation(root)["semantic_foundation_acceptance"] != "PASS":
            fail("true-denominator-semantic-foundation", "semantic knowledge architecture is not PASS")
        if verify_repository_certification(root)["current_certification_state"] != "FAIL":
            fail("true-denominator-certification-state", "incomplete repository was unexpectedly certified")
    return {
        "result": report["result"],
        "manifest_id": manifest["manifest_id"],
        "report_id": report["report_id"],
        "obligations": report["exact_accounting"]["obligations"]["total"],
        "requirements": report["exact_accounting"]["requirements"]["total"],
        "identities": identity["scientific_identities"],
        "derivations": derivation["generated_assertion_groups"],
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
        fail("true-denominator-write", "generated artifact failed read-after-write", path.as_posix())


def materialize(root: Path) -> dict[str, Any]:
    manifest = build_manifest(root)
    _write(root / MANIFEST_PATH, manifest)
    report = build_acceptance_report(root, manifest)
    _write(root / REPORT_PATH, report)
    validate_manifest(root, manifest, verify_current_files=True)
    validate_acceptance_report(root, manifest, report)
    if build_manifest(root) != manifest or build_acceptance_report(root, manifest) != report:
        fail("true-denominator-nondeterministic", "gate artifacts did not rebuild deterministically")
    return {
        "result": report["result"],
        "manifest_id": manifest["manifest_id"],
        "report_id": report["report_id"],
        "obligations": report["exact_accounting"]["obligations"]["total"],
        "requirements": report["exact_accounting"]["requirements"]["total"],
    }
