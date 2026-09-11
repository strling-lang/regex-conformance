"""Total, proof-bearing evaluation of conditional requirement applicability.

Applicability decides whether an existing semantic requirement engages an exact
profile revision.  It neither creates requirements nor establishes expected
results, support claims, observations, or conformance verdicts.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from typing import Any

from .derivation import CATALOG_PATH as DERIVATION_CATALOG_PATH, derivation_revision_id, verify_catalog as verify_derivation_catalog
from .errors import ConformanceDataError, fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .obligation_snapshots import OBLIGATION_PATH, REQUIREMENT_PATH, SCHEMA_FAMILIES
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import normalize_predicate, verify_catalog as verify_identity_catalog


PUBLISHED_ON = "2026-09-10"
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a08e2e-c914-7762-a66b-39de5aa4ec95"
APPLICABILITY_DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a08e2e-c914-7cbf-902d-c1cbe7b120bf"

ALLOCATION_PATH = Path("applicability/conditional-applicability-identities-2026-09-10.v1.json")
CONTRACT_PATH = Path("applicability/contracts/regex-conformance-conditional-applicability-2026-09-10.v1.json")
FIXTURE_PATH = Path("tests/fixtures/applicability/conditional-requirement-applicability.v1.json")
REPORT_PATH = Path("reports/applicability/conditional-requirement-applicability-2026-09-10.v1.json")
AUTHORITY_PATH = Path("applicability/current-authority.v1.json")
HANDOFF_PATH = Path("ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json")
ORACLE_CONTRACT_PATH = Path("oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json")
DENOMINATOR_GATE_PATH = Path("ontology/denominator/true-obligation-denominator-gate-2026-09-10.v1.json")

ALLOCATION_SCHEMA_PATH = Path("schemas/json/conditional-applicability-allocation.schema.json")
PREDICATE_SCHEMA_PATH = Path("schemas/json/applicability-predicate-v2.schema.json")
FACT_SCHEMA_PATH = Path("schemas/json/profile-capability-fact-snapshot.schema.json")
RESULT_SCHEMA_PATH = Path("schemas/json/applicability-evaluation-result.schema.json")
CONTRACT_SCHEMA_PATH = Path("schemas/json/conditional-applicability-contract.schema.json")
FIXTURE_SCHEMA_PATH = Path("schemas/json/conditional-applicability-fixtures.schema.json")
REPORT_SCHEMA_PATH = Path("schemas/json/conditional-applicability-report.schema.json")
AUTHORITY_SCHEMA_PATH = Path("schemas/json/conditional-applicability-authority.schema.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
CONTENT_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")
ARTIFACT_PROFILE_PATH = Path("schemas/identity-profiles/semantic-research-artifact.v1.json")

IMPLEMENTATION_PATHS = (
    Path("schemas/tooling/python/regex_conformance_schema/applicability.py"),
    Path("tools/applicability/compile_conditional_applicability.py"),
    ALLOCATION_SCHEMA_PATH, PREDICATE_SCHEMA_PATH, FACT_SCHEMA_PATH,
    RESULT_SCHEMA_PATH, CONTRACT_SCHEMA_PATH, FIXTURE_SCHEMA_PATH,
    REPORT_SCHEMA_PATH, AUTHORITY_SCHEMA_PATH,
)

FIELD_SPECS = (
    ("profile.feature_scientific_ids", "set", "stable-id", "rcid:v1:feature:", "Canonical features positively present or absent for the exact profile revision."),
    ("profile.operation_scientific_ids", "set", "stable-id", "rcid:v1:operation:", "Canonical host operations positively exposed or absent for the exact profile revision."),
    ("profile.manifestation_scientific_ids", "set", "stable-id", "rcid:v1:manifestation:", "Canonical syntax or API manifestations positively present or absent for the exact profile revision."),
    ("profile.semantic_variant_scientific_ids", "set", "stable-id", "rcid:v1:semantic-variant:", "Canonical semantic variants positively present or absent for the exact profile revision."),
    ("profile.modifier_scientific_ids", "set", "stable-id", "rcid:v1:modifier:", "Canonical modifiers positively present or absent for the exact profile revision."),
)

SET_OPERATORS = {"contains", "not-contains", "intersects", "disjoint"}
SCALAR_OPERATORS = {"eq", "neq", "in", "not-in", "exists", "lt", "lte", "gt", "gte", "range"}
GROUP_OPERATORS = {"all", "any"}
VALUE_FROM = {"feature.scientific_id", "derived.operation_scientific_ids"}
ALLOWED_AUTHORITIES = {
    "canonical-registry-profile-definition", "exact-knowledge-projection",
    "certified-adapter-capability", "certified-environment-capability",
    "frozen-campaign-policy", "reviewed-empirical-promotion",
}
FORBIDDEN_AUTHORITIES = {
    "raw-execution-observation", "mutable-host-discovery",
    "untrusted-adapter-self-report", "contributor-claim",
}
FORBIDDEN_DEPENDENCIES = {"semantic-requirement", "applicability-evaluation", "target-observation"}
MUTABLE_ALIASES = {"current", "head", "latest", "main", "master", "tip"}
TRUTH_TO_RESULT = {"true": "applicable", "false": "not-applicable", "unknown": "unresolved", "invalid": "invalid"}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@lru_cache(maxsize=8)
def _identity_context(root_text: str, profile_path: str) -> tuple[NamespaceRegistry, IdentityProfile]:
    root = Path(root_text)
    return NamespaceRegistry.load(root / NAMESPACE_PATH), IdentityProfile.from_record(load_strict(root / profile_path))


def _content_id(root: Path, namespace: str, kind: str, body: dict[str, Any], *, family: str | None = None) -> str:
    registry, profile = _identity_context(str(root.resolve()), CONTENT_PROFILE_PATH.as_posix())
    result = build_content_identity(
        registry=registry, profile=profile,
        namespace=namespace,
        identity_schema_family_id=family or SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": kind, "content_sha256": _digest(body)},
    )
    return str(result["content_id"])


def _finalize(root: Path, body: dict[str, Any], *, namespace: str, kind: str, id_field: str, digest_field: str, family: str | None = None) -> dict[str, Any]:
    return {**body, id_field: _content_id(root, namespace, kind, body, family=family), digest_field: _digest(body)}


def build_allocation() -> dict[str, Any]:
    return {
        "schema_version": "conditional-applicability-allocation.v1",
        "allocated_on": PUBLISHED_ON,
        "allocations": [
            {"entity_class": "assertion-derivation", "canonical_key": "derivation.conditional-applicability-governance", "assigned_id": APPLICABILITY_DERIVATION_ID},
            {"entity_class": "schema-family", "canonical_key": "schema.conditional-applicability", "assigned_id": SCHEMA_FAMILY_ID},
        ],
    }


@lru_cache(maxsize=4)
def _derivation_cached(root_text: str) -> dict[str, str]:
    root = Path(root_text)
    catalog = load_strict(root / DERIVATION_CATALOG_PATH)
    item = next((entry for entry in catalog["derivations"] if entry["derivation_id"] == APPLICABILITY_DERIVATION_ID), None)
    if item is None:
        item = {
            "derivation_id": APPLICABILITY_DERIVATION_ID,
            "derivation_class": "manual-decision",
            "method_key": "conditional-applicability-governance",
            "method_version": "1.0.0",
            "input_references": [
                "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json",
                "ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json",
                "oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json",
            ],
            "authority_references": ["Build applicability evaluation for conditional requirements", "GOVERNANCE.md"],
            "allowed_gate_kinds": ["governance-policy"],
            "independent_evidence": False,
        }
        item["derivation_revision_id"] = derivation_revision_id(root, item)
    return {key: item[key] for key in ("derivation_id", "derivation_revision_id", "derivation_class")}


def _derivation(root: Path) -> dict[str, str]:
    return deepcopy(_derivation_cached(str(root.resolve())))


def _field_id(root: Path, field: str) -> str:
    return _content_id(root, "applicability-rule-set", "profile-capability-field-v1", {"field": field})


def build_contract(root: Path) -> dict[str, Any]:
    requirements = load_strict(root / REQUIREMENT_PATH)
    handoff = load_strict(root / HANDOFF_PATH)
    oracle = load_strict(root / ORACLE_CONTRACT_PATH)
    fields = []
    for name, value_type, member_type, prefix, meaning in FIELD_SPECS:
        fields.append({
            "field_id": _field_id(root, name), "field": name,
            "value_type": value_type, "member_type": member_type,
            "identity_prefix": prefix, "allowed_operators": sorted(SET_OPERATORS),
            "default_world_assumption": "open", "meaning": meaning,
        })
    body = {
        "schema_version": "conditional-applicability-contract.v1",
        "contract_version": "1.0.0", "effective_on": PUBLISHED_ON,
        "authority_scope": "Prospective, proof-bearing applicability of an existing semantic requirement to an exact immutable profile revision; not semantic requirement existence, expected-result authority, observed support, exclusion policy, or conformance judgment.",
        "authority": {
            "requirement_snapshot_id": requirements["snapshot_id"],
            "requirement_snapshot_digest_sha256": requirements["snapshot_digest_sha256"],
            "profile_expansion_handoff_id": handoff["projection_id"],
            "profile_expansion_handoff_digest_sha256": handoff["projection_digest_sha256"],
            "oracle_contract_id": oracle["contract_id"],
            "oracle_contract_digest_sha256": oracle["contract_digest_sha256"],
            "evaluator_implementation": [
                {"path": path.as_posix(), "file_sha256": _sha(root / path)}
                for path in IMPLEMENTATION_PATHS
            ],
        },
        "state_algebra": {
            "states": ["applicable", "not-applicable", "unresolved", "invalid"],
            "internal_truth_values": ["true", "false", "unknown", "invalid"],
            "mapping": TRUTH_TO_RESULT,
            "and_table": {"true": {"true": "true", "false": "false", "unknown": "unknown"}, "false": {"true": "false", "false": "false", "unknown": "false"}, "unknown": {"true": "unknown", "false": "false", "unknown": "unknown"}},
            "or_table": {"true": {"true": "true", "false": "true", "unknown": "true"}, "false": {"true": "true", "false": "false", "unknown": "unknown"}, "unknown": {"true": "true", "false": "unknown", "unknown": "unknown"}},
            "not_table": {"true": "false", "false": "true", "unknown": "unknown", "invalid": "invalid"},
        },
        "predicate_language": {
            "ast_version": "applicability-predicate.v2",
            "operators": sorted(GROUP_OPERATORS | {"not", "const"} | SET_OPERATORS | SCALAR_OPERATORS),
            "types": ["boolean", "integer", "release-coordinate", "stable-id", "string", "token", "set"],
            "comparators": {"integer-v1": "Exact mathematical integer order.", "registry-release-coordinate-v1": "Order defined only by a future registered release-coordinate comparator; lexical fallback is forbidden."},
            "limits": {"maximum_depth": 16, "maximum_nodes": 128, "maximum_set_members": 256},
            "canonicalization": "NFC normalization; recursively canonicalize; sort and de-duplicate commutative all/any children and in members by JCS bytes exactly as frozen by the predecessor denominator contract. Other equivalent rewrites require a versioned predicate-identity migration; predicate IDs preserve the profile-capability-predicate.v1 identity domain.",
            "forbidden_runtime_features": ["arbitrary-code", "dynamic-import", "environment-read", "filesystem-read", "network-io", "regex-evaluation", "script-evaluation"],
        },
        "field_registry": fields,
        "world_semantics": {
            "default": "open", "unknown_is_false": False,
            "negative_fact_rule": "A member is absent only when an admissible explicit member-absent fact or an exact field-closure rule establishes absence.",
            "closed_world_rule": "No global closed world exists. A closed field must bind a versioned rule to one exact profile revision and field; missing members outside that scope remain unknown.",
        },
        "capability_fact_contract": {
            "allowed_authority_classes": sorted(ALLOWED_AUTHORITIES),
            "prohibited_direct_authority_classes": sorted(FORBIDDEN_AUTHORITIES),
            "required_provenance": ["profile identity and revision", "field identity", "fact revision", "exact source identity/revision/digest", "authority class/state", "dependency graph", "frozen snapshot identity"],
            "historical_freeze_rule": "An evaluation binds one immutable capability-fact snapshot. Later facts create a new snapshot and evaluation; they never mutate history.",
        },
        "evaluation_contract": {
            "input_bindings": ["contract", "requirement", "predicate", "profile revision", "capability-fact snapshot"],
            "facts_read_rule": "Record every decisive and unresolved fact dependency read by the normalized predicate evaluation.",
            "trace_rule": "Emit a deterministic structured tree whose node paths follow the normalized AST.",
            "not_applicable_meaning": "The predicate is affirmatively false from admissible frozen facts; this is not a skip, lack of evidence, observation, or unsupported-feature conclusion.",
            "unresolved_reasons": ["missing-fact", "conflicting-facts", "inadmissible-fact", "unresolved-authority", "field-outside-frozen-model"],
            "invalid_rule": "Malformed schemas, unknown fields/operators, type errors, identity drift, cycles, self-reference, or prohibited authority yield invalid and cannot enter canonical coordinates.",
        },
        "dependency_contract": {
            "traversal": "Traverse capability-fact dependencies by stable ID before evaluation.",
            "cycle_result": "invalid",
            "self_reference_guards": ["semantic-requirement dependency prohibited", "applicability-evaluation dependency prohibited", "target-observation dependency prohibited", "coordinate outcome cannot establish its own capability fact"],
        },
        "exclusion_boundary": {
            "ad_hoc_skip_can_decide": False,
            "not_applicable_requires": ["exact requirement predicate", "exact frozen profile facts", "versioned applicability contract"],
            "non_semantic_exclusions": "Operational skips, quarantine, safety policy, and infrastructure inability remain separate disposition objects and cannot manufacture not-applicable.",
        },
        "prospective_profile_expansion": {
            "formula": "sum over future frozen profiles of each requirement whose predicate evaluates applicable; unresolved and invalid coordinates cannot receive completion credit",
            "exact_profile_count": None, "final_execution_denominator": None,
            "historical_multiplier_substituted": False, "status": "deferred-until-empirical-profile-freeze",
        },
        "derivation": _derivation(root),
    }
    return _finalize(root, body, namespace="trust-policy-revision", kind="conditional-applicability-contract-v1", id_field="contract_id", digest_field="contract_digest_sha256")


@lru_cache(maxsize=4)
def _known_ids_cached(root_text: str) -> frozenset[str]:
    root = Path(root_text)
    return frozenset(item["scientific_id"] for item in load_strict(root / "registries/identity/scientific-identities.v1.json")["bindings"])


def _known_ids(root: Path) -> set[str]:
    return set(_known_ids_cached(str(root.resolve())))


def _predicate_id(root: Path, predicate: dict[str, Any]) -> str:
    body = {"domain": "strling.regex-conformance.profile-capability-predicate.v1", "predicate": normalize_predicate(predicate)}
    registry, profile = _identity_context(str(root.resolve()), ARTIFACT_PROFILE_PATH.as_posix())
    result = build_content_identity(
        registry=registry, profile=profile,
        namespace="applicability-rule-set",
        identity_schema_family_id=SCHEMA_FAMILIES["projection"],
        identity_schema_version="1.0.0",
        identity={"artifact_digest_sha256": _digest(body)},
    )
    return str(result["content_id"])


def _targets(node: dict[str, Any], context: dict[str, Any]) -> list[Any]:
    if "value_from" in node:
        if node["value_from"] == "feature.scientific_id":
            return [context["feature_scientific_id"]]
        return list(context["operation_scientific_ids"])
    if "values" in node:
        return list(node["values"])
    if "value" in node:
        return [node["value"]]
    return []


def _literal_matches_type(value: Any, type_name: str, identity_prefix: str | None, known_ids: set[str]) -> bool:
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name in {"string", "token", "release-coordinate"}:
        return isinstance(value, str) and bool(value)
    if type_name == "stable-id":
        return isinstance(value, str) and value.startswith(identity_prefix or "rcid:v1:") and value in known_ids
    return False


def validate_predicate(root: Path, predicate: dict[str, Any], context: dict[str, Any], contract: dict[str, Any], *, schema_check: bool = True) -> dict[str, Any]:
    if schema_check:
        validate_instance(predicate, load_strict(root / PREDICATE_SCHEMA_PATH), source="applicability predicate")
    fields = {item["field"]: item for item in contract["field_registry"]}
    known = _known_ids(root)
    stats: Counter[str] = Counter()
    nodes = 0

    def visit(node: dict[str, Any], depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > contract["predicate_language"]["limits"]["maximum_nodes"] or depth > contract["predicate_language"]["limits"]["maximum_depth"]:
            fail("applicability-predicate-limit", "predicate exceeds the governed size or depth limit")
        op = node["operator"]
        stats[f"operator:{op}"] += 1
        if op in GROUP_OPERATORS:
            for child in node["clauses"]:
                visit(child, depth + 1)
            return
        if op == "not":
            visit(node["clause"], depth + 1)
            return
        if op == "const":
            return
        if node["field"] not in fields:
            fail("applicability-unknown-field", node["field"])
        spec = fields[node["field"]]
        stats[f"field:{node['field']}"] += 1
        if op not in spec["allowed_operators"]:
            fail("applicability-operator-type", f"{op} is not admitted for {node['field']}")
        arguments = set(node) - {"operator", "field"}
        if op in {"contains", "not-contains"} and arguments not in ({"value"}, {"value_from"}):
            fail("applicability-predicate-target", f"{op} requires exactly one value or value_from")
        if op in {"intersects", "disjoint"} and arguments not in ({"values"}, {"value_from"}):
            fail("applicability-predicate-target", f"{op} requires exactly one values or value_from")
        if op in {"eq", "neq"} and arguments != {"value"}:
            fail("applicability-predicate-target", f"{op} requires exactly one literal value")
        if op in {"in", "not-in"} and arguments != {"values"}:
            fail("applicability-predicate-target", f"{op} requires exactly one values set")
        if op == "exists" and arguments:
            fail("applicability-predicate-target", "exists takes no target")
        if op in {"lt", "lte", "gt", "gte"} and arguments not in ({"value"}, {"value", "comparator"}):
            fail("applicability-predicate-target", f"{op} requires one literal value and an optional comparator")
        if op == "range":
            allowed = {"lower", "upper", "include_lower", "include_upper", "comparator"}
            if not ({"lower", "upper"} & arguments) or not arguments <= allowed:
                fail("applicability-predicate-target", "range requires at least one bound and only range options")
            if "include_lower" in arguments and "lower" not in arguments:
                fail("applicability-predicate-target", "include_lower requires lower")
            if "include_upper" in arguments and "upper" not in arguments:
                fail("applicability-predicate-target", "include_upper requires upper")
        if "value_from" in node and node["value_from"] not in VALUE_FROM:
            fail("applicability-value-source", str(node["value_from"]))
        for target in _targets(node, context):
            if not _literal_matches_type(target, spec["member_type"], spec["identity_prefix"], known):
                code = "applicability-invalid-capability-reference" if spec["member_type"] == "stable-id" else "applicability-predicate-type"
                fail(code, str(target))
        for bound in (node.get("lower"), node.get("upper")):
            if bound is not None and not _literal_matches_type(bound, spec["member_type"], spec["identity_prefix"], known):
                fail("applicability-predicate-type", str(bound))
        if node != normalize_predicate(node):
            fail("applicability-noncanonical-predicate", "predicate serialization is not canonical")

    visit(predicate, 1)
    return {"nodes": nodes, "stats": dict(sorted(stats.items()))}


def _fact_body(field_id: str, field: str, assertion: str, value: Any, authority: str, source_token: str, dependencies: list[dict[str, str]] | None = None) -> dict[str, Any]:
    digest = hashlib.sha256(source_token.encode("utf-8")).hexdigest()
    return {
        "fact_revision_id": "rcid:v1:applicability-rule-set:h:jcs-sha256-v1:" + hashlib.sha256((source_token + ":revision").encode()).hexdigest(),
        "field_id": field_id, "field": field, "assertion": assertion,
        "value_type": "stable-id", "value": value,
        "authority_class": authority, "authority_state": "admissible",
        "source": {
            "artifact_id": "rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:" + digest,
            "revision_id": "rcid:v1:ontology-projection:h:jcs-sha256-v1:" + hashlib.sha256((source_token + ":source").encode()).hexdigest(),
            "digest_sha256": digest, "locator": "synthetic-fixture:" + source_token,
        },
        "dependencies": dependencies or [],
    }


def _finalize_fact(root: Path, body: dict[str, Any]) -> dict[str, Any]:
    return _finalize(root, body, namespace="trust-assessment", kind="profile-capability-fact-v1", id_field="fact_id", digest_field="fact_digest_sha256")


def build_fact_snapshot(root: Path, profile_id: str, profile_revision_id: str, facts: list[dict[str, Any]]) -> dict[str, Any]:
    body = {
        "schema_version": "profile-capability-fact-snapshot.v1", "classification": "synthetic-non-authoritative",
        "profile_id": profile_id, "profile_revision_id": profile_revision_id,
        "world_assumption": "open", "field_closure_rules": [], "facts": facts,
    }
    return _finalize(root, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")


def validate_fact_snapshot(root: Path, snapshot: dict[str, Any], contract: dict[str, Any]) -> None:
    validate_instance(snapshot, load_strict(root / FACT_SCHEMA_PATH), source="profile capability fact snapshot")
    body = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
    expected = _content_id(root, "ontology-projection", "profile-capability-fact-snapshot-v1", body)
    if snapshot["snapshot_digest_sha256"] != _digest(body) or snapshot["snapshot_id"] != expected:
        fail("applicability-fact-snapshot-identity", "capability snapshot identity or digest differs")
    fields = {item["field"]: item for item in contract["field_registry"]}
    known = _known_ids(root)
    for closure in snapshot["field_closure_rules"]:
        spec = fields.get(closure["field"])
        if spec is None or closure["field_id"] != spec["field_id"]:
            fail("applicability-invalid-closure-field", closure["field"])
    by_id = {item["fact_id"]: item for item in snapshot["facts"]}
    if len(by_id) != len(snapshot["facts"]):
        fail("applicability-duplicate-fact", "duplicate fact identity")
    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(identifier: str) -> None:
        if identifier in visiting:
            fail("applicability-dependency-cycle", identifier)
        if identifier in visited:
            return
        visiting.add(identifier)
        for dep in by_id[identifier]["dependencies"]:
            if dep["kind"] == "capability-fact":
                if dep["dependency_id"] not in by_id:
                    fail("applicability-dangling-fact-dependency", dep["dependency_id"])
                walk(dep["dependency_id"])
        visiting.remove(identifier)
        visited.add(identifier)
    for identifier in by_id:
        walk(identifier)
    for fact in snapshot["facts"]:
        fact_body = {key: value for key, value in fact.items() if key not in {"fact_id", "fact_digest_sha256"}}
        if fact["fact_digest_sha256"] != _digest(fact_body) or fact["fact_id"] != _content_id(root, "trust-assessment", "profile-capability-fact-v1", fact_body):
            fail("applicability-fact-identity", fact["fact_id"])
        if fact["field"] not in fields or fact["field_id"] != fields[fact["field"]]["field_id"]:
            fail("applicability-invalid-capability-reference", fact["field"])
        spec = fields[fact["field"]]
        expected_assertions = {"member-present", "member-absent"} if spec["value_type"] == "set" else {"scalar-value", "scalar-absent"}
        if fact["assertion"] not in expected_assertions or fact["value_type"] != spec["member_type"]:
            fail("applicability-fact-type", fact["fact_id"])
        if fact["assertion"] == "scalar-absent":
            if fact["value"] is not None:
                fail("applicability-fact-type", fact["fact_id"])
        elif fact["value"] is None or not _literal_matches_type(fact["value"], spec["member_type"], spec["identity_prefix"], known):
            code = "applicability-invalid-capability-reference" if spec["member_type"] == "stable-id" else "applicability-fact-type"
            fail(code, str(fact["value"]))
        if fact["authority_class"] in FORBIDDEN_AUTHORITIES or fact["authority_class"] not in ALLOWED_AUTHORITIES:
            fail("applicability-prohibited-fact-authority", fact["authority_class"])
        if fact["authority_state"] != "admissible":
            continue
        for part in (fact["source"]["locator"],):
            if part.strip().lower() in MUTABLE_ALIASES:
                fail("applicability-mutable-source", part)
        for dependency in fact["dependencies"]:
            if dependency["kind"] in FORBIDDEN_DEPENDENCIES:
                fail("applicability-self-reference", dependency["kind"])


def _combine(operator: str, truths: list[str]) -> str:
    if "invalid" in truths:
        return "invalid"
    if operator == "all":
        if "false" in truths:
            return "false"
        return "unknown" if "unknown" in truths else "true"
    if "true" in truths:
        return "true"
    return "unknown" if "unknown" in truths else "false"


def _membership(snapshot: dict[str, Any], field: str, target: Any) -> tuple[str, list[dict[str, Any]], str]:
    relevant = [fact for fact in snapshot["facts"] if fact["field"] == field and fact["value"] == target]
    admissible = [fact for fact in relevant if fact["authority_state"] == "admissible"]
    present = [fact for fact in admissible if fact["assertion"] == "member-present"]
    absent = [fact for fact in admissible if fact["assertion"] == "member-absent"]
    if present and absent:
        return "unknown", relevant, "conflicting-facts"
    if present:
        return "true", relevant, "member-present"
    if absent:
        return "false", relevant, "member-absent"
    if relevant:
        reason = "unresolved-authority" if any(f["authority_state"] == "unresolved" for f in relevant) else "inadmissible-fact"
        return "unknown", relevant, reason
    if any(rule["field"] == field for rule in snapshot["field_closure_rules"]):
        return "false", [], "field-closure-absence"
    return "unknown", [], "missing-fact"


def _scalar(snapshot: dict[str, Any], field: str) -> tuple[str, Any, list[dict[str, Any]], str]:
    relevant = [fact for fact in snapshot["facts"] if fact["field"] == field]
    admissible = [fact for fact in relevant if fact["authority_state"] == "admissible"]
    values = {canonical_bytes(fact["value"]): fact["value"] for fact in admissible if fact["assertion"] == "scalar-value"}
    absent = [fact for fact in admissible if fact["assertion"] == "scalar-absent"]
    if len(values) > 1 or (values and absent):
        return "unknown", None, relevant, "conflicting-facts"
    if values:
        return "true", next(iter(values.values())), relevant, "scalar-value"
    if absent:
        return "false", None, relevant, "scalar-absent"
    if relevant:
        reason = "unresolved-authority" if any(f["authority_state"] == "unresolved" for f in relevant) else "inadmissible-fact"
        return "unknown", None, relevant, reason
    return "unknown", None, [], "missing-fact"


def _eval_node(node: dict[str, Any], snapshot: dict[str, Any], context: dict[str, Any], path: str = "$") -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    op = node["operator"]
    if op in GROUP_OPERATORS:
        evaluated = [_eval_node(child, snapshot, context, f"{path}.clauses[{index}]") for index, child in enumerate(node["clauses"])]
        truth = _combine(op, [item[0] for item in evaluated])
        trace = {"node_path": path, "operator": op, "truth_value": truth, "reason_code": f"{op}-{truth}", "fact_ids": sorted({fact["fact_id"] for item in evaluated for fact in item[2]}), "children": [item[1] for item in evaluated]}
        return truth, trace, [fact for item in evaluated for fact in item[2]]
    if op == "not":
        truth, child, facts = _eval_node(node["clause"], snapshot, context, path + ".clause")
        inverted = {"true": "false", "false": "true", "unknown": "unknown", "invalid": "invalid"}[truth]
        return inverted, {"node_path": path, "operator": op, "truth_value": inverted, "reason_code": "not-" + inverted, "fact_ids": sorted({fact["fact_id"] for fact in facts}), "children": [child]}, facts
    if op == "const":
        truth = "true" if node["value"] else "false"
        return truth, {"node_path": path, "operator": op, "truth_value": truth, "reason_code": "constant-" + truth, "fact_ids": [], "children": []}, []
    targets = _targets(node, context)
    if op in SCALAR_OPERATORS:
        established, value, facts, reason = _scalar(snapshot, node["field"])
        if op == "exists":
            truth = established
        elif established != "true":
            truth = "unknown" if established == "unknown" else "false"
        elif op == "eq": truth = "true" if value == node["value"] else "false"
        elif op == "neq": truth = "true" if value != node["value"] else "false"
        elif op == "in": truth = "true" if value in node["values"] else "false"
        elif op == "not-in": truth = "true" if value not in node["values"] else "false"
        else:
            comparator = node.get("comparator", "integer-v1")
            if comparator != "integer-v1" or isinstance(value, bool) or not isinstance(value, int):
                fail("applicability-comparator-type", comparator)
            if op == "lt": truth = "true" if value < node["value"] else "false"
            elif op == "lte": truth = "true" if value <= node["value"] else "false"
            elif op == "gt": truth = "true" if value > node["value"] else "false"
            elif op == "gte": truth = "true" if value >= node["value"] else "false"
            else:
                lower_ok = "lower" not in node or value > node["lower"] or (node.get("include_lower", True) and value == node["lower"])
                upper_ok = "upper" not in node or value < node["upper"] or (node.get("include_upper", True) and value == node["upper"])
                truth = "true" if lower_ok and upper_ok else "false"
        return truth, {"node_path": path, "operator": op, "truth_value": truth, "reason_code": reason, "fact_ids": sorted({fact["fact_id"] for fact in facts}), "children": []}, facts
    outcomes = [_membership(snapshot, node["field"], target) for target in targets]
    if op in {"contains", "not-contains"}:
        truth = outcomes[0][0]
        if op == "not-contains":
            truth = {"true": "false", "false": "true", "unknown": "unknown"}[truth]
    elif op in {"intersects", "disjoint"}:
        truth = _combine("any", [item[0] for item in outcomes])
        if op == "disjoint":
            truth = {"true": "false", "false": "true", "unknown": "unknown"}[truth]
    else:
        fail("applicability-unimplemented-operator", op)
    facts = [fact for item in outcomes for fact in item[1]]
    reasons = sorted({item[2] for item in outcomes})
    return truth, {"node_path": path, "operator": op, "truth_value": truth, "reason_code": reasons[0] if len(reasons) == 1 else "mixed-membership-evidence", "fact_ids": sorted({fact["fact_id"] for fact in facts}), "children": []}, facts


def evaluate(root: Path, contract: dict[str, Any], requirement: dict[str, Any], binding: dict[str, Any], predicate_def: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    validate_fact_snapshot(root, snapshot, contract)
    if requirement["scientific_id"] != binding["requirement_scientific_id"]:
        fail("applicability-requirement-binding", requirement["scientific_id"])
    if predicate_def["predicate_id"] != binding["predicate_id"] or _predicate_id(root, predicate_def["predicate"]) != predicate_def["predicate_id"]:
        fail("applicability-predicate-identity", binding["predicate_id"])
    context = {"feature_scientific_id": binding["feature_scientific_id"], "operation_scientific_ids": binding["operation_scientific_ids"]}
    validate_predicate(root, predicate_def["predicate"], context, contract)
    truth, trace, facts = _eval_node(predicate_def["predicate"], snapshot, context)
    unique_facts = {fact["fact_id"]: fact for fact in facts}
    unresolved = []
    def collect(node: dict[str, Any], trace_node: dict[str, Any]) -> None:
        if node["operator"] in GROUP_OPERATORS:
            for child, child_trace in zip(node["clauses"], trace_node["children"]): collect(child, child_trace)
        elif node["operator"] == "not": collect(node["clause"], trace_node["children"][0])
        elif trace_node["truth_value"] == "unknown":
            targets = _targets(node, context)
            if node["operator"] in SCALAR_OPERATORS:
                scalar_truth, _, _, reason = _scalar(snapshot, node["field"])
                targets = [None] if scalar_truth == "unknown" else []
            for target in targets:
                member_truth, _, reason = _membership(snapshot, node["field"], target) if node["operator"] not in SCALAR_OPERATORS else ("unknown", [], reason)
                if member_truth == "unknown":
                    spec = next(item for item in contract["field_registry"] if item["field"] == node["field"])
                    unresolved.append({"field_id": spec["field_id"], "field": node["field"], "target": target, "reason": reason})
    collect(predicate_def["predicate"], trace)
    result = TRUTH_TO_RESULT[truth]
    if result != "unresolved":
        unresolved = []
    body = {
        "schema_version": "applicability-evaluation-result.v1",
        "contract": {"artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"]},
        "requirement": {"artifact_id": requirement["scientific_id"], "digest_sha256": _digest(requirement)},
        "predicate": {"artifact_id": predicate_def["predicate_id"], "digest_sha256": _digest(predicate_def["predicate"])},
        "profile": {"profile_id": snapshot["profile_id"], "profile_revision_id": snapshot["profile_revision_id"]},
        "capability_snapshot": {"artifact_id": snapshot["snapshot_id"], "digest_sha256": snapshot["snapshot_digest_sha256"]},
        "result": result, "truth_value": truth,
        "reason_codes": sorted({trace["reason_code"], *[item["reason"] for item in unresolved]}),
        "facts_read": [{"fact_id": item["fact_id"], "fact_digest_sha256": item["fact_digest_sha256"]} for item in sorted(unique_facts.values(), key=lambda value: value["fact_id"])],
        "unresolved_dependencies": sorted({canonical_bytes(item): item for item in unresolved}.values(), key=canonical_bytes),
        "trace": trace,
        "semantic_boundary": {"determines_expected_result": False, "establishes_empirical_unsupported": False, "rewrites_semantic_requirement": False, "ad_hoc_skip_used": False},
    }
    finalized = _finalize(root, body, namespace="applicability-coordinate", kind="conditional-requirement-applicability-result-v1", id_field="evaluation_id", digest_field="evaluation_digest_sha256")
    validate_instance(finalized, load_strict(root / RESULT_SCHEMA_PATH), source="applicability evaluation result")
    return finalized


def _fixture_basis(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    requirements = load_strict(root / REQUIREMENT_PATH)
    handoff = load_strict(root / HANDOFF_PATH)
    req_by_id = {item["scientific_id"]: item for item in requirements["requirements"]}
    pred_by_id = {item["predicate_id"]: item for item in handoff["predicate_definitions"]}
    binding = next(item for item in handoff["requirement_predicate_bindings"] if item["semantic_applicability"] == "conditional")
    return req_by_id[binding["requirement_scientific_id"]], binding, pred_by_id[binding["predicate_id"]]


def build_fixtures(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    requirement, binding, predicate = _fixture_basis(root)
    profile_id = "rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7"
    profile_revision = "rcid:v1:profile-revision:h:jcs-sha256-v1:" + "1" * 64
    fields = {item["field"]: item for item in contract["field_registry"]}
    context = {"feature_scientific_id": binding["feature_scientific_id"], "operation_scientific_ids": binding["operation_scientific_ids"]}
    leaves = predicate["predicate"]["clauses"]
    facts = []
    for index, leaf in enumerate(leaves):
        for target in _targets(leaf, context):
            facts.append(_finalize_fact(root, _fact_body(fields[leaf["field"]]["field_id"], leaf["field"], "member-present", target, "canonical-registry-profile-definition", f"true-{index}-{target}")))
    true_snapshot = build_fact_snapshot(root, profile_id, profile_revision, facts)
    false_facts = deepcopy(facts)
    first = false_facts[0]
    false_body = {key: value for key, value in first.items() if key not in {"fact_id", "fact_digest_sha256"}}
    false_body["assertion"] = "member-absent"
    false_facts[0] = _finalize_fact(root, false_body)
    false_snapshot = build_fact_snapshot(root, profile_id, profile_revision, false_facts)
    missing_snapshot = build_fact_snapshot(root, profile_id, profile_revision, facts[1:])
    conflict_body = {key: value for key, value in false_facts[0].items() if key not in {"fact_id", "fact_digest_sha256"}}
    conflict_body["assertion"] = "member-present"
    conflict_snapshot = build_fact_snapshot(root, profile_id, profile_revision, [*false_facts, _finalize_fact(root, conflict_body)])
    # Re-finalize snapshots with the stable generic artifact kind used by verification.
    snapshots = []
    for snapshot in (true_snapshot, false_snapshot, missing_snapshot, conflict_snapshot):
        body = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
        snapshots.append(_finalize(root, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256"))
    true_snapshot, false_snapshot, missing_snapshot, conflict_snapshot = snapshots
    valid_cases = [
        {"case_id": "known-true", "kind": "authoritative-binding", "expected_result": "applicable", "snapshot_id": true_snapshot["snapshot_id"]},
        {"case_id": "known-false", "kind": "authoritative-binding", "expected_result": "not-applicable", "snapshot_id": false_snapshot["snapshot_id"]},
        {"case_id": "missing-open-world", "kind": "authoritative-binding", "expected_result": "unresolved", "snapshot_id": missing_snapshot["snapshot_id"]},
        {"case_id": "conflicting-facts", "kind": "authoritative-binding", "expected_result": "unresolved", "snapshot_id": conflict_snapshot["snapshot_id"]},
        {"case_id": "explicit-absence", "kind": "authoritative-binding", "expected_result": "not-applicable", "snapshot_id": false_snapshot["snapshot_id"]},
        {"case_id": "and-unknown-false", "kind": "raw-predicate", "expected_result": "not-applicable", "predicate": {"operator": "all", "clauses": [{"operator": "const", "value": False}, {"operator": "not", "clause": {"operator": "contains", "field": leaves[0]["field"], "value": _targets(leaves[0], context)[0]}}]}},
        {"case_id": "or-unknown-true", "kind": "raw-predicate", "expected_result": "applicable", "predicate": {"operator": "any", "clauses": [{"operator": "const", "value": True}, {"operator": "contains", "field": leaves[0]["field"], "value": _targets(leaves[0], context)[0]}]}},
        {"case_id": "negated-unknown", "kind": "raw-predicate", "expected_result": "unresolved", "predicate": {"operator": "not", "clause": {"operator": "contains", "field": leaves[0]["field"], "value": _targets(leaves[0], context)[0]}}},
    ]
    for case in valid_cases:
        if "predicate" in case:
            case["predicate"] = normalize_predicate(case["predicate"])
    return {
        "schema_version": "conditional-applicability-fixtures.v1", "classification": "synthetic-non-authoritative",
        "profile_fact_snapshots": snapshots, "valid_cases": valid_cases,
        "invalid_cases": [
            {"case_id": "invalid-capability-reference", "expected_error": "applicability-invalid-capability-reference", "mutation": "replace a stable capability ID with an unknown ID"},
            {"case_id": "type-invalid-comparison", "expected_error": "applicability-operator-type", "mutation": "use scalar equality on a set field"},
            {"case_id": "unsupported-operator", "expected_error": "schema-validation", "mutation": "insert an arbitrary predicate operator"},
            {"case_id": "dependency-cycle", "expected_error": "applicability-dependency-cycle", "mutation": "make a fact depend on itself"},
            {"case_id": "target-observation-self-reference", "expected_error": "applicability-self-reference", "mutation": "use target observation as a fact dependency"},
            {"case_id": "ad-hoc-skip", "expected_error": "schema-validation", "mutation": "add skip to an evaluation input"},
            {"case_id": "raw-observation-authority", "expected_error": "applicability-prohibited-fact-authority", "mutation": "use raw observation directly as capability authority"},
        ],
        "synthetic_denominator_example": {"authoritative": False, "profile_count": 1, "applicable_coordinates": 1, "not_applicable_coordinates": 1, "unresolved_coordinates": 1},
    }


def _exercise_fixtures(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    validate_instance(fixture, load_strict(root / FIXTURE_SCHEMA_PATH), source=FIXTURE_PATH.as_posix())
    requirement, binding, predicate = _fixture_basis(root)
    snapshots = {item["snapshot_id"]: item for item in fixture["profile_fact_snapshots"]}
    outcomes: dict[str, str] = {}
    for case in fixture["valid_cases"][:5]:
        result = evaluate(root, contract, requirement, binding, predicate, snapshots[case["snapshot_id"]])
        if result["result"] != case["expected_result"]:
            fail("applicability-fixture-outcome", case["case_id"])
        outcomes[case["case_id"]] = result["result"]
    context = {"feature_scientific_id": binding["feature_scientific_id"], "operation_scientific_ids": binding["operation_scientific_ids"]}
    missing = snapshots[fixture["valid_cases"][2]["snapshot_id"]]
    for case in fixture["valid_cases"][5:]:
        validate_predicate(root, case["predicate"], context, contract)
        truth, _, _ = _eval_node(case["predicate"], missing, context)
        if TRUTH_TO_RESULT[truth] != case["expected_result"]:
            fail("applicability-fixture-outcome", case["case_id"])
        outcomes[case["case_id"]] = TRUTH_TO_RESULT[truth]
    # Targeted invalid mutations prove each constitutional guard at its validation boundary.
    rejected = 0
    for case in fixture["invalid_cases"]:
        try:
            if case["case_id"] == "invalid-capability-reference":
                bad = {"operator": "contains", "field": "profile.feature_scientific_ids", "value": "rcid:v1:feature:u7:00000000-0000-7000-8000-000000000000"}
                validate_predicate(root, bad, context, contract)
            elif case["case_id"] == "type-invalid-comparison":
                validate_predicate(root, {"operator": "eq", "field": "profile.feature_scientific_ids", "value": binding["feature_scientific_id"]}, context, contract)
            elif case["case_id"] == "unsupported-operator":
                validate_predicate(root, {"operator": "execute", "field": "profile.feature_scientific_ids", "value": binding["feature_scientific_id"]}, context, contract)
            elif case["case_id"] == "ad-hoc-skip":
                bad = deepcopy(missing); bad["skip"] = True
                validate_fact_snapshot(root, bad, contract)
            else:
                bad = deepcopy(missing)
                source = _fact_body(contract["field_registry"][0]["field_id"], contract["field_registry"][0]["field"], "member-present", binding["feature_scientific_id"], "canonical-registry-profile-definition", case["case_id"])
                fact = _finalize_fact(root, source)
                if case["case_id"] == "dependency-cycle":
                    # A deterministic content identity cannot literally refer to itself. Two predeclared IDs still exercise graph cycle traversal.
                    a = "rcid:v1:trust-assessment:h:jcs-sha256-v1:" + "a" * 64; b = "rcid:v1:trust-assessment:h:jcs-sha256-v1:" + "b" * 64
                    first = deepcopy(fact); second = deepcopy(fact); first["fact_id"] = a; second["fact_id"] = b
                    first["dependencies"] = [{"dependency_id": b, "kind": "capability-fact"}]; second["dependencies"] = [{"dependency_id": a, "kind": "capability-fact"}]
                    bad["facts"] = [first, second]
                elif case["case_id"] == "target-observation-self-reference":
                    body = {key: value for key, value in fact.items() if key not in {"fact_id", "fact_digest_sha256"}}
                    body["dependencies"] = [{"dependency_id": "rcid:v1:observation:h:jcs-sha256-v1:" + "a" * 64, "kind": "target-observation"}]
                    fact = _finalize_fact(root, body)
                    bad["facts"] = [fact]
                elif case["case_id"] == "raw-observation-authority":
                    body = {key: value for key, value in fact.items() if key not in {"fact_id", "fact_digest_sha256"}}
                    body["authority_class"] = "raw-execution-observation"
                    fact = _finalize_fact(root, body); bad["facts"] = [fact]
                body = {key: value for key, value in bad.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
                bad = _finalize(root, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")
                validate_fact_snapshot(root, bad, contract)
        except ConformanceDataError as error:
            expected = case["expected_error"]
            if expected == "schema-validation" and "schema" in error.code:
                pass
            elif error.code != expected:
                fail("applicability-fixture-wrong-error", f"{case['case_id']} expected {expected}, got {error.code}")
            rejected += 1
        else:
            fail("applicability-fixture-not-rejected", case["case_id"])
    return {"accepted": len(outcomes), "rejected": rejected, "outcomes": dict(sorted(outcomes.items()))}


@lru_cache(maxsize=4)
def _audit_requirements_cached(root_text: str, contract_digest: str) -> dict[str, Any]:
    root = Path(root_text)
    contract = load_strict(root / CONTRACT_PATH)
    requirements = load_strict(root / REQUIREMENT_PATH)
    handoff = load_strict(root / HANDOFF_PATH)
    semantic = load_strict(root / "semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json")
    feature_by_id = {item["feature_id"]: item for item in semantic["features"]}
    identity_by_key = {item["canonical_key"]: item["scientific_id"] for item in load_strict(root / "registries/identity/scientific-identities.v1.json")["bindings"]}
    req_by_id = {item["scientific_id"]: item for item in requirements["requirements"]}
    pred_by_id = {item["predicate_id"]: item for item in handoff["predicate_definitions"]}
    field_counts: Counter[str] = Counter(); operator_counts: Counter[str] = Counter(); source_counts: Counter[str] = Counter()
    conditional = 0; required = 0; conditional_predicates: set[str] = set(); required_intrinsic_modifiers = 0; required_unexplained_dependencies = 0
    validated_predicate_ids: set[str] = set()
    verified_identity_ids: set[str] = set()
    for binding in handoff["requirement_predicate_bindings"]:
        requirement = req_by_id.get(binding["requirement_scientific_id"])
        predicate = pred_by_id.get(binding["predicate_id"])
        if requirement is None or predicate is None:
            fail("applicability-dangling-requirement-predicate", binding["requirement_scientific_id"])
        if normalize_predicate(requirement["profile_condition"]) != predicate["predicate"]:
            fail("applicability-requirement-predicate-drift", requirement["scientific_id"])
        context = {"feature_scientific_id": binding["feature_scientific_id"], "operation_scientific_ids": binding["operation_scientific_ids"]}
        first_validation = predicate["predicate_id"] not in validated_predicate_ids
        result = validate_predicate(root, predicate["predicate"], context, contract, schema_check=first_validation)
        validated_predicate_ids.add(predicate["predicate_id"])
        if predicate["predicate_id"] not in verified_identity_ids:
            if _predicate_id(root, predicate["predicate"]) != predicate["predicate_id"]:
                fail("applicability-predicate-identity", predicate["predicate_id"])
            verified_identity_ids.add(predicate["predicate_id"])
        for key, value in result["stats"].items():
            axis, token = key.split(":", 1)
            (field_counts if axis == "field" else operator_counts)[token] += value
        def collect(node: dict[str, Any]) -> None:
            if "value_from" in node: source_counts[node["value_from"]] += 1
            for child in node.get("clauses", []): collect(child)
            if "clause" in node: collect(node["clause"])
        collect(predicate["predicate"])
        if binding["semantic_applicability"] == "conditional":
            conditional += 1; conditional_predicates.add(binding["predicate_id"])
        else:
            required += 1
            extra_fields = {key.split(":", 1)[1] for key in result["stats"] if key.startswith("field:")} - {"profile.feature_scientific_ids", "profile.operation_scientific_ids"}
            if extra_fields:
                intrinsic_modifiers = {
                    identity_by_key[key]
                    for key in feature_by_id[requirement["feature_id"]].get("modifier_ids", [])
                }
                modifier_targets = {
                    target for node in predicate["predicate"].get("clauses", [])
                    if node.get("field") == "profile.modifier_scientific_ids"
                    for target in _targets(node, context)
                }
                if extra_fields == {"profile.modifier_scientific_ids"} and modifier_targets and modifier_targets <= intrinsic_modifiers:
                    required_intrinsic_modifiers += 1
                else:
                    required_unexplained_dependencies += 1
    if (len(requirements["requirements"]), required, conditional) != (3378, 1406, 1972):
        fail("applicability-denominator-drift", f"observed {len(requirements['requirements'])}/{required}/{conditional}")
    return {
        "semantic_requirements": 3378, "unconditional_requirements": required,
        "conditional_requirements": conditional, "conditional_requirements_validated": conditional,
        "distinct_predicates": len(pred_by_id), "distinct_conditional_predicates": len(conditional_predicates),
        "unexplained_conditional_requirements": 0,
        "required_intrinsic_modifier_scope_requirements": required_intrinsic_modifiers,
        "required_unexplained_capability_dependencies": required_unexplained_dependencies,
        "fields": dict(sorted(field_counts.items())), "leaf_operators": dict(sorted(operator_counts.items())),
        "value_sources": dict(sorted(source_counts.items())),
        "invalid_references": 0, "type_errors": 0, "cycles": 0,
        "identity_mismatches": 0, "noncanonical_predicates": 0,
    }


def audit_requirements(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    return deepcopy(_audit_requirements_cached(str(root.resolve()), contract["contract_digest_sha256"]))


def build_report(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> dict[str, Any]:
    coverage = audit_requirements(root, contract)
    fixture_results = _exercise_fixtures(root, contract, fixture)
    requirements = load_strict(root / REQUIREMENT_PATH); obligations = load_strict(root / OBLIGATION_PATH)
    handoff = load_strict(root / HANDOFF_PATH)
    identity = load_strict(root / "registries/identity/scientific-identities.v1.json")
    body = {
        "schema_version": "conditional-applicability-report.v1", "published_on": PUBLISHED_ON,
        "claim_scope": "Machine validation of total open-world conditional-requirement applicability, immutable capability-fact inputs, three-valued traces, self-reference guards, and prospective profile-expansion interface; not profile research, expected-result authority, observed support, or execution-denominator authority.",
        "contract": {"artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"], "file_sha256": _sha(root / CONTRACT_PATH)},
        "authoritative_inputs": [
            {"path": REQUIREMENT_PATH.as_posix(), "artifact_id": requirements["snapshot_id"], "digest_sha256": requirements["snapshot_digest_sha256"], "file_sha256": _sha(root / REQUIREMENT_PATH)},
            {"path": OBLIGATION_PATH.as_posix(), "artifact_id": obligations["snapshot_id"], "digest_sha256": obligations["snapshot_digest_sha256"], "file_sha256": _sha(root / OBLIGATION_PATH)},
            {"path": HANDOFF_PATH.as_posix(), "artifact_id": handoff["projection_id"], "digest_sha256": handoff["projection_digest_sha256"], "file_sha256": _sha(root / HANDOFF_PATH)},
            {"path": "registries/identity/scientific-identities.v1.json", "catalog_digest_sha256": identity["catalog_digest_sha256"], "binding_count": len(identity["bindings"]), "file_sha256": _sha(root / "registries/identity/scientific-identities.v1.json")},
        ],
        "coverage": {key: coverage[key] for key in ("semantic_requirements", "unconditional_requirements", "conditional_requirements", "conditional_requirements_validated", "distinct_predicates", "distinct_conditional_predicates", "unexplained_conditional_requirements", "required_intrinsic_modifier_scope_requirements", "required_unexplained_capability_dependencies")},
        "predicate_audit": {key: coverage[key] for key in ("fields", "leaf_operators", "value_sources", "invalid_references", "type_errors", "cycles", "identity_mismatches", "noncanonical_predicates")},
        "fixture_results": fixture_results,
        "checks": [
            {"check_id": "open-world-unknown-preserved", "status": "PASS", "evidence": "Missing member facts evaluate unknown/unresolved, never false."},
            {"check_id": "explicit-negative-required", "status": "PASS", "evidence": "Only admissible member-absent evidence can make membership false."},
            {"check_id": "kleene-nested-logic", "status": "PASS", "evidence": "AND/OR/NOT truth tables preserve uncertainty and decisive operands."},
            {"check_id": "predicate-language-closed", "status": "PASS", "evidence": "Typed allowlists reject unknown fields, operators, targets, and runtime code."},
            {"check_id": "conditional-requirement-closure", "status": "PASS", "evidence": "All 1,972 conditional requirements bind valid canonical predicates."},
            {"check_id": "identity-stability", "status": "PASS", "evidence": "Existing predecessor predicate IDs recompute byte-for-byte from their preserved identity domain."},
            {"check_id": "immutable-profile-input", "status": "PASS", "evidence": "Evaluations bind exact profile revision and capability snapshot IDs/digests."},
            {"check_id": "dependency-cycle-guard", "status": "PASS", "evidence": "Capability dependency traversal fails closed on cycles and dangling facts."},
            {"check_id": "observation-self-reference-guard", "status": "PASS", "evidence": "Target observations and applicability evaluations cannot establish input capability facts."},
            {"check_id": "skip-exclusion-boundary", "status": "PASS", "evidence": "Ad hoc skip is absent from the closed input schema and cannot decide applicability."},
            {"check_id": "oracle-boundary", "status": "PASS", "evidence": "Applicability results explicitly cannot establish expected output or conformance."},
            {"check_id": "profile-expansion-deferred", "status": "PASS", "evidence": "No profile count, real capability snapshot, or final execution denominator is materialized."},
        ],
        "denominator_boundary": {"obligations": 2390, "requirements": 3378, "conditional_requirements": 1972, "c4": "FAIL — 0/3378", "unchanged": True},
        "deferrals": {"exact_profile_count": None, "final_execution_denominator": None, "profile_fact_research": "deferred", "production_vectors": "deferred"},
        "result": "PASS",
    }
    return _finalize(root, body, namespace="trust-assessment", kind="conditional-applicability-report-v1", id_field="report_id", digest_field="report_digest_sha256")


def build_authority(root: Path, contract: dict[str, Any], fixture: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    requirements = load_strict(root / REQUIREMENT_PATH); handoff = load_strict(root / HANDOFF_PATH)
    def bound(path: Path, record: dict[str, Any], id_field: str, digest_field: str) -> dict[str, str]:
        return {"path": path.as_posix(), "artifact_id": record[id_field], "digest_sha256": record[digest_field], "file_sha256": _sha(root / path)}
    body = {
        "schema_version": "conditional-applicability-authority.v1",
        "current_contract": bound(CONTRACT_PATH, contract, "contract_id", "contract_digest_sha256"),
        "validation_fixture": {"path": FIXTURE_PATH.as_posix(), "artifact_id": _content_id(root, "expectation-projection", "conditional-applicability-fixtures-v1", fixture), "digest_sha256": _digest(fixture), "file_sha256": _sha(root / FIXTURE_PATH)},
        "acceptance_report": bound(REPORT_PATH, report, "report_id", "report_digest_sha256"),
        "requirement_authority": bound(REQUIREMENT_PATH, requirements, "snapshot_id", "snapshot_digest_sha256"),
        "profile_expansion_handoff": bound(HANDOFF_PATH, handoff, "projection_id", "projection_digest_sha256"),
        "historical_compatibility": {"requirements_rewritten": False, "observations_reinterpreted": False, "campaign_expectations_rewritten": False, "later_fact_snapshots_create_new_evaluations": True},
        "next_interfaces": {"empirical_profile_capability_freeze": "deferred", "real_profile_expansion": "deferred", "claims_and_adjudication": "deferred", "production_vectors": "deferred"},
        "governance": {"semantic_requirement_existence_owner": "canonical semantic denominator", "profile_applicability_owner": "this exact contract plus an immutable profile-capability snapshot", "expected_result_owner": "oracle/evidence authority, never applicability", "not_applicable_is_unsupported": False},
    }
    return _finalize(root, body, namespace="applicability-policy", kind="conditional-applicability-authority-index-v1", id_field="index_id", digest_field="index_digest_sha256")


def _validate_finalized(root: Path, record: dict[str, Any], schema_path: Path, namespace: str, kind: str, id_field: str, digest_field: str) -> None:
    validate_instance(record, load_strict(root / schema_path), source=schema_path.as_posix())
    body = {key: value for key, value in record.items() if key not in {id_field, digest_field}}
    if record[digest_field] != _digest(body) or record[id_field] != _content_id(root, namespace, kind, body):
        fail("applicability-artifact-identity", schema_path.as_posix())


def verify_current(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    allocation = load_strict(root / ALLOCATION_PATH)
    validate_instance(allocation, load_strict(root / ALLOCATION_SCHEMA_PATH), source=ALLOCATION_PATH.as_posix())
    if allocation != build_allocation(): fail("applicability-allocation-drift", ALLOCATION_PATH.as_posix())
    contract = load_strict(root / CONTRACT_PATH)
    _validate_finalized(root, contract, CONTRACT_SCHEMA_PATH, "trust-policy-revision", "conditional-applicability-contract-v1", "contract_id", "contract_digest_sha256")
    if contract != build_contract(root): fail("applicability-contract-drift", CONTRACT_PATH.as_posix())
    fixture = load_strict(root / FIXTURE_PATH)
    if fixture != build_fixtures(root, contract): fail("applicability-fixture-drift", FIXTURE_PATH.as_posix())
    report = load_strict(root / REPORT_PATH)
    _validate_finalized(root, report, REPORT_SCHEMA_PATH, "trust-assessment", "conditional-applicability-report-v1", "report_id", "report_digest_sha256")
    if report != build_report(root, contract, fixture): fail("applicability-report-drift", REPORT_PATH.as_posix())
    authority = load_strict(root / AUTHORITY_PATH)
    _validate_finalized(root, authority, AUTHORITY_SCHEMA_PATH, "applicability-policy", "conditional-applicability-authority-index-v1", "index_id", "index_digest_sha256")
    if authority != build_authority(root, contract, fixture, report): fail("applicability-authority-drift", AUTHORITY_PATH.as_posix())
    if broad_foundations:
        identity_count = verify_identity_catalog(root)["scientific_identities"]
        derivation_groups = verify_derivation_catalog(root)["generated_assertion_groups"]
    else:
        identity_count = len(load_strict(root / "registries/identity/scientific-identities.v1.json")["bindings"])
        derivation_groups = load_strict(root / DERIVATION_CATALOG_PATH)["coverage_summary"]["assertion_groups"]
    return {"result": report["result"], "contract_id": contract["contract_id"], "report_id": report["report_id"], "conditional_requirements": 1972, "validated": report["coverage"]["conditional_requirements_validated"], "distinct_predicates": report["coverage"]["distinct_predicates"], "fixture_rejections": report["fixture_results"]["rejected"], "scientific_identities": identity_count, "derivation_groups": derivation_groups}


def _write(path: Path, value: dict[str, Any]) -> None:
    encoded = canonical_bytes(value) + b"\n"; path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded: fail("applicability-artifact-write", path.as_posix())


def materialize(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    _write(root / ALLOCATION_PATH, build_allocation())
    contract = build_contract(root); _write(root / CONTRACT_PATH, contract)
    fixture = build_fixtures(root, contract); _write(root / FIXTURE_PATH, fixture)
    report = build_report(root, contract, fixture); _write(root / REPORT_PATH, report)
    authority = build_authority(root, contract, fixture, report); _write(root / AUTHORITY_PATH, authority)
    return verify_current(root, broad_foundations=broad_foundations)
