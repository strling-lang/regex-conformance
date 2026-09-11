"""Deterministic observation-to-claim adjudication.

This module consumes, but never replaces, semantic requirements, applicability
evaluations, evidence-admissibility decisions, execution lineages, and immutable
observations.  Claims and reconciliation results are regenerable projections.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import date
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from typing import Any

from . import applicability as applicability_model
from .errors import ConformanceDataError, fail
from .evidence_admissibility import (
    evaluate_admissibility,
    finalize_evidence_record,
    finalize_expectation_basis,
    validate_evidence_record,
    validate_expectation_basis,
)
from .execution_provenance import lineage_set_sha256, validate_lineage_set
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .profile import IdentityProfile
from .schema import validate_instance


PUBLISHED_ON = "2026-09-11"
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a08ef7-2c40-7aa1-8b61-0d334a5b2451"
ADJUDICATION_DERIVATION_ID = "rcid:v1:assertion-derivation:u7:01a08ef7-2c40-7cc2-91f3-3debe5bd8732"

ALLOCATION_PATH = Path("adjudication/adjudication-identities-2026-09-11.v1.json")
CONTRACT_PATH = Path("adjudication/contracts/regex-conformance-adjudication-2026-09-11.v1.json")
FIXTURE_PATH = Path("tests/fixtures/adjudication/adjudication-cases.v1.json")
REPORT_PATH = Path("reports/adjudication/adjudication-acceptance-2026-09-11.v1.json")
AUTHORITY_PATH = Path("adjudication/current-authority.v1.json")

APPLICABILITY_CONTRACT_PATH = Path("applicability/contracts/regex-conformance-conditional-applicability-2026-09-10.v1.json")
EVIDENCE_CONTRACT_PATH = Path("oracle/contracts/regex-conformance-evidence-admissibility-2026-09-10.v1.json")
EVIDENCE_FIXTURE_PATH = Path("tests/fixtures/oracle/evidence-admissibility-cases.v1.json")
EXECUTION_LINEAGE_PATH = Path("tests/fixtures/provenance/execution-lineages.v1.json")
EXECUTION_POLICY_PATH = Path("registries/provenance/execution-provenance-policy.v1.json")
REQUIREMENT_PATH = Path("vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json")
CERTIFICATION_REPORT_PATH = Path("certification/reports/current-repository-2026-09-08.v2.json")
DENOMINATOR_GATE_PATH = Path("reports/semantics/true-obligation-denominator-acceptance-2026-09-10.v1.json")
DERIVATION_PATH = Path("registries/provenance/generated-assertion-derivations.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v3.json")
CONTENT_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")

SCHEMA_PATHS = {
    "allocation": Path("schemas/json/adjudication-allocation.schema.json"),
    "contract": Path("schemas/json/adjudication-contract.schema.json"),
    "coordinate": Path("schemas/json/coordinate-state.schema.json"),
    "expectation": Path("schemas/json/expected-outcome.schema.json"),
    "discrepancy": Path("schemas/json/discrepancy-revision.schema.json"),
    "waiver": Path("schemas/json/waiver-revision.schema.json"),
    "quarantine": Path("schemas/json/quarantine-revision.schema.json"),
    "claim": Path("schemas/json/claim-revision.schema.json"),
    "result": Path("schemas/json/adjudication-result.schema.json"),
    "fixtures": Path("schemas/json/adjudication-fixtures.schema.json"),
    "report": Path("schemas/json/adjudication-report.schema.json"),
    "authority": Path("schemas/json/adjudication-authority.schema.json"),
}

IMPLEMENTATION_PATHS = (
    Path("schemas/tooling/python/regex_conformance_schema/adjudication.py"),
    Path("tools/adjudication/compile_adjudication.py"),
    Path("tests/schema/test_adjudication.py"),
)

COORDINATE_STATES = {
    "not-applicable": "Positive applicability evidence establishes that the requirement does not engage this profile.",
    "applicability-unresolved": "Open-world applicability evidence does not decide whether the requirement engages.",
    "applicability-invalid": "The applicability input is malformed or invalid and no semantic judgment is possible.",
    "not-tested": "The requirement is applicable but no physical attempt exists.",
    "unobserved": "Execution was attempted but produced no admitted target-attributable observation.",
    "inconclusive": "Admitted observation exists but the oracle role or expected-outcome state permits no correctness judgment.",
    "satisfied": "Every admitted comparable observation agrees with the exact frozen expectation inside its epistemic scope.",
    "violated": "Every admitted comparable observation disagrees with the exact frozen expectation inside its epistemic scope.",
    "permitted-divergence": "Observed disagreement is inside a range positively established as permitted by admissible authority.",
    "conflicting-evidence": "Admitted observations for the same logical coordinate have incompatible terminal scientific results.",
    "conflicting-authority": "Independently preserved admissible authorities establish incompatible expectations with no selected winner.",
    "quarantined": "An active operational quarantine overlays, but does not replace, the scientific state.",
    "waived-for-gate": "An approved exact-scope waiver changes one gate effect but does not replace the scientific state.",
}

CLAIM_KINDS = (
    "normative-conformance",
    "normative-non-conformance",
    "implementation-documentation-conformance",
    "implementation-documentation-non-conformance",
    "formal-model-satisfaction",
    "formal-model-violation",
    "authoritative-data-agreement",
    "authoritative-data-disagreement",
    "metamorphic-relation-satisfaction",
    "metamorphic-relation-violation",
    "family-relative-equivalence",
    "family-relative-divergence",
    "historical-characterization",
    "characterization-only-finding",
    "permitted-divergence-finding",
)

DISCREPANCY_RELATIONS = (
    "specification-vs-implementation-documentation",
    "specification-expectation-vs-observation",
    "formal-derivation-vs-observation",
    "authoritative-data-vs-observation",
    "implementation-documentation-vs-implementation",
    "observation-vs-observation",
    "historical-vs-later-behavior",
    "specification-vs-formal-derivation",
)

DISCREPANCY_CLASSIFICATIONS = (
    "implementation-defect",
    "specification-defect",
    "specification-ambiguity",
    "documentation-defect",
    "vector-test-defect",
    "harness-defect",
    "environment-defect",
    "data-version-source-mismatch",
    "permitted-variation",
    "profile-dialect-difference",
    "historical-regression-change",
    "unresolved-conflict",
)

PERMITTED_STRENGTHS = {"permitted", "optional", "conditional", "implementation-defined"}
NONPERMISSION_STRENGTHS = {"unspecified", "ambiguous", "silent-not-established", "informative-non-normative"}
WAIVER_TYPES = ("SPEC", "VECTOR", "HARNESS", "ENVIRONMENT")
WAIVER_STATUSES = ("proposed", "approved", "expired", "revoked", "superseded")
QUARANTINE_STATUSES = ("active", "released", "superseded")
MUTABLE_ALIASES = {"latest", "current", "main", "master", "head", "tip"}
DIRECT_VERDICT_KEYS = {"pass", "fail", "verdict", "claim", "claim_state", "conformance", "conformance_verdict"}

_ADMISSION_CACHE: dict[tuple[str, str, tuple[tuple[str, str], ...]], dict[str, Any]] = {}
_LINEAGE_VALIDATION_CACHE: set[tuple[str, str]] = set()
_CONTRACT_VALIDATION_CACHE: set[tuple[str, str, tuple[str, ...]]] = set()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _content_id(root: Path, namespace: str, artifact_kind: str, body: dict[str, Any]) -> str:
    identity = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / CONTENT_PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": artifact_kind, "content_sha256": _digest(body)},
    )
    return str(identity["content_id"])


def _finalize(
    root: Path,
    body: dict[str, Any],
    *,
    namespace: str,
    artifact_kind: str,
    id_field: str,
    digest_field: str,
) -> dict[str, Any]:
    clean = {key: value for key, value in body.items() if key not in {id_field, digest_field}}
    return {
        **clean,
        id_field: _content_id(root, namespace, artifact_kind, clean),
        digest_field: _digest(clean),
    }


def _ref(path: Path, record: dict[str, Any], id_field: str, digest_field: str) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[4]
    relative = path.resolve().relative_to(root.resolve())
    return {
        "path": relative.as_posix(),
        "artifact_id": record[id_field],
        "digest_sha256": record[digest_field],
        "file_sha256": _sha(path),
    }


def build_allocation() -> dict[str, Any]:
    return {
        "schema_version": "adjudication-allocation.v1",
        "published_on": PUBLISHED_ON,
        "allocation_status": "reviewed-one-time-allocation",
        "allocations": [
            {
                "entity_class": "assertion-derivation",
                "canonical_key": "derivation.observation-to-claim-adjudication",
                "assigned_id": ADJUDICATION_DERIVATION_ID,
            },
            {
                "entity_class": "schema-family",
                "canonical_key": "schema.observation-to-claim-adjudication",
                "assigned_id": SCHEMA_FAMILY_ID,
            },
        ],
    }


@lru_cache(maxsize=4)
def _derivation_cached(root_text: str) -> dict[str, str]:
    root = Path(root_text)
    catalog = load_strict(root / DERIVATION_PATH)
    item = next(
        (entry for entry in catalog["derivations"] if entry["derivation_id"] == ADJUDICATION_DERIVATION_ID),
        None,
    )
    if item is None:
        from .derivation import DERIVATION_IDS, _derivation_specs, derivation_revision_id

        spec = next(entry for entry in _derivation_specs(root) if entry["key"] == "observation-to-claim-adjudication")
        item = {key: value for key, value in spec.items() if key != "key"}
        item["derivation_id"] = DERIVATION_IDS[spec["key"]]
        item["derivation_revision_id"] = derivation_revision_id(root, item)
    return {
        "derivation_id": item["derivation_id"],
        "derivation_revision_id": item["derivation_revision_id"],
        "derivation_class": item["derivation_class"],
    }


def _derivation(root: Path) -> dict[str, str]:
    return _derivation_cached(str(root.resolve()))


def build_contract(root: Path) -> dict[str, Any]:
    applicability = load_strict(root / APPLICABILITY_CONTRACT_PATH)
    evidence = load_strict(root / EVIDENCE_CONTRACT_PATH)
    execution = load_strict(root / EXECUTION_POLICY_PATH)
    requirement = load_strict(root / REQUIREMENT_PATH)
    body = {
        "schema_version": "adjudication-contract.v1",
        "published_on": PUBLISHED_ON,
        "contract_version": "1.0.0",
        "authority_model": {
            "inputs": [
                "semantic-requirement",
                "profile-revision",
                "applicability-evaluation",
                "oracle-evidence-basis",
                "expected-outcome",
                "logical-execution",
                "physical-attempts",
                "immutable-observations",
            ],
            "derived_products": ["comparison", "claim", "discrepancy", "gate-effect"],
            "claim_is_independent_truth_authority": False,
            "upstream_mutation_permitted": False,
        },
        "predecessor_contracts": {
            "applicability": {
                "path": APPLICABILITY_CONTRACT_PATH.as_posix(),
                "artifact_id": applicability["contract_id"],
                "digest_sha256": applicability["contract_digest_sha256"],
                "file_sha256": _sha(root / APPLICABILITY_CONTRACT_PATH),
            },
            "evidence_admissibility": {
                "path": EVIDENCE_CONTRACT_PATH.as_posix(),
                "artifact_id": evidence["contract_id"],
                "digest_sha256": evidence["contract_digest_sha256"],
                "file_sha256": _sha(root / EVIDENCE_CONTRACT_PATH),
            },
            "execution_provenance": {
                "path": EXECUTION_POLICY_PATH.as_posix(),
                "artifact_id": "rcid:v1:trust-policy-revision:h:jcs-sha256-v1:" + execution["policy_revision_sha256"],
                "digest_sha256": execution["policy_revision_sha256"],
                "file_sha256": _sha(root / EXECUTION_POLICY_PATH),
            },
            "semantic_requirements": {
                "path": REQUIREMENT_PATH.as_posix(),
                "artifact_id": requirement["snapshot_id"],
                "digest_sha256": requirement["snapshot_digest_sha256"],
                "file_sha256": _sha(root / REQUIREMENT_PATH),
            },
        },
        "coordinate_states": [
            {"state": state, "meaning": meaning} for state, meaning in COORDINATE_STATES.items()
        ],
        "state_dimensions": {
            "scientific_state_preserved_under_overlays": True,
            "operational_states": ["normal", "quarantined"],
            "gate_states": ["unaffected", "waived", "blocked-by-quarantine"],
            "non_equivalent_terms": [
                "not-tested",
                "unknown",
                "not-applicable",
                "unsupported",
                "inconclusive",
                "non-conformant",
                "waived",
            ],
        },
        "claim_kinds": list(CLAIM_KINDS),
        "discrepancy_relations": list(DISCREPANCY_RELATIONS),
        "discrepancy_classifications": list(DISCREPANCY_CLASSIFICATIONS),
        "permitted_divergence": {
            "positive_strengths": sorted(PERMITTED_STRENGTHS),
            "nonpermission_strengths": sorted(NONPERMISSION_STRENGTHS),
            "forbidden_inferences": [
                "majority-behavior",
                "implementation-popularity",
                "historical-stability",
                "repeated-observations",
                "specification-silence",
                "lack-of-prohibition",
                "approved-waiver",
            ],
        },
        "waivers": {
            "types": list(WAIVER_TYPES),
            "may_affect": ["certification-gating", "campaign-blocking", "quarantine", "acceptance-workflow"],
            "must_not_affect": ["applicability", "expectations", "observations", "discrepancy-existence", "scientific-result"],
        },
        "quarantine": {
            "operational_not_epistemic": True,
            "preserves_attempts_and_observations": True,
            "executable_when_safe": True,
        },
        "expected_outcomes": ["exact", "one-of", "conditional", "optional-alternatives", "permitted-set", "range", "relation"],
        "attempt_derivation": [
            "physical-attempts",
            "attempt-dispositions",
            "eligible-observation-set",
            "oracle-bound-comparison",
            "adjudicated-coordinate-and-claim",
        ],
        "circularity_guards": [
            "expectation-cannot-depend-on-observation",
            "expectation-cannot-depend-on-claim",
            "applicability-cannot-depend-on-observation",
            "applicability-cannot-depend-on-claim",
            "claim-cannot-be-its-own-authority",
            "dependency-graph-must-be-acyclic",
            "predecessor-evidence-graphs-remain-validated",
        ],
        "reason_code_required_on_every_path": True,
        "derivation": _derivation(root),
    }
    return _finalize(
        root,
        body,
        namespace="trust-policy-revision",
        artifact_kind="observation-to-claim-adjudication-contract-v1",
        id_field="contract_id",
        digest_field="contract_digest_sha256",
    )


def validate_contract(root: Path, contract: dict[str, Any]) -> None:
    body = {key: value for key, value in contract.items() if key not in {"contract_id", "contract_digest_sha256"}}
    if contract["contract_digest_sha256"] != _digest(body):
        fail("adjudication-contract-digest", "adjudication contract digest differs")
    if contract["contract_id"] != _content_id(root, "trust-policy-revision", "observation-to-claim-adjudication-contract-v1", body):
        fail("adjudication-contract-identity", "adjudication contract identity differs")
    predecessor_files = tuple(_sha(root / item["path"]) for item in contract["predecessor_contracts"].values())
    if predecessor_files != tuple(item["file_sha256"] for item in contract["predecessor_contracts"].values()):
        fail("adjudication-predecessor-drift", "a predecessor contract changed")
    cache_key = (str(root.resolve()), contract["contract_digest_sha256"], predecessor_files)
    if cache_key in _CONTRACT_VALIDATION_CACHE:
        return
    validate_instance(contract, load_strict(root / SCHEMA_PATHS["contract"]), source=CONTRACT_PATH.as_posix())
    if contract != build_contract(root):
        fail("adjudication-contract-drift", "tracked adjudication contract differs from current predecessors and implementation")
    _CONTRACT_VALIDATION_CACHE.add(cache_key)


@lru_cache(maxsize=4)
def _requirement_bindings_cached(root_text: str) -> dict[str, dict[str, Any]]:
    snapshot = load_strict(Path(root_text) / REQUIREMENT_PATH)
    return {
        item["scientific_id"]: {
            "requirement_id": item["scientific_id"],
            "requirement_digest_sha256": _digest(item),
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_digest_sha256": snapshot["snapshot_digest_sha256"],
        }
        for item in snapshot["requirements"]
    }


def _requirement_binding(root: Path, requirement_id: str) -> dict[str, Any]:
    binding = _requirement_bindings_cached(str(root.resolve())).get(requirement_id)
    if binding is None:
        fail("unknown-adjudication-requirement", requirement_id)
    return deepcopy(binding)


def finalize_expected_outcome(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    return _finalize(
        root,
        record,
        namespace="expectation-projection",
        artifact_kind="adjudication-expected-outcome-v1",
        id_field="expectation_id",
        digest_field="expectation_digest_sha256",
    )


def _validate_outcome_model(model: dict[str, Any], *, depth: int = 0) -> None:
    if depth > 8:
        fail("expected-outcome-depth", "expected outcome exceeds the bounded nesting depth")
    kind = model.get("kind")
    if kind == "exact":
        if set(model) != {"kind", "value"}:
            fail("expected-outcome-shape", "exact outcome requires only kind and value")
    elif kind in {"one-of", "optional-alternatives", "permitted-set"}:
        if set(model) != {"kind", "values"} or not model["values"]:
            fail("expected-outcome-shape", f"{kind} requires a non-empty values set")
        encoded = [canonical_bytes(item) for item in model["values"]]
        if encoded != sorted(set(encoded)):
            fail("expected-outcome-order", f"{kind} values must be unique and canonically ordered")
    elif kind == "range":
        if set(model) != {"kind", "field", "minimum", "maximum", "minimum_inclusive", "maximum_inclusive"}:
            fail("expected-outcome-shape", "range outcome has an invalid shape")
        if model["field"] not in {"semantic_result.value", "semantic_result.start", "semantic_result.end"}:
            fail("expected-outcome-field", "range may read only governed numeric result fields")
        if model["minimum"] > model["maximum"]:
            fail("expected-outcome-range", "range minimum exceeds maximum")
    elif kind == "relation":
        if set(model) != {"kind", "relation_id", "operator", "value"} or model["operator"] not in {"equals", "not-equals"}:
            fail("expected-outcome-shape", "relation outcome has an invalid shape")
    elif kind == "conditional":
        if set(model) != {"kind", "condition_contract_ref", "branches"} or not model["branches"]:
            fail("expected-outcome-shape", "conditional outcome has an invalid shape")
        if str(model["condition_contract_ref"].get("revision", "")).lower() in MUTABLE_ALIASES:
            fail("mutable-expectation-condition", "conditional outcomes require an exact governed condition contract")
        true_count = 0
        for branch in model["branches"]:
            if set(branch) != {"condition_id", "condition_result", "outcome"}:
                fail("expected-outcome-shape", "conditional branch has an invalid shape")
            if branch["condition_result"] == "true":
                true_count += 1
            if branch["condition_result"] not in {"true", "false", "unknown", "invalid"}:
                fail("expected-outcome-condition", "conditional result is outside strong-Kleene states")
            _validate_outcome_model(branch["outcome"], depth=depth + 1)
        if true_count > 1:
            fail("ambiguous-conditional-outcome", "more than one conditional expectation branch is true")
    else:
        fail("unknown-expected-outcome-kind", str(kind))


def validate_expected_outcome(
    root: Path,
    record: dict[str, Any],
    basis: dict[str, Any],
    requirement: dict[str, Any],
    profile: dict[str, str],
) -> None:
    validate_instance(record, load_strict(root / SCHEMA_PATHS["expectation"]), source="expected outcome")
    body = {key: value for key, value in record.items() if key not in {"expectation_id", "expectation_digest_sha256"}}
    if record["expectation_digest_sha256"] != _digest(body) or record["expectation_id"] != _content_id(root, "expectation-projection", "adjudication-expected-outcome-v1", body):
        fail("expected-outcome-identity", "expected outcome identity or digest differs")
    if record["requirement"] != requirement or record["profile"] != profile:
        fail("expected-outcome-coordinate", "expected outcome binds another requirement or profile revision")
    expected_ref = {"basis_id": basis["basis_id"], "basis_digest_sha256": basis["basis_digest_sha256"]}
    if record["basis_ref"] != expected_ref:
        fail("historical-expectation-rewrite", "expected outcome does not bind the campaign-frozen basis")
    if record["oracle_class"] == "O8" and record["outcome_model"] is not None:
        fail("o8-normative-escalation", "O8 characterization cannot carry a correctness expectation")
    if record["oracle_class"] == "O5" and not basis["scope"]["profile_family_ids"]:
        fail("o5-universalization", "O5 requires an exact family-relative scope")
    if record["outcome_model"] is not None:
        _validate_outcome_model(record["outcome_model"])


def _actual_value(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "outcome_class": observation["outcome_class"],
        "semantic_result": observation["semantic_result"],
    }


def compare_expected_outcome(model: dict[str, Any], observation: dict[str, Any]) -> tuple[str, str]:
    actual = _actual_value(observation)
    kind = model["kind"]
    if kind == "exact":
        return ("agreement", "exact-outcome-agreement") if canonical_bytes(actual) == canonical_bytes(model["value"]) else ("disagreement", "exact-outcome-disagreement")
    if kind in {"one-of", "optional-alternatives", "permitted-set"}:
        state = "agreement" if canonical_bytes(actual) in {canonical_bytes(item) for item in model["values"]} else "disagreement"
        return state, f"{kind}-{state}"
    if kind == "range":
        value: Any = observation
        for part in model["field"].split("."):
            if not isinstance(value, dict) or part not in value:
                return "not-comparable", "range-field-missing"
            value = value[part]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return "not-comparable", "range-field-not-numeric"
        lower = value >= model["minimum"] if model["minimum_inclusive"] else value > model["minimum"]
        upper = value <= model["maximum"] if model["maximum_inclusive"] else value < model["maximum"]
        state = "agreement" if lower and upper else "disagreement"
        return state, f"range-{state}"
    if kind == "relation":
        equal = canonical_bytes(actual) == canonical_bytes(model["value"])
        agrees = equal if model["operator"] == "equals" else not equal
        state = "agreement" if agrees else "disagreement"
        return state, f"relation-{state}"
    if kind == "conditional":
        true_branches = [branch for branch in model["branches"] if branch["condition_result"] == "true"]
        if len(true_branches) != 1:
            reason = "conditional-outcome-invalid" if any(branch["condition_result"] == "invalid" for branch in model["branches"]) else "conditional-outcome-unresolved"
            return "not-comparable", reason
        return compare_expected_outcome(true_branches[0]["outcome"], observation)
    fail("unknown-expected-outcome-kind", str(kind))


def _finalize_revision(root: Path, record: dict[str, Any], kind: str) -> dict[str, Any]:
    return _finalize(root, record, namespace="finding-revision", artifact_kind=kind, id_field="revision_id", digest_field="revision_digest_sha256")


def finalize_discrepancy(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    return _finalize_revision(root, record, "adjudication-discrepancy-revision-v1")


def finalize_waiver(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    return _finalize_revision(root, record, "adjudication-waiver-revision-v1")


def finalize_quarantine(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    return _finalize_revision(root, record, "adjudication-quarantine-revision-v1")


def finalize_claim(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    return _finalize_revision(root, record, "adjudication-claim-revision-v1")


def _validate_revision_identity(root: Path, record: dict[str, Any], kind: str, code: str) -> None:
    body = {key: value for key, value in record.items() if key not in {"revision_id", "revision_digest_sha256"}}
    if record["revision_digest_sha256"] != _digest(body) or record["revision_id"] != _content_id(root, "finding-revision", kind, body):
        fail(code, f"{kind} identity or digest differs")


def validate_discrepancy(root: Path, record: dict[str, Any], predecessors: list[dict[str, Any]] | None = None) -> None:
    validate_instance(record, load_strict(root / SCHEMA_PATHS["discrepancy"]), source="discrepancy revision")
    _validate_revision_identity(root, record, "adjudication-discrepancy-revision-v1", "discrepancy-revision-identity")
    if record["relationship"] not in DISCREPANCY_RELATIONS or record["classification"] not in DISCREPANCY_CLASSIFICATIONS:
        fail("unknown-discrepancy-vocabulary", record["relationship"])
    claimant_digest = _digest(record["claimants"])
    if record["claimants_digest_sha256"] != claimant_digest:
        fail("discrepancy-claimant-rewrite", "claimant commitment differs from preserved claimant records")
    if record["resolution_method"] in {"majority-vote", "implementation-popularity", "delete-claimant"}:
        fail("majority-cannot-resolve-discrepancy", "consensus or deletion cannot resolve preserved disagreement")
    history = {item["revision_id"]: item for item in predecessors or []}
    predecessor_id = record["supersedes_revision_id"]
    if predecessor_id is not None:
        predecessor = history.get(predecessor_id)
        if predecessor is None:
            fail("missing-discrepancy-predecessor", predecessor_id)
        if predecessor["discrepancy_id"] != record["discrepancy_id"] or predecessor["claimants_digest_sha256"] != record["claimants_digest_sha256"]:
            fail("discrepancy-history-rewrite", "a discrepancy revision cannot replace its identity or historical claimants")
    divergence = record["permitted_divergence"]
    if divergence is not None:
        strength = divergence["normative_strength"]
        if strength not in PERMITTED_STRENGTHS or strength in NONPERMISSION_STRENGTHS or not divergence["positively_established"]:
            fail("permitted-divergence-not-established", "divergence requires positive admissible authority")
        if divergence["basis_kind"] in {"majority-behavior", "historical-stability", "repeated-observations", "waiver", "silence"}:
            fail("permitted-divergence-forbidden-inference", divergence["basis_kind"])
        _validate_outcome_model(divergence["allowed_outcomes"])


def validate_waiver(root: Path, record: dict[str, Any], predecessors: list[dict[str, Any]] | None = None) -> None:
    validate_instance(record, load_strict(root / SCHEMA_PATHS["waiver"]), source="waiver revision")
    _validate_revision_identity(root, record, "adjudication-waiver-revision-v1", "waiver-revision-identity")
    if record["waiver_type"] not in WAIVER_TYPES or record["status"] not in WAIVER_STATUSES:
        fail("unknown-waiver-vocabulary", record["waiver_type"])
    boundary = record["scientific_boundary"]
    if boundary != {
        "alters_applicability": False,
        "alters_expectation": False,
        "alters_observation": False,
        "alters_discrepancy_existence": False,
        "alters_scientific_result": False,
    }:
        fail("waiver-rewrites-scientific-truth", "waiver scientific boundary must be entirely non-mutating")
    history = {item["revision_id"]: item for item in predecessors or []}
    if record["supersedes_revision_id"] is not None:
        predecessor = history.get(record["supersedes_revision_id"])
        if predecessor is None or predecessor["waiver_id"] != record["waiver_id"]:
            fail("waiver-lineage", "waiver supersession must retain stable identity")


def validate_quarantine(root: Path, record: dict[str, Any], predecessors: list[dict[str, Any]] | None = None) -> None:
    validate_instance(record, load_strict(root / SCHEMA_PATHS["quarantine"]), source="quarantine revision")
    _validate_revision_identity(root, record, "adjudication-quarantine-revision-v1", "quarantine-revision-identity")
    if record["status"] not in QUARANTINE_STATUSES:
        fail("unknown-quarantine-status", record["status"])
    if not record["preserves_attempts"] or not record["preserves_observations"] or record["evidence_of_conformance"]:
        fail("quarantine-erases-evidence", "quarantine must preserve evidence and has no conformance authority")
    history = {item["revision_id"]: item for item in predecessors or []}
    if record["supersedes_revision_id"] is not None:
        predecessor = history.get(record["supersedes_revision_id"])
        if predecessor is None or predecessor["quarantine_id"] != record["quarantine_id"]:
            fail("quarantine-lineage", "quarantine supersession must retain stable identity")


def _selector_matches(selector: dict[str, Any], request: dict[str, Any], gate: str) -> bool:
    coordinate_id = request["applicability"]["evaluation_id"]
    requirement_id = request["requirement"]["requirement_id"]
    profile_id = request["profile"]["profile_id"]
    return (
        (not selector["coordinate_ids"] or coordinate_id in selector["coordinate_ids"])
        and (not selector["requirement_ids"] or requirement_id in selector["requirement_ids"])
        and (not selector["profile_ids"] or profile_id in selector["profile_ids"])
        and (not selector["gate_ids"] or gate in selector["gate_ids"])
    )


def _contains_direct_verdict(value: Any) -> bool:
    if isinstance(value, dict):
        if any(str(key).lower() in DIRECT_VERDICT_KEYS for key in value):
            return True
        return any(_contains_direct_verdict(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_direct_verdict(item) for item in value)
    return False


def validate_dependency_graph(graph: dict[str, Any], claim_id: str | None = None) -> None:
    nodes = graph["nodes"]
    by_id = {node["node_id"]: node for node in nodes}
    if len(by_id) != len(nodes):
        fail("adjudication-duplicate-dependency", "dependency node IDs must be unique")
    for node in nodes:
        if len(node["upstream_node_ids"]) != len(set(node["upstream_node_ids"])) or any(item not in by_id for item in node["upstream_node_ids"]):
            fail("adjudication-dangling-dependency", node["node_id"])
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            fail("claim-evidence-circularity", identifier)
        if identifier in visited:
            return
        visiting.add(identifier)
        for upstream in by_id[identifier]["upstream_node_ids"]:
            visit(upstream)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in by_id:
        visit(identifier)

    reachable_cache: dict[str, set[str]] = {}

    def reachable_kinds(identifier: str) -> set[str]:
        if identifier in reachable_cache:
            return reachable_cache[identifier]
        result = {by_id[identifier]["kind"]}
        for upstream in by_id[identifier]["upstream_node_ids"]:
            result.update(reachable_kinds(upstream))
        reachable_cache[identifier] = result
        return result

    for node in nodes:
        kinds = set().union(*(reachable_kinds(item) for item in node["upstream_node_ids"])) if node["upstream_node_ids"] else set()
        if node["kind"] in {"expectation", "expectation-basis"} and kinds.intersection({"observation", "physical-attempt", "logical-execution", "claim", "target-output"}):
            fail("expectation-authority-laundering", node["node_id"])
        if node["kind"] == "applicability" and kinds.intersection({"observation", "claim", "target-output"}):
            fail("applicability-authority-laundering", node["node_id"])
    if claim_id is not None:
        claim_nodes = [node for node in nodes if node["kind"] == "claim"]
        if len(claim_nodes) != 1 or claim_nodes[0]["node_id"] != claim_id:
            fail("claim-authority-node", "claim graph must contain exactly its own derived claim node")
        for node in nodes:
            if node["kind"] != "claim" and claim_id in node["upstream_node_ids"]:
                fail("claim-used-as-authority", node["node_id"])


def _validate_applicability(root: Path, request: dict[str, Any], applicability_contract: dict[str, Any]) -> None:
    result = request["applicability"]
    validate_instance(result, load_strict(root / applicability_model.RESULT_SCHEMA_PATH), source="adjudication applicability")
    expected_contract = {"artifact_id": applicability_contract["contract_id"], "digest_sha256": applicability_contract["contract_digest_sha256"]}
    if result["contract"] != expected_contract:
        fail("adjudication-applicability-contract", "applicability result does not bind the exact predecessor contract")
    if result["requirement"]["artifact_id"] != request["requirement"]["requirement_id"] or result["requirement"]["digest_sha256"] != request["requirement"]["requirement_digest_sha256"]:
        fail("adjudication-applicability-requirement", "applicability result binds another requirement")
    if result["profile"] != request["profile"]:
        fail("adjudication-applicability-profile", "applicability result binds another profile revision")
    expected_truth = {"applicable": "true", "not-applicable": "false", "unresolved": "unknown", "invalid": "invalid"}[result["result"]]
    if result["truth_value"] != expected_truth:
        fail("adjudication-applicability-state", "applicability result and truth value disagree")


def _observation_admissions(lineage: dict[str, Any], request: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations = lineage["observations"]
    by_id = {item["observation_id"]: item for item in observations}
    admissions = {item["observation_id"]: item for item in request["observation_admissions"]}
    if set(admissions) != set(by_id):
        fail("observation-admission-coverage", "every preserved observation requires exactly one admission decision")
    admitted: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for identifier, observation in by_id.items():
        admission = admissions[identifier]
        if admission["observation_content_id"] != observation["observation_content_id"]:
            fail("observation-admission-binding", identifier)
        body = {key: value for key, value in admission.items() if key != "decision_digest_sha256"}
        if admission["decision_digest_sha256"] != _digest(body):
            fail("observation-admission-digest", identifier)
        if admission["decision"] == "admitted" and admission["integrity_status"] == "verified" and admission["preservation_status"] == "immutable-complete":
            admitted.append(observation)
        else:
            excluded.append(observation)
    return admitted, excluded


def _claim_kind(oracle_class: str, scientific_state: str) -> str:
    disagree = scientific_state in {"violated", "conflicting-evidence"}
    return {
        "O1": "normative-non-conformance" if disagree else "normative-conformance",
        "O2": "formal-model-violation" if disagree else "formal-model-satisfaction",
        "O3": "authoritative-data-disagreement" if disagree else "authoritative-data-agreement",
        "O4": "metamorphic-relation-violation" if disagree else "metamorphic-relation-satisfaction",
        "O5": "family-relative-divergence" if disagree else "family-relative-equivalence",
        "O6": "implementation-documentation-non-conformance" if disagree else "implementation-documentation-conformance",
        "O7": "historical-characterization",
        "O8": "characterization-only-finding",
    }[oracle_class]


def _permitted_by(discrepancy: dict[str, Any], observations: list[dict[str, Any]]) -> bool:
    divergence = discrepancy["permitted_divergence"]
    if divergence is None:
        return False
    return all(compare_expected_outcome(divergence["allowed_outcomes"], observation)[0] == "agreement" for observation in observations)


def _build_dependency_graph(
    request: dict[str, Any],
    claim_id: str | None,
    expectation_details: list[dict[str, Any]],
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}

    def add(identifier: str, kind: str, upstream: list[str]) -> None:
        candidate = {"node_id": identifier, "kind": kind, "upstream_node_ids": sorted(set(upstream))}
        prior = by_id.get(identifier)
        if prior is not None and prior != candidate:
            fail("adjudication-dependency-identity-collision", identifier)
        if prior is None:
            by_id[identifier] = candidate
            nodes.append(candidate)

    requirement_id = request["requirement"]["requirement_id"]
    profile_revision_id = request["profile"]["profile_revision_id"]
    applicability = request["applicability"]
    applicability_id = applicability["evaluation_id"]
    applicability_contract_id = applicability["contract"]["artifact_id"]
    predicate_id = applicability["predicate"]["artifact_id"]
    capability_snapshot_id = applicability["capability_snapshot"]["artifact_id"]
    add(requirement_id, "requirement", [])
    add(profile_revision_id, "profile", [])
    add(applicability_contract_id, "applicability-contract", [])
    add(predicate_id, "applicability-predicate", [])
    add(capability_snapshot_id, "capability-snapshot", [])
    fact_ids = [item["fact_id"] for item in applicability["facts_read"]]
    for fact_id in fact_ids:
        add(fact_id, "profile-fact", [])
    add(
        applicability_id,
        "applicability",
        [profile_revision_id, requirement_id, applicability_contract_id, predicate_id, capability_snapshot_id, *fact_ids],
    )
    claim_upstream = [applicability_id]
    for item, detail in zip(request["expectations"], expectation_details, strict=True):
        basis = item["basis"]
        evidence_ids: list[str] = []
        for evidence in detail["records"]:
            evidence_id = evidence["evidence_id"]
            evidence_ids.append(evidence_id)
            graph = evidence["dependency_graph"]
            for dependency in graph["nodes"]:
                add(dependency["dependency_id"], "evidence-dependency", dependency["upstream_dependency_ids"])
            oracle_id = evidence["oracle_ref"]["oracle_id"]
            evidence_contract_id = evidence["contract_ref"]["contract_id"]
            oracle_contract_id = evidence["oracle_contract_ref"]["contract_id"]
            add(evidence_contract_id, "evidence-contract", [])
            add(oracle_contract_id, "oracle-contract", [])
            add(oracle_id, "oracle", graph["root_dependency_ids"])
            add(evidence_id, "evidence", [evidence_contract_id, oracle_contract_id, oracle_id])
        add(basis["basis_id"], "expectation-basis", evidence_ids)
        add(item["expected_outcome"]["expectation_id"], "expectation", [basis["basis_id"]])
        claim_upstream.append(item["expected_outcome"]["expectation_id"])
    lineage_set = request["execution_lineage_set"]
    if lineage_set is not None:
        selected = next(item for item in lineage_set["lineages"] if item["logical_execution_id"] == request["logical_execution_id"])
        logical_id = selected["logical_execution_id"]
        add(logical_id, "logical-execution", [])
        for attempt in selected["attempts"]:
            add(attempt["physical_run_id"], "physical-attempt", [logical_id])
        for observation in selected["observations"]:
            add(observation["observation_id"], "observation", [observation["terminal_attempt_id"]])
            claim_upstream.append(observation["observation_id"])
    for discrepancy in request["discrepancies"]:
        add(discrepancy["revision_id"], "discrepancy", [])
        claim_upstream.append(discrepancy["revision_id"])
    for waiver in request["waivers"]:
        add(waiver["revision_id"], "waiver", [])
        claim_upstream.append(waiver["revision_id"])
    for quarantine in request["quarantines"]:
        add(quarantine["revision_id"], "quarantine", [])
        claim_upstream.append(quarantine["revision_id"])
    if claim_id is not None:
        add(claim_id, "claim", claim_upstream)
    return {"nodes": sorted(nodes, key=lambda item: item["node_id"])}


def validate_claim(root: Path, claim: dict[str, Any]) -> None:
    validate_instance(claim, load_strict(root / SCHEMA_PATHS["claim"]), source="claim revision")
    _validate_revision_identity(root, claim, "adjudication-claim-revision-v1", "claim-revision-identity")
    if claim["epistemic_kind"] not in CLAIM_KINDS:
        fail("unknown-claim-kind", claim["epistemic_kind"])
    if claim["derived_product"] is not True or claim["independent_truth_authority"] is not False:
        fail("claim-authority-escalation", "claims must remain regenerable derived products")
    if claim["waiver_effect"]["alters_scientific_result"] or claim["quarantine_effect"]["alters_scientific_result"]:
        fail("claim-overlay-rewrites-science", "waiver and quarantine cannot alter scientific result")
    validate_dependency_graph(claim["dependency_graph"], claim["claim_id"])


def adjudicate(root: Path, contract: dict[str, Any], request: dict[str, Any], evidence_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Adjudicate one exact coordinate and emit an immutable-input trace."""

    validate_contract(root, contract)
    if "scientific_override" in request:
        fail("scientific-result-override", "callers cannot inject a scientific result")
    if request.get("include_inadmissible_observations"):
        fail("inadmissible-evidence-influence", "inadmissible observations cannot enter comparison")
    requirement = _requirement_binding(root, request["requirement"]["requirement_id"])
    if request["requirement"] != requirement:
        fail("adjudication-requirement-revision", "requirement binding is stale or incomplete")
    applicability_contract = load_strict(root / APPLICABILITY_CONTRACT_PATH)
    evidence_contract = load_strict(root / EVIDENCE_CONTRACT_PATH)
    _validate_applicability(root, request, applicability_contract)

    evidence_by_id = {item["evidence_id"]: item for item in evidence_records}
    if len(evidence_by_id) != len(evidence_records):
        fail("duplicate-adjudication-evidence", "evidence record identities must be unique")
    expectation_details: list[dict[str, Any]] = []
    campaign_bindings = {(item["basis_id"], item["basis_digest_sha256"]) for item in request["campaign_expectation_bindings"]}
    for item in request["expectations"]:
        basis = item["basis"]
        basis_body = {key: value for key, value in basis.items() if key not in {"basis_id", "basis_digest_sha256"}}
        if basis["basis_digest_sha256"] != _digest(basis_body):
            fail("expectation-basis-identity", "expectation basis digest differs")
        if (basis["basis_id"], basis["basis_digest_sha256"]) not in campaign_bindings:
            fail("historical-expectation-rewrite", "adjudication basis differs from the immutable campaign binding")
        outcome = item["expected_outcome"]
        validate_expected_outcome(root, outcome, basis, requirement, request["profile"])
        selected_records = [evidence_by_id[ref["evidence_id"]] for ref in basis["evidence_refs"]]
        request_record = {
            "schema_version": "evidence-admissibility-request.v1",
            "evidence_refs": basis["evidence_refs"],
            "epistemic_use": basis["epistemic_use"],
            "requested_conclusion": basis["conclusion"],
            "scope": {"requirement_scientific_ids": [basis["semantic_requirement_id"]], **basis["scope"]},
            "oracle_class": outcome["oracle_class"],
            "require_independent_authorities": False,
            "minimum_authority_domains": 1,
        }
        evidence_key = tuple(sorted((record["evidence_id"], record["evidence_digest_sha256"]) for record in selected_records))
        for record in selected_records:
            record_body = {key: value for key, value in record.items() if key not in {"evidence_id", "evidence_digest_sha256"}}
            if record["evidence_digest_sha256"] != _digest(record_body):
                fail("evidence-record-digest", record["evidence_id"])
        cache_key = (str(root.resolve()), basis["basis_digest_sha256"], evidence_key)
        admission = _ADMISSION_CACHE.get(cache_key)
        if admission is None:
            validate_expectation_basis(root, evidence_contract, evidence_records, basis)
            admission = evaluate_admissibility(root, evidence_contract, selected_records, request_record)
            _ADMISSION_CACHE[cache_key] = deepcopy(admission)
        else:
            admission = deepcopy(admission)
        expectation_details.append({"basis": basis, "outcome": outcome, "admission": admission, "records": selected_records})

    lineage = None
    admitted_observations: list[dict[str, Any]] = []
    excluded_observations: list[dict[str, Any]] = []
    if request["execution_lineage_set"] is not None:
        for candidate in request["execution_lineage_set"]["lineages"]:
            for observation in candidate["observations"]:
                if _contains_direct_verdict(observation["semantic_result"]):
                    fail("observation-direct-verdict", "observation payload cannot write PASS, FAIL, or a claim")
        lineage_key = (str(root.resolve()), request["execution_lineage_set"]["lineage_set_sha256"])
        if request["execution_lineage_set"]["lineage_set_sha256"] != lineage_set_sha256(request["execution_lineage_set"]):
            fail("lineage-set-digest-mismatch", "lineage set digest differs")
        if lineage_key not in _LINEAGE_VALIDATION_CACHE:
            validate_lineage_set(root, request["execution_lineage_set"])
            _LINEAGE_VALIDATION_CACHE.add(lineage_key)
        lineage = next((item for item in request["execution_lineage_set"]["lineages"] if item["logical_execution_id"] == request["logical_execution_id"]), None)
        if lineage is None:
            fail("missing-logical-execution", request["logical_execution_id"])
        admitted_observations, excluded_observations = _observation_admissions(lineage, request)
    elif request["logical_execution_id"] is not None or request["observation_admissions"]:
        fail("execution-lineage-binding", "execution identity and admissions require an immutable lineage set")

    discrepancy_history = request.get("discrepancy_history", [])
    for predecessor in discrepancy_history:
        validate_discrepancy(root, predecessor)
    for discrepancy in request["discrepancies"]:
        validate_discrepancy(root, discrepancy, discrepancy_history)
    waiver_history = request.get("waiver_history", [])
    for predecessor in waiver_history:
        validate_waiver(root, predecessor)
    for waiver in request["waivers"]:
        validate_waiver(root, waiver, waiver_history)
    quarantine_history = request.get("quarantine_history", [])
    for predecessor in quarantine_history:
        validate_quarantine(root, predecessor)
    for quarantine in request["quarantines"]:
        validate_quarantine(root, quarantine, quarantine_history)

    trace: list[dict[str, Any]] = []
    app_state = request["applicability"]["result"]
    if app_state == "not-applicable":
        scientific_state = "not-applicable"
        reason = "applicability-negated"
    elif app_state == "unresolved":
        scientific_state = "applicability-unresolved"
        reason = "applicability-open-world-unresolved"
    elif app_state == "invalid":
        scientific_state = "applicability-invalid"
        reason = "applicability-input-invalid"
    elif lineage is None:
        scientific_state = "not-tested"
        reason = "applicable-without-attempt"
    elif not admitted_observations:
        scientific_state = "unobserved"
        reason = "attempted-without-admitted-observation"
    else:
        models = [item["outcome"]["outcome_model"] for item in expectation_details]
        concrete_models = [model for model in models if model is not None]
        if len({canonical_bytes(model) for model in concrete_models}) > 1:
            scientific_state = "conflicting-authority"
            reason = "incompatible-admissible-expectations"
        elif not concrete_models:
            scientific_state = "inconclusive"
            reason = "oracle-role-permits-characterization-only"
        else:
            comparisons = [compare_expected_outcome(concrete_models[0], observation) for observation in admitted_observations]
            comparison_states = {item[0] for item in comparisons}
            signatures = {canonical_bytes(_actual_value(observation)) for observation in admitted_observations}
            if len(signatures) > 1 or len(comparison_states) > 1:
                scientific_state = "conflicting-evidence"
                reason = "admitted-observations-conflict"
            elif comparison_states == {"not-comparable"}:
                scientific_state = "inconclusive"
                reason = comparisons[0][1]
            elif comparison_states == {"agreement"}:
                scientific_state = "satisfied"
                reason = comparisons[0][1]
            else:
                applicable_discrepancies = [item for item in request["discrepancies"] if _permitted_by(item, admitted_observations)]
                if applicable_discrepancies:
                    scientific_state = "permitted-divergence"
                    reason = "positive-authority-permits-observed-divergence"
                else:
                    scientific_state = "violated"
                    reason = comparisons[0][1]
    trace.append({"stage": "applicability-and-evidence", "reason_code": reason, "result": scientific_state})

    discrepancy_exists = bool(request["discrepancies"]) or scientific_state in {"violated", "conflicting-evidence", "conflicting-authority", "permitted-divergence"}
    discrepancy_complete = not discrepancy_exists or bool(request["discrepancies"])
    today = date.fromisoformat(request["adjudicated_on"])
    gate = request["gate_id"]
    active_waivers = [
        item for item in request["waivers"]
        if item["status"] == "approved"
        and date.fromisoformat(item["created_on"]) <= today <= date.fromisoformat(item["review_or_expiry_on"])
        and _selector_matches(item["selector"], request, gate)
    ]
    active_quarantines = [
        item for item in request["quarantines"]
        if item["status"] == "active"
        and today <= date.fromisoformat(item["review_on"])
        and _selector_matches(item["selector"], request, gate)
    ]
    gate_state = "waived" if active_waivers else ("blocked-by-quarantine" if active_quarantines else "unaffected")
    operational_state = "quarantined" if active_quarantines else "normal"
    coordinate_state = "quarantined" if active_quarantines else ("waived-for-gate" if active_waivers else scientific_state)
    trace.append({"stage": "operational-and-gate-overlays", "reason_code": "overlay-preserves-scientific-state", "result": coordinate_state})

    claimable = scientific_state in {"satisfied", "violated", "permitted-divergence", "conflicting-evidence", "conflicting-authority", "inconclusive"}
    if discrepancy_exists and not discrepancy_complete:
        claimable = False
        trace.append({"stage": "claim-eligibility", "reason_code": "missing-discrepancy-record", "result": "no-claim"})
    claim = None
    claim_id = request["claim_id"] if claimable else None
    dependency_graph = _build_dependency_graph(request, claim_id, expectation_details)
    validate_dependency_graph(dependency_graph, claim_id)
    if claimable:
        oracle_class = expectation_details[0]["outcome"]["oracle_class"] if expectation_details else "O8"
        kind = (
            "characterization-only-finding"
            if scientific_state in {"conflicting-authority", "conflicting-evidence"}
            else ("permitted-divergence-finding" if scientific_state == "permitted-divergence" else _claim_kind(oracle_class, scientific_state))
        )
        claim_body = {
            "schema_version": "claim-revision.v1",
            "claim_id": claim_id,
            "revision_number": request["claim_revision_number"],
            "supersedes_revision_id": request["supersedes_claim_revision_id"],
            "epistemic_kind": kind,
            "polarity": "agreement" if scientific_state == "satisfied" else ("disagreement" if scientific_state in {"violated", "permitted-divergence"} else ("conflict" if scientific_state.startswith("conflicting") else "characterization")),
            "scientific_result_state": scientific_state,
            "coordinate_state": coordinate_state,
            "requirement": requirement,
            "profile": request["profile"],
            "applicability": {"evaluation_id": request["applicability"]["evaluation_id"], "evaluation_digest_sha256": request["applicability"]["evaluation_digest_sha256"]},
            "oracle_evidence_bases": [
                {"basis_id": item["basis"]["basis_id"], "basis_digest_sha256": item["basis"]["basis_digest_sha256"], "oracle_class": item["outcome"]["oracle_class"]}
                for item in expectation_details
            ],
            "evidence_admissions": [
                {
                    "basis_id": item["basis"]["basis_id"],
                    "decision": item["admission"]["decision"],
                    "evidence_ids": item["admission"]["evidence_ids"],
                    "epistemic_use": item["admission"]["epistemic_use"],
                    "requested_conclusion": item["admission"]["requested_conclusion"],
                    "decision_digest_sha256": _digest(item["admission"]),
                }
                for item in expectation_details
            ],
            "expectations": [
                {"expectation_id": item["outcome"]["expectation_id"], "expectation_digest_sha256": item["outcome"]["expectation_digest_sha256"]}
                for item in expectation_details
            ],
            "logical_execution_id": request["logical_execution_id"],
            "physical_attempt_ids": [] if lineage is None else [item["physical_run_id"] for item in lineage["attempts"]],
            "admitted_observations": [
                {"observation_id": item["observation_id"], "observation_content_id": item["observation_content_id"]}
                for item in admitted_observations
            ],
            "excluded_observations": [
                {"observation_id": item["observation_id"], "observation_content_id": item["observation_content_id"]}
                for item in excluded_observations
            ],
            "adjudication_contract": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
            "discrepancy_revisions": [
                {"discrepancy_id": item["discrepancy_id"], "revision_id": item["revision_id"], "revision_digest_sha256": item["revision_digest_sha256"], "state": item["adjudication_state"]}
                for item in request["discrepancies"]
            ],
            "waiver_effect": {
                "waiver_revision_ids": [item["revision_id"] for item in active_waivers],
                "gate_id": gate,
                "gate_effect": gate_state,
                "alters_scientific_result": False,
            },
            "quarantine_effect": {
                "quarantine_revision_ids": [item["revision_id"] for item in active_quarantines],
                "operational_state": operational_state,
                "alters_scientific_result": False,
            },
            "dependency_graph": dependency_graph,
            "derivation": _derivation(root),
            "derived_product": True,
            "independent_truth_authority": False,
            "adjudicated_on": request["adjudicated_on"],
        }
        claim = finalize_claim(root, claim_body)
        validate_claim(root, claim)
        trace.append({"stage": "claim-derivation", "reason_code": "epistemic-claim-derived", "result": kind})
    elif not any(item["stage"] == "claim-eligibility" for item in trace):
        trace.append({"stage": "claim-eligibility", "reason_code": "no-epistemic-claim-permitted", "result": "no-claim"})

    coordinate = {
        "schema_version": "coordinate-state.v1",
        "coordinate_id": request["applicability"]["evaluation_id"],
        "scientific_state": scientific_state,
        "coordinate_state": coordinate_state,
        "operational_state": operational_state,
        "gate_state": gate_state,
        "gate_id": gate,
        "reason_codes": sorted({item["reason_code"] for item in trace}),
        "derivation_inputs": {
            "requirement_id": requirement["requirement_id"],
            "profile_revision_id": request["profile"]["profile_revision_id"],
            "applicability_evaluation_id": request["applicability"]["evaluation_id"],
            "expectation_ids": [item["outcome"]["expectation_id"] for item in expectation_details],
            "logical_execution_id": request["logical_execution_id"],
            "observation_ids": [] if lineage is None else [item["observation_id"] for item in lineage["observations"]],
            "admitted_observation_ids": [item["observation_id"] for item in admitted_observations],
            "discrepancy_revision_ids": [item["revision_id"] for item in request["discrepancies"]],
            "waiver_revision_ids": [item["revision_id"] for item in active_waivers],
            "quarantine_revision_ids": [item["revision_id"] for item in active_quarantines],
        },
    }
    validate_instance(coordinate, load_strict(root / SCHEMA_PATHS["coordinate"]), source="coordinate state")
    answers = {
        "requirement_applies": app_state,
        "admissible_expectation_available": bool(expectation_details),
        "admissible_observation_available": bool(admitted_observations),
        "permitted_epistemic_claim_type": None if claim is None else claim["epistemic_kind"],
        "comparison": "not-performed" if scientific_state in {"not-applicable", "applicability-unresolved", "applicability-invalid", "not-tested", "unobserved", "inconclusive"} else ("conflict" if scientific_state.startswith("conflicting") else ("agreement" if scientific_state == "satisfied" else "disagreement")),
        "discrepancy_exists": discrepancy_exists,
        "permitted_divergence_established": scientific_state == "permitted-divergence",
        "waiver_alters_gate": bool(active_waivers),
        "resulting_state": coordinate_state,
        "immutable_input_digest_sha256": _digest({"request": request, "evidence_refs": sorted((item["evidence_id"], item["evidence_digest_sha256"]) for item in evidence_records)}),
    }
    immutable_input_digest = answers["immutable_input_digest_sha256"]
    result_body = {
        "schema_version": "adjudication-result.v1",
        "contract": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "coordinate": coordinate,
        "answers": answers,
        "claim": claim,
        "trace": trace,
        "historical_reconstruction": {
            "adjudication_contract": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
            "requirement": requirement,
            "profile": request["profile"],
            "applicability": {"evaluation_id": request["applicability"]["evaluation_id"], "evaluation_digest_sha256": request["applicability"]["evaluation_digest_sha256"]},
            "campaign_expectation_bindings": request["campaign_expectation_bindings"],
            "expectation_refs": [
                {
                    "basis_id": item["basis"]["basis_id"],
                    "basis_digest_sha256": item["basis"]["basis_digest_sha256"],
                    "expectation_id": item["outcome"]["expectation_id"],
                    "expectation_digest_sha256": item["outcome"]["expectation_digest_sha256"],
                }
                for item in expectation_details
            ],
            "execution_lineage_set_sha256": None if request["execution_lineage_set"] is None else request["execution_lineage_set"]["lineage_set_sha256"],
            "evidence_record_refs": sorted(
                ({"evidence_id": item["evidence_id"], "evidence_digest_sha256": item["evidence_digest_sha256"]} for item in evidence_records),
                key=lambda item: item["evidence_id"],
            ),
            "discrepancy_revision_refs": [
                {"revision_id": item["revision_id"], "revision_digest_sha256": item["revision_digest_sha256"]}
                for item in [*request.get("discrepancy_history", []), *request["discrepancies"]]
            ],
            "waiver_revision_refs": [
                {"revision_id": item["revision_id"], "revision_digest_sha256": item["revision_digest_sha256"]}
                for item in [*request.get("waiver_history", []), *request["waivers"]]
            ],
            "quarantine_revision_refs": [
                {"revision_id": item["revision_id"], "revision_digest_sha256": item["revision_digest_sha256"]}
                for item in [*request.get("quarantine_history", []), *request["quarantines"]]
            ],
            "input_request_digest_sha256": immutable_input_digest,
            "adjudicated_on": request["adjudicated_on"],
            "regenerable": True,
        },
    }
    result = _finalize(root, result_body, namespace="reconciliation-set", artifact_kind="coordinate-adjudication-result-v1", id_field="result_id", digest_field="result_digest_sha256")
    validate_instance(result, load_strict(root / SCHEMA_PATHS["result"]), source="adjudication result")
    return result


def _u(namespace: str, number: int) -> str:
    return f"rcid:v1:{namespace}:u7:01a08ef7-2c40-7aa1-8b61-{number:012x}"


def _h(namespace: str, number: int) -> str:
    return f"rcid:v1:{namespace}:h:jcs-sha256-v1:{number:064x}"


def _synthetic_applicability(root: Path, requirement: dict[str, Any], profile: dict[str, str], state: str, number: int) -> dict[str, Any]:
    contract = load_strict(root / APPLICABILITY_CONTRACT_PATH)
    truth = {"applicable": "true", "not-applicable": "false", "unresolved": "unknown", "invalid": "invalid"}[state]
    body = {
        "schema_version": "applicability-evaluation-result.v1",
        "contract": {"artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"]},
        "requirement": {"artifact_id": requirement["requirement_id"], "digest_sha256": requirement["requirement_digest_sha256"]},
        "predicate": {"artifact_id": _h("applicability-rule-set", number), "digest_sha256": f"{number:064x}"},
        "profile": profile,
        "capability_snapshot": {"artifact_id": _h("ontology-projection", number), "digest_sha256": f"{number:064x}"},
        "result": state,
        "truth_value": truth,
        "reason_codes": [f"synthetic-{state}"],
        "facts_read": [],
        "unresolved_dependencies": [] if state != "unresolved" else [{"field_id": _h("applicability-rule-set", number + 100), "field": "profile.feature_scientific_ids", "target": requirement["requirement_id"], "reason": "missing-fact"}],
        "trace": {"node_path": "$", "operator": "fixture", "truth_value": truth, "reason_code": f"synthetic-{state}", "fact_ids": [], "children": []},
        "semantic_boundary": {"determines_expected_result": False, "establishes_empirical_unsupported": False, "rewrites_semantic_requirement": False, "ad_hoc_skip_used": False},
    }
    return applicability_model._finalize(root, body, namespace="applicability-coordinate", kind="conditional-requirement-applicability-result-v1", id_field="evaluation_id", digest_field="evaluation_digest_sha256")


def _basis_from_case(root: Path, evidence_contract: dict[str, Any], records: list[dict[str, Any]], case: dict[str, Any]) -> dict[str, Any]:
    request = case["request"]
    record = next(item for item in records if item["evidence_id"] == request["evidence_refs"][0]["evidence_id"])
    body = {
        "schema_version": "expectation-basis.v1",
        "contract_ref": {"contract_id": evidence_contract["contract_id"], "contract_digest_sha256": evidence_contract["contract_digest_sha256"]},
        "oracle_contract_ref": record["oracle_contract_ref"],
        "semantic_requirement_id": request["scope"]["requirement_scientific_ids"][0],
        "epistemic_use": request["epistemic_use"],
        "conclusion": request["requested_conclusion"],
        "evidence_refs": request["evidence_refs"],
        "oracle_refs": [{"oracle_id": record["oracle_ref"]["oracle_id"], "oracle_digest_sha256": record["oracle_ref"]["oracle_digest_sha256"]}],
        "scope": {
            "profile_ids": request["scope"]["profile_ids"],
            "profile_family_ids": request["scope"]["profile_family_ids"],
            "operation_scientific_ids": request["scope"]["operation_scientific_ids"],
        },
        "resolution_state": "oracle-established",
        "frozen_at": "2026-09-10T12:00:00Z",
        "mutable_latest_alias_used": False,
    }
    basis = finalize_expectation_basis(root, body)
    return basis


def _outcome(
    root: Path,
    requirement: dict[str, Any],
    profile: dict[str, str],
    basis: dict[str, Any],
    oracle_class: str,
    model: dict[str, Any] | None,
) -> dict[str, Any]:
    body = {
        "schema_version": "expected-outcome.v1",
        "requirement": requirement,
        "profile": profile,
        "basis_ref": {"basis_id": basis["basis_id"], "basis_digest_sha256": basis["basis_digest_sha256"]},
        "oracle_class": oracle_class,
        "epistemic_use": basis["epistemic_use"],
        "conclusion": basis["conclusion"],
        "outcome_model": model,
        "frozen_at": basis["frozen_at"],
        "mutable_latest_alias_used": False,
    }
    return finalize_expected_outcome(root, body)


def _claimant(identifier: str, revision: str, kind: str, digest: str | None = None) -> dict[str, str]:
    return {
        "claimant_id": identifier,
        "claimant_revision_id": revision,
        "claimant_digest_sha256": digest or _digest({"id": identifier, "revision": revision}),
        "claimant_kind": kind,
    }


def _discrepancy(
    root: Path,
    number: int,
    relationship: str,
    classification: str,
    claimants: list[dict[str, str]],
    *,
    state: str = "unresolved",
    supersedes: str | None = None,
    revision_number: int = 1,
    divergence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "schema_version": "discrepancy-revision.v1",
        "discrepancy_id": _u("discrepancy", number),
        "revision_number": revision_number,
        "supersedes_revision_id": supersedes,
        "relationship": relationship,
        "scope": {"kind": "synthetic-coordinate", "coordinate_token": f"fixture-{number}"},
        "claimants": claimants,
        "claimants_digest_sha256": _digest(claimants),
        "supporting_evidence": [{"kind": "immutable-claimant-set", "digest_sha256": _digest(claimants)}],
        "classification": classification,
        "adjudication_state": state,
        "reviewer": None if state == "unresolved" else {"reviewer_id": "reviewer:fixture", "reviewed_on": PUBLISHED_ON},
        "resolution_method": "none" if state in {"unresolved", "reviewed-unresolved"} else "authority-and-evidence-review",
        "permitted_divergence": divergence,
        "history_preserved": True,
        "recorded_on": PUBLISHED_ON,
    }
    return finalize_discrepancy(root, body)


def _selector(requirement: dict[str, Any], profile: dict[str, str], coordinate_id: str) -> dict[str, list[str]]:
    return {
        "coordinate_ids": [coordinate_id],
        "requirement_ids": [requirement["requirement_id"]],
        "profile_ids": [profile["profile_id"]],
        "gate_ids": ["C4"],
    }


def _waiver(root: Path, number: int, kind: str, selector: dict[str, list[str]]) -> dict[str, Any]:
    return finalize_waiver(root, {
        "schema_version": "waiver-revision.v1",
        "waiver_id": _u("certification-action", number),
        "revision_number": 1,
        "supersedes_revision_id": None,
        "waiver_type": kind,
        "owner_id": "owner:fixture",
        "reviewer_id": "reviewer:fixture",
        "selector": selector,
        "justification": f"Synthetic {kind} waiver proving gate-only behavior.",
        "issue_reference": f"urn:strling:fixture:waiver:{kind.lower()}",
        "created_on": PUBLISHED_ON,
        "review_or_expiry_on": "2026-10-11",
        "status": "approved",
        "revocation_reference": None,
        "scientific_boundary": {"alters_applicability": False, "alters_expectation": False, "alters_observation": False, "alters_discrepancy_existence": False, "alters_scientific_result": False},
    })


def _quarantine(root: Path, number: int, selector: dict[str, list[str]]) -> dict[str, Any]:
    return finalize_quarantine(root, {
        "schema_version": "quarantine-revision.v1",
        "quarantine_id": _u("finding", number),
        "revision_number": 1,
        "supersedes_revision_id": None,
        "owner_id": "owner:fixture",
        "reviewer_id": "reviewer:fixture",
        "selector": selector,
        "issue_reference": "urn:strling:fixture:quarantine",
        "reason": "Synthetic operational quarantine preserving every attempt and observation.",
        "created_on": PUBLISHED_ON,
        "review_on": "2026-10-11",
        "status": "active",
        "safe_execution": "remain-executable",
        "gate_policy": "block",
        "preserves_attempts": True,
        "preserves_observations": True,
        "evidence_of_conformance": False,
    })


def _admissions(lineage: dict[str, Any], *, admitted: bool = True) -> list[dict[str, Any]]:
    result = []
    for observation in lineage["observations"]:
        body = {
            "observation_id": observation["observation_id"],
            "observation_content_id": observation["observation_content_id"],
            "decision": "admitted" if admitted else "inadmissible",
            "integrity_status": "verified" if admitted else "failed",
            "preservation_status": "immutable-complete",
            "reason_codes": ["verified-terminal-observation"] if admitted else ["injected-inadmissible-fixture"],
        }
        result.append({**body, "decision_digest_sha256": _digest(body)})
    return result


def build_fixtures(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    evidence_contract = load_strict(root / EVIDENCE_CONTRACT_PATH)
    evidence_fixture = load_strict(root / EVIDENCE_FIXTURE_PATH)
    evidence_records = deepcopy(evidence_fixture["valid_evidence"])
    valid_cases = deepcopy(evidence_fixture["valid_cases"])

    optional_record = deepcopy(next(item for item in evidence_records if item["oracle_ref"]["oracle_class"] == "O1"))
    optional_record["normative_strength"] = "optional"
    optional_record = finalize_evidence_record(root, optional_record)
    evidence_records.append(optional_record)
    optional_case = deepcopy(next(item for item in valid_cases if item["case_id"] == "o1-normative"))
    optional_case["case_id"] = "o1-optional"
    optional_case["request"]["evidence_refs"] = [{"evidence_id": optional_record["evidence_id"], "evidence_digest_sha256": optional_record["evidence_digest_sha256"]}]
    optional_case["request"]["requested_conclusion"] = "normative-optionality"
    valid_cases.append(optional_case)

    basis_by_role = {
        case["request"]["oracle_class"] if case["case_id"] != "o1-optional" else "O1-optional": _basis_from_case(root, evidence_contract, evidence_records, case)
        for case in valid_cases
    }
    profile = {
        "profile_id": "rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7",
        "profile_revision_id": _h("profile-revision", 1),
    }
    actual_match = {"outcome_class": "match", "semantic_result": {"match": True, "spans": [[0, 1]]}}
    actual_no_match = {"outcome_class": "no-match", "semantic_result": {"match": False}}
    role_models: dict[str, dict[str, Any] | None] = {
        "O1": {"kind": "exact", "value": actual_match},
        "O2": {"kind": "exact", "value": actual_no_match},
        "O3": {"kind": "exact", "value": actual_match},
        "O4": {"kind": "relation", "relation_id": "urn:strling:relation:quoting-round-trip", "operator": "equals", "value": actual_match},
        "O5": {"kind": "exact", "value": actual_no_match},
        "O6": {"kind": "exact", "value": actual_no_match},
        "O7": {"kind": "exact", "value": actual_no_match},
        "O8": None,
        "O1-optional": {"kind": "exact", "value": actual_no_match},
    }
    outcomes: dict[str, dict[str, Any]] = {}
    applicability: dict[tuple[str, str], dict[str, Any]] = {}
    for number, (role, basis) in enumerate(basis_by_role.items(), 1):
        requirement = _requirement_binding(root, basis["semantic_requirement_id"])
        oracle_class = "O1" if role == "O1-optional" else role
        outcomes[role] = _outcome(root, requirement, profile, basis, oracle_class, role_models[role])
        for state_number, state in enumerate(("applicable", "not-applicable", "unresolved", "invalid"), 1):
            applicability[(role, state)] = _synthetic_applicability(root, requirement, profile, state, number * 10 + state_number)

    extra_models = [
        {"kind": "one-of", "values": sorted([actual_match, actual_no_match], key=canonical_bytes)},
        {"kind": "optional-alternatives", "values": sorted([actual_match, actual_no_match], key=canonical_bytes)},
        {"kind": "permitted-set", "values": sorted([actual_match, actual_no_match], key=canonical_bytes)},
        {"kind": "range", "field": "semantic_result.value", "minimum": 1, "maximum": 3, "minimum_inclusive": True, "maximum_inclusive": False},
        {"kind": "conditional", "condition_contract_ref": {"contract_id": _h("applicability-policy", 7), "revision": "1.0.0", "digest_sha256": "7" * 64}, "branches": [{"condition_id": _h("applicability-rule-set", 7), "condition_result": "true", "outcome": {"kind": "exact", "value": actual_match}}, {"condition_id": _h("applicability-rule-set", 8), "condition_result": "false", "outcome": {"kind": "exact", "value": actual_no_match}}]},
    ]
    for index, model in enumerate(extra_models, 1):
        role = "O1"
        basis = basis_by_role[role]
        requirement = _requirement_binding(root, basis["semantic_requirement_id"])
        outcomes[f"model-{index}"] = _outcome(root, requirement, profile, basis, role, model)

    lineage_set = load_strict(root / EXECUTION_LINEAGE_PATH)
    lineages = lineage_set["lineages"]
    observation_match = lineages[0]["observations"][0]
    expectation_claimant = lambda role: _claimant(outcomes[role]["expectation_id"], basis_by_role[role]["basis_id"], "expectation", outcomes[role]["expectation_digest_sha256"])
    observation_claimant = lambda observation, kind="observation": _claimant(observation["observation_id"], observation["observation_content_id"], kind, observation["result_signature"]["sha256"])
    discrepancy_records = [
        _discrepancy(root, 1, "specification-expectation-vs-observation", "implementation-defect", [expectation_claimant("O1"), observation_claimant(observation_match)]),
        _discrepancy(root, 2, "formal-derivation-vs-observation", "implementation-defect", [expectation_claimant("O2"), observation_claimant(observation_match)]),
        _discrepancy(root, 3, "authoritative-data-vs-observation", "data-version-source-mismatch", [expectation_claimant("O3"), observation_claimant(observation_match)]),
        _discrepancy(root, 4, "implementation-documentation-vs-implementation", "documentation-defect", [expectation_claimant("O6"), observation_claimant(observation_match)]),
        _discrepancy(root, 5, "historical-vs-later-behavior", "historical-regression-change", [expectation_claimant("O7"), observation_claimant(observation_match, "later-observation")]),
        _discrepancy(root, 6, "observation-vs-observation", "unresolved-conflict", [observation_claimant(lineages[4]["observations"][0]), observation_claimant(lineages[4]["observations"][1])]),
    ]
    divergence = {
        "positively_established": True,
        "normative_strength": "optional",
        "basis_kind": "normative-authority",
        "authority_evidence_refs": basis_by_role["O1-optional"]["evidence_refs"],
        "allowed_outcomes": {"kind": "optional-alternatives", "values": [actual_match]},
    }
    discrepancy_records.append(_discrepancy(root, 7, "specification-expectation-vs-observation", "permitted-variation", [expectation_claimant("O1-optional"), observation_claimant(observation_match)], divergence=divergence))
    unresolved_predecessor = _discrepancy(root, 8, "specification-vs-implementation-documentation", "unresolved-conflict", [_claimant("urn:strling:fixture:spec", _h("finding-revision", 81), "specification"), _claimant("urn:strling:fixture:docs", _h("finding-revision", 82), "implementation-documentation")])
    resolved_current = _discrepancy(root, 8, "specification-vs-implementation-documentation", "documentation-defect", unresolved_predecessor["claimants"], state="resolved", supersedes=unresolved_predecessor["revision_id"], revision_number=2)
    discrepancy_records.append(resolved_current)

    def request_for(role: str, state: str = "applicable", lineage_index: int | None = 0, *, admitted: bool = True, discrepancies: list[dict[str, Any]] | None = None, waivers: list[dict[str, Any]] | None = None, quarantines: list[dict[str, Any]] | None = None, claim_number: int = 1) -> dict[str, Any]:
        basis = basis_by_role[role]
        requirement = _requirement_binding(root, basis["semantic_requirement_id"])
        selected = None if lineage_index is None else lineages[lineage_index]
        return {
            "requirement": requirement,
            "profile": profile,
            "applicability": applicability[(role, state)],
            "expectations": [{"basis": basis, "expected_outcome": outcomes[role]}],
            "campaign_expectation_bindings": [{"basis_id": basis["basis_id"], "basis_digest_sha256": basis["basis_digest_sha256"]}],
            "execution_lineage_set": None if lineage_index is None else lineage_set,
            "logical_execution_id": None if selected is None else selected["logical_execution_id"],
            "observation_admissions": [] if selected is None else _admissions(selected, admitted=admitted),
            "discrepancies": [] if discrepancies is None else discrepancies,
            "discrepancy_history": [unresolved_predecessor],
            "waivers": [] if waivers is None else waivers,
            "waiver_history": [],
            "quarantines": [] if quarantines is None else quarantines,
            "quarantine_history": [],
            "gate_id": "C4",
            "claim_id": _u("finding", 100 + claim_number),
            "claim_revision_number": 1,
            "supersedes_claim_revision_id": None,
            "adjudicated_on": PUBLISHED_ON,
        }

    waiver_selector = _selector(_requirement_binding(root, basis_by_role["O1"]["semantic_requirement_id"]), profile, applicability[("O1", "applicable")]["evaluation_id"])
    o2_waiver_selector = _selector(_requirement_binding(root, basis_by_role["O2"]["semantic_requirement_id"]), profile, applicability[("O2", "applicable")]["evaluation_id"])
    waiver_records = [_waiver(root, 1, "SPEC", o2_waiver_selector)] + [_waiver(root, index, kind, waiver_selector) for index, kind in enumerate(WAIVER_TYPES[1:], 2)]
    quarantine_records = [_quarantine(root, 1, waiver_selector)]

    cases: list[tuple[str, dict[str, Any]]] = [
        ("o1-normative-satisfied", request_for("O1", claim_number=1)),
        ("o2-formal-violation", request_for("O2", discrepancies=[discrepancy_records[1]], claim_number=2)),
        ("o3-data-agreement", request_for("O3", claim_number=3)),
        ("o4-relation-satisfaction", request_for("O4", claim_number=4)),
        ("o5-family-divergence", request_for("O5", discrepancies=[_discrepancy(root, 9, "observation-vs-observation", "profile-dialect-difference", [expectation_claimant("O5"), observation_claimant(observation_match)])], claim_number=5)),
        ("o6-documentation-violation", request_for("O6", discrepancies=[discrepancy_records[3]], claim_number=6)),
        ("o7-historical-divergence", request_for("O7", discrepancies=[discrepancy_records[4]], claim_number=7)),
        ("o8-characterization", request_for("O8", claim_number=8)),
        ("not-applicable", request_for("O1", "not-applicable", None, claim_number=9)),
        ("applicability-unresolved", request_for("O1", "unresolved", None, claim_number=10)),
        ("applicability-invalid", request_for("O1", "invalid", None, claim_number=11)),
        ("applicable-not-tested", request_for("O1", "applicable", None, claim_number=12)),
        ("attempted-infrastructure-no-observation", request_for("O1", lineage_index=3, claim_number=13)),
        ("inadmissible-observation-excluded", request_for("O1", admitted=False, claim_number=14)),
        ("conflicting-observations", request_for("O1", lineage_index=4, discrepancies=[discrepancy_records[5]], claim_number=15)),
        ("permitted-divergence", request_for("O1-optional", discrepancies=[discrepancy_records[6]], claim_number=16)),
        ("waived-normative-violation", request_for("O2", discrepancies=[discrepancy_records[1]], waivers=[waiver_records[0]], claim_number=17)),
        ("quarantined-satisfied", request_for("O1", quarantines=quarantine_records, claim_number=18)),
        ("retry-preserves-failed-attempt", request_for("O1", lineage_index=1, discrepancies=[discrepancy_records[0]], claim_number=19)),
        ("resolved-discrepancy-history-preserved", request_for("O1", discrepancies=[resolved_current], claim_number=20)),
    ]
    conflict_request = request_for("O1", discrepancies=[_discrepancy(root, 10, "specification-vs-formal-derivation", "unresolved-conflict", [expectation_claimant("O1"), expectation_claimant("O2")])], claim_number=21)
    conflict_request["expectations"].append({"basis": basis_by_role["O2"], "expected_outcome": outcomes["O2"]})
    conflict_request["campaign_expectation_bindings"].append({"basis_id": basis_by_role["O2"]["basis_id"], "basis_digest_sha256": basis_by_role["O2"]["basis_digest_sha256"]})
    cases.append(("conflicting-authorities", conflict_request))
    expected_by_case: dict[str, tuple[str, str, str | None, bool, bool]] = {
        "o1-normative-satisfied": ("satisfied", "satisfied", "normative-conformance", False, False),
        "o2-formal-violation": ("violated", "violated", "formal-model-violation", True, False),
        "o3-data-agreement": ("satisfied", "satisfied", "authoritative-data-agreement", False, False),
        "o4-relation-satisfaction": ("satisfied", "satisfied", "metamorphic-relation-satisfaction", False, False),
        "o5-family-divergence": ("violated", "violated", "family-relative-divergence", True, False),
        "o6-documentation-violation": ("violated", "violated", "implementation-documentation-non-conformance", True, False),
        "o7-historical-divergence": ("violated", "violated", "historical-characterization", True, False),
        "o8-characterization": ("inconclusive", "inconclusive", "characterization-only-finding", False, False),
        "not-applicable": ("not-applicable", "not-applicable", None, False, False),
        "applicability-unresolved": ("applicability-unresolved", "applicability-unresolved", None, False, False),
        "applicability-invalid": ("applicability-invalid", "applicability-invalid", None, False, False),
        "applicable-not-tested": ("not-tested", "not-tested", None, False, False),
        "attempted-infrastructure-no-observation": ("unobserved", "unobserved", None, False, False),
        "inadmissible-observation-excluded": ("unobserved", "unobserved", None, False, False),
        "conflicting-observations": ("conflicting-evidence", "conflicting-evidence", "characterization-only-finding", True, False),
        "permitted-divergence": ("permitted-divergence", "permitted-divergence", "permitted-divergence-finding", True, False),
        "waived-normative-violation": ("violated", "waived-for-gate", "formal-model-violation", True, True),
        "quarantined-satisfied": ("satisfied", "quarantined", "normative-conformance", False, False),
        "retry-preserves-failed-attempt": ("violated", "violated", "normative-non-conformance", True, False),
        "resolved-discrepancy-history-preserved": ("satisfied", "satisfied", "normative-conformance", True, False),
        "conflicting-authorities": ("conflicting-authority", "conflicting-authority", "characterization-only-finding", True, False),
    }
    valid_fixture_cases = []
    for case_id, request in cases:
        scientific, coordinate, claim_kind, discrepancy_exists, waiver_alters_gate = expected_by_case[case_id]
        valid_fixture_cases.append({"case_id": case_id, "request": request, "expected": {"scientific_state": scientific, "coordinate_state": coordinate, "claim_kind": claim_kind, "discrepancy_exists": discrepancy_exists, "waiver_alters_gate": waiver_alters_gate}})

    adversarial = [
        ("observation-direct-pass-fail", "observation-direct-verdict", "observation-direct-verdict"),
        ("unresolved-is-not-nonconformance", "valid-case:applicability-unresolved", "applicability-unresolved"),
        ("not-applicable-is-not-unsupported", "valid-case:not-applicable", "not-applicable"),
        ("infrastructure-is-not-implementation-failure", "valid-case:attempted-infrastructure-no-observation", "unobserved"),
        ("o8-cannot-be-normative-pass", "o8-normative-escalation", "o8-normative-escalation"),
        ("o5-cannot-be-universal", "o5-universalization", "o5-universalization"),
        ("majority-cannot-resolve", "majority-resolution", "majority-cannot-resolve-discrepancy"),
        ("silence-is-not-permission", "silence-permitted-divergence", "permitted-divergence-not-established"),
        ("waiver-is-not-scientific-pass", "valid-case:waived-normative-violation", "violated"),
        ("waiver-cannot-delete-discrepancy", "waiver-delete-discrepancy", "waiver-rewrites-scientific-truth"),
        ("quarantine-cannot-delete-observation", "quarantine-delete-observation", "quarantine-erases-evidence"),
        ("retry-cannot-erase-attempt", "valid-case:retry-preserves-failed-attempt", "2"),
        ("inadmissible-evidence-cannot-influence", "valid-case:inadmissible-observation-excluded", "unobserved"),
        ("new-expectation-cannot-rewrite-campaign", "expectation-rewrite", "historical-expectation-rewrite"),
        ("claim-evidence-cycle-rejected", "claim-cycle", "claim-evidence-circularity"),
        ("claim-cannot-be-authority", "claim-own-authority", "claim-used-as-authority"),
        ("discrepancy-history-cannot-rewrite-claimants", "discrepancy-history-rewrite", "discrepancy-history-rewrite"),
    ]
    body = {
        "schema_version": "adjudication-fixtures.v1",
        "classification": "synthetic-non-authoritative-no-production-credit",
        "contract_ref": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]},
        "evidence_records": evidence_records,
        "expected_outcomes": list(outcomes.values()),
        "applicability_results": list(applicability.values()),
        "discrepancy_records": discrepancy_records,
        "discrepancy_history": [unresolved_predecessor],
        "waiver_records": waiver_records,
        "quarantine_records": quarantine_records,
        "execution_lineage_set": lineage_set,
        "valid_cases": valid_fixture_cases,
        "adversarial_cases": [{"case_id": case_id, "mode": mode, "expected": expected} for case_id, mode, expected in adversarial],
    }
    return _finalize(root, body, namespace="artifact-set-manifest", artifact_kind="adjudication-fixtures-v1", id_field="fixture_set_id", digest_field="fixture_set_digest_sha256")


def _fixture_body(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key not in {"fixture_set_id", "fixture_set_digest_sha256"}}


def _refinalize_claim(root: Path, claim: dict[str, Any]) -> dict[str, Any]:
    return finalize_claim(root, {key: value for key, value in claim.items() if key not in {"revision_id", "revision_digest_sha256"}})


def _assert_fails(expected: str, operation: Any) -> None:
    try:
        operation()
    except ConformanceDataError as error:
        if error.code != expected:
            raise AssertionError(f"expected {expected}, received {error.code}") from error
        return
    raise AssertionError(f"expected failure {expected}")


def validate_fixtures(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> dict[str, int]:
    validate_instance(fixture, load_strict(root / SCHEMA_PATHS["fixtures"]), source=FIXTURE_PATH.as_posix())
    body = _fixture_body(fixture)
    if fixture["fixture_set_digest_sha256"] != _digest(body) or fixture["fixture_set_id"] != _content_id(root, "artifact-set-manifest", "adjudication-fixtures-v1", body):
        fail("adjudication-fixture-identity", "fixture identity or digest differs")
    if fixture["contract_ref"] != {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"]}:
        fail("adjudication-fixture-contract", "fixture binds another adjudication contract")
    evidence_records = fixture["evidence_records"]
    evidence_contract = load_strict(root / EVIDENCE_CONTRACT_PATH)
    lineage_key = (str(root.resolve()), fixture["execution_lineage_set"]["lineage_set_sha256"])
    if lineage_key not in _LINEAGE_VALIDATION_CACHE:
        validate_lineage_set(root, fixture["execution_lineage_set"])
        _LINEAGE_VALIDATION_CACHE.add(lineage_key)
    for predecessor in fixture["discrepancy_history"]:
        validate_discrepancy(root, predecessor)
    for record in fixture["discrepancy_records"]:
        validate_discrepancy(root, record, fixture["discrepancy_history"])
    for record in fixture["waiver_records"]:
        validate_waiver(root, record)
    for record in fixture["quarantine_records"]:
        validate_quarantine(root, record)

    results: dict[str, dict[str, Any]] = {}
    requests: dict[str, dict[str, Any]] = {}
    for case_index, case in enumerate(fixture["valid_cases"]):
        result = adjudicate(root, contract, case["request"], evidence_records)
        if case_index == 0 and result != adjudicate(root, contract, deepcopy(case["request"]), evidence_records):
            fail("nondeterministic-adjudication", case["case_id"])
        actual = {
            "scientific_state": result["coordinate"]["scientific_state"],
            "coordinate_state": result["coordinate"]["coordinate_state"],
            "claim_kind": result["answers"]["permitted_epistemic_claim_type"],
            "discrepancy_exists": result["answers"]["discrepancy_exists"],
            "waiver_alters_gate": result["answers"]["waiver_alters_gate"],
        }
        if actual != case["expected"]:
            fail("adjudication-fixture-result", f"{case['case_id']} expected {case['expected']!r}, received {actual!r}")
        results[case["case_id"]] = result
        requests[case["case_id"]] = case["request"]

    expected_adversarial = {item["mode"]: item["expected"] for item in fixture["adversarial_cases"]}
    for mode, expected in expected_adversarial.items():
        if mode.startswith("valid-case:"):
            case_id = mode.split(":", 1)[1]
            result = results[case_id]
            if case_id == "retry-preserves-failed-attempt":
                value: Any = len(result["claim"]["physical_attempt_ids"])
                if str(value) != expected:
                    fail("adversarial-valid-case", f"{mode} expected {expected}, received {value}")
            else:
                value = result["coordinate"]["scientific_state"]
                if value != expected:
                    fail("adversarial-valid-case", f"{mode} expected {expected}, received {value}")
            continue
        if mode == "observation-direct-verdict":
            request = deepcopy(requests["o1-normative-satisfied"])
            request["execution_lineage_set"]["lineages"][0]["observations"][0]["semantic_result"]["conformance_verdict"] = "PASS"
            _assert_fails(expected, lambda: adjudicate(root, contract, request, evidence_records))
        elif mode == "o8-normative-escalation":
            request = deepcopy(requests["o8-characterization"])
            outcome = request["expectations"][0]["expected_outcome"]
            body = {key: value for key, value in outcome.items() if key not in {"expectation_id", "expectation_digest_sha256"}}
            body["outcome_model"] = {"kind": "exact", "value": {"outcome_class": "match", "semantic_result": {"match": True, "spans": [[0, 1]]}}}
            request["expectations"][0]["expected_outcome"] = finalize_expected_outcome(root, body)
            _assert_fails(expected, lambda: adjudicate(root, contract, request, evidence_records))
        elif mode == "o5-universalization":
            request = deepcopy(requests["o5-family-divergence"])
            basis = request["expectations"][0]["basis"]
            basis_body = {key: value for key, value in basis.items() if key not in {"basis_id", "basis_digest_sha256"}}
            basis_body["scope"]["profile_family_ids"] = []
            new_basis = finalize_expectation_basis(root, basis_body)
            outcome = request["expectations"][0]["expected_outcome"]
            outcome_body = {key: value for key, value in outcome.items() if key not in {"expectation_id", "expectation_digest_sha256"}}
            outcome_body["basis_ref"] = {"basis_id": new_basis["basis_id"], "basis_digest_sha256": new_basis["basis_digest_sha256"]}
            request["expectations"][0] = {"basis": new_basis, "expected_outcome": finalize_expected_outcome(root, outcome_body)}
            request["campaign_expectation_bindings"] = [{"basis_id": new_basis["basis_id"], "basis_digest_sha256": new_basis["basis_digest_sha256"]}]
            _assert_fails(expected, lambda: adjudicate(root, contract, request, evidence_records))
        elif mode == "majority-resolution":
            record = deepcopy(fixture["discrepancy_records"][0])
            body = {key: value for key, value in record.items() if key not in {"revision_id", "revision_digest_sha256"}}
            body["resolution_method"] = "majority-vote"
            record = finalize_discrepancy(root, body)
            _assert_fails(expected, lambda: validate_discrepancy(root, record))
        elif mode == "silence-permitted-divergence":
            record = deepcopy(next(item for item in fixture["discrepancy_records"] if item["permitted_divergence"] is not None))
            body = {key: value for key, value in record.items() if key not in {"revision_id", "revision_digest_sha256"}}
            body["permitted_divergence"]["normative_strength"] = "silent-not-established"
            record = finalize_discrepancy(root, body)
            _assert_fails(expected, lambda: validate_discrepancy(root, record))
        elif mode == "waiver-delete-discrepancy":
            record = deepcopy(fixture["waiver_records"][0])
            body = {key: value for key, value in record.items() if key not in {"revision_id", "revision_digest_sha256"}}
            body["scientific_boundary"]["alters_discrepancy_existence"] = True
            record = finalize_waiver(root, body)
            _assert_fails(expected, lambda: validate_waiver(root, record))
        elif mode == "quarantine-delete-observation":
            record = deepcopy(fixture["quarantine_records"][0])
            body = {key: value for key, value in record.items() if key not in {"revision_id", "revision_digest_sha256"}}
            body["preserves_observations"] = False
            record = finalize_quarantine(root, body)
            _assert_fails(expected, lambda: validate_quarantine(root, record))
        elif mode == "expectation-rewrite":
            request = deepcopy(requests["o1-normative-satisfied"])
            outcome = request["expectations"][0]["expected_outcome"]
            body = {key: value for key, value in outcome.items() if key not in {"expectation_id", "expectation_digest_sha256"}}
            other = requests["o2-formal-violation"]["expectations"][0]["basis"]
            body["basis_ref"] = {"basis_id": other["basis_id"], "basis_digest_sha256": other["basis_digest_sha256"]}
            request["expectations"][0]["expected_outcome"] = finalize_expected_outcome(root, body)
            _assert_fails(expected, lambda: adjudicate(root, contract, request, evidence_records))
        elif mode == "claim-cycle":
            claim = deepcopy(results["o1-normative-satisfied"]["claim"])
            requirement_node = next(item for item in claim["dependency_graph"]["nodes"] if item["kind"] == "requirement")
            requirement_node["upstream_node_ids"] = [claim["claim_id"]]
            claim = _refinalize_claim(root, claim)
            _assert_fails(expected, lambda: validate_claim(root, claim))
        elif mode == "claim-own-authority":
            claim = deepcopy(results["waived-normative-violation"]["claim"])
            claim_node = next(item for item in claim["dependency_graph"]["nodes"] if item["kind"] == "claim")
            waiver_node = next(item for item in claim["dependency_graph"]["nodes"] if item["kind"] == "waiver")
            claim_node["upstream_node_ids"].remove(waiver_node["node_id"])
            waiver_node["upstream_node_ids"] = [claim["claim_id"]]
            claim = _refinalize_claim(root, claim)
            _assert_fails(expected, lambda: validate_claim(root, claim))
        elif mode == "discrepancy-history-rewrite":
            predecessor = fixture["discrepancy_history"][0]
            current = deepcopy(next(item for item in fixture["discrepancy_records"] if item["supersedes_revision_id"] == predecessor["revision_id"]))
            body = {key: value for key, value in current.items() if key not in {"revision_id", "revision_digest_sha256"}}
            body["claimants"][0]["claimant_digest_sha256"] = "f" * 64
            body["claimants_digest_sha256"] = _digest(body["claimants"])
            current = finalize_discrepancy(root, body)
            _assert_fails(expected, lambda: validate_discrepancy(root, current, [predecessor]))
        else:
            fail("unknown-adversarial-mode", mode)
    return {
        "valid_case_count": len(fixture["valid_cases"]),
        "adversarial_case_count": len(fixture["adversarial_cases"]),
        "evidence_role_count": len({item["oracle_ref"]["oracle_class"] for item in evidence_records}),
        "coordinate_state_count": len({case["expected"]["coordinate_state"] for case in fixture["valid_cases"]}),
        "scientific_state_count": len({case["expected"]["scientific_state"] for case in fixture["valid_cases"]}),
        "waiver_type_count": len({item["waiver_type"] for item in fixture["waiver_records"]}),
    }


def build_report(root: Path, contract: dict[str, Any], fixture: dict[str, Any], counts: dict[str, int] | None = None) -> dict[str, Any]:
    counts = counts or validate_fixtures(root, contract, fixture)
    requirement = load_strict(root / REQUIREMENT_PATH)
    certification = load_strict(root / CERTIFICATION_REPORT_PATH)
    c4 = next(item for item in certification["criteria"] if item["criterion_id"] == "C4")
    checks = [
        "authority-separation",
        "closed-coordinate-state-algebra",
        "o1-through-o8-claim-boundaries",
        "deterministic-adjudication",
        "reason-code-totality",
        "missing-evidence-is-not-failure",
        "infrastructure-is-not-target-failure",
        "immutable-attempt-and-observation-lineage",
        "discrepancy-history-preservation",
        "permitted-divergence-positive-authority",
        "waiver-gate-only-effect",
        "quarantine-evidence-preservation",
        "expectation-revision-freeze",
        "claim-circularity-rejection",
        "inadmissible-evidence-exclusion",
        "denominator-unchanged",
        "certification-honesty",
        "production-boundary",
    ]
    body = {
        "schema_version": "adjudication-report.v1",
        "published_on": PUBLISHED_ON,
        "claim_scope": "Acceptance of deterministic, synthetic-fixture-only observation-to-claim adjudication; no production profile coordinate, empirical execution, evidence credit, public compatibility projection, or repository-wide certification is created.",
        "contract": {"path": CONTRACT_PATH.as_posix(), "artifact_id": contract["contract_id"], "digest_sha256": contract["contract_digest_sha256"]},
        "fixtures": {"path": FIXTURE_PATH.as_posix(), "artifact_id": fixture["fixture_set_id"], "digest_sha256": fixture["fixture_set_digest_sha256"]},
        "implementation_bindings": [{"path": path.as_posix(), "sha256": _sha(root / path)} for path in IMPLEMENTATION_PATHS],
        "coverage": {**counts, "contract_coordinate_state_count": len(COORDINATE_STATES), "contract_claim_kind_count": len(CLAIM_KINDS), "discrepancy_relationship_count": len(DISCREPANCY_RELATIONS), "discrepancy_classification_count": len(DISCREPANCY_CLASSIFICATIONS), "expected_outcome_kind_count": 7},
        "checks": [{"check": item, "status": "PASS"} for item in checks],
        "denominator_boundary": {
            "obligations": 2390,
            "requirements": len(requirement["requirements"]),
            "unconditional_requirements": sum(item["requirement_state"] == "required" for item in requirement["requirements"]),
            "conditional_requirements": sum(item["requirement_state"] == "conditionally-required" for item in requirement["requirements"]),
            "real_profile_coordinates_generated": 0,
            "profile_expanded_denominator": None,
            "production_coverage_credit": 0,
        },
        "certification_state": {
            "final_state": certification["final_state"],
            "C1": next(item["status"] for item in certification["criteria"] if item["criterion_id"] == "C1"),
            "C2": next(item["status"] for item in certification["criteria"] if item["criterion_id"] == "C2"),
            "C3": next(item["status"] for item in certification["criteria"] if item["criterion_id"] == "C3"),
            "C4": c4["status"],
            "C4_completed": c4["numerator_count"],
            "C4_denominator": c4["denominator_count"],
            "C5": next(item["status"] for item in certification["criteria"] if item["criterion_id"] == "C5"),
            "C6": next(item["status"] for item in certification["criteria"] if item["criterion_id"] == "C6"),
            "C7": next(item["status"] for item in certification["criteria"] if item["criterion_id"] == "C7"),
        },
        "result": "PASS",
    }
    return _finalize(root, body, namespace="trust-assessment", artifact_kind="adjudication-acceptance-report-v1", id_field="report_id", digest_field="report_digest_sha256")


def build_authority(root: Path, contract: dict[str, Any], fixture: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    body = {
        "schema_version": "adjudication-authority.v1",
        "published_on": PUBLISHED_ON,
        "current_contract": _ref(root / CONTRACT_PATH, contract, "contract_id", "contract_digest_sha256"),
        "predecessors": contract["predecessor_contracts"],
        "validation_fixture": _ref(root / FIXTURE_PATH, fixture, "fixture_set_id", "fixture_set_digest_sha256"),
        "acceptance_report": _ref(root / REPORT_PATH, report, "report_id", "report_digest_sha256"),
        "historical_compatibility": {
            "observations_rewritten": False,
            "expectations_rewritten": False,
            "applicability_rewritten": False,
            "discrepancy_history_rewritten": False,
            "claims_regenerable_from_exact_inputs": True,
        },
        "production_boundary": {
            "synthetic_only": True,
            "real_profile_coordinates": 0,
            "production_evidence_created": False,
            "coverage_credit_created": False,
            "successor_work_activated": False,
        },
        "governance": {
            "claims_are_derived": True,
            "waivers_are_gate_only": True,
            "quarantine_is_operational": True,
            "authoritative_main_unchanged": True,
            "promotion_authorized": False,
        },
    }
    return _finalize(root, body, namespace="artifact-set-manifest", artifact_kind="adjudication-authority-index-v1", id_field="index_id", digest_field="index_digest_sha256")


def _validate_finalized(root: Path, record: dict[str, Any], schema_key: str, namespace: str, kind: str, id_field: str, digest_field: str, source: str) -> None:
    validate_instance(record, load_strict(root / SCHEMA_PATHS[schema_key]), source=source)
    body = {key: value for key, value in record.items() if key not in {id_field, digest_field}}
    if record[digest_field] != _digest(body) or record[id_field] != _content_id(root, namespace, kind, body):
        fail("adjudication-artifact-identity", source)


def verify_current(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    allocation = load_strict(root / ALLOCATION_PATH)
    contract = load_strict(root / CONTRACT_PATH)
    fixture = load_strict(root / FIXTURE_PATH)
    report = load_strict(root / REPORT_PATH)
    authority = load_strict(root / AUTHORITY_PATH)
    validate_instance(allocation, load_strict(root / SCHEMA_PATHS["allocation"]), source=ALLOCATION_PATH.as_posix())
    if allocation != build_allocation():
        fail("adjudication-allocation-drift", "identity allocation differs")
    validate_contract(root, contract)
    expected_fixture = build_fixtures(root, contract)
    if fixture != expected_fixture:
        fail("adjudication-fixture-drift", "tracked fixture differs from deterministic build")
    counts = validate_fixtures(root, contract, fixture)
    expected_report = build_report(root, contract, fixture, counts)
    if report != expected_report:
        fail("adjudication-report-drift", "tracked report differs from deterministic build")
    _validate_finalized(root, report, "report", "trust-assessment", "adjudication-acceptance-report-v1", "report_id", "report_digest_sha256", REPORT_PATH.as_posix())
    expected_authority = build_authority(root, contract, fixture, report)
    if authority != expected_authority:
        fail("adjudication-authority-drift", "tracked authority differs from deterministic build")
    _validate_finalized(root, authority, "authority", "artifact-set-manifest", "adjudication-authority-index-v1", "index_id", "index_digest_sha256", AUTHORITY_PATH.as_posix())
    if broad_foundations:
        if load_strict(root / DENOMINATOR_GATE_PATH)["result"] != "PASS":
            fail("adjudication-denominator-foundation", "true denominator gate is not PASS")
        certification = load_strict(root / CERTIFICATION_REPORT_PATH)
        c4 = next(item for item in certification["criteria"] if item["criterion_id"] == "C4")
        if certification["final_state"] != "FAIL" or c4["status"] != "FAIL" or c4["numerator_count"] != 0 or c4["denominator_count"] != 3378:
            fail("adjudication-certification-honesty", "C4 must remain FAIL at 0/3378")
    return {**counts, "result": report["result"], "c4": report["certification_state"]["C4"], "c4_completed": report["certification_state"]["C4_completed"], "c4_denominator": report["certification_state"]["C4_denominator"]}


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    encoded = canonical_bytes(value) + b"\n"
    with temporary.open("wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != encoded:
        raise RuntimeError(f"read-after-write verification failed for {path}")


def materialize(root: Path, *, broad_foundations: bool = True) -> dict[str, Any]:
    allocation = build_allocation()
    _write(root / ALLOCATION_PATH, allocation)
    contract = build_contract(root)
    _write(root / CONTRACT_PATH, contract)
    fixture = build_fixtures(root, contract)
    _write(root / FIXTURE_PATH, fixture)
    counts = validate_fixtures(root, contract, fixture)
    report = build_report(root, contract, fixture, counts)
    _write(root / REPORT_PATH, report)
    authority = build_authority(root, contract, fixture, report)
    _write(root / AUTHORITY_PATH, authority)
    if broad_foundations:
        certification = load_strict(root / CERTIFICATION_REPORT_PATH)
        c4 = next(item for item in certification["criteria"] if item["criterion_id"] == "C4")
        if certification["final_state"] != "FAIL" or c4["status"] != "FAIL" or (c4["numerator_count"], c4["denominator_count"]) != (0, 3378):
            fail("adjudication-certification-honesty", "C4 must remain FAIL at 0/3378")
    return {**counts, "result": report["result"], "c4": report["certification_state"]["C4"], "c4_completed": report["certification_state"]["C4_completed"], "c4_denominator": report["certification_state"]["C4_denominator"]}
