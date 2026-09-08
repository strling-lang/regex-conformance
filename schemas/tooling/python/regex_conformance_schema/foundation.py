"""Integrated acceptance for the scientific identity and certification foundation."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import re
from typing import Any

from .certification import (
    CONTRACT_PATH,
    CURRENT_AUTHORITY_PATH,
    CURRENT_INPUT_PATH,
    CURRENT_REPORT_PATH,
    FIXTURE_PATH as CERTIFICATION_FIXTURE_PATH,
    _finalize_input,
    _refinalize_fixture_input,
    _subset_lineage,
    evaluate,
    validate_input_set,
    verify_repository_certification,
)
from .derivation import (
    CATALOG_PATH as DERIVATION_CATALOG_PATH,
    derivation_revision_id,
    validate_catalog_integrity,
    verify_catalog as verify_derivation_catalog,
)
from .errors import ConformanceDataError, fail
from .evidence import load_and_validate_evidence_records
from .execution_provenance import (
    FIXTURE_PATH as EXECUTION_FIXTURE_PATH,
    POLICY_PATH as EXECUTION_POLICY_PATH,
    lineage_set_sha256,
    validate_lineage_set,
    verify_repository_execution_provenance,
)
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import (
    CATALOG_PATH as IDENTITY_CATALOG_PATH,
    NAMESPACE_PATH,
    ScientificDescriptor,
    catalog_digest,
    collect_descriptors,
    lineage_record_id,
    semantic_fingerprint,
    validate_lineage_records,
    verify_catalog as verify_scientific_identity_catalog,
)


MANIFEST_PATH = Path("foundation/scientific-foundation.v1.json")
ACCEPTANCE_PATH = Path("foundation/scientific-foundation-acceptance.v1.json")
MANIFEST_SCHEMA_PATH = Path("schemas/json/scientific-foundation-manifest.schema.json")
ACCEPTANCE_SCHEMA_PATH = Path("schemas/json/scientific-foundation-acceptance.schema.json")
CONTENT_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")
NAMESPACE_REGISTRY_PATH = Path("registries/identity/namespaces.v2.json")
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a07c22-29fd-789f-b6be-42074f88b6ba"
ACCEPTED_SOURCE_SHA = "167ebd5c55065f33191fe5843be902db53f3187e"
ACCEPTED_HOSTED_RUN = {
    "repository_sha": ACCEPTED_SOURCE_SHA,
    "status": "success",
    "workflow_url": "https://github.com/strling-lang/regex-conformance/actions/runs/34086445673",
    "jobs": [
        "first-end-to-end-campaign",
        "minimal-adapter-certification",
        "minimal-environment-certification",
        "public-validation",
    ],
}

SCIENTIFIC_BASELINE_PATHS = (
    "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json",
    "ontology/projections/regex-semantic-projection-2026-08-22.v1.json",
    "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json",
    "reports/scale/regex-semantic-denominator-forecast.json",
)

FOUNDATION_BINDINGS: dict[str, tuple[tuple[str, str], ...]] = {
    "scientific-identity": (
        ("identity-contract", "docs/architecture/scientific-identities.md"),
        ("identity-lock", IDENTITY_CATALOG_PATH.as_posix()),
        ("namespace-registry", NAMESPACE_REGISTRY_PATH.as_posix()),
        ("identity-validator", "schemas/tooling/python/regex_conformance_schema/scientific_identity.py"),
        ("identity-lock-schema", "schemas/json/scientific-identity-catalog.schema.json"),
    ),
    "generated-assertion-derivation": (
        ("derivation-contract", "docs/architecture/generated-assertion-derivations.md"),
        ("derivation-catalog", DERIVATION_CATALOG_PATH.as_posix()),
        ("derivation-validator", "schemas/tooling/python/regex_conformance_schema/derivation.py"),
        ("derivation-schema", "schemas/json/generated-assertion-derivation-catalog.schema.json"),
    ),
    "execution-provenance": (
        ("execution-contract", "docs/architecture/execution-provenance.md"),
        ("execution-policy", EXECUTION_POLICY_PATH.as_posix()),
        ("execution-validator", "schemas/tooling/python/regex_conformance_schema/execution_provenance.py"),
        ("attempt-schema", "schemas/json/physical-attempt-evidence-v2.schema.json"),
        ("terminal-observation-schema", "schemas/json/terminal-observation-content-v2.schema.json"),
        ("logical-disposition-schema", "schemas/json/logical-execution-disposition.schema.json"),
        ("lineage-set-schema", "schemas/json/execution-lineage-set.schema.json"),
        ("lineage-fixture", EXECUTION_FIXTURE_PATH.as_posix()),
    ),
    "certification-predicates": (
        ("certification-contract-documentation", "certification/README.md"),
        ("certification-contract", CONTRACT_PATH.as_posix()),
        ("certification-evaluator", "schemas/tooling/python/regex_conformance_schema/certification.py"),
        ("certification-input", CURRENT_INPUT_PATH.as_posix()),
        ("certification-report", CURRENT_REPORT_PATH.as_posix()),
        ("certification-authority", CURRENT_AUTHORITY_PATH.as_posix()),
        ("certification-fixtures", CERTIFICATION_FIXTURE_PATH.as_posix()),
        ("certification-contract-schema", "schemas/json/certification-contract.schema.json"),
        ("certification-input-schema", "schemas/json/certification-input-set.schema.json"),
        ("certification-report-schema", "schemas/json/certification-report.schema.json"),
        ("certification-authority-schema", "schemas/json/certification-authority-index.schema.json"),
    ),
}

AUTHORITY_MATRIX = (
    {
        "decision_domain": "scientific-entity-identity",
        "question": "What scientific entity or immutable artifact is this?",
        "canonical_owner": "scientific-identity",
        "consumes_from": [],
        "forbidden_alternate_owners": ["certification-predicates", "execution-provenance", "generated-assertion-derivation"],
        "enforcement": "Typed namespace, content constructor, scientific catalog, and lineage validation are authoritative; consumers may only reference their results.",
    },
    {
        "decision_domain": "generated-assertion-justification",
        "question": "Why is a generated assertion justified, and at what evidence strength?",
        "canonical_owner": "generated-assertion-derivation",
        "consumes_from": ["scientific-identity"],
        "forbidden_alternate_owners": ["certification-predicates", "execution-provenance"],
        "enforcement": "Certification admits or rejects catalogued strength but cannot reclassify a derivation.",
    },
    {
        "decision_domain": "physical-execution-truth",
        "question": "What physically happened, and did it produce target-attributable terminal evidence?",
        "canonical_owner": "execution-provenance",
        "consumes_from": ["generated-assertion-derivation", "scientific-identity"],
        "forbidden_alternate_owners": ["certification-predicates"],
        "enforcement": "Attempt lineage and terminality are validated once; certification consumes the logical disposition instead of reconstructing process symptoms.",
    },
    {
        "decision_domain": "governed-certification-status",
        "question": "Does explicit evidence satisfy a governed certification criterion?",
        "canonical_owner": "certification-predicates",
        "consumes_from": ["execution-provenance", "generated-assertion-derivation", "scientific-identity"],
        "forbidden_alternate_owners": [],
        "enforcement": "Only the versioned predicate evaluator can produce an authoritative C1-C7 result; campaign and qualification reports remain scope-limited inputs.",
    },
)

REQUIRED_GATE_CHECKS = (
    "authority-matrix",
    "certification-bypass-audit",
    "certification-contract",
    "cross-contract-identity",
    "derivation-catalog",
    "deterministic-regeneration",
    "execution-provenance",
    "foundation-manifest-closure",
    "historical-compatibility",
    "identity-lock",
    "integration-scenarios",
    "scientific-input-baseline",
)

CLAIM_SCAN_SUFFIXES = {".json", ".md", ".py", ".rst"}
CLAIM_SCAN_EXCLUDED_PARTS = {".git", ".venv", "node_modules", "__pycache__"}
AUTHORITATIVE_REPORT_MARKERS = (
    re.compile(r'"schema_version"\s*:\s*"certification-report\.v1"'),
    re.compile(r'\bcertification_eligible\b'),
)
FULL_PASS_MARKERS = (
    re.compile(r"\bC[1-7]\b.{0,120}\bPASS\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bPASS\b.{0,120}\bC[1-7]\b", re.IGNORECASE | re.DOTALL),
)
ALLOWED_AUTHORITATIVE_MARKER_PATHS = {
    "certification/reports/current-repository.v1.json",
    "certification/reports/current-repository-2026-09-08.v2.json",
    "registries/provenance/generated-assertion-derivations.v1.json",
    "schemas/json/scientific-foundation-acceptance.schema.json",
    "schemas/json/certification-report.schema.json",
    "schemas/tooling/python/regex_conformance_schema/certification.py",
    "schemas/tooling/python/regex_conformance_schema/derivation.py",
    "schemas/tooling/python/regex_conformance_schema/foundation.py",
    "tests/schema/test_certification_predicates.py",
    "tests/schema/test_scientific_foundation.py",
}
ALLOWED_AUTHORITATIVE_MARKER_PREFIXES = ("foundation/",)
ALLOWED_FULL_PASS_PREFIXES = (
    "certification/",
    "docs/architecture/",
    "foundation/",
    "tests/",
)
ALLOWED_FULL_PASS_PATHS = {
    "README.md",
    "reports/semantics/semantic-knowledge-architecture-acceptance-2026-09-08.v1.json",
}
ALLOWED_FULL_PASS_SCHEMA_PATHS = {
    "schemas/json/certification-contract.schema.json",
    "schemas/json/certification-predicate-fixtures.schema.json",
    "schemas/json/scientific-foundation-acceptance.schema.json",
    "schemas/json/semantic-knowledge-foundation-acceptance.schema.json",
    "schemas/tooling/python/regex_conformance_schema/certification.py",
    "schemas/tooling/python/regex_conformance_schema/foundation.py",
    "schemas/tooling/python/regex_conformance_schema/semantic_foundation.py",
}


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha(value: Any) -> str:
    return _sha_bytes(canonical_bytes(value))


def _record_digest(record: dict[str, Any], *excluded: str) -> str:
    omitted = set(excluded)
    return _sha({key: value for key, value in record.items() if key not in omitted})


def _content_id(root: Path, namespace: str, artifact_kind: str, digest: str) -> str:
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_REGISTRY_PATH),
        profile=IdentityProfile.from_record(load_strict(root / CONTENT_PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": artifact_kind, "content_sha256": digest},
    )
    return str(result["content_id"])


def _finalize(
    root: Path,
    record: dict[str, Any],
    *,
    namespace: str,
    artifact_kind: str,
    id_field: str,
    digest_field: str,
) -> dict[str, Any]:
    result = deepcopy(record)
    result["identity_schema_family_id"] = SCHEMA_FAMILY_ID
    result["identity_schema_version"] = "1.0.0"
    result[id_field] = ""
    result[digest_field] = ""
    digest = _record_digest(result, id_field, digest_field)
    result[digest_field] = digest
    result[id_field] = _content_id(root, namespace, artifact_kind, digest)
    return result


def _artifact(root: Path, role: str, relative: str) -> dict[str, str]:
    path = root / relative
    if not path.is_file():
        fail("missing-foundation-artifact", "a bound foundation artifact is absent", relative)
    return {"relative_path": relative, "role": role, "sha256": _sha_bytes(path.read_bytes())}


def _derivations_by_method(root: Path) -> dict[str, dict[str, Any]]:
    catalog = load_strict(root / DERIVATION_CATALOG_PATH)
    return {item["method_key"]: item for item in catalog["derivations"]}


def _derivation_bindings(root: Path) -> list[dict[str, str]]:
    records = _derivations_by_method(root)
    requested = (
        ("acceptance-conjunction", "certification-predicate-evaluation", "calculation"),
        ("authority-boundary", "governed-registry-selection", "manual-decision"),
        ("bound-artifact-digests", "qualified-artifact-measurement", "measurement"),
    )
    return [
        {
            "binding_key": key,
            "derivation_class": expected_class,
            "derivation_revision_id": records[method]["derivation_revision_id"],
            "method_key": method,
        }
        for key, method, expected_class in requested
    ]


def _foundation_facts(root: Path) -> dict[str, list[dict[str, Any]]]:
    identity = load_strict(root / IDENTITY_CATALOG_PATH)
    derivation = load_strict(root / DERIVATION_CATALOG_PATH)
    execution = load_strict(root / EXECUTION_POLICY_PATH)
    contract = load_strict(root / CONTRACT_PATH)
    report = load_strict(root / CURRENT_REPORT_PATH)
    return {
        "scientific-identity": [
            {"name": "catalog-digest", "value": identity["catalog_digest_sha256"]},
            {"name": "scientific-identity-count", "value": identity["counts"]["total"]},
            {"name": "lineage-record-count", "value": identity["counts"]["lineage_records"]},
        ],
        "generated-assertion-derivation": [
            {"name": "catalog-digest", "value": derivation["catalog_digest_sha256"]},
            {"name": "inventoried-artifact-count", "value": derivation["coverage_summary"]["inventoried_artifacts"]},
            {"name": "assertion-group-count", "value": derivation["coverage_summary"]["assertion_groups"]},
            {"name": "assertion-occurrence-count", "value": derivation["coverage_summary"]["assertion_occurrences"]},
        ],
        "execution-provenance": [
            {"name": "policy-revision", "value": execution["policy_revision_sha256"]},
            {"name": "historical-contract-count", "value": len(execution["compatibility"]["historical_contracts"])},
            {"name": "historical-records-rewritten", "value": execution["compatibility"]["historical_records_rewritten"]},
        ],
        "certification-predicates": [
            {"name": "contract-id", "value": contract["contract_id"]},
            {"name": "contract-digest", "value": contract["contract_digest_sha256"]},
            {"name": "contract-version", "value": contract["contract_version"]},
            {"name": "current-report-id", "value": report["report_id"]},
            {"name": "current-report-digest", "value": report["report_digest_sha256"]},
            {"name": "current-final-state", "value": report["final_state"]},
        ],
    }


def build_manifest(root: Path) -> dict[str, Any]:
    facts = _foundation_facts(root)
    identity_catalog = load_strict(root / IDENTITY_CATALOG_PATH)
    semantic_snapshot = load_strict(root / SCIENTIFIC_BASELINE_PATHS[0])
    policy = load_strict(root / EXECUTION_POLICY_PATH)
    foundations = []
    for key in sorted(FOUNDATION_BINDINGS):
        bindings = FOUNDATION_BINDINGS[key]
        foundations.append(
            {
                "foundation_key": key,
                "artifacts": [_artifact(root, role, relative) for role, relative in bindings],
                "facts": facts[key],
            }
        )
    body = {
        "schema_version": "scientific-foundation-manifest.v1",
        "acceptance_implementation": [
            _artifact(root, "foundation-evaluator", "schemas/tooling/python/regex_conformance_schema/foundation.py"),
            _artifact(root, "foundation-tool", "tools/foundation/certify.py"),
            _artifact(root, "foundation-manifest-schema", MANIFEST_SCHEMA_PATH.as_posix()),
            _artifact(root, "foundation-acceptance-schema", ACCEPTANCE_SCHEMA_PATH.as_posix()),
            _artifact(root, "foundation-tests", "tests/schema/test_scientific_foundation.py"),
        ],
        "accepted_source_repository_sha": ACCEPTED_SOURCE_SHA,
        "acceptance_date": "2026-09-07",
        "assertion_derivations": _derivation_bindings(root),
        "authority_matrix": [deepcopy(item) for item in AUTHORITY_MATRIX],
        "claim_authority": {
            "authoritative_full_certification": "The versioned certification predicate evaluator and its authority index.",
            "narrow_qualification": "A scope-bound environment, adapter, evidence, storage, or campaign report that does not claim full C1-C7 status.",
            "development_probe": "A fixture or probe result with no authoritative certification effect.",
        },
        "deferred_findings": [
            {"finding": "Canonical ownership of identity, assertion justification, execution truth, and certification truth", "classification": "resolved-by-foundation", "destination": "accepted-foundation"},
            {"finding": "Certification-bypass and generated-evidence-strength ambiguity", "classification": "resolved-by-foundation", "destination": "accepted-foundation"},
            {"finding": "Feature-specific semantic research and justified ontology corrections", "classification": "correctly-deferred-to-semantic-reconstruction", "destination": "semantic-knowledge-work"},
            {"finding": "True obligation-denominator derivation", "classification": "correctly-deferred-to-later-architecture", "destination": "denominator-work"},
            {"finding": "Oracle, applicability, claims, waiver, and adjudication semantics", "classification": "correctly-deferred-to-later-architecture", "destination": "adjudication-work"},
            {"finding": "Empirical profile discrimination, richer reproducibility states, and exact profile-universe freeze", "classification": "correctly-deferred-to-later-architecture", "destination": "profile-universe-work"},
            {"finding": "Production-distinct evidence capacity, diagnostics, sampling, and compact indexing", "classification": "correctly-deferred-to-later-evidence-or-storage-work", "destination": "evidence-storage-work"},
            {"finding": "Attempt-provenance retained-byte impact", "classification": "correctly-deferred-to-later-evidence-or-storage-work", "destination": "evidence-storage-work"},
            {"finding": "Final sustained production-architecture qualification", "classification": "correctly-deferred-to-later-architecture", "destination": "production-readiness-work"},
        ],
        "foundations": foundations,
        "historical_compatibility": {
            "historical_records_rewritten": False,
            "migration_rule": policy["compatibility"]["migration_rule"],
            "schema_contracts": deepcopy(policy["compatibility"]["historical_contracts"]),
        },
        "hosted_validation_basis": deepcopy(ACCEPTED_HOSTED_RUN),
        "scientific_input_baseline": {
            "artifacts": [
                _artifact(root, "accepted-scientific-input", relative)
                for relative in SCIENTIFIC_BASELINE_PATHS
            ],
            "scientific_identity_count": identity_catalog["counts"]["total"],
            "semantic_snapshot_identity": semantic_snapshot["snapshot_id"],
        },
    }
    return _finalize(
        root,
        body,
        namespace="artifact-set-manifest",
        artifact_kind="scientific-foundation-manifest-v1",
        id_field="foundation_manifest_id",
        digest_field="foundation_manifest_digest_sha256",
    )


def _fact(name: str, value: Any) -> dict[str, Any]:
    return {"name": name, "value": value}


def _check(check_id: str, *evidence: str) -> dict[str, Any]:
    return {"check_id": check_id, "status": "PASS", "evidence": list(evidence)}


def _case_by_name(root: Path, name: str) -> dict[str, Any]:
    fixture = load_strict(root / CERTIFICATION_FIXTURE_PATH)
    return next(item for item in fixture["cases"] if item["name"] == name)


def _criterion(report: dict[str, Any], criterion_id: str) -> dict[str, Any]:
    return next(item for item in report["criteria"] if item["criterion_id"] == criterion_id)


def _c5_for_lineage(root: Path, lineage_set: dict[str, Any]) -> dict[str, Any]:
    contract = load_strict(root / CONTRACT_PATH)
    candidate = deepcopy(_case_by_name(root, "full-pass")["input_set"])
    candidate["criteria"]["C5"]["lineage_set"] = lineage_set
    candidate = _refinalize_fixture_input(root, candidate)
    return _criterion(evaluate(root, contract, candidate), "C5")


def _adapter_crash_lineage(root: Path) -> dict[str, Any]:
    lineage_set = _subset_lineage(root, [3])
    lineage = lineage_set["lineages"][0]
    for index, attempt in enumerate(lineage["attempts"]):
        terminality = attempt["terminality"]
        terminality["fault_attribution"].update(
            attribution_layer="adapter",
            reason_code="adapter-process-failure",
            target_attributable=False,
        )
        terminality["outcome_class"] = "adapter-process-failure"
        terminality["protocol_status"]["state"] = "missing"
        terminality["target_process_status"]["target_started"] = False
        if index:
            attempt["retry"].update(
                policy_rule="adapter-process-failure",
                reason_code="adapter-process-failure",
            )
            attempt["reset"]["reason_code"] = "adapter-process-failure"
    lineage["disposition"]["retry_budget_exhausted"] = False
    lineage["disposition"]["unresolved_reason"] = "retry-not-attempted"
    lineage_set["lineage_set_sha256"] = lineage_set_sha256(lineage_set)
    validate_lineage_set(root, lineage_set)
    return lineage_set


@lru_cache(maxsize=4)
def _execution_scenarios_cached(root: Path) -> tuple[dict[str, Any], ...]:
    contract = load_strict(root / CONTRACT_PATH)
    full = evaluate(root, contract, _case_by_name(root, "full-pass")["input_set"])
    retry = evaluate(root, contract, _case_by_name(root, "retry-completion")["input_set"])
    exhausted = evaluate(root, contract, _case_by_name(root, "physical-attempt-exclusion")["input_set"])
    scenarios = [
        (
            "one-terminal-attempt",
            _criterion(full, "C5"),
            [_fact("physical-attempts", 1), _fact("logical-completion-credit", 1)],
        ),
        (
            "retry-after-inconclusive",
            _criterion(retry, "C5"),
            [_fact("physical-attempts", 2), _fact("logical-completion-credit", 1)],
        ),
        (
            "retry-exhaustion",
            _criterion(exhausted, "C5"),
            [_fact("physical-attempts", 2), _fact("logical-completion-credit", 0)],
        ),
        (
            "repeat-measurement",
            _c5_for_lineage(root, _subset_lineage(root, [4])),
            [_fact("physical-attempts", 2), _fact("logical-completion-credit", 1)],
        ),
        (
            "target-crash",
            _c5_for_lineage(root, _subset_lineage(root, [2])),
            [_fact("target-attributable", True), _fact("logical-completion-credit", 1)],
        ),
        (
            "adapter-crash",
            _c5_for_lineage(root, _adapter_crash_lineage(root)),
            [_fact("target-attributable", False), _fact("logical-completion-credit", 0)],
        ),
    ]
    results = []
    for name, result, facts in scenarios:
        expected = "FAIL" if name in {"retry-exhaustion", "adapter-crash"} else "PASS"
        expected_ratio = "0/1" if expected == "FAIL" else "1/1"
        if result["status"] != expected or result["exact_ratio"] != expected_ratio:
            fail("foundation-c5-integration", f"{name} produced {result['status']} {result['exact_ratio']}")
        results.append(
            {
                "scenario": name,
                "status": "PASS",
                "facts": [*facts, _fact("c5-status", result["status"]), _fact("c5-ratio", result["exact_ratio"])],
            }
        )
    return tuple(results)


def _execution_scenarios(root: Path) -> list[dict[str, Any]]:
    return deepcopy(list(_execution_scenarios_cached(root)))


def _expected_error(action: Any) -> str:
    try:
        action()
    except ConformanceDataError as error:
        return error.code
    fail("foundation-adversarial-fixture", "a corruption fixture was not rejected")


@lru_cache(maxsize=4)
def _c6_integrity_scenarios_cached(root: Path) -> tuple[dict[str, Any], ...]:
    identity = deepcopy(load_strict(root / IDENTITY_CATALOG_PATH))
    identity["bindings"].append(deepcopy(identity["bindings"][0]))
    identity["catalog_digest_sha256"] = catalog_digest(identity)

    derivation = deepcopy(load_strict(root / DERIVATION_CATALOG_PATH))
    derivation["artifacts"][0]["assertion_bindings"][0]["derivation_id"] = (
        "rcid:v1:assertion-derivation:u7:019ffeff-0000-7000-8000-ffffffffffff"
    )

    broken_predecessor = _subset_lineage(root, [1])
    broken_predecessor["lineages"][0]["attempts"][1]["predecessor_physical_run_id"] = (
        "rcid:v1:physical-run:u7:019ffeff-0000-7000-8000-ffffffffffff"
    )
    broken_predecessor["lineage_set_sha256"] = lineage_set_sha256(broken_predecessor)

    wrong_attempt = _subset_lineage(root, [0])
    wrong_attempt["lineages"][0]["observations"][0]["terminal_attempt_id"] = (
        "rcid:v1:physical-run:u7:019ffeff-0000-7000-8000-ffffffffffff"
    )
    wrong_attempt["lineage_set_sha256"] = lineage_set_sha256(wrong_attempt)

    contract = load_strict(root / CONTRACT_PATH)
    stale_input = deepcopy(load_strict(root / CURRENT_INPUT_PATH))
    stale_input["source_artifacts"][0]["sha256"] = "f" * 64
    stale_input = _finalize_input(
        root,
        {key: value for key, value in stale_input.items() if key not in {"input_set_id", "input_set_digest_sha256"}},
    )

    evidence_report = load_strict(root / "reports/small-scale/evidence-verification-qualification.json")
    evidence_case = next(item for item in evidence_report["cases"] if item["case_key"] == "artifact-digest-substitution")
    load_and_validate_evidence_records(root, validate_instance=validate_instance)

    detectors = [
        ("identity-mismatch", lambda: verify_scientific_identity_catalog(root, identity)),
        ("dangling-derivation", lambda: validate_catalog_integrity(root, derivation)),
        ("broken-attempt-predecessor", lambda: validate_lineage_set(root, broken_predecessor)),
        ("observation-wrong-attempt", lambda: validate_lineage_set(root, wrong_attempt)),
        ("certification-input-digest-drift", lambda: validate_input_set(root, contract, stale_input)),
    ]
    expected_codes = {
        "identity-mismatch": "reused-scientific-id",
        "dangling-derivation": "dangling-derivation-reference",
        "broken-attempt-predecessor": "invalid-attempt-predecessor",
        "observation-wrong-attempt": "missing-terminal-observation",
        "certification-input-digest-drift": "stale-certification-source",
    }
    c6_report = evaluate(root, contract, _case_by_name(root, "evidence-corruption")["input_set"])
    c6 = _criterion(c6_report, "C6")
    if c6["status"] != "FAIL" or any(
        item["status"] != "PASS" for item in c6_report["criteria"] if item["criterion_id"] != "C6"
    ):
        fail("foundation-c6-integration", "C6 corruption did not fail independently")
    results = []
    for name, action in detectors:
        code = _expected_error(action)
        if code != expected_codes[name]:
            fail("foundation-integrity-detector", f"{name} produced {code}, expected {expected_codes[name]}")
        results.append(
            {
                "scenario": name,
                "status": "PASS",
                "facts": [_fact("detector-code", code), _fact("c6-status", "FAIL"), _fact("other-criteria-reportable", True)],
            }
        )
    if evidence_case["expected_code"] != "artifact-digest-mismatch":
        fail("foundation-evidence-corruption", "seeded evidence digest corruption no longer maps to the expected detector")
    results.append(
        {
            "scenario": "evidence-object-digest-mismatch",
            "status": "PASS",
            "facts": [_fact("detector-code", evidence_case["expected_code"]), _fact("c6-status", "FAIL"), _fact("other-criteria-reportable", True)],
        }
    )
    return tuple(results)


def _c6_integrity_scenarios(root: Path) -> list[dict[str, Any]]:
    return deepcopy(list(_c6_integrity_scenarios_cached(root)))


def _lineage(root: Path, **overrides: Any) -> dict[str, Any]:
    record = {
        "change_kind": "renamed-from",
        "current_fingerprints": [],
        "current_keys": ["new-key"],
        "effective_date": "2026-09-07",
        "identity_effect": "retained",
        "prior_fingerprints": [],
        "prior_keys": ["old-key"],
        "rationale": "Synthetic migration-readiness fixture.",
        "source_ids": [],
        "target_ids": [],
    }
    record.update(overrides)
    record["lineage_record_id"] = lineage_record_id(root, record)
    return record


@lru_cache(maxsize=4)
def _migration_scenarios_cached(root: Path) -> tuple[dict[str, Any], ...]:
    catalog = load_strict(root / IDENTITY_CATALOG_PATH)
    descriptors, _ = collect_descriptors(root)
    identities = {
        key: binding["scientific_id"]
        for binding in catalog["bindings"]
        for key in [binding["canonical_key"], *binding["former_keys"]]
    }
    feature = next(item for item in descriptors if item.entity_class == "feature")
    presentation = deepcopy(feature.record)
    presentation["canonical_name"] = "Synthetic clearer wording"
    presentation["category"] = "synthetic-category-move"
    presentation_descriptor = ScientificDescriptor(feature.entity_class, feature.key, feature.source_role, presentation)
    original_fingerprint = semantic_fingerprint(feature, identities)
    presentation_fingerprint = semantic_fingerprint(presentation_descriptor, identities)
    if original_fingerprint != presentation_fingerprint:
        fail("foundation-migration-rename", "presentation-only changes altered scientific identity basis")

    corrected = deepcopy(feature.record)
    corrected["semantic_definition"] += " Synthetic material semantic correction."
    corrected_descriptor = ScientificDescriptor(feature.entity_class, feature.key, feature.source_role, corrected)
    corrected_fingerprint = semantic_fingerprint(corrected_descriptor, identities)
    if original_fingerprint == corrected_fingerprint:
        fail("foundation-migration-correction", "material semantic correction retained the old fingerprint")

    ids = [item["scientific_id"] for item in catalog["bindings"][:7]]
    lineage = [
        _lineage(root, source_ids=[ids[0]], target_ids=[ids[0]]),
        _lineage(root, change_kind="supersedes", identity_effect="new-identity", source_ids=[ids[0]], target_ids=[ids[1]]),
        _lineage(root, change_kind="split-from", identity_effect="new-identity", source_ids=[ids[1]], target_ids=[ids[2], ids[3]]),
        _lineage(root, change_kind="merged-from", identity_effect="new-identity", source_ids=[ids[2], ids[3]], target_ids=[ids[4]]),
        _lineage(root, change_kind="deprecated", source_ids=[ids[5]], target_ids=[], current_keys=[]),
    ]
    validate_lineage_records(root, lineage, set(ids))

    obligation = next(item for item in catalog["bindings"] if item["entity_class"] == "obligation")
    new_obligation = "rcid:v1:obligation:u7:019ffeff-0000-7000-8000-ffffffffffff"
    NamespaceRegistry.load(root / NAMESPACE_PATH).validate(new_obligation)
    if new_obligation in {item["scientific_id"] for item in catalog["bindings"]}:
        fail("foundation-migration-new-identity", "synthetic new obligation reused an existing ID")

    ordinary = {
        item.key: semantic_fingerprint(item, identities)
        for item in descriptors
    }
    reordered = {item.key: ordinary[item.key] for item in reversed(descriptors)}
    if ordinary != reordered:
        fail("foundation-migration-reorder", "generator reordering changed contained scientific identities")

    derivation = deepcopy(_derivations_by_method(root)["certification-predicate-evaluation"])
    old_revision = derivation["derivation_revision_id"]
    derivation["method_version"] = "2.0.0"
    derivation["metadata"]["formula"] += " Synthetic materially revised method."
    new_revision = derivation_revision_id(root, derivation)
    if new_revision == old_revision:
        fail("foundation-migration-derivation", "material derivation change retained its content revision")

    contract = load_strict(root / CONTRACT_PATH)
    full_input = deepcopy(_case_by_name(root, "full-pass")["input_set"])
    old_report = evaluate(root, contract, full_input)
    old_report_bytes = canonical_bytes(old_report)
    additional = deepcopy(full_input["criteria"]["C4"]["members"][0])
    additional["member_id"] = "rcid:v1:semantic-requirement:u7:019ffeff-0000-7000-8000-ffffffffffff"
    full_input["criteria"]["C4"]["members"].append(additional)
    new_input = _refinalize_fixture_input(root, full_input)
    new_report = evaluate(root, contract, new_input)
    if old_report["report_id"] == new_report["report_id"] or canonical_bytes(old_report) != old_report_bytes:
        fail("foundation-migration-snapshot", "new semantic input did not advance report identity or changed historical bytes")

    hypothetical_v2_digest = _sha(
        {
            "contract_version": "2.0.0",
            "supersedes_contract_id": contract["contract_id"],
            "predicate_change": "synthetic-versioned-fixture",
        }
    )
    hypothetical_v2_id = _content_id(
        root,
        "certification-definition",
        "regex-conformance-certification-contract-v2-fixture",
        hypothetical_v2_digest,
    )
    if hypothetical_v2_id == contract["contract_id"]:
        fail("foundation-migration-contract", "successor contract reused the predecessor identity")

    scenarios = [
        ("feature-rename", ["scientific identity retained", "former key remains resolvable"]),
        ("feature-category-move", ["scientific identity retained", "presentation relocation excluded from fingerprint"]),
        ("feature-semantic-correction", ["semantic fingerprint changed", "successor identity required"]),
        ("feature-split", ["predecessor preserved", "two successor identities validated"]),
        ("feature-merge", ["predecessors preserved", "distinct merged successor validated"]),
        ("obligation-removal", [f"historical obligation remains resolvable: {obligation['scientific_id']}", "deprecation lineage validated"]),
        ("new-obligation", [f"new typed identity validated: {new_obligation}", "existing identity population unchanged"]),
        ("generator-reorder", ["contained scientific fingerprints unchanged", "enclosing artifact may change independently"]),
        ("derivation-method-revision", [f"stable handle retained: {derivation['derivation_id']}", f"revision changed from {old_revision} to {new_revision}"]),
        ("semantic-snapshot-successor", ["new input and report identities produced", "historical report bytes unchanged"]),
        ("certification-contract-successor", [f"v1 remains {contract['contract_id']}", f"current authority may advance to {hypothetical_v2_id}"]),
    ]
    return tuple(
        {"scenario": name, "status": "PASS", "evidence": evidence}
        for name, evidence in scenarios
    )


def _migration_scenarios(root: Path) -> list[dict[str, Any]]:
    return deepcopy(list(_migration_scenarios_cached(root)))


def scan_certification_bypasses(root: Path) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    paths: list[Path] = []
    for directory, names, files in os.walk(root):
        names[:] = sorted(name for name in names if name not in CLAIM_SCAN_EXCLUDED_PARTS)
        base = Path(directory)
        paths.extend(base / name for name in sorted(files))
    for path in paths:
        if path.suffix.lower() not in CLAIM_SCAN_SUFFIXES:
            continue
        relative = path.relative_to(root).as_posix()
        if path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if relative not in ALLOWED_AUTHORITATIVE_MARKER_PATHS and not relative.startswith(ALLOWED_AUTHORITATIVE_MARKER_PREFIXES):
            for marker in AUTHORITATIVE_REPORT_MARKERS:
                if marker.search(text):
                    violations.append({"path": relative, "reason": "authoritative-report-marker-outside-canonical-owner"})
                    break
        if relative not in ALLOWED_FULL_PASS_PATHS and relative not in ALLOWED_FULL_PASS_SCHEMA_PATHS and not relative.startswith(ALLOWED_FULL_PASS_PREFIXES):
            for marker in FULL_PASS_MARKERS:
                if marker.search(text):
                    violations.append({"path": relative, "reason": "full-certification-pass-claim-outside-authority-surface"})
                    break
    return sorted(violations, key=lambda item: (item["path"], item["reason"]))


def _validate_derivation_bindings(
    root: Path,
    bindings: list[dict[str, str]],
    *,
    require_current_revision: bool,
) -> None:
    records = _derivations_by_method(root) if require_current_revision else {}
    registry = NamespaceRegistry.load(root / NAMESPACE_REGISTRY_PATH)
    seen: set[str] = set()
    for binding in bindings:
        key = binding["binding_key"]
        if key in seen:
            fail("duplicate-foundation-derivation", "foundation derivation binding is duplicated", key)
        seen.add(key)
        registry.validate(binding["derivation_revision_id"])
        if not require_current_revision:
            continue
        record = records.get(binding["method_key"])
        if record is None or record["derivation_revision_id"] != binding["derivation_revision_id"]:
            fail("stale-foundation-derivation", "foundation assertion references a missing or stale derivation", key)
        if record["derivation_class"] != binding["derivation_class"]:
            fail("foundation-evidence-escalation", "foundation assertion changes the catalogued evidence strength", key)


def _validate_authority_matrix(matrix: list[dict[str, Any]]) -> None:
    expected_domains = {item["decision_domain"] for item in AUTHORITY_MATRIX}
    actual_domains = [item["decision_domain"] for item in matrix]
    if set(actual_domains) != expected_domains or len(actual_domains) != len(set(actual_domains)):
        fail("foundation-authority-conflict", "each authority decision domain must have exactly one canonical owner")
    known = set(FOUNDATION_BINDINGS)
    for item in matrix:
        if item["canonical_owner"] not in known:
            fail("foundation-authority-owner", "authority matrix names an unknown canonical owner", item["decision_domain"])
        if item["canonical_owner"] in item["forbidden_alternate_owners"]:
            fail("foundation-authority-conflict", "canonical owner is also forbidden", item["decision_domain"])
        if not set(item["consumes_from"] + item["forbidden_alternate_owners"]).issubset(known):
            fail("foundation-authority-owner", "authority matrix names an unknown subsystem", item["decision_domain"])


def validate_manifest(root: Path, manifest: dict[str, Any], *, verify_current_files: bool) -> None:
    validate_instance(manifest, load_strict(root / MANIFEST_SCHEMA_PATH), source="scientific foundation manifest")
    digest = _record_digest(manifest, "foundation_manifest_id", "foundation_manifest_digest_sha256")
    if manifest["foundation_manifest_digest_sha256"] != digest:
        fail("foundation-manifest-digest-mismatch", "foundation manifest digest differs")
    expected_id = _content_id(root, "artifact-set-manifest", "scientific-foundation-manifest-v1", digest)
    if manifest["foundation_manifest_id"] != expected_id:
        fail("foundation-manifest-id-mismatch", "foundation manifest content identity differs")
    if manifest["accepted_source_repository_sha"] != ACCEPTED_SOURCE_SHA:
        fail("foundation-source-revision-mismatch", "foundation manifest names another accepted source revision")
    _validate_derivation_bindings(
        root,
        manifest["assertion_derivations"],
        require_current_revision=verify_current_files,
    )
    _validate_authority_matrix(manifest["authority_matrix"])
    foundation_keys = [item["foundation_key"] for item in manifest["foundations"]]
    if foundation_keys != sorted(FOUNDATION_BINDINGS):
        fail("foundation-set-mismatch", "foundation manifest must bind the exact four accepted subsystems")
    if verify_current_files:
        expected = build_manifest(root)
        if canonical_bytes(manifest) != canonical_bytes(expected):
            fail("foundation-manifest-drift", "tracked foundation manifest differs from the accepted current source")


@lru_cache(maxsize=4)
def _verified_foundation_counts(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    identity_counts = verify_scientific_identity_catalog(root)
    derivation_counts = verify_derivation_catalog(root)
    execution_counts = verify_repository_execution_provenance(root)
    certification_counts = verify_repository_certification(root)
    return identity_counts, derivation_counts, execution_counts, certification_counts


def _foundation_checks(root: Path, manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    identity_counts, derivation_counts, execution_counts, certification_counts = _verified_foundation_counts(root)
    if identity_counts["scientific_identities"] < 22359:
        fail(
            "foundation-identity-population",
            "current scientific identity population dropped below the accepted 22,359-identity foundation baseline",
        )
    if load_strict(root / CURRENT_REPORT_PATH)["final_state"] != "FAIL":
        fail("foundation-scientific-certification-state", "current scientific certification state unexpectedly changed")
    bypasses = scan_certification_bypasses(root)
    if bypasses:
        fail("foundation-certification-bypass", "a non-canonical surface can emit or claim full certification", bypasses[0]["path"])
    execution_scenarios = _execution_scenarios(root)
    integrity_scenarios = _c6_integrity_scenarios(root)
    migrations = _migration_scenarios(root)
    checks = [
        _check("authority-matrix", "four decision domains have one canonical owner each"),
        _check("certification-bypass-audit", "no authoritative report marker or full C1-C7 PASS claim escaped its governed surface"),
        _check("certification-contract", f"criteria={certification_counts['certification_criteria']}", f"state={certification_counts['current_certification_state']}"),
        _check("cross-contract-identity", "all typed references and content-derived report identities validated"),
        _check("derivation-catalog", f"artifacts={derivation_counts['generated_assertion_artifacts']}", f"groups={derivation_counts['generated_assertion_groups']}"),
        _check("deterministic-regeneration", "foundation manifest and report rebuild byte-identically"),
        _check("execution-provenance", f"logical-executions={execution_counts['logical_execution_count']}", f"physical-attempts={execution_counts['physical_attempt_count']}"),
        _check("foundation-manifest-closure", manifest["foundation_manifest_digest_sha256"]),
        _check("historical-compatibility", "four historical execution/evidence schemas retain exact digests", "historical records rewritten=false"),
        _check("identity-lock", f"identities={identity_counts['scientific_identities']}", f"lineage={identity_counts['scientific_lineage_records']}"),
        _check("integration-scenarios", f"execution={len(execution_scenarios)}", f"integrity={len(integrity_scenarios)}"),
        _check("scientific-input-baseline", *[item["sha256"] for item in manifest["scientific_input_baseline"]["artifacts"]]),
    ]
    if tuple(sorted(item["check_id"] for item in checks)) != REQUIRED_GATE_CHECKS:
        fail("foundation-check-set", "acceptance evaluator did not execute the exact required check set")
    return checks, [*execution_scenarios, *integrity_scenarios], migrations


def build_acceptance_report(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    checks, integrations, migrations = _foundation_checks(root, manifest)
    certification = load_strict(root / CURRENT_REPORT_PATH)
    criterion_states = [
        {"criterion_id": item["criterion_id"], "status": item["status"]}
        for item in certification["criteria"]
    ]
    body = {
        "schema_version": "scientific-foundation-acceptance.v1",
        "accepted_source_repository_sha": manifest["accepted_source_repository_sha"],
        "assertion_derivations": deepcopy(manifest["assertion_derivations"]),
        "checks": checks,
        "current_scientific_certification": {
            "certification_eligible": certification["certification_eligible"],
            "contract_id": certification["contract_id"],
            "criteria": criterion_states,
            "final_state": certification["final_state"],
            "report_digest_sha256": certification["report_digest_sha256"],
            "report_id": certification["report_id"],
        },
        "deferred_finding_dispositions": Counter(item["classification"] for item in manifest["deferred_findings"]),
        "foundation_acceptance": "PASS",
        "foundation_manifest_digest_sha256": manifest["foundation_manifest_digest_sha256"],
        "foundation_manifest_id": manifest["foundation_manifest_id"],
        "hosted_validation_basis": deepcopy(manifest["hosted_validation_basis"]),
        "integration_scenarios": integrations,
        "migration_readiness": migrations,
        "scientific_input_change_count": 0,
    }
    body["deferred_finding_dispositions"] = dict(sorted(body["deferred_finding_dispositions"].items()))
    return _finalize(
        root,
        body,
        namespace="trust-assessment",
        artifact_kind="scientific-foundation-acceptance-v1",
        id_field="acceptance_report_id",
        digest_field="acceptance_report_digest_sha256",
    )


def validate_acceptance_report(
    root: Path,
    manifest: dict[str, Any],
    report: dict[str, Any],
    *,
    verify_current_derivations: bool = True,
) -> None:
    validate_instance(report, load_strict(root / ACCEPTANCE_SCHEMA_PATH), source="scientific foundation acceptance")
    digest = _record_digest(report, "acceptance_report_id", "acceptance_report_digest_sha256")
    if report["acceptance_report_digest_sha256"] != digest:
        fail("foundation-acceptance-digest-mismatch", "foundation acceptance report digest differs")
    expected_id = _content_id(root, "trust-assessment", "scientific-foundation-acceptance-v1", digest)
    if report["acceptance_report_id"] != expected_id:
        fail("foundation-acceptance-id-mismatch", "foundation acceptance report identity differs")
    if (
        report["foundation_manifest_id"] != manifest["foundation_manifest_id"]
        or report["foundation_manifest_digest_sha256"] != manifest["foundation_manifest_digest_sha256"]
    ):
        fail("foundation-acceptance-manifest-mismatch", "acceptance report binds another foundation manifest")
    if report["foundation_acceptance"] != "PASS" or any(item["status"] != "PASS" for item in report["checks"]):
        fail("foundation-acceptance-failed", "foundation acceptance report is not fully passing")
    if tuple(sorted(item["check_id"] for item in report["checks"])) != REQUIRED_GATE_CHECKS:
        fail("foundation-check-set", "acceptance report does not contain the exact required check set")
    if report["scientific_input_change_count"] != 0:
        fail("foundation-scientific-input-churn", "foundation acceptance changed scientific baseline artifacts")
    if report["current_scientific_certification"]["final_state"] == "PASS":
        fail("foundation-certification-conflation", "foundation acceptance is not full scientific certification")
    _validate_derivation_bindings(
        root,
        report["assertion_derivations"],
        require_current_revision=verify_current_derivations,
    )


def verify_foundation_history(root: Path) -> dict[str, Any]:
    manifest = load_strict(root / MANIFEST_PATH)
    report = load_strict(root / ACCEPTANCE_PATH)
    validate_manifest(root, manifest, verify_current_files=False)
    validate_acceptance_report(root, manifest, report, verify_current_derivations=False)
    return {
        "foundation_acceptance": report["foundation_acceptance"],
        "foundation_checks": len(report["checks"]),
        "foundation_integration_scenarios": len(report["integration_scenarios"]),
        "foundation_migration_scenarios": len(report["migration_readiness"]),
    }


def verify_current_foundation(root: Path) -> dict[str, Any]:
    manifest = load_strict(root / MANIFEST_PATH)
    validate_manifest(root, manifest, verify_current_files=True)
    report = load_strict(root / ACCEPTANCE_PATH)
    expected = build_acceptance_report(root, manifest)
    validate_acceptance_report(root, manifest, report)
    if canonical_bytes(report) != canonical_bytes(expected):
        fail("foundation-acceptance-drift", "tracked acceptance report differs from fresh integrated evaluation")
    return verify_foundation_history(root)


def _write(root: Path, relative: Path, value: dict[str, Any]) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(dump_pretty(value), encoding="utf-8", newline="\n")
    os.replace(temporary, path)
    if load_strict(path) != value:
        fail("foundation-write-verification-failed", "read-after-write differs", relative.as_posix())


def materialize_foundation(root: Path) -> dict[str, Any]:
    manifest = build_manifest(root)
    report = build_acceptance_report(root, manifest)
    _write(root, MANIFEST_PATH, manifest)
    _write(root, ACCEPTANCE_PATH, report)
    return verify_current_foundation(root)
