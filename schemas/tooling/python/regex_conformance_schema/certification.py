"""Versioned C1-C7 certification predicates and deterministic evaluation."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from functools import lru_cache
import hashlib
import os
from pathlib import Path
from typing import Any

from .derivation import verify_catalog as verify_derivation_catalog
from .errors import ConformanceDataError, fail
from .execution_provenance import (
    FIXTURE_PATH as EXECUTION_FIXTURE_PATH,
    POLICY_PATH as EXECUTION_POLICY_PATH,
    lineage_set_sha256,
    validate_lineage_set,
)
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import verify_catalog as verify_scientific_identity_catalog


CONTRACT_PATH = Path("certification/contracts/regex-conformance-certification.v1.json")
CURRENT_INPUT_PATH = Path("certification/inputs/current-repository.v1.json")
CURRENT_REPORT_PATH = Path("certification/reports/current-repository.v1.json")
CURRENT_AUTHORITY_PATH = Path("certification/current-authority.v1.json")
FIXTURE_PATH = Path("tests/fixtures/certification/certification-predicates.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v2.json")
CONTENT_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")
DERIVATION_CATALOG_PATH = Path("registries/provenance/generated-assertion-derivations.v1.json")
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a079d7-bff3-79f7-bd14-3184c831b9f5"

SCHEMA_PATHS = {
    "authority": Path("schemas/json/certification-authority-index.schema.json"),
    "contract": Path("schemas/json/certification-contract.schema.json"),
    "fixtures": Path("schemas/json/certification-predicate-fixtures.schema.json"),
    "input": Path("schemas/json/certification-input-set.schema.json"),
    "report": Path("schemas/json/certification-report.schema.json"),
}

CRITERION_ORDER = ("C1", "C2", "C3", "C4", "C5", "C6", "C7")
INDEPENDENT_CLASSES = {"external-evidence", "measurement", "research-derived"}
FAILURE_PRECEDENCE = {"PASS": 0, "BLOCKED": 1, "FAIL": 2}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _record_digest(record: dict[str, Any], *excluded: str) -> str:
    return _sha({key: value for key, value in record.items() if key not in set(excluded)})


def _artifact_content_id(root: Path, namespace: str, artifact_kind: str, content_sha256: str) -> str:
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / CONTENT_PROFILE_PATH)),
        namespace=namespace,
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": artifact_kind, "content_sha256": content_sha256},
    )
    return str(result["content_id"])


def _finalize_content_record(
    root: Path,
    record: dict[str, Any],
    *,
    namespace: str,
    artifact_kind: str,
    id_field: str,
    digest_field: str,
) -> dict[str, Any]:
    record = deepcopy(record)
    record["identity_schema_family_id"] = SCHEMA_FAMILY_ID
    record["identity_schema_version"] = "1.0.0"
    record[id_field] = ""
    record[digest_field] = ""
    digest = _record_digest(record, id_field, digest_field)
    record[digest_field] = digest
    record[id_field] = _artifact_content_id(root, namespace, artifact_kind, digest)
    return record


def _authority_names() -> list[str]:
    return [
        "Certify campaigns and evidence through exact manifests, complete completeness proofs, and append-only validity selection",
        "Define completeness as exact snapshot-bound set ratios",
        "Regex Conformance Foundation Specification",
        "Use immutable lineage-aware universe snapshots and qualified certification claims",
        "Use latest stable patch or update as the active representative of each release line",
    ]


def _implementation_bindings(root: Path) -> list[dict[str, str]]:
    paths = [
        "schemas/tooling/python/regex_conformance_schema/certification.py",
        "schemas/tooling/python/regex_conformance_schema/execution_provenance.py",
        "schemas/tooling/python/regex_conformance_schema/scientific_identity.py",
        *(path.as_posix() for path in SCHEMA_PATHS.values()),
    ]
    return [
        {"relative_path": relative, "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest()}
        for relative in sorted(paths)
    ]


def _criterion(
    criterion_id: str,
    title: str,
    *,
    inputs: list[str],
    derivations: list[str],
    independent: bool,
    dependencies: list[str],
    operation: str,
    allowed: list[str],
    qualifying: list[str],
    details: list[str],
    empty: str,
    exclusion: str,
    failures: list[str],
    blockers: list[str],
    diagnostics: list[str],
    authorities: list[str],
) -> dict[str, Any]:
    return {
        "criterion_id": criterion_id,
        "version": "1.0.0",
        "title": title,
        "predicate_digest_sha256": "",
        "required_for_final": True,
        "governing_authorities": sorted(authorities),
        "input_artifact_classes": sorted(inputs),
        "admitted_derivation_classes": sorted(derivations),
        "independent_evidence_required": independent,
        "dependencies": dependencies,
        "predicate": {
            "operation": operation,
            "allowed_states": allowed,
            "qualifying_states": qualifying,
            "required_member_details": details,
            "empty_denominator": empty,
            "denominator_exclusion_rule": exclusion,
        },
        "failure_conditions": failures,
        "blocked_conditions": blockers,
        "diagnostic_codes": diagnostics,
        "revision_policy": "Change the criterion version and content digest whenever its population, admitted evidence, state semantics, or predicate meaning changes; never reinterpret an old report in place.",
        "revocation_conditions": [
            "A referenced canonical input or evidence member is invalidated.",
            "A defect is confirmed in this criterion predicate or its authoritative source validator.",
        ],
    }


def build_contract(root: Path) -> dict[str, Any]:
    exact_sets = "Define completeness as exact snapshot-bound set ratios"
    foundation = "Regex Conformance Foundation Specification"
    campaign = "Certify campaigns and evidence through exact manifests, complete completeness proofs, and append-only validity selection"
    release_line = "Use latest stable patch or update as the active representative of each release line"
    evidence = "Publish empirical evidence append-only and correct it through explicit validity, replacement, and selection graphs"
    discrepancy = "Qualify evidence integrity, replication, confidence, reconciliation, and discrepancy independently"
    criteria = [
        _criterion(
            "C1", "Universe disposition coverage",
            inputs=["candidate-disposition-ledger", "universe-snapshot"],
            derivations=["calculation", "external-evidence", "research-derived"],
            independent=True, dependencies=[], operation="all-qualified",
            allowed=["alias", "in-scope", "not-a-regex-facility", "normative-only", "out-of-scope", "pending", "resolved-by-split"],
            qualifying=["alias", "in-scope", "not-a-regex-facility", "normative-only", "out-of-scope", "resolved-by-split"],
            details=["record_complete"], empty="FAIL",
            exclusion="No frozen candidate is excluded. A split predecessor remains in the denominator but creates no downstream release, profile, or execution obligations.",
            failures=["A candidate is undispositioned or pending.", "Canonical ownership is duplicated.", "A split, alias, or disposition graph is invalid."],
            blockers=["The discovery cutoff or canonical universe snapshot is absent or provisional."],
            diagnostics=["candidate-disposition-incomplete", "duplicate-canonical-owner", "empty-universe-denominator", "invalid-candidate-lineage", "universe-input-blocked"],
            authorities=[exact_sets, foundation],
        ),
        _criterion(
            "C2", "Governed release-line representative coverage",
            inputs=["release-line-registry", "universe-snapshot"],
            derivations=["calculation", "external-evidence", "research-derived"],
            independent=True, dependencies=["C1"], operation="all-qualified",
            allowed=["accounted", "channel-conflict", "missing", "stale-representative"],
            qualifying=["accounted"], details=["record_complete"], empty="FAIL",
            exclusion="Only candidates validly dispositioned outside the governed executable universe by C1 are excluded; historic exceptions remain explicit denominator members.",
            failures=["A governed release line lacks its valid latest stable representative.", "A representative is stale, duplicated, or lacks provenance."],
            blockers=["Universe admission, channel evidence, or release-line selection remains provisional."],
            diagnostics=["duplicate-canonical-owner", "empty-release-denominator", "release-representative-incomplete", "release-input-blocked"],
            authorities=[exact_sets, foundation, release_line],
        ),
        _criterion(
            "C3", "Concrete-profile reproducibility accounting",
            inputs=["profile-reproducibility-ledger", "release-line-registry"],
            derivations=["calculation", "external-evidence", "measurement", "research-derived"],
            independent=True, dependencies=["C2"], operation="report-actual",
            allowed=["access-or-license-blocked", "artifact-unavailable", "attainable-unverified", "identity-or-provenance-insufficient", "pending-assessment", "platform-or-hardware-blocked", "reconstruction-failed", "service-retired-or-unreachable", "verified-reproducible"],
            qualifying=["verified-reproducible"], details=["record_complete"], empty="BLOCKED",
            exclusion="No derived concrete-profile obligation is excluded. Controlled non-reproducible and unresolved states remain in the denominator.",
            failures=["A profile obligation is omitted, duplicated, or uses an uncontrolled assessment state."],
            blockers=["Stable representatives or concrete-profile derivation are incomplete."],
            diagnostics=["duplicate-canonical-owner", "profile-input-blocked", "reproducibility-accounting-invalid"],
            authorities=[exact_sets, foundation, release_line],
        ),
        _criterion(
            "C4", "Semantic obligation and vector coverage",
            inputs=["applicability-ledger", "scientific-identity-catalog", "semantic-requirement-ledger", "vector-attribution-ledger"],
            derivations=["calculation", "external-evidence", "manual-decision", "research-derived"],
            independent=True, dependencies=["C1", "C2"], operation="all-qualified",
            allowed=["approved-unperformable", "certified-vector-mapping", "invalid-lineage", "missing", "prose-exclusion"],
            qualifying=["approved-unperformable", "certified-vector-mapping"], details=[], empty="FAIL",
            exclusion="Only coordinates proven non-applicable by the canonical applicability authority are excluded. Prose exclusions and prerequisite labels do not remove a member.",
            failures=["An applicable obligation has no explicit certified vector attribution or approved machine-readable unperformable disposition.", "Requirement ownership or generated-instance lineage is duplicate, stale, or invalid."],
            blockers=["The profile, semantic, applicability, or obligation population is absent or provisional."],
            diagnostics=["construction-evidence-rejected", "duplicate-requirement-owner", "empty-vector-denominator", "semantic-identity-stale", "vector-coverage-incomplete", "vector-input-blocked"],
            authorities=[exact_sets, foundation],
        ),
        _criterion(
            "C5", "Logical execution completion",
            inputs=["execution-lineage-set", "execution-policy", "logical-campaign-manifest"],
            derivations=["calculation", "measurement"],
            independent=True, dependencies=["C4"], operation="all-qualified",
            allowed=["satisfied", "unresolved"], qualifying=["satisfied"], details=[], empty="FAIL",
            exclusion="Physical attempts and repeats are never denominator members; the denominator is the exact frozen set of unique logical executions.",
            failures=["A planned logical execution lacks an admissible target-attributable terminal observation set.", "Retry, recovery, or repeat attempts create duplicate logical credit."],
            blockers=["No frozen production campaign or complete execution-lineage set exists."],
            diagnostics=["execution-input-blocked", "inconclusive-attempt-no-credit", "logical-execution-incomplete", "nonmeasurement-execution-evidence"],
            authorities=[campaign, exact_sets, foundation],
        ),
        _criterion(
            "C6", "Evidence integrity coverage",
            inputs=["evidence-integrity-assessment", "evidence-manifest", "observation-validity-graph"],
            derivations=["calculation", "external-evidence", "measurement"],
            independent=True, dependencies=["C5"], operation="all-qualified",
            allowed=["corrupt", "correction-graph-valid", "dangling-reference", "integrity-valid", "schema-invalid"],
            qualifying=["correction-graph-valid", "integrity-valid"], details=["validator_receipt_sha256"], empty="FAIL",
            exclusion="No official observation is excluded, including invalidated and superseded history; correction and selection state is represented in the validity graph.",
            failures=["An official observation or preserved correction-history member fails content, manifest, schema, provenance, or reference integrity."],
            blockers=["No complete official observation population and current integrity assessments exist."],
            diagnostics=["evidence-input-blocked", "evidence-integrity-incomplete", "missing-integrity-validator-receipt"],
            authorities=[campaign, evidence, exact_sets, foundation],
        ),
        _criterion(
            "C7", "Discrepancy detection and triage coverage",
            inputs=["discrepancy-ledger", "reconciliation-set", "zero-result-detection-manifest"],
            derivations=["calculation", "external-evidence", "manual-decision", "measurement", "research-derived"],
            independent=True, dependencies=["C5", "C6"], operation="all-qualified-or-certified-empty",
            allowed=["bare-unresolved", "confirmed-deviation", "expected-differential", "resolved", "structured-unresolved"],
            qualifying=["confirmed-deviation", "expected-differential", "resolved", "structured-unresolved"], details=["record_complete"], empty="CERTIFIED_ZERO_RESULT",
            exclusion="No detected discrepancy is excluded. An empty set is authoritative only with a completed independently evidenced zero-result detection manifest.",
            failures=["A detected discrepancy lacks a proof-bearing disposition or structured unresolved triage.", "Reconciliation/accounting debt is orphaned or inconsistent."],
            blockers=["No completed reconciliation detection pass exists."],
            diagnostics=["discrepancy-input-blocked", "discrepancy-triage-incomplete", "missing-zero-result-manifest"],
            authorities=[campaign, discrepancy, exact_sets, foundation],
        ),
    ]
    for item in criteria:
        item["predicate_digest_sha256"] = _record_digest(item, "predicate_digest_sha256")
    body = {
        "schema_version": "certification-contract.v1",
        "contract_key": "regex-conformance-completeness",
        "contract_version": "1.0.0",
        "governing_authorities": sorted(_authority_names()),
        "implementation_bindings": _implementation_bindings(root),
        "authority_boundary": {
            "program_authority": "The canonical program workspace owns governance intent, accepted decisions, and amendments requiring Program Owner authority.",
            "repository_authority": "This versioned contract, its schemas, evaluator, fixtures, and deterministic reports own the exact executable predicates.",
            "policy_change_rule": "A policy defect requires a recorded consequential amendment and a new contract revision; an evaluator cannot waive or silently reinterpret a predicate.",
        },
        "result_states": {
            "PASS": "The predicate is true over complete admissible inputs.",
            "FAIL": "The inputs are sufficient to prove the predicate false or invalid.",
            "BLOCKED": "The predicate lacks complete authoritative prerequisites and makes no semantic failure claim.",
        },
        "criteria": criteria,
        "final_composition": {
            "criterion_order": list(CRITERION_ORDER),
            "failure_precedence": ["FAIL", "BLOCKED", "PASS"],
            "operator": "required-criterion-conjunction",
            "pass_condition": "Every required criterion reports PASS under this exact contract revision.",
        },
        "supersession_and_revocation": {
            "authority_location": "separate-certification-authority-index",
            "historical_reports_immutable": True,
            "supersession_triggers": [
                "A newer canonical semantic snapshot, universe/profile registry, requirement set, evidence contract, or certification contract becomes current authority.",
                "A newer certification report covers the same governed scope under current inputs.",
            ],
            "revocation_triggers": [
                "Referenced evidence is proven corrupt or invalid.",
                "A referenced canonical artifact is invalidated.",
                "A certification-predicate or evaluator defect is confirmed.",
                "The prior governed scope no longer represents current authority.",
            ],
        },
    }
    return _finalize_content_record(
        root, body, namespace="certification-definition",
        artifact_kind="regex-conformance-certification-contract-v1",
        id_field="contract_id", digest_field="contract_digest_sha256",
    )


def validate_contract(root: Path, contract: dict[str, Any]) -> None:
    validate_instance(contract, load_strict(root / SCHEMA_PATHS["contract"]), source="certification contract")
    if contract["contract_digest_sha256"] != _record_digest(contract, "contract_id", "contract_digest_sha256"):
        fail("certification-contract-digest-mismatch", "certification contract digest differs")
    expected_id = _artifact_content_id(
        root, "certification-definition", "regex-conformance-certification-contract-v1",
        contract["contract_digest_sha256"],
    )
    if contract["contract_id"] != expected_id:
        fail("certification-contract-id-mismatch", "certification contract identity differs")
    identifiers = [item["criterion_id"] for item in contract["criteria"]]
    if identifiers != list(CRITERION_ORDER):
        fail("certification-criterion-order", "contract must define C1-C7 exactly once in order")
    for item in contract["criteria"]:
        if item["predicate_digest_sha256"] != _record_digest(item, "predicate_digest_sha256"):
            fail("certification-predicate-digest-mismatch", "criterion predicate digest differs", item["criterion_id"])
        if item["independent_evidence_required"] and "constant-by-construction" in item["admitted_derivation_classes"]:
            fail("certification-evidence-escalation", "construction evidence cannot satisfy an independent criterion", item["criterion_id"])
    seen_bindings: set[str] = set()
    for binding in contract["implementation_bindings"]:
        relative = binding["relative_path"]
        if relative in seen_bindings:
            fail("duplicate-certification-implementation", "an implementation binding is duplicated", relative)
        if ".." in relative.split("/") or relative.startswith("/"):
            fail("unsafe-certification-implementation", "implementation binding must be repository-relative", relative)
        source = root / relative
        if not source.is_file():
            fail("missing-certification-implementation", "a bound certification implementation is missing", relative)
        if hashlib.sha256(source.read_bytes()).hexdigest() != binding["sha256"]:
            fail("stale-certification-implementation", "a bound certification implementation digest differs", relative)
        seen_bindings.add(relative)


def _artifact_reference(root: Path, relative: str, artifact_class: str, authority_status: str, artifact_id: str | None = None) -> dict[str, Any]:
    path = root / relative
    return {
        "artifact_class": artifact_class,
        "artifact_id": artifact_id,
        "authority_status": authority_status,
        "relative_path": relative,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _derivation_revisions(root: Path) -> dict[str, str]:
    return {
        item["method_key"]: revision
        for revision, item in _catalog_by_revision(root).items()
    }


def _blocked_input(*codes: tuple[str, str], sources: list[str]) -> dict[str, Any]:
    return {
        "input_mode": "blocked",
        "population_status": "absent",
        "source_artifact_refs": sources,
        "derivation_revision_ids": [],
        "blockers": [{"code": code, "message": message} for code, message in codes],
        "members": [],
        "lineage_set": None,
        "zero_result_manifest": None,
    }


def _finalize_input(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    return _finalize_content_record(
        root, record, namespace="certification-input-set",
        artifact_kind="regex-conformance-certification-input-set-v1",
        id_field="input_set_id", digest_field="input_set_digest_sha256",
    )


def build_current_input(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    requirement_path = "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json"
    identity_path = "registries/identity/scientific-identities.v1.json"
    universe_path = "registries/universe/full-known-universe-2026-08-15.v1.json"
    profile_path = "registries/profiles/vertical-slice-coordinates.v1.json"
    campaign_path = "campaigns/compiled/first-vertical-slice.v1.json"
    evidence_path = "reports/small-scale/evidence-verification-qualification.json"
    execution_path = EXECUTION_FIXTURE_PATH.as_posix()
    campaign_manifest_id = load_strict(root / campaign_path)["campaign_manifest_id"]
    source_artifacts = [
        _artifact_reference(root, universe_path, "universe-planning-index", "planning-only"),
        _artifact_reference(root, identity_path, "scientific-identity-catalog", "canonical"),
        _artifact_reference(root, requirement_path, "semantic-requirement-ledger", "canonical"),
        _artifact_reference(root, profile_path, "profile-registry-slice", "qualification-only"),
        _artifact_reference(root, campaign_path, "campaign-plan", "qualification-only", campaign_manifest_id),
        _artifact_reference(root, execution_path, "execution-lineage-fixture", "validation-fixture"),
        _artifact_reference(root, evidence_path, "evidence-integrity-qualification", "historical"),
    ]
    revisions = _derivation_revisions(root)
    criteria = {
        "C1": _blocked_input(
            ("canonical-universe-snapshot-absent", "The available universe artifact is explicitly planning-only and cannot satisfy universe disposition certification."),
            sources=[universe_path],
        ),
        "C2": _blocked_input(
            ("canonical-release-line-registry-absent", "No canonical release-line representative registry covers the governed universe."),
            sources=[universe_path, profile_path],
        ),
        "C3": _blocked_input(
            ("canonical-profile-reproducibility-ledger-absent", "Only a three-profile qualification slice exists; the governed profile population is not materialized."),
            sources=[profile_path],
        ),
        "C4": {
            "input_mode": "semantic-vector-requirements-v1",
            "population_status": "complete",
            "source_artifact_refs": [identity_path, requirement_path],
            "derivation_revision_ids": sorted([
                revisions["semantic-source-synthesis"],
                revisions["vector-requirement-accounting"],
            ]),
            "blockers": [], "members": [], "lineage_set": None, "zero_result_manifest": None,
        },
        "C5": _blocked_input(
            ("production-campaign-absent", "The repository contains qualification plans and lineage fixtures, not a frozen production conformance campaign with official observations."),
            sources=[campaign_path, execution_path],
        ),
        "C6": _blocked_input(
            ("official-evidence-set-absent", "No official production observation/evidence manifest set exists; the tracked report is a corruption-qualification artifact."),
            sources=[evidence_path],
        ),
        "C7": _blocked_input(
            ("production-reconciliation-pass-absent", "No completed production reconciliation detection pass or discrepancy ledger exists."),
            sources=[],
        ),
    }
    return _finalize_input(root, {
        "schema_version": "certification-input-set.v1",
        "contract_id": contract["contract_id"],
        "scope_kind": "current-repository",
        "authority_claim_requested": False,
        "source_artifacts": sorted(source_artifacts, key=lambda item: item["relative_path"]),
        "criteria": criteria,
    })


@lru_cache(maxsize=4)
def _verified_derivation_catalog(root: Path) -> dict[str, Any]:
    catalog = load_strict(root / DERIVATION_CATALOG_PATH)
    verify_derivation_catalog(root, catalog)
    return catalog


def _catalog_by_revision(root: Path) -> dict[str, dict[str, Any]]:
    catalog = _verified_derivation_catalog(root)
    return {item["derivation_revision_id"]: item for item in catalog["derivations"]}


@lru_cache(maxsize=4)
def _verified_scientific_identity_catalog(root: Path) -> dict[str, int]:
    return verify_scientific_identity_catalog(root)


def validate_input_set(root: Path, contract: dict[str, Any], record: dict[str, Any]) -> None:
    validate_instance(record, load_strict(root / SCHEMA_PATHS["input"]), source="certification input set")
    if record["contract_id"] != contract["contract_id"]:
        fail("certification-input-contract-mismatch", "input set references another certification contract")
    if record["input_set_digest_sha256"] != _record_digest(record, "input_set_id", "input_set_digest_sha256"):
        fail("certification-input-digest-mismatch", "certification input-set digest differs")
    expected_id = _artifact_content_id(
        root, "certification-input-set", "regex-conformance-certification-input-set-v1",
        record["input_set_digest_sha256"],
    )
    if record["input_set_id"] != expected_id:
        fail("certification-input-id-mismatch", "certification input-set identity differs")
    paths: dict[str, dict[str, Any]] = {}
    namespace_registry = NamespaceRegistry.load(root / NAMESPACE_PATH)
    for source in record["source_artifacts"]:
        relative = source["relative_path"]
        if relative in paths:
            fail("duplicate-certification-source", "source artifact path is duplicated", relative)
        if ".." in relative.split("/") or relative.startswith("/"):
            fail("unsafe-certification-source", "source path must be repository-relative", relative)
        path = root / relative
        if not path.is_file():
            fail("missing-certification-source", "source artifact is missing", relative)
        if hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
            fail("stale-certification-source", "source artifact digest differs", relative)
        if source["artifact_id"] is not None:
            namespace_registry.validate(source["artifact_id"])
        paths[relative] = source
    known_revisions = _catalog_by_revision(root)
    for criterion_id in CRITERION_ORDER:
        item = record["criteria"][criterion_id]
        for relative in item["source_artifact_refs"]:
            if relative not in paths:
                fail("dangling-certification-source", "criterion source is absent from the input-set manifest", criterion_id)
        for revision in item["derivation_revision_ids"]:
            if revision not in known_revisions:
                fail("dangling-certification-derivation", "criterion derivation revision is unknown", criterion_id)
        if item["population_status"] == "complete" and not item["derivation_revision_ids"]:
            fail("missing-certification-derivation", "a complete criterion population requires its calculation or assembly derivation", criterion_id)
        for member in item["members"]:
            namespace_registry.validate(member["member_id"])
            for revision in member["derivation_revision_ids"]:
                if revision not in known_revisions:
                    fail("dangling-certification-derivation", "member derivation revision is unknown", member["member_id"])
        if item["zero_result_manifest"]:
            namespace_registry.validate(item["zero_result_manifest"]["manifest_id"])
            for revision in item["zero_result_manifest"]["derivation_revision_ids"]:
                if revision not in known_revisions:
                    fail("dangling-certification-derivation", "zero-result derivation revision is unknown", criterion_id)
        if item["population_status"] == "complete" and item["input_mode"] == "blocked":
            fail("contradictory-certification-input", "a blocked input cannot claim a complete population", criterion_id)
        if item["population_status"] != "complete" and not item["blockers"]:
            fail("unexplained-certification-input", "an incomplete population requires a blocker", criterion_id)
        if record["scope_kind"] != "validation-fixture" and item["input_mode"] == "normalized-member-ledger-v1" and not item["source_artifact_refs"]:
            fail("unbound-normalized-ledger", "authoritative normalized members require source artifacts", criterion_id)


def _derivation_classes(
    root: Path,
    revisions: list[str],
    criterion: dict[str, Any],
    diagnostics: list[dict[str, Any]],
) -> set[str]:
    by_revision = _catalog_by_revision(root)
    classes: set[str] = set()
    for revision in revisions:
        record = by_revision.get(revision)
        if record is None:
            diagnostics.append({"code": "dangling-derivation-reference", "message": "A derivation revision does not exist."})
            continue
        classification = record["derivation_class"]
        classes.add(classification)
        if classification not in criterion["admitted_derivation_classes"]:
            diagnostics.append({
                "code": "construction-evidence-rejected" if classification == "constant-by-construction" else "inadmissible-evidence-strength",
                "message": f"Derivation class {classification} is not admitted by {criterion['criterion_id']}.",
            })
    return classes


def _set_fields(denominator: list[str], numerator: list[str]) -> dict[str, Any]:
    denominator = sorted(denominator)
    numerator = sorted(numerator)
    return {
        "denominator_count": len(denominator),
        "denominator_members_sha256": _sha(denominator),
        "numerator_count": len(numerator),
        "numerator_members_sha256": _sha(numerator),
        "exact_ratio": f"{len(numerator)}/{len(denominator)}",
    }


def _result(
    criterion: dict[str, Any], status: str, *, denominator: list[str] | None,
    numerator: list[str] | None, derivation_classes: set[str], evidence: set[str],
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    sets = (
        _set_fields(denominator, numerator)
        if denominator is not None and numerator is not None
        else {
            "denominator_count": None, "denominator_members_sha256": None,
            "numerator_count": None, "numerator_members_sha256": None, "exact_ratio": None,
        }
    )
    return {
        "criterion_id": criterion["criterion_id"],
        "predicate_version": criterion["version"],
        "predicate_digest_sha256": criterion["predicate_digest_sha256"],
        "status": status,
        **sets,
        "admitted_derivation_classes_used": sorted(derivation_classes),
        "evidence_references": sorted(evidence),
        "diagnostics": diagnostics,
    }


def _evaluate_members(root: Path, criterion: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    diagnostics: list[dict[str, Any]] = []
    evidence = set(item["source_artifact_refs"])
    criterion_classes = _derivation_classes(root, item["derivation_revision_ids"], criterion, diagnostics)
    denominator: list[str] = []
    numerator: list[str] = []
    seen: set[str] = set()
    canonical_owners: dict[str, str] = {}
    split_graph: dict[str, list[str]] = {}
    allowed = set(criterion["predicate"]["allowed_states"])
    qualifying = set(criterion["predicate"]["qualifying_states"])
    operation = criterion["predicate"]["operation"]
    for member in item["members"]:
        identifier = member["member_id"]
        if identifier in seen:
            diagnostics.append({"code": "duplicate-member-identity", "message": "A denominator member identity is duplicated.", "member_ids": [identifier]})
            continue
        seen.add(identifier)
        denominator.append(identifier)
        evidence.update(member["evidence_references"])
        classes = _derivation_classes(root, member["derivation_revision_ids"], criterion, diagnostics)
        criterion_classes.update(classes)
        state = member["state"]
        if state not in allowed:
            diagnostics.append({"code": f"{criterion['criterion_id'].lower()}-uncontrolled-state", "message": f"State {state} is not admitted by the predicate.", "member_ids": [identifier]})
            continue
        if member.get("claims_canonical_ownership"):
            owner = member.get("canonical_owner_id")
            if not owner:
                diagnostics.append({"code": "missing-canonical-owner", "message": "Canonical ownership is claimed without an owner identity.", "member_ids": [identifier]})
            elif owner in canonical_owners:
                diagnostics.append({"code": "duplicate-canonical-owner", "message": "Two canonical records claim one owner.", "member_ids": sorted([canonical_owners[owner], identifier])})
            else:
                canonical_owners[owner] = identifier
        details = member.get("details", {})
        missing_detail = next((name for name in criterion["predicate"]["required_member_details"] if not details.get(name)), None)
        if missing_detail:
            code = "missing-integrity-validator-receipt" if missing_detail == "validator_receipt_sha256" else f"{criterion['criterion_id'].lower()}-member-incomplete"
            diagnostics.append({"code": code, "message": f"Required member detail {missing_detail} is absent.", "member_ids": [identifier]})
            continue
        if state == "resolved-by-split":
            successors = details.get("lineage_successor_ids", [])
            if not successors or identifier in successors or details.get("downstream_obligation_count") != 0:
                diagnostics.append({"code": "invalid-candidate-lineage", "message": "A split disposition must name distinct successors and create no downstream obligations for the predecessor.", "member_ids": [identifier]})
                continue
            split_graph[identifier] = successors
        if state == "certified-vector-mapping" and not (details.get("mapping_explicit") and details.get("lineage_valid")):
            diagnostics.append({"code": "vector-coverage-incomplete", "message": "A vector mapping lacks explicit attribution or valid lineage.", "member_ids": [identifier]})
            continue
        if state == "structured-unresolved" and not all(details.get(name) for name in ("owner_present", "severity_present", "next_action_present", "review_condition_present")):
            diagnostics.append({"code": "discrepancy-triage-incomplete", "message": "Structured unresolved triage lacks owner, severity, next action, or review condition.", "member_ids": [identifier]})
            continue
        if (state in qualifying or operation == "report-actual") and not any(item in INDEPENDENT_CLASSES for item in classes):
            diagnostics.append({"code": "independent-evidence-absent", "message": "A qualifying member has no independent evidence derivation.", "member_ids": [identifier]})
            continue
        if state in qualifying:
            numerator.append(identifier)
    for predecessor, successors in split_graph.items():
        missing = sorted(set(successors) - seen)
        if missing:
            diagnostics.append({"code": "invalid-candidate-lineage", "message": "A split disposition references a successor outside the frozen candidate set.", "member_ids": [predecessor, *missing]})
    completed: set[str] = set()

    def split_cycle(node: str, active: set[str]) -> set[str] | None:
        if node in active:
            return {*active, node}
        if node in completed:
            return None
        next_active = {*active, node}
        for successor in split_graph.get(node, []):
            cycle = split_cycle(successor, next_active)
            if cycle:
                return cycle
        completed.add(node)
        return None

    for start in split_graph:
        cycle = split_cycle(start, set())
        if cycle:
            diagnostics.append({"code": "invalid-candidate-lineage", "message": "The candidate split graph contains a cycle.", "member_ids": sorted(cycle)})
            break
    if not denominator:
        if operation == "all-qualified-or-certified-empty" and item["zero_result_manifest"]:
            manifest = item["zero_result_manifest"]
            zero_classes = _derivation_classes(root, manifest["derivation_revision_ids"], criterion, diagnostics)
            criterion_classes.update(zero_classes)
            evidence.update(manifest["evidence_references"])
            status = "PASS" if not diagnostics and zero_classes & INDEPENDENT_CLASSES else "FAIL"
            return _result(criterion, status, denominator=[], numerator=[], derivation_classes=criterion_classes, evidence=evidence, diagnostics=diagnostics)
        empty = criterion["predicate"]["empty_denominator"]
        status = "BLOCKED" if empty in {"BLOCKED", "CERTIFIED_ZERO_RESULT"} else "FAIL"
        diagnostics.append({"code": "missing-zero-result-manifest" if operation == "all-qualified-or-certified-empty" else f"empty-{criterion['criterion_id'].lower()}-denominator", "message": "An empty denominator cannot satisfy this predicate."})
        return _result(criterion, status, denominator=[], numerator=[], derivation_classes=criterion_classes, evidence=evidence, diagnostics=diagnostics)
    if operation == "report-actual":
        status = "FAIL" if diagnostics else "PASS"
    else:
        status = "PASS" if not diagnostics and len(numerator) == len(denominator) else "FAIL"
        if status == "FAIL" and len(numerator) != len(denominator) and not diagnostics:
            diagnostics.append({"code": f"{criterion['criterion_id'].lower()}-coverage-incomplete", "message": "The qualifying member set does not equal the denominator set."})
    return _result(criterion, status, denominator=denominator, numerator=numerator, derivation_classes=criterion_classes, evidence=evidence, diagnostics=diagnostics)


def _evaluate_c4_repository(root: Path, criterion: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    diagnostics: list[dict[str, Any]] = []
    classes = _derivation_classes(root, item["derivation_revision_ids"], criterion, diagnostics)
    requirement_path = next((path for path in item["source_artifact_refs"] if "vector-requirements" in path), None)
    if requirement_path is None:
        diagnostics.append({"code": "vector-input-blocked", "message": "No semantic vector-requirement ledger is bound."})
        return _result(criterion, "BLOCKED", denominator=None, numerator=None, derivation_classes=classes, evidence=set(item["source_artifact_refs"]), diagnostics=diagnostics)
    ledger = load_strict(root / requirement_path)
    requirements = ledger["requirements"]
    declared = ledger["counts"]["minimum_vector_definitions"]
    if declared != len(requirements):
        diagnostics.append({"code": "vector-requirement-count-mismatch", "message": "The declared vector-requirement count differs from its collection."})
    _verified_scientific_identity_catalog(root)
    catalog = load_strict(root / "registries/identity/scientific-identities.v1.json")
    by_key = {entry["canonical_key"]: entry for entry in catalog["bindings"] if entry["entity_class"] == "semantic-requirement"}
    denominator: list[str] = []
    numerator: list[str] = []
    seen: set[str] = set()
    for requirement in requirements:
        binding = by_key.get(requirement["requirement_id"])
        if binding is None:
            diagnostics.append({"code": "semantic-identity-stale", "message": "A requirement has no frozen scientific identity."})
            continue
        identifier = binding["scientific_id"]
        if identifier in seen:
            diagnostics.append({"code": "duplicate-requirement-owner", "message": "Two requirements resolve to one scientific identity.", "member_ids": [identifier]})
            continue
        seen.add(identifier)
        denominator.append(identifier)
        if binding["status"] != "active":
            diagnostics.append({"code": "semantic-identity-stale", "message": "A requirement resolves only to a retired identity.", "member_ids": [identifier]})
            continue
        if requirement["status"] != "missing" and requirement["existing_vector_ids"] and requirement["required_attribution"]:
            numerator.append(identifier)
    status = "PASS" if not diagnostics and len(numerator) == len(denominator) and denominator else "FAIL"
    if len(numerator) != len(denominator):
        diagnostics.append({"code": "vector-coverage-incomplete", "message": f"{len(denominator) - len(numerator)} applicable requirements lack certified explicit vector attribution."})
    return _result(criterion, status, denominator=denominator, numerator=numerator, derivation_classes=classes, evidence=set(item["source_artifact_refs"]), diagnostics=diagnostics)


def _evaluate_c5(root: Path, criterion: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    diagnostics: list[dict[str, Any]] = []
    classes = _derivation_classes(root, item["derivation_revision_ids"], criterion, diagnostics)
    if "measurement" not in classes:
        diagnostics.append({"code": "nonmeasurement-execution-evidence", "message": "Logical completion requires measurement-derived attempt and observation evidence."})
    policy = load_strict(root / EXECUTION_POLICY_PATH)
    try:
        validate_lineage_set(root, item["lineage_set"], policy)
    except ConformanceDataError as error:
        diagnostics.append({"code": "execution-lineage-invalid", "message": f"{error.code}: {error.message}"})
        return _result(criterion, "FAIL", denominator=[], numerator=[], derivation_classes=classes, evidence=set(item["source_artifact_refs"]), diagnostics=diagnostics)
    denominator = [lineage["logical_execution_id"] for lineage in item["lineage_set"]["lineages"]]
    numerator = [lineage["logical_execution_id"] for lineage in item["lineage_set"]["lineages"] if lineage["disposition"]["status"] == "satisfied"]
    if len(numerator) != len(denominator):
        diagnostics.append({"code": "logical-execution-incomplete", "message": "One or more logical executions have only inconclusive attempts."})
    status = "PASS" if denominator and len(numerator) == len(denominator) and not diagnostics else "FAIL"
    evidence = set(item["source_artifact_refs"])
    evidence.update(observation["observation_content_id"] for lineage in item["lineage_set"]["lineages"] for observation in lineage["observations"])
    return _result(criterion, status, denominator=denominator, numerator=numerator, derivation_classes=classes, evidence=evidence, diagnostics=diagnostics)


def evaluate(root: Path, contract: dict[str, Any], input_set: dict[str, Any]) -> dict[str, Any]:
    validate_contract(root, contract)
    validate_input_set(root, contract, input_set)
    definitions = {item["criterion_id"]: item for item in contract["criteria"]}
    results: list[dict[str, Any]] = []
    for criterion_id in CRITERION_ORDER:
        definition = definitions[criterion_id]
        item = input_set["criteria"][criterion_id]
        if item["population_status"] in {"absent", "provisional"}:
            results.append(_result(
                definition, "BLOCKED", denominator=None, numerator=None,
                derivation_classes=set(), evidence=set(item["source_artifact_refs"]),
                diagnostics=deepcopy(item["blockers"]),
            ))
        elif item["population_status"] == "invalid":
            results.append(_result(
                definition, "FAIL", denominator=None, numerator=None,
                derivation_classes=set(), evidence=set(item["source_artifact_refs"]),
                diagnostics=deepcopy(item["blockers"]),
            ))
        elif item["input_mode"] == "semantic-vector-requirements-v1" and criterion_id == "C4":
            results.append(_evaluate_c4_repository(root, definition, item))
        elif item["input_mode"] == "execution-lineage-set-v1" and criterion_id == "C5":
            results.append(_evaluate_c5(root, definition, item))
        elif item["input_mode"] == "normalized-member-ledger-v1":
            results.append(_evaluate_members(root, definition, item))
        else:
            fail("unsupported-certification-input-mode", f"{criterion_id} cannot consume {item['input_mode']}")
    final_state = max((item["status"] for item in results), key=lambda value: FAILURE_PRECEDENCE[value])
    authority_path = root / CURRENT_AUTHORITY_PATH
    current_contract = load_strict(authority_path)["current_contract"] if authority_path.is_file() else {}
    contract_is_current = (
        current_contract.get("contract_id") == contract["contract_id"]
        and current_contract.get("contract_digest_sha256") == contract["contract_digest_sha256"]
    )
    eligible = (
        input_set["authority_claim_requested"]
        and input_set["scope_kind"] == "certification-candidate"
        and final_state == "PASS"
        and contract_is_current
    )
    body = {
        "schema_version": "certification-report.v1",
        "contract_id": contract["contract_id"],
        "contract_digest_sha256": contract["contract_digest_sha256"],
        "input_set_id": input_set["input_set_id"],
        "input_set_digest_sha256": input_set["input_set_digest_sha256"],
        "input_artifacts": deepcopy(input_set["source_artifacts"]),
        "scope_kind": input_set["scope_kind"],
        "authority_status": "eligible-for-issuance" if eligible else ("validation-fixture" if input_set["scope_kind"] == "validation-fixture" else "evaluation-only"),
        "certification_eligible": eligible,
        "criteria": results,
        "final_state": final_state,
    }
    return _finalize_content_record(
        root, body, namespace="certification-report",
        artifact_kind="regex-conformance-certification-report-v1",
        id_field="report_id", digest_field="report_digest_sha256",
    )


def validate_report(root: Path, contract: dict[str, Any], input_set: dict[str, Any], report: dict[str, Any]) -> None:
    validate_instance(report, load_strict(root / SCHEMA_PATHS["report"]), source="certification report")
    expected = evaluate(root, contract, input_set)
    if canonical_bytes(report) != canonical_bytes(expected):
        fail("certification-report-drift", "report differs from fresh deterministic predicate evaluation")


def _authority_digest(record: dict[str, Any]) -> str:
    return _record_digest(record, "authority_index_sha256")


def build_current_authority(
    contract: dict[str, Any],
    report: dict[str, Any],
    prior: dict[str, Any] | None = None,
) -> dict[str, Any]:
    preserved = deepcopy(prior) if prior is not None else {}
    record = {
        "schema_version": "certification-authority-index.v1",
        "current_contract": {
            "contract_id": contract["contract_id"],
            "contract_digest_sha256": contract["contract_digest_sha256"],
            "contract_version": contract["contract_version"],
        },
        "current_evaluation": {
            "report_id": report["report_id"],
            "report_digest_sha256": report["report_digest_sha256"],
            "final_state": report["final_state"],
        },
        "current_certification_id": preserved.get("current_certification_id"),
        "certifications": preserved.get("certifications", []),
        "actions": preserved.get("actions", []),
        "authority_index_sha256": "",
    }
    record["authority_index_sha256"] = _authority_digest(record)
    return record


def validate_authority_index(root: Path, record: dict[str, Any]) -> None:
    validate_instance(record, load_strict(root / SCHEMA_PATHS["authority"]), source="certification authority index")
    if record["authority_index_sha256"] != _authority_digest(record):
        fail("certification-authority-digest-mismatch", "authority index digest differs")
    certifications = {item["certification_id"]: item for item in record["certifications"]}
    if len(certifications) != len(record["certifications"]):
        fail("duplicate-certification-identity", "a certification identity is reused")
    action_ids: set[str] = set()
    supersedes: dict[str, str] = {}
    for action in record["actions"]:
        if action["action_id"] in action_ids:
            fail("duplicate-certification-action", "a certification action identity is reused")
        action_ids.add(action["action_id"])
        subject = action["subject_certification_id"]
        successor = action["successor_certification_id"]
        if subject not in certifications:
            fail("dangling-certification-action", "certification action subject is missing")
        if action["kind"] == "supersede":
            if successor is None or successor not in certifications or successor == subject:
                fail("invalid-certification-supersession", "supersession requires a distinct existing successor")
            if certifications[subject]["status"] != "superseded":
                fail("certification-status-action-mismatch", "superseded subject status differs")
            supersedes[subject] = successor
        elif successor is not None or certifications[subject]["status"] != "revoked":
            fail("invalid-certification-revocation", "revocation cannot have a successor and must mark the subject revoked")
    for start in supersedes:
        seen: set[str] = set()
        current = start
        while current in supersedes:
            if current in seen:
                fail("certification-supersession-cycle", "certification supersession graph contains a cycle")
            seen.add(current)
            current = supersedes[current]
    current = record["current_certification_id"]
    if current is not None and (current not in certifications or certifications[current]["status"] != "current"):
        fail("invalid-current-certification", "current certification pointer does not identify a current record")
    current_records = [item for item in certifications.values() if item["status"] == "current"]
    if len(current_records) > 1 or bool(current_records) != (current is not None):
        fail("multiple-current-certifications", "authority index must have exactly the pointed current record or none")


def _u7(namespace: str, value: int) -> str:
    return f"rcid:v1:{namespace}:u7:019ffeff-0000-7000-8000-{value:012x}"


def _h(namespace: str, value: int) -> str:
    return f"rcid:v1:{namespace}:h:jcs-sha256-v1:{value:064x}"


def _subset_lineage(root: Path, indexes: list[int]) -> dict[str, Any]:
    source = load_strict(root / EXECUTION_FIXTURE_PATH)
    policy = load_strict(root / EXECUTION_POLICY_PATH)
    lineages = [deepcopy(source["lineages"][index]) for index in indexes]
    counts = Counter({"logical_execution_count": len(lineages)})
    for lineage in lineages:
        disposition = lineage["disposition"]
        counts.update(
            physical_attempt_count=len(lineage["attempts"]),
            inconclusive_attempt_count=disposition["inconclusive_attempt_count"],
            recovered_attempt_count=disposition["recovered_attempt_count"],
            repeat_measurement_attempt_count=disposition["repeat_measurement_attempt_count"],
            retry_attempt_count=disposition["retry_attempt_count"],
            terminal_attempt_count=disposition["terminal_attempt_count"],
            terminal_observation_count=len(lineage["observations"]),
        )
    record = {
        "schema_version": "execution-lineage-set.v1",
        "campaign_manifest_id": source["campaign_manifest_id"],
        "execution_policy_revision_sha256": source["execution_policy_revision_sha256"],
        "count_derivation_revision_id": source["count_derivation_revision_id"],
        "counts": {key: counts[key] for key in policy["reporting_populations"]},
        "lineages": lineages,
        "lineage_set_sha256": "",
    }
    record["lineage_set_sha256"] = lineage_set_sha256(record)
    validate_lineage_set(root, record, policy)
    return record


def _fixture_member(identifier: str, state: str, revision: str, *, details: dict[str, Any], owner: str | None = None) -> dict[str, Any]:
    return {
        "member_id": identifier,
        "state": state,
        "derivation_revision_ids": [revision],
        "evidence_references": [f"fixture-evidence:{identifier}"],
        "canonical_owner_id": owner,
        "claims_canonical_ownership": owner is not None,
        "details": details,
    }


def _fixture_input(root: Path, contract: dict[str, Any], *, retry: bool = False) -> dict[str, Any]:
    revisions = _derivation_revisions(root)
    research = revisions["semantic-source-synthesis"]
    measurement = revisions["qualified-artifact-measurement"]
    manual = revisions["governed-registry-selection"]
    calculation = revisions["reconciliation-aggregation"]
    c5_lineage = _subset_lineage(root, [1] if retry else [0])
    criteria = {
        "C1": {"input_mode": "normalized-member-ledger-v1", "population_status": "complete", "source_artifact_refs": [], "derivation_revision_ids": [calculation], "blockers": [], "members": [_fixture_member(_u7("candidate", 1), "in-scope", research, details={"record_complete": True}, owner=_u7("system", 1))], "lineage_set": None, "zero_result_manifest": None},
        "C2": {"input_mode": "normalized-member-ledger-v1", "population_status": "complete", "source_artifact_refs": [], "derivation_revision_ids": [calculation], "blockers": [], "members": [_fixture_member(_u7("release", 1), "accounted", research, details={"record_complete": True}, owner=_u7("release", 101))], "lineage_set": None, "zero_result_manifest": None},
        "C3": {"input_mode": "normalized-member-ledger-v1", "population_status": "complete", "source_artifact_refs": [], "derivation_revision_ids": [calculation], "blockers": [], "members": [_fixture_member(_u7("profile", 1), "verified-reproducible", measurement, details={"record_complete": True}), _fixture_member(_u7("profile", 2), "artifact-unavailable", measurement, details={"record_complete": True})], "lineage_set": None, "zero_result_manifest": None},
        "C4": {"input_mode": "normalized-member-ledger-v1", "population_status": "complete", "source_artifact_refs": [], "derivation_revision_ids": [calculation], "blockers": [], "members": [_fixture_member(_u7("semantic-requirement", 1), "certified-vector-mapping", research, details={"record_complete": True, "mapping_explicit": True, "lineage_valid": True})], "lineage_set": None, "zero_result_manifest": None},
        "C5": {"input_mode": "execution-lineage-set-v1", "population_status": "complete", "source_artifact_refs": [], "derivation_revision_ids": sorted([calculation, measurement]), "blockers": [], "members": [], "lineage_set": c5_lineage, "zero_result_manifest": None},
        "C6": {"input_mode": "normalized-member-ledger-v1", "population_status": "complete", "source_artifact_refs": [], "derivation_revision_ids": [calculation], "blockers": [], "members": [_fixture_member(_u7("observation", 1), "integrity-valid", measurement, details={"validator_receipt_sha256": "1" * 64})], "lineage_set": None, "zero_result_manifest": None},
        "C7": {"input_mode": "normalized-member-ledger-v1", "population_status": "complete", "source_artifact_refs": [], "derivation_revision_ids": [calculation], "blockers": [], "members": [_fixture_member(_u7("discrepancy", 1), "resolved", measurement, details={"record_complete": True})], "lineage_set": None, "zero_result_manifest": None},
    }
    return _finalize_input(root, {
        "schema_version": "certification-input-set.v1",
        "contract_id": contract["contract_id"],
        "scope_kind": "validation-fixture",
        "authority_claim_requested": False,
        "source_artifacts": [],
        "criteria": criteria,
    })


def _refinalize_fixture_input(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    return _finalize_input(root, {key: deepcopy(value) for key, value in record.items() if key not in {"input_set_id", "input_set_digest_sha256"}})


def _expected(report: dict[str, Any]) -> dict[str, str]:
    return {item["criterion_id"]: item["status"] for item in report["criteria"]}


def build_fixture_set(root: Path, contract: dict[str, Any]) -> dict[str, Any]:
    revisions = _derivation_revisions(root)
    cases: list[tuple[str, dict[str, Any]]] = []
    full = _fixture_input(root, contract)
    cases.append(("full-pass", full))
    mutations = {
        "c1-failure": ("C1", lambda item: item["members"][0].update(state="pending")),
        "c2-failure": ("C2", lambda item: item["members"][0].update(state="missing")),
        "c3-failure": ("C3", lambda item: item["members"][0].update(state="suppressed")),
        "c4-failure": ("C4", lambda item: item["members"][0].update(state="missing")),
        "c6-failure": ("C6", lambda item: item["members"][0].update(state="corrupt")),
        "c7-failure": ("C7", lambda item: item["members"][0].update(state="bare-unresolved")),
        "construction-evidence-rejected": ("C4", lambda item: item["members"][0].update(derivation_revision_ids=[revisions["legacy-literal-emission"]])),
        "evidence-corruption": ("C6", lambda item: item["members"][0].update(state="schema-invalid")),
        "reconciliation-debt": ("C7", lambda item: item["members"][0].update(state="structured-unresolved", details={"record_complete": True, "owner_present": True, "severity_present": True, "next_action_present": False, "review_condition_present": True})),
    }
    for name, (criterion_id, mutate) in mutations.items():
        candidate = deepcopy(full)
        mutate(candidate["criteria"][criterion_id])
        cases.append((name, _refinalize_fixture_input(root, candidate)))
    blocked = deepcopy(full)
    blocked["criteria"]["C2"].update(
        input_mode="blocked", population_status="provisional", members=[],
        derivation_revision_ids=[], blockers=[{"code": "release-input-blocked", "message": "Release-line authority is provisional."}],
    )
    cases.append(("blocked-prerequisite", _refinalize_fixture_input(root, blocked)))
    inconclusive = deepcopy(full)
    inconclusive["criteria"]["C5"]["lineage_set"] = _subset_lineage(root, [3])
    cases.append(("c5-failure", _refinalize_fixture_input(root, inconclusive)))
    cases.append(("physical-attempt-exclusion", _refinalize_fixture_input(root, inconclusive)))
    cases.append(("retry-completion", _fixture_input(root, contract, retry=True)))
    valid_split = deepcopy(full)
    split = valid_split["criteria"]["C1"]["members"][0]
    split.update(
        state="resolved-by-split",
        details={
            "record_complete": True,
            "lineage_successor_ids": [_u7("candidate", 2), _u7("candidate", 3)],
            "downstream_obligation_count": 0,
        },
    )
    valid_split["criteria"]["C1"]["members"].extend([
        _fixture_member(_u7("candidate", 2), "in-scope", revisions["semantic-source-synthesis"], details={"record_complete": True}, owner=_u7("system", 2)),
        _fixture_member(_u7("candidate", 3), "in-scope", revisions["semantic-source-synthesis"], details={"record_complete": True}, owner=_u7("system", 3)),
    ])
    cases.append(("valid-split-disposition", _refinalize_fixture_input(root, valid_split)))
    invalid_split = deepcopy(full)
    invalid_split["criteria"]["C1"]["members"][0].update(
        state="resolved-by-split",
        details={"record_complete": True, "downstream_obligation_count": 0},
    )
    cases.append(("invalid-split-lineage", _refinalize_fixture_input(root, invalid_split)))
    certified_empty = deepcopy(full)
    certified_empty["criteria"]["C7"]["members"] = []
    certified_empty["criteria"]["C7"]["zero_result_manifest"] = {
        "completed": True,
        "manifest_id": _h("reconciliation-set", 1),
        "derivation_revision_ids": [revisions["qualified-artifact-measurement"]],
        "evidence_references": ["fixture-evidence:completed-zero-result-detection"],
    }
    cases.append(("certified-empty-reconciliation", _refinalize_fixture_input(root, certified_empty)))
    rows: list[dict[str, Any]] = []
    for name, input_set in sorted(cases, key=lambda item: item[0]):
        report = evaluate(root, contract, input_set)
        rows.append({
            "name": name,
            "input_set": input_set,
            "expected_criterion_states": _expected(report),
            "expected_final_state": report["final_state"],
        })
    old_certification = "rcid:v1:certification:u7:01a079d7-da99-7a6a-bcb8-b7bc94e534d5"
    new_certification = "rcid:v1:certification:u7:01a079d7-f747-7d05-8468-8338e45adca4"
    old_report = _h("certification-report", 301)
    new_report = _h("certification-report", 302)
    authority = {
        "schema_version": "certification-authority-index.v1",
        "current_contract": {"contract_id": contract["contract_id"], "contract_digest_sha256": contract["contract_digest_sha256"], "contract_version": "1.0.0"},
        "current_evaluation": {"report_id": new_report, "report_digest_sha256": "3" * 64, "final_state": "PASS"},
        "current_certification_id": new_certification,
        "certifications": [
            {"certification_id": old_certification, "report_id": old_report, "report_digest_sha256": "2" * 64, "scope_id": "fixture-scope", "issued_at": "2026-01-01T00:00:00Z", "status": "superseded"},
            {"certification_id": new_certification, "report_id": new_report, "report_digest_sha256": "3" * 64, "scope_id": "fixture-scope", "issued_at": "2026-02-01T00:00:00Z", "status": "current"},
        ],
        "actions": [{
            "action_id": "rcid:v1:certification-action:u7:01a079d7-da99-7ab2-a57f-fcd732910702",
            "kind": "supersede", "subject_certification_id": old_certification,
            "successor_certification_id": new_certification,
            "reason": "A newer canonical scope and contract evaluation became current.",
            "evidence_references": ["fixture-evidence:scope-change"],
            "effective_at": "2026-02-01T00:00:00Z",
        }],
        "authority_index_sha256": "",
    }
    authority["authority_index_sha256"] = _authority_digest(authority)
    validate_authority_index(root, authority)
    fixture = {
        "schema_version": "certification-predicate-fixtures.v1",
        "contract_id": contract["contract_id"],
        "cases": rows,
        "supersession_fixture": {
            "authority_index": authority,
            "historical_report_digest_before": "2" * 64,
            "historical_report_digest_after": "2" * 64,
        },
        "fixture_digest_sha256": "",
    }
    fixture["fixture_digest_sha256"] = _record_digest(fixture, "fixture_digest_sha256")
    return fixture


def validate_fixture_set(root: Path, contract: dict[str, Any], fixture: dict[str, Any]) -> None:
    validate_instance(fixture, load_strict(root / SCHEMA_PATHS["fixtures"]), source="certification fixtures")
    if fixture["fixture_digest_sha256"] != _record_digest(fixture, "fixture_digest_sha256"):
        fail("certification-fixture-digest-mismatch", "certification fixture digest differs")
    if fixture["contract_id"] != contract["contract_id"]:
        fail("certification-fixture-contract-mismatch", "fixture set references another contract")
    names: set[str] = set()
    for case in fixture["cases"]:
        if case["name"] in names:
            fail("duplicate-certification-fixture", "fixture name is duplicated", case["name"])
        names.add(case["name"])
        report = evaluate(root, contract, case["input_set"])
        if report["final_state"] != case["expected_final_state"] or _expected(report) != case["expected_criterion_states"]:
            fail("certification-fixture-result-mismatch", "fixture expectation differs from evaluation", case["name"])
    required = {"full-pass", "blocked-prerequisite", "certified-empty-reconciliation", "construction-evidence-rejected", "physical-attempt-exclusion", "retry-completion", "evidence-corruption", "reconciliation-debt", "valid-split-disposition", "invalid-split-lineage", *(f"c{number}-failure" for number in range(1, 8))}
    if not required.issubset(names):
        fail("incomplete-certification-fixtures", "required positive, criterion-failure, blocked, provenance, and reconciliation fixtures are missing")
    supersession = fixture["supersession_fixture"]
    validate_authority_index(root, supersession["authority_index"])
    if supersession["historical_report_digest_before"] != supersession["historical_report_digest_after"]:
        fail("historical-certification-mutated", "supersession changed historical report bytes")


def verify_repository_certification(root: Path) -> dict[str, Any]:
    derivation_catalog = _verified_derivation_catalog(root)
    contract = load_strict(root / CONTRACT_PATH)
    validate_contract(root, contract)
    expected_contract = build_contract(root)
    if canonical_bytes(contract) != canonical_bytes(expected_contract):
        fail("certification-contract-drift", "tracked contract differs from deterministic source")
    input_set = load_strict(root / CURRENT_INPUT_PATH)
    expected_input = build_current_input(root, contract)
    if canonical_bytes(input_set) != canonical_bytes(expected_input):
        fail("certification-input-drift", "tracked current input differs from fresh canonical state")
    report = load_strict(root / CURRENT_REPORT_PATH)
    validate_report(root, contract, input_set, report)
    authority = load_strict(root / CURRENT_AUTHORITY_PATH)
    validate_authority_index(root, authority)
    expected_authority = build_current_authority(contract, report, authority)
    if canonical_bytes(authority) != canonical_bytes(expected_authority):
        fail("certification-authority-drift", "current authority index differs from fresh evaluation")
    fixture = load_strict(root / FIXTURE_PATH)
    validate_fixture_set(root, contract, fixture)
    expected_fixture = build_fixture_set(root, contract)
    if canonical_bytes(fixture) != canonical_bytes(expected_fixture):
        fail("certification-fixture-drift", "tracked certification fixtures differ from deterministic rebuild")
    return {
        "generated_assertion_artifacts": derivation_catalog["coverage_summary"]["inventoried_artifacts"],
        "generated_assertion_groups": derivation_catalog["coverage_summary"]["assertion_groups"],
        "generated_assertion_occurrences": derivation_catalog["coverage_summary"]["assertion_occurrences"],
        "generated_count_contracts": derivation_catalog["coverage_summary"]["count_contracts"],
        "certification_contracts": 1,
        "certification_criteria": 7,
        "certification_fixtures": len(fixture["cases"]),
        "current_certification_state": report["final_state"],
    }


def _write(root: Path, relative: Path, value: dict[str, Any]) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(dump_pretty(value), encoding="utf-8", newline="\n")
    os.replace(temporary, path)
    if load_strict(path) != value:
        fail("certification-write-verification-failed", "read-after-write differs", relative.as_posix())


def materialize_repository_certification(root: Path) -> dict[str, Any]:
    contract = build_contract(root)
    input_set = build_current_input(root, contract)
    report = evaluate(root, contract, input_set)
    authority_path = root / CURRENT_AUTHORITY_PATH
    prior_authority = load_strict(authority_path) if authority_path.is_file() else None
    if prior_authority is not None:
        validate_authority_index(root, prior_authority)
    authority = build_current_authority(contract, report, prior_authority)
    fixture = build_fixture_set(root, contract)
    for relative, value in (
        (CONTRACT_PATH, contract),
        (CURRENT_INPUT_PATH, input_set),
        (CURRENT_REPORT_PATH, report),
        (CURRENT_AUTHORITY_PATH, authority),
        (FIXTURE_PATH, fixture),
    ):
        _write(root, relative, value)
    return verify_repository_certification(root)
