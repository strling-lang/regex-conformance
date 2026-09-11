"""Local authoritative certification and bounded hosted integrity verification."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(SCHEMA_TOOLING) not in sys.path:
    sys.path.insert(0, str(SCHEMA_TOOLING))

from regex_conformance_schema.jsonio import canonical_bytes, dump_pretty, load_strict

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
FULL_DIGEST = re.compile(r"^[0-9a-f]{64}$")
LOCAL_CHECK_PASS = "PASS"
MANIFEST_PATH = Path("certification/local/current-local-certification.v1.json")
SCHEMA_PATH = Path("schemas/json/local-authoritative-certification.schema.json")
IDENTITY_CATALOG = Path("registries/identity/scientific-identities.v1.json")
DERIVATION_CATALOG = Path("registries/provenance/generated-assertion-derivations.v1.json")

ARTIFACT_ROLES: tuple[tuple[str, str], ...] = (
    ("certification-contract", "certification/contracts/regex-conformance-certification.v1.1.json"),
    ("semantic-snapshot", "semantic-corpus/snapshots/regex-semantic-features-2026-09-08.v4.json"),
    ("obligation-snapshot", "ontology/obligations/regex-semantic-obligations-2026-09-08.v1.json"),
    ("requirement-snapshot", "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json"),
    ("migration-ledger", "ontology/migrations/regex-semantic-denominator-2026-09-08.v1.json"),
    ("semantic-projection", "ontology/projections/regex-semantic-projection-2026-09-08.v2.json"),
    ("denominator-authority", "ontology/authority/current-semantic-denominator.v1.json"),
    ("materialization-report", "reports/semantics/semantic-denominator-materialization-2026-09-08.v1.json"),
    ("denominator-accounting-contract", "ontology/denominator/regex-semantic-denominator-accounting-2026-09-10.v1.json"),
    ("denominator-audit-report", "reports/semantics/regex-semantic-denominator-audit-2026-09-10.v1.json"),
    ("profile-expansion-handoff", "ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json"),
    ("denominator-audit-authority", "ontology/authority/current-semantic-denominator-audit.v1.json"),
    ("true-denominator-foundation", "ontology/denominator/true-obligation-denominator-foundation-2026-09-10.v1.json"),
    ("true-denominator-gate-report", "reports/semantics/true-obligation-denominator-acceptance-2026-09-10.v1.json"),
    ("oracle-foundation-allocation", "oracle/oracle-foundation-identities-2026-09-10.v1.json"),
    ("oracle-foundation-contract", "oracle/contracts/regex-conformance-oracles-2026-09-10.v1.json"),
    ("oracle-validation-fixtures", "tests/fixtures/oracle/oracle-validation-cases.v1.json"),
    ("oracle-foundation-report", "reports/oracle/oracle-foundation-2026-09-10.v1.json"),
    ("oracle-authority", "oracle/current-authority.v1.json"),
    ("evidence-admissibility-allocation", "oracle/evidence/evidence-admissibility-identities-2026-09-10.v1.json"),
    ("evidence-admissibility-contract", "oracle/contracts/regex-conformance-evidence-admissibility-2026-09-10.v1.json"),
    ("evidence-admissibility-fixtures", "tests/fixtures/oracle/evidence-admissibility-cases.v1.json"),
    ("evidence-admissibility-report", "reports/oracle/evidence-admissibility-2026-09-10.v1.json"),
    ("evidence-admissibility-authority", "oracle/evidence/current-authority.v1.json"),
    ("applicability-allocation", "applicability/conditional-applicability-identities-2026-09-10.v1.json"),
    ("applicability-contract", "applicability/contracts/regex-conformance-conditional-applicability-2026-09-10.v1.json"),
    ("applicability-fixtures", "tests/fixtures/applicability/conditional-requirement-applicability.v1.json"),
    ("applicability-report", "reports/applicability/conditional-requirement-applicability-2026-09-10.v1.json"),
    ("applicability-authority", "applicability/current-authority.v1.json"),
    ("adjudication-allocation", "adjudication/adjudication-identities-2026-09-11.v1.json"),
    ("adjudication-contract", "adjudication/contracts/regex-conformance-adjudication-2026-09-11.v1.json"),
    ("adjudication-fixtures", "tests/fixtures/adjudication/adjudication-cases.v1.json"),
    ("adjudication-report", "reports/adjudication/adjudication-acceptance-2026-09-11.v1.json"),
    ("adjudication-authority", "adjudication/current-authority.v1.json"),
    ("evidence-adjudication-closure", "certification/reports/evidence-adjudication-architecture-closure-2026-09-11.v1.json"),
    ("certification-input", "certification/inputs/current-repository-2026-09-08.v2.json"),
    ("certification-report", "certification/reports/current-repository-2026-09-08.v2.json"),
    ("certification-authority", "certification/current-authority.v1.json"),
    ("identity-catalog", str(IDENTITY_CATALOG).replace("\\", "/")),
    ("derivation-catalog", str(DERIVATION_CATALOG).replace("\\", "/")),
    ("scientific-foundation-acceptance", "foundation/scientific-foundation-acceptance.v1.json"),
    ("semantic-foundation-acceptance", "semantic-corpus/foundation/semantic-knowledge-architecture.v1.json"),
    ("local-certification-schema", str(SCHEMA_PATH).replace("\\", "/")),
    ("denominator-accounting-schema", "schemas/json/semantic-denominator-accounting-contract.schema.json"),
    ("denominator-audit-report-schema", "schemas/json/semantic-denominator-audit-report.schema.json"),
    ("profile-expansion-handoff-schema", "schemas/json/semantic-profile-expansion-handoff.schema.json"),
    ("denominator-audit-authority-schema", "schemas/json/semantic-denominator-audit-authority.schema.json"),
    ("true-denominator-foundation-schema", "schemas/json/true-obligation-denominator-foundation.schema.json"),
    ("true-denominator-gate-report-schema", "schemas/json/true-obligation-denominator-acceptance.schema.json"),
    ("applicability-contract-schema", "schemas/json/conditional-applicability-contract.schema.json"),
    ("applicability-result-schema", "schemas/json/applicability-evaluation-result.schema.json"),
    ("profile-capability-fact-schema", "schemas/json/profile-capability-fact-snapshot.schema.json"),
    ("adjudication-allocation-schema", "schemas/json/adjudication-allocation.schema.json"),
    ("adjudication-contract-schema", "schemas/json/adjudication-contract.schema.json"),
    ("coordinate-state-schema", "schemas/json/coordinate-state.schema.json"),
    ("expected-outcome-schema", "schemas/json/expected-outcome.schema.json"),
    ("discrepancy-revision-schema", "schemas/json/discrepancy-revision.schema.json"),
    ("waiver-revision-schema", "schemas/json/waiver-revision.schema.json"),
    ("quarantine-revision-schema", "schemas/json/quarantine-revision.schema.json"),
    ("claim-revision-schema", "schemas/json/claim-revision.schema.json"),
    ("adjudication-result-schema", "schemas/json/adjudication-result.schema.json"),
    ("adjudication-fixtures-schema", "schemas/json/adjudication-fixtures.schema.json"),
    ("adjudication-report-schema", "schemas/json/adjudication-report.schema.json"),
    ("adjudication-authority-schema", "schemas/json/adjudication-authority.schema.json"),
    ("evidence-adjudication-closure-schema", "schemas/json/evidence-adjudication-architecture-closure.schema.json"),
)

LOCAL_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("python", "tools/semantics/generate_obligation_snapshots.py", "--check"),
    ("python", "tools/semantics/audit_scientific_denominator.py", "--check"),
    ("python", "tools/semantics/certify_true_denominator.py", "--history"),
    ("python", "tools/oracle/compile_oracle_foundation.py", "--check", "--bounded"),
    ("python", "tools/oracle/compile_evidence_admissibility.py", "--check", "--bounded"),
    ("python", "tools/applicability/compile_conditional_applicability.py", "--check", "--bounded"),
    ("python", "tools/adjudication/compile_adjudication.py", "--check", "--bounded"),
    ("python", "tools/certification/compile_evidence_adjudication_closure.py", "--check", "--history"),
    ("python", "tools/certification/evaluate.py", "--check"),
    ("python", "tools/semantics/certify_semantic_knowledge.py", "--check"),
    ("python", "tools/foundation/certify.py", "--history"),
    ("python", "tools/identity/freeze_scientific_identities.py", "--check"),
    ("python", "tools/provenance/compile_generated_assertion_derivations.py", "--check"),
    ("python", "schemas/tooling/python/run.py", "validate-repository"),
    ("python", "schemas/tooling/python/run.py", "verify-fixtures"),
    ("python", "tools/ci/verify_repository_identifier_hygiene.py", "--root", "."),
    ("python", "-m", "unittest", "discover", "-s", "tests/schema", "-p", "test_denominator_audit.py", "-v"),
    ("python", "-m", "unittest", "discover", "-s", "tests/schema", "-p", "test_true_obligation_denominator_gate.py", "-v"),
    ("python", "-m", "unittest", "discover", "-s", "tests/schema", "-p", "test_evidence_admissibility.py", "-v"),
    ("python", "-m", "unittest", "discover", "-s", "tests/schema", "-p", "test_conditional_applicability.py", "-v"),
    ("python", "-m", "unittest", "discover", "-s", "tests/schema", "-p", "test_adjudication.py", "-v"),
    ("python", "-m", "unittest", "discover", "-s", "tests/ci", "-v"),
)


class LocalCertificationError(ValueError):
    """Raised when a local certificate or hosted verification fails closed."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_binding(root: Path, role: str, relative: str) -> dict[str, Any]:
    path = root / relative
    data = path.read_bytes()
    return {"role": role, "path": relative, "sha256": sha256_bytes(data), "byte_length": len(data)}


def merkleless_root(entries: Sequence[dict[str, Any]]) -> str:
    """Commit an ordered JCS list; this is a closure root, not a new hash scheme."""
    ordered = sorted(entries, key=lambda item: (item.get("role", ""), item.get("path", ""), item.get("test_id", "")))
    return sha256_bytes(canonical_bytes(ordered))


def git_output(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


def require_clean_source(root: Path) -> str:
    if git_output(root, "status", "--porcelain=v1"):
        raise LocalCertificationError("local certification requires a clean committed worktree")
    source_sha = git_output(root, "rev-parse", "HEAD")
    if FULL_SHA.fullmatch(source_sha) is None:
        raise LocalCertificationError("HEAD did not resolve to an exact commit SHA")
    return source_sha


def run_local_suite(root: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for ordinal, logical_argv in enumerate(LOCAL_COMMANDS, 1):
        actual = [sys.executable, *logical_argv[1:]]
        started = time.monotonic()
        completed = subprocess.run(actual, cwd=root, capture_output=True, text=True, env={**os.environ, "PYTHONHASHSEED": "0"})
        output = (completed.stdout + completed.stderr).encode("utf-8")
        result = {
            "test_id": f"local-{ordinal:02d}",
            "argv": list(logical_argv),
            "result": "PASS" if completed.returncode == 0 else "FAIL",
            "exit_code": completed.returncode,
            "output_sha256": sha256_bytes(output),
            "duration_milliseconds": round((time.monotonic() - started) * 1000),
        }
        results.append(result)
        print(f"{result['test_id']} {result['result']}: {' '.join(logical_argv)}", flush=True)
        if completed.returncode != 0:
            sys.stderr.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            raise LocalCertificationError(f"local authoritative check {result['test_id']} failed")
    return results


def _artifact_payload(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries = [file_binding(root, role, path) for role, path in ARTIFACT_ROLES]
    by_role = {entry["role"]: entry for entry in entries}
    contract = load_strict(root / by_role["certification-contract"]["path"])
    semantic = load_strict(root / by_role["semantic-snapshot"]["path"])
    obligation = load_strict(root / by_role["obligation-snapshot"]["path"])
    requirement = load_strict(root / by_role["requirement-snapshot"]["path"])
    migration = load_strict(root / by_role["migration-ledger"]["path"])
    identity = load_strict(root / by_role["identity-catalog"]["path"])
    derivation = load_strict(root / by_role["derivation-catalog"]["path"])
    report = load_strict(root / by_role["certification-report"]["path"])
    accounting = load_strict(root / by_role["denominator-accounting-contract"]["path"])
    audit = load_strict(root / by_role["denominator-audit-report"]["path"])
    handoff = load_strict(root / by_role["profile-expansion-handoff"]["path"])
    audit_authority = load_strict(root / by_role["denominator-audit-authority"]["path"])
    denominator_foundation = load_strict(root / by_role["true-denominator-foundation"]["path"])
    denominator_gate = load_strict(root / by_role["true-denominator-gate-report"]["path"])
    oracle_contract = load_strict(root / by_role["oracle-foundation-contract"]["path"])
    oracle_report = load_strict(root / by_role["oracle-foundation-report"]["path"])
    oracle_authority = load_strict(root / by_role["oracle-authority"]["path"])
    evidence_contract = load_strict(root / by_role["evidence-admissibility-contract"]["path"])
    evidence_report = load_strict(root / by_role["evidence-admissibility-report"]["path"])
    evidence_authority = load_strict(root / by_role["evidence-admissibility-authority"]["path"])
    applicability_contract = load_strict(root / by_role["applicability-contract"]["path"])
    applicability_report = load_strict(root / by_role["applicability-report"]["path"])
    applicability_authority = load_strict(root / by_role["applicability-authority"]["path"])
    adjudication_contract = load_strict(root / by_role["adjudication-contract"]["path"])
    adjudication_fixtures = load_strict(root / by_role["adjudication-fixtures"]["path"])
    adjudication_report = load_strict(root / by_role["adjudication-report"]["path"])
    adjudication_authority = load_strict(root / by_role["adjudication-authority"]["path"])
    evidence_adjudication_closure = load_strict(root / by_role["evidence-adjudication-closure"]["path"])
    bindings = {
        "certification_contract": {"id": contract["contract_id"], **by_role["certification-contract"]},
        "semantic_snapshot": {"id": semantic["snapshot_id"], **by_role["semantic-snapshot"]},
        "obligation_snapshot": {"id": obligation["snapshot_id"], **by_role["obligation-snapshot"]},
        "requirement_snapshot": {"id": requirement["snapshot_id"], **by_role["requirement-snapshot"]},
        "migration_ledger": {"id": migration["ledger_id"], **by_role["migration-ledger"]},
        "denominator_accounting_contract": {"id": accounting["contract_id"], **by_role["denominator-accounting-contract"]},
        "denominator_audit": {"id": audit["report_id"], "result": audit["result"], **by_role["denominator-audit-report"]},
        "profile_expansion_handoff": {"id": handoff["projection_id"], **by_role["profile-expansion-handoff"]},
        "denominator_audit_authority": {"id": audit_authority["index_id"], **by_role["denominator-audit-authority"]},
        "true_denominator_foundation": {"id": denominator_foundation["manifest_id"], **by_role["true-denominator-foundation"]},
        "true_denominator_gate": {"id": denominator_gate["report_id"], "result": denominator_gate["result"], **by_role["true-denominator-gate-report"]},
        "oracle_foundation_contract": {"id": oracle_contract["contract_id"], **by_role["oracle-foundation-contract"]},
        "oracle_foundation_report": {"id": oracle_report["report_id"], "result": oracle_report["result"], **by_role["oracle-foundation-report"]},
        "oracle_authority": {"id": oracle_authority["index_id"], **by_role["oracle-authority"]},
        "evidence_admissibility_contract": {"id": evidence_contract["contract_id"], **by_role["evidence-admissibility-contract"]},
        "evidence_admissibility_report": {"id": evidence_report["report_id"], "result": evidence_report["result"], **by_role["evidence-admissibility-report"]},
        "evidence_admissibility_authority": {"id": evidence_authority["index_id"], **by_role["evidence-admissibility-authority"]},
        "applicability_contract": {"id": applicability_contract["contract_id"], **by_role["applicability-contract"]},
        "applicability_report": {"id": applicability_report["report_id"], "result": applicability_report["result"], **by_role["applicability-report"]},
        "applicability_authority": {"id": applicability_authority["index_id"], **by_role["applicability-authority"]},
        "adjudication_contract": {"id": adjudication_contract["contract_id"], **by_role["adjudication-contract"]},
        "adjudication_fixtures": {"id": adjudication_fixtures["fixture_set_id"], **by_role["adjudication-fixtures"]},
        "adjudication_report": {"id": adjudication_report["report_id"], "result": adjudication_report["result"], **by_role["adjudication-report"]},
        "adjudication_authority": {"id": adjudication_authority["index_id"], **by_role["adjudication-authority"]},
        "evidence_adjudication_closure": {"id": evidence_adjudication_closure["report_id"], "result": evidence_adjudication_closure["result"], **by_role["evidence-adjudication-closure"]},
        "identity_catalog": {"schema_version": identity["schema_version"], "entry_count": len(identity["bindings"]), **by_role["identity-catalog"]},
        "derivation_catalog": {"schema_version": derivation["schema_version"], "derivation_count": len(derivation["derivations"]), **by_role["derivation-catalog"]},
        "current_certification": {"id": report["report_id"], "result": report["final_state"], **by_role["certification-report"]},
    }
    return entries, bindings


def build_manifest(root: Path, source_sha: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    entries, bindings = _artifact_payload(root)
    payload: dict[str, Any] = {
        "schema_version": "local-authoritative-certification.v1",
        "architecture": "Local Authoritative Certification / Hosted Integrity Verification",
        "hash_policy": "jcs-sha256-v1",
        "certified_source": {"git_sha": source_sha, "tree_sha": git_output(root, "rev-parse", f"{source_sha}^{{tree}}"), "worktree_clean": True},
        "promotion_envelope": {"manifest_path": str(MANIFEST_PATH).replace("\\", "/"), "source_must_be_single_parent": True, "manifest_only_commit_required": True},
        "bindings": bindings,
        "generated_artifacts": {"entries": entries, "root_sha256": merkleless_root(entries)},
        "test_results": {"entries": results, "root_sha256": merkleless_root(results)},
        "cheap_aggregates": _cheap_aggregates(root),
        "final_local_certification": {"result": "PASS", "scientific_certification_result": bindings["current_certification"]["result"], "all_authoritative_checks_passed": all(item["result"] == "PASS" for item in results)},
    }
    root_digest = sha256_bytes(canonical_bytes(payload))
    payload["local_certification_root"] = root_digest
    payload["manifest_id"] = f"rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:{root_digest}"
    return payload


def _cheap_aggregates(root: Path) -> dict[str, Any]:
    obligation = load_strict(root / "ontology/obligations/regex-semantic-obligations-2026-09-08.v1.json")
    requirement = load_strict(root / "vectors/requirements/regex-semantic-vector-requirements-2026-09-08.v2.json")
    migration = load_strict(root / "ontology/migrations/regex-semantic-denominator-2026-09-08.v1.json")
    report = load_strict(root / "certification/reports/current-repository-2026-09-08.v2.json")
    audit = load_strict(root / "reports/semantics/regex-semantic-denominator-audit-2026-09-10.v1.json")
    gate = load_strict(root / "reports/semantics/true-obligation-denominator-acceptance-2026-09-10.v1.json")
    handoff = load_strict(root / "ontology/projections/regex-semantic-profile-expansion-handoff-2026-09-10.v1.json")
    dry_run = load_strict(root / "reports/semantics/obligation-derivation-dry-run-2026-09-08.v1.json")
    obligations = obligation["obligations"]
    requirements = requirement["requirements"]
    c4 = next(item for item in report["criteria"] if item["criterion_id"] == "C4")
    audit_result = audit["independent_recomputation"]
    conditional_predicates = {
        canonical_bytes(item["profile_condition"])
        for item in requirements
        if item["requirement_state"] == "conditionally-required"
    }
    obligation_by_id = {item["scientific_id"]: item for item in obligations}
    requirement_by_id = {item["scientific_id"]: item for item in requirements}
    decision_keys = {
        (item["feature_scientific_id"], item["facet_id"], item["decision"], item["rule_revision_id"])
        for item in dry_run["decisions"]
    }
    samples = audit_result["sample_audit"]
    for sample in samples["included_reconstructions"]:
        obligation_item = obligation_by_id.get(sample["obligation_scientific_id"])
        requirement_item = requirement_by_id.get(sample["requirement_scientific_id"])
        if obligation_item is None or requirement_item is None:
            raise LocalCertificationError("denominator audit sample references a missing current object")
        if requirement_item["obligation_scientific_ids"] != [obligation_item["scientific_id"]]:
            raise LocalCertificationError("denominator audit sample attribution is inconsistent")
        if obligation_item["derivation"]["rule_revision_id"] != sample["rule_revision_id"]:
            raise LocalCertificationError("denominator audit sample rule revision is inconsistent")
    for sample in samples["excluded_reconstructions"]:
        key = (sample["feature_scientific_id"], sample["sample_value"], sample["decision"], sample["rule_revision_id"])
        if key not in decision_keys:
            raise LocalCertificationError("denominator audit exclusion sample is not reconstructable")
    return {
        "obligation_count": len(obligations),
        "required_obligation_count": sum(item["requirement_state"] == "required" for item in obligations),
        "conditional_obligation_count": sum(item["requirement_state"] == "conditionally-required" for item in obligations),
        "requirement_count": len(requirements),
        "required_requirement_count": sum(item["requirement_state"] == "required" for item in requirements),
        "conditional_requirement_count": sum(item["requirement_state"] == "conditionally-required" for item in requirements),
        "characterization_requirement_count": sum(item["requirement_type"] == "characterization-only" for item in requirements),
        "executable_requirement_count": sum(audit_result["base_partitions"]["execution_disposition"]["counts"][key] for key in ("executable-conformance", "executable-relational", "executable-characterization")),
        "informative_requirement_count": audit_result["overlapping_rollups"]["informative"],
        "prohibited_requirement_count": audit_result["overlapping_rollups"]["prohibited"],
        "unresolved_requirement_count": audit_result["overlapping_rollups"]["unresolved"],
        "cardinality_expansion_count": sum(item["requirement_cardinality"]["minimum_requirements"] - 1 for item in obligations),
        "distinct_conditional_predicate_count": len(conditional_predicates),
        "distinct_predicate_count": audit_result["predicate_audit"]["distinct_predicates"],
        "conformance_capable_requirement_count": audit_result["base_partitions"]["scientific_purpose"]["counts"]["conformance-capable"],
        "relational_metamorphic_requirement_count": audit_result["base_partitions"]["scientific_purpose"]["counts"]["relational/metamorphic-candidate"],
        "positive_requirement_count": audit_result["base_partitions"]["evidence_role"]["counts"]["positive"],
        "negative_requirement_count": audit_result["base_partitions"]["evidence_role"]["counts"]["negative"],
        "boundary_requirement_count": audit_result["base_partitions"]["evidence_role"]["counts"]["boundary"],
        "true_denominator_gate_result": gate["result"],
        "true_denominator_gate_check_count": len(gate["checks"]),
        "over_count_suspect_count": gate["over_count_audit"]["suspected_over_count"],
        "under_count_suspect_count": gate["under_count_audit"]["suspected_under_count"],
        "expected_requirement_count": None,
        "expected_requirement_lower_bound": sum(item["requirement_state"] == "required" for item in requirements),
        "expected_requirement_upper_bound": len(requirements),
        "authoritative_unexplained_multiplier_count": audit_result["multiplier_audit"]["authoritative_unexplained_multiplier_count"],
        "profile_expansion_deferred": handoff["deferral"]["status"] == "deferred" and handoff["counts"]["exact_profiles"] is None,
        "included_sample_reconstruction_count": len(samples["included_reconstructions"]),
        "excluded_sample_reconstruction_count": len(samples["excluded_reconstructions"]),
        "predecessor_obligation_count": len(migration["obligation_migrations"]),
        "predecessor_requirement_count": len(migration["requirement_migrations"]),
        "c4_result": c4["status"],
        "c4_completed": c4["numerator_count"],
        "c4_denominator": c4["denominator_count"],
    }


def _payload_without_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key not in {"local_certification_root", "manifest_id"}}


def _verify_adjudication_scientific_boundary(adjudication_report: dict[str, Any]) -> None:
    certification_state = adjudication_report.get("certification_state", {})
    denominator = adjudication_report.get("denominator_boundary", {})
    if adjudication_report.get("result") != LOCAL_CHECK_PASS or adjudication_report.get("coverage", {}).get("adversarial_case_count") != 17:
        raise LocalCertificationError("adjudication acceptance result or adversarial coverage is invalid")
    if certification_state.get("C4") != "FAIL" or certification_state.get("C4_completed") != 0 or certification_state.get("C4_denominator") != 3378:
        raise LocalCertificationError("adjudication report does not preserve the honest C4 result")
    if denominator.get("obligations") != 2390 or denominator.get("requirements") != 3378 or denominator.get("real_profile_coordinates_generated") != 0:
        raise LocalCertificationError("adjudication report changes the semantic or profile-coordinate boundary")


def verify_manifest(root: Path, manifest_path: Path, *, expected_envelope_sha: str | None = None, expected_root: str | None = None, require_envelope: bool = True) -> dict[str, Any]:
    manifest = load_strict(root / manifest_path)
    if manifest.get("schema_version") != "local-authoritative-certification.v1":
        raise LocalCertificationError("unsupported local certification schema")
    calculated_root = sha256_bytes(canonical_bytes(_payload_without_identity(manifest)))
    if manifest.get("local_certification_root") != calculated_root:
        raise LocalCertificationError("local certification root mismatch")
    if manifest.get("manifest_id") != f"rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:{calculated_root}":
        raise LocalCertificationError("local certification typed identity mismatch")
    if expected_root is not None and expected_root != calculated_root:
        raise LocalCertificationError("caller-recorded local certification root mismatch")
    source_sha = manifest["certified_source"]["git_sha"]
    if FULL_SHA.fullmatch(source_sha) is None:
        raise LocalCertificationError("manifest source SHA is not exact")
    if manifest["certified_source"].get("worktree_clean") is not True:
        raise LocalCertificationError("manifest does not attest a clean source worktree")
    entries = manifest["generated_artifacts"]["entries"]
    for entry in entries:
        observed = file_binding(root, entry["role"], entry["path"])
        if observed != entry:
            raise LocalCertificationError(f"artifact binding mismatch: {entry['path']}")
    if merkleless_root(entries) != manifest["generated_artifacts"]["root_sha256"]:
        raise LocalCertificationError("generated-artifact closure root mismatch")
    tests = manifest["test_results"]["entries"]
    if not tests or any(item["result"] != "PASS" or item["exit_code"] != 0 for item in tests):
        raise LocalCertificationError("local authoritative test-result set is not all PASS")
    if merkleless_root(tests) != manifest["test_results"]["root_sha256"]:
        raise LocalCertificationError("test-result closure root mismatch")
    if manifest["final_local_certification"] != {
        "result": "PASS",
        "scientific_certification_result": manifest["bindings"]["current_certification"]["result"],
        "all_authoritative_checks_passed": True,
    }:
        raise LocalCertificationError("final local certification result is malformed or not PASS")
    if _cheap_aggregates(root) != manifest["cheap_aggregates"]:
        raise LocalCertificationError("independent cheap aggregate verification failed")
    identity_text = (root / IDENTITY_CATALOG).read_text(encoding="utf-8")
    derivation_text = (root / DERIVATION_CATALOG).read_text(encoding="utf-8")
    for binding_name in ("semantic_snapshot", "obligation_snapshot", "requirement_snapshot", "migration_ledger", "denominator_accounting_contract", "denominator_audit", "profile_expansion_handoff", "denominator_audit_authority", "true_denominator_foundation", "true_denominator_gate"):
        if manifest["bindings"][binding_name]["id"] not in identity_text and ":h:" not in manifest["bindings"][binding_name]["id"]:
            raise LocalCertificationError(f"assigned identity binding is absent from identity catalog: {binding_name}")
    materialization = load_strict(root / "reports/semantics/semantic-denominator-materialization-2026-09-08.v1.json")
    if materialization["derivations"]["materialization_derivation_revision_id"] not in derivation_text:
        raise LocalCertificationError("materialization derivation revision is absent from derivation catalog")
    audit = load_strict(root / manifest["bindings"]["denominator_audit"]["path"])
    if audit.get("result") != "PASS" or audit.get("derivation_revision_id") not in derivation_text:
        raise LocalCertificationError("denominator audit is not PASS or its derivation revision is absent from the catalog")
    gate = load_strict(root / manifest["bindings"]["true_denominator_gate"]["path"])
    if gate.get("result") != "PASS" or len(gate.get("checks", [])) != 20:
        raise LocalCertificationError("true denominator gate is not PASS with its exact predicate set")
    foundation = load_strict(root / manifest["bindings"]["true_denominator_foundation"]["path"])
    if gate["foundation_manifest"]["artifact_id"] != foundation.get("manifest_id"):
        raise LocalCertificationError("true denominator gate does not bind its exact foundation manifest")
    oracle_binding = manifest["bindings"].get("oracle_foundation_report")
    if oracle_binding is not None:
        oracle_report = load_strict(root / oracle_binding["path"])
        if oracle_report.get("result") != "PASS":
            raise LocalCertificationError("oracle foundation report is not PASS")
        oracle_contract = load_strict(root / manifest["bindings"]["oracle_foundation_contract"]["path"])
        oracle_authority = load_strict(root / manifest["bindings"]["oracle_authority"]["path"])
        if oracle_report.get("contract", {}).get("artifact_id") != oracle_contract.get("contract_id"):
            raise LocalCertificationError("oracle foundation report does not bind its exact contract")
        if oracle_authority.get("current_contract", {}).get("artifact_id") != oracle_contract.get("contract_id"):
            raise LocalCertificationError("oracle authority does not bind its exact current contract")
    evidence_binding = manifest["bindings"].get("evidence_admissibility_report")
    if evidence_binding is not None:
        evidence_report = load_strict(root / evidence_binding["path"])
        evidence_contract = load_strict(root / manifest["bindings"]["evidence_admissibility_contract"]["path"])
        evidence_authority = load_strict(root / manifest["bindings"]["evidence_admissibility_authority"]["path"])
        if evidence_report.get("result") != "PASS":
            raise LocalCertificationError("evidence admissibility report is not PASS")
        if evidence_report.get("contract", {}).get("artifact_id") != evidence_contract.get("contract_id"):
            raise LocalCertificationError("evidence admissibility report does not bind its exact contract")
        if evidence_authority.get("current_contract", {}).get("artifact_id") != evidence_contract.get("contract_id"):
            raise LocalCertificationError("evidence admissibility authority does not bind its exact current contract")
        if evidence_contract.get("oracle_foundation", {}).get("artifact_id") != manifest["bindings"]["oracle_foundation_contract"].get("id"):
            raise LocalCertificationError("evidence admissibility contract does not bind the fixed oracle foundation")
    applicability_binding = manifest["bindings"].get("applicability_report")
    if applicability_binding is not None:
        applicability_report = load_strict(root / applicability_binding["path"])
        applicability_contract = load_strict(root / manifest["bindings"]["applicability_contract"]["path"])
        applicability_authority = load_strict(root / manifest["bindings"]["applicability_authority"]["path"])
        if applicability_report.get("result") != "PASS" or applicability_report.get("coverage", {}).get("conditional_requirements_validated") != 1972:
            raise LocalCertificationError("conditional applicability report is not PASS with complete requirement coverage")
        if applicability_report.get("contract", {}).get("artifact_id") != applicability_contract.get("contract_id"):
            raise LocalCertificationError("conditional applicability report does not bind its exact contract")
        if applicability_authority.get("current_contract", {}).get("artifact_id") != applicability_contract.get("contract_id"):
            raise LocalCertificationError("conditional applicability authority does not bind its exact contract")
    adjudication_binding = manifest["bindings"].get("adjudication_report")
    if adjudication_binding is not None:
        adjudication_report = load_strict(root / adjudication_binding["path"])
        adjudication_contract = load_strict(root / manifest["bindings"]["adjudication_contract"]["path"])
        adjudication_fixtures = load_strict(root / manifest["bindings"]["adjudication_fixtures"]["path"])
        adjudication_authority = load_strict(root / manifest["bindings"]["adjudication_authority"]["path"])
        _verify_adjudication_scientific_boundary(adjudication_report)
        if adjudication_report.get("contract", {}).get("artifact_id") != adjudication_contract.get("contract_id"):
            raise LocalCertificationError("adjudication report does not bind its exact contract")
        if adjudication_authority.get("current_contract", {}).get("artifact_id") != adjudication_contract.get("contract_id"):
            raise LocalCertificationError("adjudication authority does not bind its exact current contract")
        if adjudication_authority.get("validation_fixture", {}).get("artifact_id") != adjudication_fixtures.get("fixture_set_id"):
            raise LocalCertificationError("adjudication authority does not bind its exact fixture set")
        predecessors = adjudication_contract.get("predecessor_contracts", {})
        if predecessors.get("applicability", {}).get("artifact_id") != manifest["bindings"]["applicability_contract"].get("id"):
            raise LocalCertificationError("adjudication does not bind the exact applicability predecessor")
        if predecessors.get("evidence_admissibility", {}).get("artifact_id") != manifest["bindings"]["evidence_admissibility_contract"].get("id"):
            raise LocalCertificationError("adjudication does not bind the exact evidence-admissibility predecessor")
    closure_binding = manifest["bindings"].get("evidence_adjudication_closure")
    if closure_binding is not None:
        closure = load_strict(root / closure_binding["path"])
        if closure.get("result") != LOCAL_CHECK_PASS or len(closure.get("gate_checks", [])) != 15:
            raise LocalCertificationError("evidence-adjudication architecture closure is not PASS")
        if closure.get("denominator", {}).get("production_coverage_credit") != 0 or closure.get("certification", {}).get("C4") != "FAIL":
            raise LocalCertificationError("architecture closure manufactures scientific coverage")
        if closure.get("promotion", {}).get("promoted_repository_sha") != "89ffaabebaa487cf2f2357e84aa1f4943bca3eac":
            raise LocalCertificationError("architecture closure does not bind the reviewed promotion")
    if require_envelope:
        envelope_sha = expected_envelope_sha or git_output(root, "rev-parse", "HEAD")
        if FULL_SHA.fullmatch(envelope_sha) is None or git_output(root, "rev-parse", "HEAD") != envelope_sha:
            raise LocalCertificationError("checked-out envelope does not equal the exact expected SHA")
        parents = git_output(root, "show", "-s", "--format=%P", envelope_sha).split()
        if parents != [source_sha]:
            raise LocalCertificationError("certification envelope must have the certified source as its single parent")
        changed = git_output(root, "diff", "--name-only", source_sha, envelope_sha).splitlines()
        if changed != [str(manifest_path).replace("\\", "/")]:
            raise LocalCertificationError("certification envelope must change only its manifest")
        if git_output(root, "rev-parse", f"{source_sha}^{{tree}}") != manifest["certified_source"]["tree_sha"]:
            raise LocalCertificationError("certified source tree binding mismatch")
    return {"result": "PASS", "envelope_sha": expected_envelope_sha, "certified_source_sha": source_sha, "local_certification_root": calculated_root, "verified_artifact_count": len(entries), "verified_test_result_count": len(tests), "cheap_aggregates": manifest["cheap_aggregates"]}


def write_manifest(root: Path, path: Path, manifest: dict[str, Any]) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(dump_pretty(manifest), encoding="utf-8")
