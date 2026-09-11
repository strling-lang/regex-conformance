#!/usr/bin/env python3
"""Build or verify the evidence-adjudication architecture closure record."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity
from regex_conformance_schema.jsonio import canonical_bytes, dump_pretty, load_strict
from regex_conformance_schema.profile import IdentityProfile

BASE_SHA = "9ab4d93a8f4d41796f34639ee0e2eaab79a12748"
SOURCE_CANDIDATE_SHA = "a07f539239bfdd0fe838caae9e186db7be27a5c9"
REFERENCE_TREE_SHA = "8182858771c1ad8dc71c67154e5980ff5e254f76"
PROMOTED_SHA = "89ffaabebaa487cf2f2357e84aa1f4943bca3eac"
CERTIFIED_SOURCE_SHA = "2532eb424c5336bcddaf9e3378dd814b4b597b3f"
CERTIFICATION_ROOT = "a97f1c7b847765282730aba8b5c7cbc8300b6c02b872b2acb949a2936e2d1485"
SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a08ef7-2c40-7aa1-8b61-0d334a5b2451"
REPORT_PATH = Path("certification/reports/evidence-adjudication-architecture-closure-2026-09-11.v1.json")
SCHEMA_PATH = Path("schemas/json/evidence-adjudication-architecture-closure.schema.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v1.json")
CONTENT_PROFILE_PATH = Path("schemas/identity-profiles/campaign-content.v1.json")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _artifact_ref(path: str, id_field: str, digest_field: str) -> dict[str, Any]:
    record = load_strict(ROOT / path)
    return {
        "path": path,
        "artifact_id": record[id_field],
        "digest_sha256": record[digest_field],
        "file_sha256": _sha(ROOT / path),
    }


def _finalize(body: dict[str, Any]) -> dict[str, Any]:
    digest = _digest(body)
    identity = build_content_identity(
        registry=NamespaceRegistry.load(ROOT / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(ROOT / CONTENT_PROFILE_PATH)),
        namespace="trust-assessment",
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": "evidence-adjudication-architecture-closure-v1", "content_sha256": digest},
    )
    return {**body, "report_id": identity["content_id"], "report_digest_sha256": digest}


def build_report() -> dict[str, Any]:
    certification = load_strict(ROOT / "certification/reports/current-repository-2026-09-08.v2.json")
    body = {
        "schema_version": "evidence-adjudication-architecture-closure.v1",
        "published_on": "2026-09-11",
        "closure_scope": "Rules for correctness, profile applicability, evidence admission, observation adjudication, typed claims, discrepancies, permitted divergence, waiver gating, and quarantine operations. This closure creates no empirical coverage.",
        "reconstruction": {
            "reason": "linear-promotion-policy",
            "authoritative_base_sha": BASE_SHA,
            "source_integrated_candidate_sha": SOURCE_CANDIDATE_SHA,
            "source_integrated_candidate_tree_sha": REFERENCE_TREE_SHA,
            "original_implementation_commits": {
                "evidence_admissibility": "4023b09b87927e5ad4a54b5fbc01b053bcf82dd4",
                "conditional_applicability": "d3679c752abc012779fa9b6b0a584f5002e6209c",
                "observation_to_claim_adjudication": SOURCE_CANDIDATE_SHA,
            },
            "original_integration_merge_commits": [
                "47693526e97bcc975dbba7041d564760e35ec619",
                "1bc259b391dd05f9ad447d362e626f719c76d96f",
            ],
            "replacement_commits": {
                "evidence_admissibility": "5392663bcbf7cef0547a7856e819c761634e3049",
                "conditional_applicability": "f1836e940b66d47b1319ebaf2b89c99ccb009634",
                "observation_to_claim_adjudication": "c17477a15ac9350792f3e6b8b56c55297a632bd9",
            },
            "content_equivalence": {
                "reference_sha": SOURCE_CANDIDATE_SHA,
                "reconstructed_sha": "c17477a15ac9350792f3e6b8b56c55297a632bd9",
                "reference_tree_sha": REFERENCE_TREE_SHA,
                "reconstructed_tree_sha": REFERENCE_TREE_SHA,
                "git_diff_exit_code": 0,
                "result": "PASS",
            },
            "review_correction": {
                "commit_sha": CERTIFIED_SOURCE_SHA,
                "classification": "hosted-certificate-verifier-integration-defect",
                "changed_paths": [
                    "tests/ci/test_local_certification.py",
                    "tools/ci/certify_local.py",
                    "tools/ci/local_certification.py",
                ],
                "scientific_semantics_changed": False,
            },
            "promotion_range_merge_count": 0,
        },
        "authority_bindings": {
            "evidence_admissibility_contract": _artifact_ref("oracle/contracts/regex-conformance-evidence-admissibility-2026-09-10.v1.json", "contract_id", "contract_digest_sha256"),
            "evidence_admissibility_acceptance": _artifact_ref("reports/oracle/evidence-admissibility-2026-09-10.v1.json", "report_id", "report_digest_sha256"),
            "conditional_applicability_contract": _artifact_ref("applicability/contracts/regex-conformance-conditional-applicability-2026-09-10.v1.json", "contract_id", "contract_digest_sha256"),
            "conditional_applicability_acceptance": _artifact_ref("reports/applicability/conditional-requirement-applicability-2026-09-10.v1.json", "report_id", "report_digest_sha256"),
            "adjudication_contract": _artifact_ref("adjudication/contracts/regex-conformance-adjudication-2026-09-11.v1.json", "contract_id", "contract_digest_sha256"),
            "adjudication_acceptance": _artifact_ref("reports/adjudication/adjudication-acceptance-2026-09-11.v1.json", "report_id", "report_digest_sha256"),
            "semantic_denominator_authority": _artifact_ref("ontology/authority/current-semantic-denominator.v1.json", "index_id", "index_digest_sha256"),
            "certification_state": _artifact_ref("certification/reports/current-repository-2026-09-08.v2.json", "report_id", "report_digest_sha256"),
        },
        "promotion": {
            "certified_source_sha": CERTIFIED_SOURCE_SHA,
            "local_certification_root": CERTIFICATION_ROOT,
            "promoted_repository_sha": PROMOTED_SHA,
            "hosted_verification": [
                {"run_id": 34615173291, "job_id": 103315176362, "event": "workflow_dispatch", "head_sha": PROMOTED_SHA, "result": "PASS"},
                {"run_id": 34615490107, "job_id": 103316251389, "event": "push", "head_sha": PROMOTED_SHA, "result": "PASS"},
            ],
        },
        "denominator": {
            "obligations": 2390,
            "requirements": 3378,
            "unconditional_requirements": 1406,
            "conditional_requirements": 1972,
            "conditional_requirements_represented": 1972,
            "real_profile_coordinates_generated": 0,
            "profile_expanded_denominator": None,
            "production_coverage_credit": 0,
        },
        "certification": {
            "C1": "BLOCKED", "C2": "BLOCKED", "C3": "BLOCKED", "C4": "FAIL",
            "C4_completed": 0, "C4_denominator": 3378, "C5": "BLOCKED", "C6": "BLOCKED", "C7": "BLOCKED",
            "final_state": certification["final_state"],
        },
        "gate_checks": [
            {"check_id": check_id, "status": "PASS"}
            for check_id in (
                "requirement-identity", "profile-applicability", "applicability-trace", "evidence-admission",
                "oracle-conclusion-boundary", "expectation-binding", "physical-attempt-history", "eligible-observation-selection",
                "expectation-comparison", "typed-claim-derivation", "discrepancy-preservation", "positive-permitted-divergence",
                "waiver-quarantine-boundary", "immutable-reconstruction", "certification-honesty",
            )
        ],
        "boundary": {
            "linear_reconstruction_changes_history_not_science": True,
            "production_campaign_executed": False,
            "empirical_coverage_created": False,
            "profile_expansion_performed": False,
            "successor_implementation_started": False,
        },
        "result": "PASS",
    }
    if certification["final_state"] != "FAIL":
        raise ValueError("scientific certification unexpectedly improved")
    return _finalize(body)


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=ROOT, check=check, capture_output=True, text=True)


def _verify_history() -> None:
    commits = [
        BASE_SHA, SOURCE_CANDIDATE_SHA, PROMOTED_SHA, CERTIFIED_SOURCE_SHA,
        "4023b09b87927e5ad4a54b5fbc01b053bcf82dd4", "d3679c752abc012779fa9b6b0a584f5002e6209c",
        "47693526e97bcc975dbba7041d564760e35ec619", "1bc259b391dd05f9ad447d362e626f719c76d96f",
        "5392663bcbf7cef0547a7856e819c761634e3049", "f1836e940b66d47b1319ebaf2b89c99ccb009634",
        "c17477a15ac9350792f3e6b8b56c55297a632bd9",
    ]
    for commit in commits:
        if _git("cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode != 0:
            raise ValueError(f"unresolvable reconstruction commit: {commit}")
    if _git("show", "-s", "--format=%T", SOURCE_CANDIDATE_SHA).stdout.strip() != REFERENCE_TREE_SHA:
        raise ValueError("source candidate tree drift")
    if _git("show", "-s", "--format=%T", "c17477a15ac9350792f3e6b8b56c55297a632bd9").stdout.strip() != REFERENCE_TREE_SHA:
        raise ValueError("linear reconstruction tree drift")
    if _git("diff", "--quiet", SOURCE_CANDIDATE_SHA, "c17477a15ac9350792f3e6b8b56c55297a632bd9", check=False).returncode != 0:
        raise ValueError("linear reconstruction differs from source candidate")
    if _git("rev-list", "--merges", f"{BASE_SHA}..{PROMOTED_SHA}").stdout.strip():
        raise ValueError("promoted range contains a merge commit")
    for replacement in ("5392663bcbf7cef0547a7856e819c761634e3049", "f1836e940b66d47b1319ebaf2b89c99ccb009634", "c17477a15ac9350792f3e6b8b56c55297a632bd9"):
        message = _git("show", "-s", "--format=%B", replacement).stdout
        if "Reconstruction-Reason: linear-promotion-policy" not in message or f"Source-Candidate: {SOURCE_CANDIDATE_SHA}" not in message:
            raise ValueError(f"replacement commit lacks reconstruction trailers: {replacement}")


def verify_current(*, history: bool) -> dict[str, Any]:
    expected = build_report()
    observed = load_strict(ROOT / REPORT_PATH)
    Draft202012Validator.check_schema(load_strict(ROOT / SCHEMA_PATH))
    Draft202012Validator(load_strict(ROOT / SCHEMA_PATH)).validate(observed)
    if observed != expected:
        raise ValueError("tracked evidence-adjudication closure report differs from deterministic build")
    if history:
        _verify_history()
    return {"result": "PASS", "report_id": observed["report_id"], "gate_checks": len(observed["gate_checks"]), "history_verified": history}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--bounded", action="store_true")
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    if args.bounded and args.history:
        parser.error("--bounded and --history are mutually exclusive")
    try:
        if not args.check:
            target = ROOT / REPORT_PATH
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(dump_pretty(build_report()), encoding="utf-8")
        result = verify_current(history=args.history)
        print(result)
    except (OSError, ValueError) as error:
        print(f"closure verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
