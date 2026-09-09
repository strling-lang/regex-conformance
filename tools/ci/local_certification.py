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
    ("certification-input", "certification/inputs/current-repository-2026-09-08.v2.json"),
    ("certification-report", "certification/reports/current-repository-2026-09-08.v2.json"),
    ("certification-authority", "certification/current-authority.v1.json"),
    ("identity-catalog", str(IDENTITY_CATALOG).replace("\\", "/")),
    ("derivation-catalog", str(DERIVATION_CATALOG).replace("\\", "/")),
    ("scientific-foundation-acceptance", "foundation/scientific-foundation-acceptance.v1.json"),
    ("semantic-foundation-acceptance", "semantic-corpus/foundation/semantic-knowledge-architecture.v1.json"),
    ("local-certification-schema", str(SCHEMA_PATH).replace("\\", "/")),
)

LOCAL_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("python", "tools/semantics/generate_obligation_snapshots.py", "--check"),
    ("python", "tools/certification/evaluate.py", "--check"),
    ("python", "tools/semantics/certify_semantic_knowledge.py", "--check"),
    ("python", "tools/foundation/certify.py", "--check"),
    ("python", "tools/identity/freeze_scientific_identities.py", "--check"),
    ("python", "tools/provenance/compile_generated_assertion_derivations.py", "--check"),
    ("python", "schemas/tooling/python/run.py", "validate-repository"),
    ("python", "schemas/tooling/python/run.py", "verify-fixtures"),
    ("python", "tools/ci/verify_repository_identifier_hygiene.py", "--root", "."),
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
    bindings = {
        "certification_contract": {"id": contract["contract_id"], **by_role["certification-contract"]},
        "semantic_snapshot": {"id": semantic["snapshot_id"], **by_role["semantic-snapshot"]},
        "obligation_snapshot": {"id": obligation["snapshot_id"], **by_role["obligation-snapshot"]},
        "requirement_snapshot": {"id": requirement["snapshot_id"], **by_role["requirement-snapshot"]},
        "migration_ledger": {"id": migration["ledger_id"], **by_role["migration-ledger"]},
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
    obligations = obligation["obligations"]
    requirements = requirement["requirements"]
    c4 = next(item for item in report["criteria"] if item["criterion_id"] == "C4")
    return {
        "obligation_count": len(obligations),
        "required_obligation_count": sum(item["requirement_state"] == "required" for item in obligations),
        "conditional_obligation_count": sum(item["requirement_state"] == "conditionally-required" for item in obligations),
        "requirement_count": len(requirements),
        "conditional_requirement_count": sum(item["requirement_state"] == "conditionally-required" for item in requirements),
        "predecessor_obligation_count": len(migration["obligation_migrations"]),
        "predecessor_requirement_count": len(migration["requirement_migrations"]),
        "c4_result": c4["status"],
        "c4_completed": c4["numerator_count"],
        "c4_denominator": c4["denominator_count"],
    }


def _payload_without_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key not in {"local_certification_root", "manifest_id"}}


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
    for binding_name in ("semantic_snapshot", "obligation_snapshot", "requirement_snapshot", "migration_ledger"):
        if manifest["bindings"][binding_name]["id"] not in identity_text and ":h:" not in manifest["bindings"][binding_name]["id"]:
            raise LocalCertificationError(f"assigned identity binding is absent from identity catalog: {binding_name}")
    materialization = load_strict(root / "reports/semantics/semantic-denominator-materialization-2026-09-08.v1.json")
    if materialization["derivations"]["materialization_derivation_revision_id"] not in derivation_text:
        raise LocalCertificationError("materialization derivation revision is absent from derivation catalog")
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
