"""Fail-closed structural policy for the disposable public CI trust zone."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SHA = r"[0-9a-f]{40}"
HASH = r"[0-9a-f]{64}"
USE_PATTERN = re.compile(r"^\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(\S+)", re.MULTILINE)
PACKAGE_PATTERN = re.compile(r"^([a-z0-9-]+)==([^\s\\]+)", re.MULTILINE)
WHEEL_HASH_PATTERN = re.compile(r"--hash=sha256:(" + HASH + r")")


@dataclass(frozen=True)
class Violation:
    code: str
    message: str


class PublicCiPolicyError(ValueError):
    def __init__(self, violations: list[Violation]) -> None:
        self.violations = violations
        super().__init__("; ".join(f"{item.code}: {item.message}" for item in violations))


def _require(condition: bool, violations: list[Violation], code: str, message: str) -> None:
    if not condition:
        violations.append(Violation(code, message))


def _package_versions(text: str) -> dict[str, str]:
    return {name: version for name, version in PACKAGE_PATTERN.findall(text)}


def evaluate(root: Path) -> list[Violation]:
    violations: list[Violation] = []
    workflows = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    expected_workflow = root / ".github" / "workflows" / "public-validation.yml"
    _require(workflows == [expected_workflow], violations, "workflow-scope", "bootstrap permits exactly one public workflow")
    if not expected_workflow.is_file():
        return violations

    workflow = expected_workflow.read_text(encoding="utf-8")
    folded = workflow.casefold()
    forbidden = {
        "forbidden-trigger": ["pull_request_target:", "repository_dispatch:", "workflow_run:", "workflow_call:"],
        "self-hosted-runner": ["self-hosted"],
        "secret-reference": ["secrets.", "secrets["],
        "artifact-handoff": ["actions/upload-artifact", "actions/download-artifact"],
        "trusted-publication": ["environment:", "sigstore", "publish evidence"],
    }
    for code, markers in forbidden.items():
        for marker in markers:
            _require(marker not in folded, violations, code, f"public workflow contains forbidden marker {marker!r}")

    _require("\n  pull_request:\n" in workflow, violations, "missing-pr-trigger", "pull_request validation is required")
    _require("\npermissions:\n  contents: read\n" in workflow, violations, "workflow-permissions", "top-level permissions must be contents: read")
    _require(re.search(r"^\s+[a-z-]+:\s+write\s*$", workflow, re.MULTILINE) is None, violations, "write-permission", "public workflow may not request write permission")
    _require("runs-on: ubuntu-24.04" in workflow, violations, "runner-class", "public workflow must use the audited disposable hosted image")
    _require("timeout-minutes: 10" in workflow, violations, "missing-timeout", "public job must have a bounded timeout")
    _require("persist-credentials: false" in workflow, violations, "checkout-credentials", "checkout credentials must not persist")
    _require("--require-hashes" in workflow and "--only-binary=:all:" in workflow, violations, "dependency-install", "CI dependency installation must enforce hashes and wheels")
    for command in [
        "verify_public_ci.py --root .",
        "validate-repository",
        "verify-fixtures",
        "unittest discover -s tests/schema",
        "unittest discover -s tests/ci",
        "materialize-fixtures",
        "git diff --exit-code -- tests/fixtures/identity/manifest.json",
    ]:
        _require(command in workflow, violations, "missing-validation", f"workflow omits required command {command!r}")

    policy_path = root / ".github" / "policies" / "main-protection.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        violations.append(Violation("invalid-protection-policy", str(error)))
        return violations

    allowed = policy.get("actions", {}).get("allowed_actions", {})
    observed_actions = USE_PATTERN.findall(workflow)
    _require(bool(observed_actions), violations, "missing-action", "workflow must contain its audited setup actions")
    for action, revision in observed_actions:
        _require(re.fullmatch(SHA, revision) is not None, violations, "floating-action", f"{action} is not pinned to a full commit SHA")
        _require(action in allowed, violations, "unapproved-action", f"{action} is absent from the allowlist")
        if action in allowed:
            _require(allowed[action].get("revision") == revision, violations, "action-revision-mismatch", f"{action} does not match its audited revision")
    _require(set(action for action, _ in observed_actions) == set(allowed), violations, "action-allowlist-drift", "workflow actions and allowlist differ")

    _require(policy.get("branch") == "main" and policy.get("enforcement") == "active", violations, "protection-target", "main protection must be active")
    rules = policy.get("rules", {})
    _require(rules.get("required_status_checks") == ["public-validation"], violations, "required-check", "public-validation must be the sole bootstrap required check")
    for key in ["block_deletions", "block_force_pushes", "require_linear_history"]:
        _require(rules.get(key) is True, violations, "branch-protection", f"{key} must be true")
    pull_request = policy.get("pull_request", {})
    _require(pull_request.get("required") is True, violations, "pull-request-boundary", "main must require pull requests")
    _require(pull_request.get("require_conversation_resolution") is True, violations, "conversation-resolution", "main must require conversation resolution")
    actions = policy.get("actions", {})
    _require(actions.get("default_workflow_permissions") == "read", violations, "default-token-permission", "default workflow token must be read-only")
    _require(actions.get("can_approve_pull_requests") is False, violations, "workflow-approval", "workflows may not approve pull requests")
    _require(actions.get("organization_actions_allowed") is True, violations, "organization-action-policy", "repository enforcement must admit organization-owned actions")
    _require(actions.get("require_full_length_sha") is True, violations, "action-pinning-policy", "repository enforcement must require full-length action SHAs")
    _require(actions.get("public_artifact_upload") is False, violations, "artifact-policy", "public artifact upload must be disabled")
    trusted_runner = policy.get("trusted_runner", {})
    _require(trusted_runner.get("admission_from_public_workflow") is False, violations, "trusted-admission", "public workflow may not admit trusted execution")
    _require(trusted_runner.get("self_hosted_labels_allowed") == [], violations, "trusted-labels", "public workflow must allow no self-hosted labels")

    canonical_lock = (root / "requirements.lock").read_text(encoding="utf-8")
    ci_lock = (root / "requirements.ci.lock").read_text(encoding="utf-8")
    _require(_package_versions(canonical_lock) == _package_versions(ci_lock), violations, "dependency-version-drift", "CI and canonical dependency versions differ")
    packages = _package_versions(ci_lock)
    hashes = WHEEL_HASH_PATTERN.findall(ci_lock)
    _require(len(hashes) == len(packages), violations, "dependency-hash-count", "every CI package must have exactly one audited wheel hash")
    _require(all(len(value) == 64 for value in hashes), violations, "invalid-dependency-hash", "CI wheel hash is malformed")

    codeowners = (root / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
    for owned_path in ["/.github/", "/tools/ci/", "/requirements.ci.lock"]:
        _require(owned_path in codeowners, violations, "ownership-gap", f"{owned_path} lacks explicit owner routing")
    return violations


def verify(root: Path) -> None:
    violations = evaluate(root)
    if violations:
        raise PublicCiPolicyError(violations)
