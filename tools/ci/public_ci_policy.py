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
    trusted_workflow = root / ".github" / "workflows" / "trusted-r2-publication-canary.yml"
    million_workflow = root / ".github" / "workflows" / "trusted-million-qualification.yml"
    _require(
        workflows == sorted([expected_workflow, trusted_workflow, million_workflow]),
        violations,
        "workflow-scope",
        "repository permits exactly public validation and the two audited trusted manual workflows",
    )
    if (
        not expected_workflow.is_file()
        or not trusted_workflow.is_file()
        or not million_workflow.is_file()
    ):
        return violations

    workflow = expected_workflow.read_text(encoding="utf-8")
    trusted = trusted_workflow.read_text(encoding="utf-8")
    million = million_workflow.read_text(encoding="utf-8")
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
    _require("\n      - main\n" in workflow, violations, "missing-main-trigger", "main pushes must receive public validation")
    _require("\npermissions:\n  contents: read\n" in workflow, violations, "workflow-permissions", "top-level permissions must be contents: read")
    _require(re.search(r"^\s+[a-z-]+:\s+write\s*$", workflow, re.MULTILINE) is None, violations, "write-permission", "public workflow may not request write permission")
    _require("runs-on: ubuntu-24.04" in workflow, violations, "runner-class", "public workflow must use the audited disposable hosted image")
    _require("timeout-minutes: 30" in workflow, violations, "missing-timeout", "public job must have a bounded timeout")
    checkout_count = len(re.findall(r"^\s*uses:\s*actions/checkout@", workflow, re.MULTILINE))
    _require(
        checkout_count > 0 and workflow.count("persist-credentials: false") == checkout_count,
        violations,
        "checkout-credentials",
        "every checkout must explicitly disable persisted credentials",
    )
    _require("--require-hashes" in workflow and "--only-binary=:all:" in workflow, violations, "dependency-install", "CI dependency installation must enforce hashes and wheels")
    for command in [
        "verify_public_ci.py --root .",
        "validate-repository",
        "verify-fixtures",
        "unittest discover -s tests/schema",
        "unittest discover -s tests/adapters",
        "unittest discover -s tests/campaign",
        "python -m unittest discover -s tests/control_plane -v",
        "unittest discover -s tests/ci",
        "materialize-fixtures",
        "git diff --exit-code -- tests/fixtures/identity/manifest.json",
        "minimal-environment-certification:",
        "if: github.event_name != 'pull_request'",
        "timeout-minutes: 45",
        (
            "python tools/environments/certify_minimal.py "
            '--state-root "$RUNNER_TEMP/strling-regex-state" '
            '--evidence-dir "$RUNNER_TEMP/strling-regex-evidence" '
            "--trust-class untrusted_public "
            '--compact-report "$RUNNER_TEMP/minimal-environment-certification.json"'
        ),
        "minimal-environment-certification.schema.json",
        "docker ps --all --quiet --filter name=strling-rc-",
        "git diff --exit-code",
        "minimal-adapter-certification:",
        "needs: minimal-environment-certification",
        (
            "python tools/adapters/certify_minimal.py "
            '--state-root "$RUNNER_TEMP/strling-regex-adapter-state" '
            '--evidence-dir "$RUNNER_TEMP/strling-regex-adapter-evidence" '
            "--trust-class untrusted_public "
            '--compact-report "$RUNNER_TEMP/minimal-adapter-certification.json"'
        ),
        "minimal-adapter-certification.schema.json",
        "strling-regex-adapter-state",
        "first-end-to-end-campaign:",
        "needs: minimal-adapter-certification",
        (
            "python tools/campaigns/run_vertical_slice.py "
            '--state-root "$RUNNER_TEMP/strling-regex-campaign-state" '
            '--evidence-dir "$RUNNER_TEMP/strling-regex-campaign-evidence" '
            '--warehouse-dir "$RUNNER_TEMP/strling-regex-campaign-warehouse" '
            "--trust-class untrusted_public "
            '--compact-report "$RUNNER_TEMP/first-campaign-report.json"'
        ),
        "first-campaign-report.schema.json",
        "strling-regex-campaign-evidence",
        "strling-regex-campaign-warehouse",
    ]:
        _require(command in workflow, violations, "missing-validation", f"workflow omits required command {command!r}")

    trusted_folded = trusted.casefold()
    for marker in ["pull_request:", "pull_request_target:", "push:", "schedule:", "repository_dispatch:", "workflow_run:", "workflow_call:"]:
        _require(marker not in trusted_folded, violations, "trusted-trigger", f"trusted R2 canary contains forbidden trigger {marker!r}")
    _require("\n  workflow_dispatch:\n" in trusted, violations, "trusted-trigger", "trusted R2 canary must be manual-only")
    _require("\npermissions:\n  contents: read\n" in trusted, violations, "trusted-permissions", "trusted R2 canary must retain read-only repository permissions")
    _require(re.search(r"^\s+[a-z-]+:\s+write\s*$", trusted, re.MULTILINE) is None, violations, "trusted-write-permission", "trusted R2 canary may not request repository write permission")
    _require("self-hosted" not in trusted_folded, violations, "trusted-runner", "R2 canary must use a bounded hosted runner")
    _require("runs-on: ubuntu-24.04" in trusted, violations, "trusted-runner", "R2 canary must use the audited hosted image")
    trusted_checkout_count = len(re.findall(r"^\s*uses:\s*actions/checkout@", trusted, re.MULTILINE))
    _require(
        trusted_checkout_count == 1
        and trusted.count("persist-credentials: false") == trusted_checkout_count,
        violations,
        "trusted-checkout-credentials",
        "trusted R2 canary checkout must disable persisted credentials",
    )
    _require("if: github.ref == 'refs/heads/main'" in trusted, violations, "trusted-main-only", "R2 canary must reject non-main dispatches")
    _require("timeout-minutes: 10" in trusted, violations, "trusted-timeout", "R2 canary must have the ten-minute bound")
    _require("actions/upload-artifact" not in trusted_folded and "actions/download-artifact" not in trusted_folded, violations, "trusted-artifact-handoff", "R2 canary may not hand credentials or receipts through artifacts")
    expected_secrets = {"STRLING_R2_ACCESS_KEY_ID", "STRLING_R2_SECRET_ACCESS_KEY"}
    expected_variables = {"STRLING_R2_ACCOUNT_ID", "STRLING_R2_BUCKET_NAME", "STRLING_R2_ENDPOINT", "STRLING_R2_REGION"}
    _require(set(re.findall(r"secrets\.([A-Z0-9_]+)", trusted)) == expected_secrets, violations, "trusted-secret-interface", "R2 canary must consume exactly the two approved secret names")
    _require(set(re.findall(r"vars\.([A-Z0-9_]+)", trusted)) == expected_variables, violations, "trusted-variable-interface", "R2 canary must consume exactly the four approved variable names")
    _require("secrets[" not in trusted_folded and "vars[" not in trusted_folded, violations, "trusted-indirect-configuration", "R2 canary may not use indirect secret or variable lookups")
    for command in [
        "persist-credentials: false",
        "--only-binary=:all: --require-hashes --requirement requirements.ci.lock",
        "python tools/campaigns/run_r2_publication_canary.py --check-configuration",
        'python tools/campaigns/run_r2_publication_canary.py --state-root "$RUNNER_TEMP/strling-r2-canary-state"',
    ]:
        _require(command in trusted, violations, "trusted-canary-contract", f"trusted R2 canary omits required command {command!r}")

    million_folded = million.casefold()
    for marker in [
        "pull_request:",
        "pull_request_target:",
        "push:",
        "schedule:",
        "repository_dispatch:",
        "workflow_run:",
        "workflow_call:",
        "/var/run/docker.sock",
        "self-hosted",
    ]:
        _require(
            marker not in million_folded,
            violations,
            "million-trust-boundary",
            f"trusted 1M workflow contains forbidden marker {marker!r}",
        )
    _require("\n  workflow_dispatch:\n" in million, violations, "million-trigger", "trusted 1M workflow must be manual-only")
    _require("\npermissions:\n  contents: read\n" in million, violations, "million-permissions", "trusted 1M workflow must retain read-only repository permissions")
    _require(re.search(r"^\s+[a-z-]+:\s+write\s*$", million, re.MULTILINE) is None, violations, "million-write-permission", "trusted 1M workflow may not request repository write permission")
    _require("if: github.ref == 'refs/heads/main'" in million, violations, "million-main-only", "trusted 1M workflow must reject non-main dispatches")
    _require(million.count("runs-on: ubuntu-24.04") == 3, violations, "million-runner", "all trusted 1M jobs must use the audited hosted image")
    million_checkout_count = len(re.findall(r"^\s*uses:\s*actions/checkout@", million, re.MULTILINE))
    _require(million_checkout_count == 3 and million.count("persist-credentials: false") == million_checkout_count, violations, "million-checkout-credentials", "every trusted 1M checkout must disable persisted credentials")
    _require("timeout-minutes: 360" in million and million.count("timeout-minutes: 45") == 2, violations, "million-timeout", "trusted 1M preparation, execution, and reconciliation must be bounded")
    _require("max-parallel: 20" in million, violations, "million-concurrency", "trusted 1M worker fanout must retain the certified concurrency bound")
    _require(set(re.findall(r"secrets\.([A-Z0-9_]+)", million)) == expected_secrets, violations, "million-secret-interface", "trusted 1M workflow must consume exactly the two approved secret names")
    _require(set(re.findall(r"vars\.([A-Z0-9_]+)", million)) == expected_variables, violations, "million-variable-interface", "trusted 1M workflow must consume exactly the four approved variable names")
    _require("secrets[" not in million_folded and "vars[" not in million_folded, violations, "million-indirect-configuration", "trusted 1M workflow may not use indirect secret or variable lookups")
    for command in [
        "--partition-root \"$RUNNER_TEMP/million-inputs\"",
        "--partition-index \"${{ matrix.partition }}\"",
        "run_million_partition.py",
        "publish_million_partition.py",
        "recover_million_partition.py",
        "finalize_million_qualification.py",
        "run_r2_publication_canary.py --check-configuration",
        "million-scale-partition-execution-report.schema.json",
        "million-scale-partition-publication-receipt.schema.json",
        "million-scale-execution-report.schema.json",
        "docker ps --all --quiet --filter name=strling-rc-",
        "git diff --exit-code",
        "steps.partition-recovery.outputs.completed != 'true'",
        "partition: [\"000\"",
        "\"063\"]",
        "retention-days: 14",
        "retention-days: 30",
    ]:
        _require(command in million, violations, "million-campaign-contract", f"trusted 1M workflow omits required command {command!r}")
    _require("million-input-" not in million, violations, "million-input-artifacts", "trusted 1M workflow must materialize exact inputs locally rather than retain large input artifacts")
    _require(million.count("uses: actions/upload-artifact@") == 2 and million.count("uses: actions/download-artifact@") == 1, violations, "million-artifact-contract", "trusted 1M workflow may retain only compact partition receipts and the final report")

    policy_path = root / ".github" / "policies" / "main-protection.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        violations.append(Violation("invalid-protection-policy", str(error)))
        return violations

    allowed = policy.get("actions", {}).get("allowed_actions", {})
    observed_actions = USE_PATTERN.findall(workflow + "\n" + trusted + "\n" + million)
    _require(bool(observed_actions), violations, "missing-action", "workflow must contain its audited setup actions")
    for action, revision in observed_actions:
        _require(re.fullmatch(SHA, revision) is not None, violations, "floating-action", f"{action} is not pinned to a full commit SHA")
        _require(action in allowed, violations, "unapproved-action", f"{action} is absent from the allowlist")
        if action in allowed:
            _require(allowed[action].get("revision") == revision, violations, "action-revision-mismatch", f"{action} does not match its audited revision")
    _require(set(action for action, _ in observed_actions) == set(allowed), violations, "action-allowlist-drift", "workflow actions and allowlist differ")

    _require(
        policy.get("branch") == "main" and policy.get("enforcement") == "verified-local-fast-forward",
        violations,
        "promotion-target",
        "main must use verified local fast-forward promotion",
    )
    promotion = policy.get("promotion", {})
    _require(promotion.get("source_branch_prefix") == "codex/", violations, "promotion-source", "program work must originate on codex/ branches")
    _require(promotion.get("clean_worktree_required") is True, violations, "clean-worktree", "promotion requires a clean working tree")
    _require(promotion.get("verified_commit_required") is True, violations, "verified-commit", "promotion requires the exact caller-recorded verified commit")
    _require(promotion.get("fast_forward_only") is True, violations, "fast-forward-only", "main promotion must preserve the validated commit SHA")
    _require(promotion.get("merge_commits_allowed") is False, violations, "merge-commit", "promotion ranges may not contain merge commits")
    _require(promotion.get("force_push_allowed") is False, violations, "force-push", "main promotion may not force-push")
    _require(promotion.get("pull_request_required") is False, violations, "pull-request-delivery", "program delivery must not require a pull request")
    _require(promotion.get("server_side_review_required") is False, violations, "server-review", "program delivery must not require server-side review")
    _require(
        promotion.get("server_ruleset_required") is False and promotion.get("legacy_branch_protection_required") is False,
        violations,
        "server-enforcement",
        "ordinary delivery must not depend on a ruleset or legacy branch protection",
    )
    _require(promotion.get("working_branch_push_required") is False, violations, "working-branch-push", "the verified local branch need not be pushed before main")
    _require(promotion.get("remote_sha_verification_required") is True, violations, "remote-sha", "local main and origin/main must be reconciled after push")
    _require(promotion.get("remote_restriction_behavior") == "stop-and-report", violations, "remote-restriction", "real remote push restrictions must stop and be reported")
    promotion_tool = root / str(promotion.get("tool", ""))
    _require(promotion_tool == root / "tools" / "ci" / "promote_verified.py" and promotion_tool.is_file(), violations, "promotion-tool", "the authorized promotion tool is missing or misdirected")
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
