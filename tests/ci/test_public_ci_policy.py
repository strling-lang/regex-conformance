from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "tools" / "ci"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from public_ci_policy import evaluate


class PublicCiPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in [
            ".github/CODEOWNERS",
            ".github/policies/main-protection.json",
            ".github/workflows/public-validation.yml",
            ".github/workflows/trusted-r2-publication-canary.yml",
            "requirements.lock",
            "requirements.ci.lock",
            "tools/ci/promote_verified.py",
        ]:
            source = ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def codes(self) -> set[str]:
        return {item.code for item in evaluate(self.root)}

    def mutate_workflow(self, old: str, new: str) -> None:
        path = self.root / ".github" / "workflows" / "public-validation.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def mutate_trusted_workflow(self, old: str, new: str) -> None:
        path = self.root / ".github" / "workflows" / "trusted-r2-publication-canary.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_repository_contract_passes(self) -> None:
        self.assertEqual(evaluate(ROOT), [])

    def test_public_fork_cannot_select_self_hosted_runner(self) -> None:
        self.mutate_workflow("runs-on: ubuntu-24.04", "runs-on: [self-hosted, trusted]")
        self.assertIn("self-hosted-runner", self.codes())

    def test_privileged_pull_request_trigger_is_rejected(self) -> None:
        self.mutate_workflow("  pull_request:", "  pull_request_target:")
        self.assertIn("forbidden-trigger", self.codes())

    def test_missing_main_push_trigger_is_rejected(self) -> None:
        self.mutate_workflow("      - main", "      - release")
        self.assertIn("missing-main-trigger", self.codes())

    def test_missing_control_plane_tests_are_rejected(self) -> None:
        self.mutate_workflow(
            "python -m unittest discover -s tests/control_plane -v",
            "python -m unittest discover -s tests/schema -v",
        )
        self.assertIn("missing-validation", self.codes())

    def test_missing_or_trust_upgraded_environment_certification_is_rejected(self) -> None:
        self.mutate_workflow("certify_minimal.py", "certification-disabled.py")
        self.assertIn("missing-validation", self.codes())
        self.mutate_workflow("certification-disabled.py", "certify_minimal.py")
        self.mutate_workflow("--trust-class untrusted_public", "--trust-class trusted_executioner")
        self.assertIn("missing-validation", self.codes())

    def test_missing_or_trust_upgraded_adapter_certification_is_rejected(self) -> None:
        self.mutate_workflow("tools/adapters/certify_minimal.py", "tools/adapters/certification-disabled.py")
        self.assertIn("missing-validation", self.codes())
        self.mutate_workflow("tools/adapters/certification-disabled.py", "tools/adapters/certify_minimal.py")
        command = (
            'python tools/adapters/certify_minimal.py --state-root "$RUNNER_TEMP/strling-regex-adapter-state" '
            '--evidence-dir "$RUNNER_TEMP/strling-regex-adapter-evidence" --trust-class untrusted_public '
            '--compact-report "$RUNNER_TEMP/minimal-adapter-certification.json"'
        )
        self.mutate_workflow(
            command,
            command.replace("--trust-class untrusted_public", "--trust-class trusted_executioner"),
        )
        self.assertIn("missing-validation", self.codes())

    def test_write_permission_is_rejected(self) -> None:
        self.mutate_workflow("contents: read", "contents: write")
        self.assertIn("write-permission", self.codes())

    def test_secret_reference_is_rejected(self) -> None:
        self.mutate_workflow('PYTHONHASHSEED: "0"', "TOKEN: secrets.PUBLICATION_TOKEN")
        self.assertIn("secret-reference", self.codes())

    def test_trusted_r2_canary_is_manual_main_only(self) -> None:
        self.mutate_trusted_workflow("  workflow_dispatch:", "  pull_request_target:")
        self.assertIn("trusted-trigger", self.codes())

    def test_trusted_r2_canary_rejects_an_extra_secret(self) -> None:
        self.mutate_trusted_workflow(
            '      PIP_NO_INPUT: "1"',
            '      PIP_NO_INPUT: "1"\n      EXTRA: ${{ secrets.EXTRA_SECRET }}',
        )
        self.assertIn("trusted-secret-interface", self.codes())

    def test_trusted_r2_canary_cannot_dispatch_a_non_main_ref(self) -> None:
        self.mutate_trusted_workflow(
            "if: github.ref == 'refs/heads/main'",
            "if: github.ref != ''",
        )
        self.assertIn("trusted-main-only", self.codes())

    def test_floating_action_tag_is_rejected(self) -> None:
        self.mutate_workflow(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
        )
        self.assertIn("floating-action", self.codes())

    def test_artifact_handoff_is_rejected(self) -> None:
        self.mutate_workflow(
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "uses: actions/upload-artifact@3d3c42e5aac5ba805825da76410c181273ba90b1",
        )
        self.assertIn("artifact-handoff", self.codes())

    def test_persisted_checkout_credentials_are_rejected(self) -> None:
        self.mutate_workflow("persist-credentials: false", "persist-credentials: true")
        self.assertIn("checkout-credentials", self.codes())

    def test_dependency_version_drift_is_rejected(self) -> None:
        path = self.root / "requirements.ci.lock"
        path.write_text(path.read_text(encoding="utf-8").replace("attrs==26.1.0", "attrs==25.0.0"), encoding="utf-8")
        self.assertIn("dependency-version-drift", self.codes())

    def test_missing_dependency_hash_is_rejected(self) -> None:
        path = self.root / "requirements.ci.lock"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("    --hash=sha256:c647aa4a12dfbad9333ca4e71fe62ddc36f4e63b2d260a37a8b83d2f043ac309", ""), encoding="utf-8")
        self.assertIn("dependency-hash-count", self.codes())

    def test_server_ruleset_dependency_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"server_ruleset_required": false', '"server_ruleset_required": true'), encoding="utf-8")
        self.assertIn("server-enforcement", self.codes())

    def test_unverified_commit_promotion_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"verified_commit_required": true', '"verified_commit_required": false'), encoding="utf-8")
        self.assertIn("verified-commit", self.codes())

    def test_non_fast_forward_promotion_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"fast_forward_only": true', '"fast_forward_only": false'), encoding="utf-8")
        self.assertIn("fast-forward-only", self.codes())

    def test_pull_request_delivery_dependency_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"pull_request_required": false', '"pull_request_required": true'), encoding="utf-8")
        self.assertIn("pull-request-delivery", self.codes())

    def test_force_push_permission_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"force_push_allowed": false', '"force_push_allowed": true'), encoding="utf-8")
        self.assertIn("force-push", self.codes())

    def test_missing_remote_sha_reconciliation_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"remote_sha_verification_required": true', '"remote_sha_verification_required": false'), encoding="utf-8")
        self.assertIn("remote-sha", self.codes())

    def test_unvalidated_source_prefix_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"source_branch_prefix": "codex/"', '"source_branch_prefix": "feature/"'), encoding="utf-8")
        self.assertIn("promotion-source", self.codes())

    def test_repository_action_policy_drift_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"require_full_length_sha": true', '"require_full_length_sha": false'), encoding="utf-8")
        self.assertIn("action-pinning-policy", self.codes())

    def test_organization_action_policy_drift_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"organization_actions_allowed": true', '"organization_actions_allowed": false'), encoding="utf-8")
        self.assertIn("organization-action-policy", self.codes())
