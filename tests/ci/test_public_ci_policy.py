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
            "requirements.lock",
            "requirements.ci.lock",
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

    def test_repository_contract_passes(self) -> None:
        self.assertEqual(evaluate(ROOT), [])

    def test_public_fork_cannot_select_self_hosted_runner(self) -> None:
        self.mutate_workflow("runs-on: ubuntu-24.04", "runs-on: [self-hosted, trusted]")
        self.assertIn("self-hosted-runner", self.codes())

    def test_privileged_pull_request_trigger_is_rejected(self) -> None:
        self.mutate_workflow("  pull_request:", "  pull_request_target:")
        self.assertIn("forbidden-trigger", self.codes())

    def test_write_permission_is_rejected(self) -> None:
        self.mutate_workflow("contents: read", "contents: write")
        self.assertIn("write-permission", self.codes())

    def test_secret_reference_is_rejected(self) -> None:
        self.mutate_workflow('PYTHONHASHSEED: "0"', "TOKEN: secrets.PUBLICATION_TOKEN")
        self.assertIn("secret-reference", self.codes())

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

    def test_branch_protection_drift_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"block_force_pushes": true', '"block_force_pushes": false'), encoding="utf-8")
        self.assertIn("branch-protection", self.codes())

    def test_repository_action_policy_drift_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"require_full_length_sha": true', '"require_full_length_sha": false'), encoding="utf-8")
        self.assertIn("action-pinning-policy", self.codes())

    def test_organization_action_policy_drift_is_rejected(self) -> None:
        path = self.root / ".github" / "policies" / "main-protection.json"
        path.write_text(path.read_text(encoding="utf-8").replace('"organization_actions_allowed": true', '"organization_actions_allowed": false'), encoding="utf-8")
        self.assertIn("organization-action-policy", self.codes())
