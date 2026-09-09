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


class CampaignCiPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in [
            ".github/CODEOWNERS",
            ".github/policies/main-protection.json",
            ".github/workflows/public-validation.yml",
            ".github/workflows/trusted-million-qualification.yml",
            ".github/workflows/trusted-r2-publication-canary.yml",
            "requirements.lock",
            "requirements.ci.lock",
            "tools/ci/promote_verified.py",
        ]:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _replace(self, old: str, new: str) -> set[str]:
        path = self.root / ".github" / "workflows" / "public-validation.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        return {item.code for item in evaluate(self.root)}

    def test_hosted_workflow_does_not_execute_a_campaign(self) -> None:
        text = (self.root / ".github/workflows/public-validation.yml").read_text(encoding="utf-8")
        self.assertNotIn("run_vertical_slice.py", text)
        self.assertNotIn("certify_minimal.py", text)

    def test_local_certificate_verification_cannot_be_removed(self) -> None:
        codes = self._replace(
            "python tools/ci/verify_local_certification.py",
            "python tools/ci/local-verification-disabled.py",
        )
        self.assertIn("missing-validation", codes)

    def test_hosted_verification_retains_ten_minute_bound(self) -> None:
        codes = self._replace("timeout-minutes: 10", "timeout-minutes: 45")
        self.assertIn("missing-timeout", codes)


if __name__ == "__main__":
    unittest.main()
