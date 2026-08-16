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

    def test_campaign_execution_cannot_be_removed(self) -> None:
        codes = self._replace(
            "python tools/campaigns/run_vertical_slice.py",
            "python tools/campaigns/campaign-disabled.py",
        )
        self.assertIn("missing-validation", codes)

    def test_campaign_public_job_cannot_claim_trusted_execution(self) -> None:
        command = (
            'python tools/campaigns/run_vertical_slice.py --state-root "$RUNNER_TEMP/strling-regex-campaign-state" '
            '--evidence-dir "$RUNNER_TEMP/strling-regex-campaign-evidence" '
            '--warehouse-dir "$RUNNER_TEMP/strling-regex-campaign-warehouse" '
            '--trust-class untrusted_public --compact-report "$RUNNER_TEMP/first-campaign-report.json"'
        )
        codes = self._replace(
            command,
            command.replace("--trust-class untrusted_public", "--trust-class trusted_executioner"),
        )
        self.assertIn("missing-validation", codes)


if __name__ == "__main__":
    unittest.main()
