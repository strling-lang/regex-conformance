from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "tools" / "ci" / "verify_repository_identifier_hygiene.py"


class RepositoryIdentifierHygieneTests(unittest.TestCase):
    def test_tracked_human_authored_surfaces_are_clean(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(VERIFIER)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("violations=0", completed.stdout)


if __name__ == "__main__":
    unittest.main()
