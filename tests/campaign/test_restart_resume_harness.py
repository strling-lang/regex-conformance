from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_schema.jsonio import load_strict

SPEC = importlib.util.spec_from_file_location(
    "exercise_restart_resume",
    ROOT / "tools" / "campaigns" / "exercise_restart_resume.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load restart/resume exercise")
exercise_restart_resume = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exercise_restart_resume)


class RestartResumeHarnessTests(unittest.TestCase):
    def test_closed_harness_forces_restarts_and_publishes_one_external_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary = exercise_restart_resume.exercise(root)
            self.assertEqual(summary["case_count"], 14)
            self.assertEqual(summary["completed_case_count"], 13)
            self.assertEqual(summary["quarantined_case_count"], 1)
            self.assertEqual(summary["forced_process_exit_count"], 1)
            self.assertGreaterEqual(summary["restart_count"], 10)
            evidence = load_strict(Path(summary["evidence_path"]))
            by_key = {item["case_key"]: item for item in evidence["cases"]}
            repeated = by_key["repeated-running-restarts"]
            self.assertEqual(repeated["attempt_count"], 4)
            self.assertEqual(repeated["distinct_physical_run_count"], 4)
            self.assertEqual(repeated["interrupted_attempt_count"], 3)
            self.assertEqual(repeated["committed_attempt_count"], 1)
            self.assertEqual(
                by_key["restart-after-manifest-committed"]["observed_action"],
                "committed",
            )
            self.assertEqual(
                by_key["corrupt-checkpoint-chain"]["observed_action"],
                "quarantine",
            )
            self.assertEqual(len(list(root.glob("*.json"))), 1)
            self.assertEqual(len(list(root.glob("*.sqlite3*"))), 0)

    def test_evidence_destination_inside_git_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the Git repository"):
            exercise_restart_resume._outside_repository(
                ROOT / "evidence" / "forbidden-recovery", "evidence directory"
            )


if __name__ == "__main__":
    unittest.main()
