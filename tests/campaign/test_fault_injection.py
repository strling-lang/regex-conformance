from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "control-plane" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_schema.jsonio import load_strict

SPEC = importlib.util.spec_from_file_location(
    "exercise_faults", ROOT / "tools" / "campaigns" / "exercise_faults.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load deliberate fault exercise")
exercise_faults = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exercise_faults)


class DeliberateFaultInjectionTests(unittest.TestCase):
    def test_closed_fault_harness_executes_and_publishes_external_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary = exercise_faults.exercise(root)
            self.assertEqual(summary["case_count"], 7)
            self.assertEqual(summary["accepted_terminal_count"], 2)
            self.assertEqual(summary["inconclusive_attempt_count"], 5)
            evidence = load_strict(Path(summary["evidence_path"]))
            self.assertEqual(evidence["summary"]["case_count"], 7)
            by_key = {item["stimulus"]["fault_key"]: item for item in evidence["cases"]}
            self.assertEqual(by_key["target-timeout"]["execution"]["outcome"], "wall-time-limit")
            self.assertLess(by_key["target-process-crash"]["execution"]["exit_code"], 0)
            self.assertLess(by_key["worker-kill"]["execution"]["exit_code"], 0)
            self.assertTrue(
                by_key["malformed-adapter-response"]["execution"]["strict_decoder_rejected"]
            )
            self.assertEqual(
                by_key["network-acquisition-failure"]["assessment"]["completion_disposition"],
                "inconclusive-attempt",
            )
            self.assertEqual(
                by_key["storage-publication-failure"]["assessment"]["completion_disposition"],
                "inconclusive-attempt",
            )
            self.assertEqual(len(list(root.rglob("*.json"))), 1)

    def test_evidence_destination_inside_git_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the Git repository"):
            exercise_faults._outside_repository(
                ROOT / "evidence" / "forbidden", "evidence directory"
            )


if __name__ == "__main__":
    unittest.main()
