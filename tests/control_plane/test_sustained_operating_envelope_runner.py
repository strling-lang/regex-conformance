from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "tools" / "control_plane" / "run_sustained_operating_envelope.py"
SPEC = importlib.util.spec_from_file_location("sustained_operating_envelope_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load sustained operating-envelope runner")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class SustainedOperatingEnvelopeRunnerTests(unittest.TestCase):
    def test_input_tree_digest_is_deterministic_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "a.json").write_text("alpha", encoding="utf-8")
            (root / "nested" / "b.json").write_text("beta", encoding="utf-8")
            first = runner._tree_digest(root)
            self.assertEqual(first, runner._tree_digest(root))
            self.assertEqual(first[1], 9)
            (root / "nested" / "b.json").write_text("changed", encoding="utf-8")
            self.assertNotEqual(first, runner._tree_digest(root))

    def test_immutable_writer_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            runner._write_new(path, b"first\n")
            with self.assertRaisesRegex(runner.OperatingEnvelopeError, "already exists"):
                runner._write_new(path, b"second\n")
            self.assertEqual(path.read_bytes(), b"first\n")

    def test_resource_boundary_evaluation_uses_observed_extrema(self) -> None:
        plan = {
            "resource_boundaries": [
                {
                    "boundary": "maximum",
                    "measurement": "environment-cache-size",
                    "value": 10,
                },
                {
                    "boundary": "minimum",
                    "measurement": "persistent-disk-available",
                    "value": 40,
                },
            ]
        }
        summaries = [
            {
                "maximum": 10,
                "measurement": "environment-cache-size",
                "minimum": 1,
                "status": "observed",
            },
            {
                "maximum": 50,
                "measurement": "persistent-disk-available",
                "minimum": 40,
                "status": "observed",
            },
        ]
        self.assertEqual(runner._resource_boundary_breach(plan, summaries), 0)
        summaries[1]["minimum"] = 39
        self.assertEqual(runner._resource_boundary_breach(plan, summaries), 1)

    def test_terminal_report_is_recovered_exactly_and_never_replaced(self) -> None:
        expected = {"report_digest_sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as directory, patch.object(
            runner, "build_report", return_value=expected
        ):
            root = Path(directory)
            self.assertEqual(runner._ensure_report(root, {}, []), expected)
            path = root / runner.REPORT_NAME
            original = path.read_bytes()
            self.assertEqual(runner._ensure_report(root, {}, []), expected)
            path.write_bytes(b"tampered\n")
            with self.assertRaisesRegex(runner.OperatingEnvelopeError, "differs"):
                runner._ensure_report(root, {}, [])
            self.assertNotEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
