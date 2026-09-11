from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools/certification/compile_evidence_adjudication_closure.py"
SPEC = importlib.util.spec_from_file_location("evidence_adjudication_closure", TOOL)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceAdjudicationClosureTests(unittest.TestCase):
    def test_tracked_closure_is_deterministic_and_bounded(self) -> None:
        result = MODULE.verify_current(history=False)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["gate_checks"], 15)

    def test_tracked_closure_uses_platform_stable_bytes(self) -> None:
        tracked = (ROOT / MODULE.REPORT_PATH).read_bytes()
        self.assertEqual(tracked, MODULE.render_report())
        self.assertNotIn(b"\r\n", tracked)

    def test_closure_preserves_denominator_and_nonpassing_certification(self) -> None:
        report = MODULE.build_report()
        self.assertEqual(report["denominator"]["conditional_requirements_represented"], 1972)
        self.assertEqual(report["denominator"]["production_coverage_credit"], 0)
        self.assertEqual(report["certification"]["C4"], "FAIL")
        self.assertEqual(report["certification"]["final_state"], "FAIL")


if __name__ == "__main__":
    unittest.main()
