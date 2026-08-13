from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "control-plane" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_control_plane.fault_attribution import (
    FaultAttributionError,
    build_reference_report,
    classify_fault,
    reference_stimuli,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance


EXPECTED = {
    "adapter-process-crash": ("adapter-protocol-failure", False),
    "malformed-adapter-response": ("adapter-protocol-failure", False),
    "network-acquisition-failure": ("network-failure", False),
    "storage-publication-failure": ("storage-publication-failure", False),
    "target-process-crash": ("target-crash", True),
    "target-timeout": ("target-timeout", True),
    "worker-kill": ("worker-failure", False),
}


class FaultAttributionTests(unittest.TestCase):
    def test_reference_matrix_is_deterministic_schema_valid_and_fail_closed(self) -> None:
        report = build_reference_report()
        validate_instance(
            report,
            load_strict(ROOT / "schemas" / "json" / "fault-classification-report.schema.json"),
            source="fault reference report",
        )
        self.assertEqual(canonical_bytes(report), canonical_bytes(build_reference_report()))
        self.assertEqual(report["summary"], {
            "accepted_terminal_count": 2,
            "case_count": 7,
            "inconclusive_attempt_count": 5,
        })
        observed = {
            item["stimulus"]["fault_key"]: (
                item["assessment"]["outcome_class"],
                item["assessment"]["c5_terminal_eligible"],
            )
            for item in report["cases"]
        }
        self.assertEqual(observed, EXPECTED)

    def test_timeout_symptom_is_not_target_timeout_without_exact_attribution(self) -> None:
        target = next(
            deepcopy(item) for item in reference_stimuli() if item["fault_key"] == "target-timeout"
        )
        for mutation in (
            {"injection_point": "adapter-process"},
            {"protocol_checkpoint": "target-not-started"},
            {"environment_health_after": "unknown"},
            {"supervisor_health": "unknown"},
            {"adapter_response_state": "malformed"},
        ):
            value = {**target, **mutation}
            assessment = classify_fault(value)
            with self.subTest(mutation=mutation):
                self.assertFalse(assessment["c5_terminal_eligible"])
                self.assertFalse(assessment["logical_execution_satisfied"])
                self.assertEqual(assessment["completion_disposition"], "inconclusive-attempt")

    def test_negative_exit_is_not_target_crash_at_another_layer(self) -> None:
        target = next(
            deepcopy(item)
            for item in reference_stimuli()
            if item["fault_key"] == "target-process-crash"
        )
        for point, expected in (
            ("adapter-process", "adapter-protocol-failure"),
            ("worker-process", "worker-failure"),
        ):
            target["injection_point"] = point
            result = classify_fault(target)
            with self.subTest(point=point):
                self.assertEqual(result["outcome_class"], expected)
                self.assertFalse(result["c5_terminal_eligible"])

    def test_malformed_or_contradictory_facts_are_rejected(self) -> None:
        value = deepcopy(reference_stimuli()[0])
        value["containment"] = {"exit_code": 0, "outcome": "not-run"}
        with self.assertRaisesRegex(FaultAttributionError, "cannot have an exit code"):
            classify_fault(value)
        value = deepcopy(reference_stimuli()[0])
        value["unexpected"] = True
        with self.assertRaisesRegex(FaultAttributionError, "exact bounded fact set"):
            classify_fault(value)

    def test_assessment_binds_exact_stimulus_bytes(self) -> None:
        value = deepcopy(reference_stimuli()[0])
        first = classify_fault(value)
        value["environment_health_after"] = "unknown"
        second = classify_fault(value)
        self.assertNotEqual(first["stimulus_sha256"], second["stimulus_sha256"])


if __name__ == "__main__":
    unittest.main()
