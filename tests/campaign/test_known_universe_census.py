from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "campaigns"))

from verify_known_universe_census import (  # noqa: E402
    CensusVerificationError,
    verify_report,
)


REPORT = ROOT / "reports" / "scale" / "known-universe-census-forecast.json"


def load_report() -> dict:
    value = json.loads(REPORT.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class KnownUniverseCensusTests(unittest.TestCase):
    def test_report_schema_bindings_digest_and_arithmetic_verify(self) -> None:
        verify_report(load_report())

    def test_catalog_and_candidate_dispositions_close(self) -> None:
        report = load_report()
        ledger = report["ledger"]
        self.assertEqual(sum(ledger["candidate_disposition_counts"].values()), 6677)
        self.assertEqual(sum(ledger["catalog_disposition_counts"].values()), 664)
        self.assertEqual(ledger["catalog_disposition_counts"]["pending"], 0)
        self.assertEqual(ledger["quality_checks"], {
            "blank_required_fields": 0,
            "duplicate_candidate_ids": 0,
            "duplicate_language_root_ids": 0,
            "duplicate_scan_ids": 0,
        })

    def test_material_surfaces_are_bounded_not_equated_to_roots(self) -> None:
        report = load_report()
        bounds = report["material_surface_accounting"]["bounds"]
        self.assertEqual(bounds, {"lower": 543, "expected": 746, "conservative": 1025})
        self.assertEqual(report["ledger"]["language_roots"], 1025)
        self.assertIn(
            "coincidental",
            report["material_surface_accounting"]["method"]["conservative"],
        )
        self.assertEqual(report["ledger"]["unresolved_candidate_facts"], 3071)

    def test_capacity_gate_fails_closed(self) -> None:
        report = load_report()
        cases = report["evidence_pack_v2_storage_forecast"]["cases"]
        self.assertEqual(cases["lower"]["total_retained_bytes"], 8_050_807_550)
        self.assertEqual(cases["expected"]["total_retained_bytes"], 27_372_369_951)
        self.assertEqual(cases["conservative"]["total_retained_bytes"], 77_597_999_432)
        self.assertTrue(cases["lower"]["exceeds_soft_stop"])
        self.assertFalse(cases["lower"]["exceeds_hard_cap"])
        self.assertTrue(cases["expected"]["exceeds_hard_cap"])
        self.assertTrue(cases["conservative"]["exceeds_hard_cap"])
        combined = report["local_million_qualification_retention"][
            "combined_if_later_published"
        ]
        self.assertEqual(combined["lower"]["retained_bytes"], 8_091_359_853)
        self.assertEqual(combined["expected"]["retained_bytes"], 27_412_922_254)
        self.assertEqual(combined["conservative"]["retained_bytes"], 77_638_551_735)
        gate = report["capacity_gate"]
        self.assertEqual(gate["publication_admission"], "blocked")
        self.assertTrue(gate["program_owner_decision_required"])
        self.assertFalse(gate["paid_capacity_authorized"])
        self.assertFalse(gate["scientific_scope_reduction_authorized"])

    def test_verifier_rejects_forged_capacity_admission(self) -> None:
        forged = deepcopy(load_report())
        forged["capacity_gate"]["publication_admission"] = "admitted"
        with self.assertRaises(CensusVerificationError):
            verify_report(forged)


if __name__ == "__main__":
    unittest.main()
