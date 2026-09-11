from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.adjudication import (
    CLAIM_KINDS,
    COORDINATE_STATES,
    CONTRACT_PATH,
    FIXTURE_PATH,
    adjudicate,
    build_fixtures,
    compare_expected_outcome,
    validate_fixtures,
    verify_current,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


class AdjudicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_strict(ROOT / CONTRACT_PATH)
        cls.fixture = load_strict(ROOT / FIXTURE_PATH)
        cls.by_case = {item["case_id"]: item for item in cls.fixture["valid_cases"]}

    def test_current_artifacts_close(self) -> None:
        result = verify_current(ROOT, broad_foundations=False)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["c4"], "FAIL")
        self.assertEqual((result["c4_completed"], result["c4_denominator"]), (0, 3378))

    def test_fixture_regeneration_is_deterministic(self) -> None:
        self.assertEqual(build_fixtures(ROOT, self.contract), self.fixture)
        self.assertEqual(canonical_bytes(build_fixtures(ROOT, self.contract)), canonical_bytes(self.fixture))

    def test_all_o1_through_o8_roles_are_exercised(self) -> None:
        roles = {item["oracle_ref"]["oracle_class"] for item in self.fixture["evidence_records"]}
        self.assertEqual(roles, {f"O{number}" for number in range(1, 9)})
        claims = {item["expected"]["claim_kind"] for item in self.fixture["valid_cases"] if item["case_id"].startswith("o")}
        self.assertIn("normative-conformance", claims)
        self.assertIn("formal-model-violation", claims)
        self.assertIn("metamorphic-relation-satisfaction", claims)
        self.assertIn("family-relative-divergence", claims)
        self.assertIn("historical-characterization", claims)
        self.assertIn("characterization-only-finding", claims)

    def test_coordinate_states_remain_distinct(self) -> None:
        expected = {item["expected"]["coordinate_state"] for item in self.fixture["valid_cases"]}
        for state in ("not-applicable", "applicability-unresolved", "applicability-invalid", "not-tested", "unobserved", "inconclusive", "satisfied", "violated", "permitted-divergence", "conflicting-evidence", "conflicting-authority", "quarantined", "waived-for-gate"):
            self.assertIn(state, COORDINATE_STATES)
            self.assertIn(state, expected)

    def test_waiver_changes_gate_not_scientific_result(self) -> None:
        case = self.by_case["waived-normative-violation"]
        result = adjudicate(ROOT, self.contract, case["request"], self.fixture["evidence_records"])
        self.assertEqual(result["coordinate"]["scientific_state"], "violated")
        self.assertEqual(result["coordinate"]["coordinate_state"], "waived-for-gate")
        self.assertEqual(result["claim"]["scientific_result_state"], "violated")
        self.assertFalse(result["claim"]["waiver_effect"]["alters_scientific_result"])
        self.assertTrue(result["answers"]["discrepancy_exists"])

    def test_quarantine_preserves_observations(self) -> None:
        case = self.by_case["quarantined-satisfied"]
        result = adjudicate(ROOT, self.contract, case["request"], self.fixture["evidence_records"])
        self.assertEqual(result["coordinate"]["scientific_state"], "satisfied")
        self.assertEqual(result["coordinate"]["coordinate_state"], "quarantined")
        self.assertEqual(len(result["claim"]["admitted_observations"]), 1)

    def test_infrastructure_and_missing_evidence_do_not_fail(self) -> None:
        self.assertEqual(self.by_case["attempted-infrastructure-no-observation"]["expected"]["scientific_state"], "unobserved")
        self.assertEqual(self.by_case["inadmissible-observation-excluded"]["expected"]["scientific_state"], "unobserved")
        self.assertEqual(self.by_case["applicability-unresolved"]["expected"]["scientific_state"], "applicability-unresolved")

    def test_retry_preserves_all_attempts(self) -> None:
        case = self.by_case["retry-preserves-failed-attempt"]
        result = adjudicate(ROOT, self.contract, case["request"], self.fixture["evidence_records"])
        self.assertEqual(len(result["claim"]["physical_attempt_ids"]), 2)
        self.assertEqual(result["claim"]["physical_attempt_ids"][0], case["request"]["execution_lineage_set"]["lineages"][1]["attempts"][0]["physical_run_id"])

    def test_claim_binds_admission_and_reconstruction_inputs(self) -> None:
        case = self.by_case["o1-normative-satisfied"]
        result = adjudicate(ROOT, self.contract, case["request"], self.fixture["evidence_records"])
        self.assertEqual(result["claim"]["evidence_admissions"][0]["decision"], "admissible")
        reconstruction = result["historical_reconstruction"]
        self.assertEqual(reconstruction["input_request_digest_sha256"], result["answers"]["immutable_input_digest_sha256"])
        self.assertEqual(reconstruction["applicability"]["evaluation_id"], case["request"]["applicability"]["evaluation_id"])
        self.assertTrue(reconstruction["regenerable"])

    def test_discrepancy_resolution_preserves_history(self) -> None:
        case = self.by_case["resolved-discrepancy-history-preserved"]
        current = case["request"]["discrepancies"][0]
        predecessor = case["request"]["discrepancy_history"][0]
        self.assertEqual(current["supersedes_revision_id"], predecessor["revision_id"])
        self.assertEqual(current["claimants_digest_sha256"], predecessor["claimants_digest_sha256"])
        self.assertTrue(adjudicate(ROOT, self.contract, case["request"], self.fixture["evidence_records"])["answers"]["discrepancy_exists"])

    def test_expected_outcome_forms(self) -> None:
        observation = {"outcome_class": "match", "semantic_result": {"match": True, "spans": [[0, 1]]}}
        models = {item["outcome_model"]["kind"]: item["outcome_model"] for item in self.fixture["expected_outcomes"] if item["outcome_model"] is not None}
        for kind in ("one-of", "optional-alternatives", "permitted-set", "relation", "conditional"):
            self.assertIn(kind, models)
            self.assertEqual(compare_expected_outcome(models[kind], observation)[0], "agreement")
        exact_observation = models["exact"]["value"]
        self.assertEqual(compare_expected_outcome(models["exact"], exact_observation)[0], "agreement")
        ranged = {"outcome_class": "match", "semantic_result": {"value": 2}}
        self.assertEqual(compare_expected_outcome(models["range"], ranged)[0], "agreement")

    def test_claim_taxonomy_is_typed_not_boolean(self) -> None:
        self.assertNotIn("pass", CLAIM_KINDS)
        self.assertIn("normative-non-conformance", CLAIM_KINDS)
        self.assertIn("implementation-documentation-conformance", CLAIM_KINDS)
        self.assertIn("authoritative-data-disagreement", CLAIM_KINDS)
        self.assertIn("permitted-divergence-finding", CLAIM_KINDS)

    def test_permitted_divergence_preserves_underlying_disagreement(self) -> None:
        case = self.by_case["permitted-divergence"]
        result = adjudicate(ROOT, self.contract, case["request"], self.fixture["evidence_records"])
        self.assertEqual(result["coordinate"]["scientific_state"], "permitted-divergence")
        self.assertEqual(result["claim"]["polarity"], "disagreement")

    def test_adversarial_suite_closes(self) -> None:
        counts = validate_fixtures(ROOT, self.contract, self.fixture)
        self.assertEqual(counts["adversarial_case_count"], 17)


if __name__ == "__main__":
    unittest.main()
