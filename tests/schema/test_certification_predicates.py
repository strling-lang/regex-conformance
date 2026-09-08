from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.certification import (
    CONTRACT_PATH,
    CURRENT_AUTHORITY_PATH,
    CURRENT_INPUT_PATH,
    CURRENT_REPORT_PATH,
    FIXTURE_PATH,
    _authority_digest,
    _finalize_input,
    build_current_authority,
    evaluate,
    validate_authority_index,
    validate_input_set,
    verify_repository_certification,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import load_strict


class CertificationPredicateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_strict(ROOT / CONTRACT_PATH)
        cls.current_input = load_strict(ROOT / CURRENT_INPUT_PATH)
        cls.current_report = load_strict(ROOT / CURRENT_REPORT_PATH)
        cls.authority = load_strict(ROOT / CURRENT_AUTHORITY_PATH)
        cls.fixtures = load_strict(ROOT / FIXTURE_PATH)
        cls.cases = {item["name"]: item for item in cls.fixtures["cases"]}
        cls.fixture_reports = {
            name: evaluate(ROOT, cls.contract, item["input_set"])
            for name, item in cls.cases.items()
        }

    def test_contract_materializes_all_versioned_criteria_and_exact_conjunction(self) -> None:
        criteria = self.contract["criteria"]
        self.assertEqual([item["criterion_id"] for item in criteria], [f"C{number}" for number in range(1, 8)])
        self.assertTrue(all(item["version"] == "1.0.0" for item in criteria))
        self.assertTrue(all(item["required_for_final"] for item in criteria))
        self.assertEqual(len({item["predicate_digest_sha256"] for item in criteria}), 7)
        self.assertIn(
            "schemas/tooling/python/regex_conformance_schema/certification.py",
            {item["relative_path"] for item in self.contract["implementation_bindings"]},
        )
        self.assertEqual(self.contract["final_composition"]["operator"], "required-criterion-conjunction")
        self.assertEqual(self.contract["final_composition"]["failure_precedence"], ["FAIL", "BLOCKED", "PASS"])

    def test_full_pass_fixture_and_each_independent_failure_are_explicit(self) -> None:
        full = self.fixture_reports["full-pass"]
        self.assertEqual(full["final_state"], "PASS")
        self.assertEqual({item["status"] for item in full["criteria"]}, {"PASS"})
        self.assertEqual(next(item for item in full["criteria"] if item["criterion_id"] == "C3")["exact_ratio"], "1/2")

        for number in range(1, 8):
            name = f"c{number}-failure"
            with self.subTest(fixture=name):
                report = self.fixture_reports[name]
                states = {item["criterion_id"]: item["status"] for item in report["criteria"]}
                self.assertEqual(report["final_state"], "FAIL")
                self.assertEqual(states[f"C{number}"], "FAIL")
                self.assertEqual(
                    {criterion for criterion, state in states.items() if state != "PASS"},
                    {f"C{number}"},
                )

    def test_blocked_input_does_not_create_a_false_semantic_failure(self) -> None:
        report = self.fixture_reports["blocked-prerequisite"]
        states = {item["criterion_id"]: item["status"] for item in report["criteria"]}
        self.assertEqual(states["C2"], "BLOCKED")
        self.assertEqual(report["final_state"], "BLOCKED")
        self.assertEqual({state for criterion, state in states.items() if criterion != "C2"}, {"PASS"})

    def test_construction_evidence_cannot_satisfy_independent_coverage(self) -> None:
        result = next(
            item
            for item in self.fixture_reports["construction-evidence-rejected"]["criteria"]
            if item["criterion_id"] == "C4"
        )
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("constant-by-construction", result["admitted_derivation_classes_used"])
        self.assertIn("construction-evidence-rejected", {item["code"] for item in result["diagnostics"]})

    def test_c5_counts_logical_executions_and_excludes_inconclusive_attempts(self) -> None:
        excluded = next(
            item
            for item in self.fixture_reports["physical-attempt-exclusion"]["criteria"]
            if item["criterion_id"] == "C5"
        )
        self.assertEqual(excluded["status"], "FAIL")
        self.assertEqual(excluded["exact_ratio"], "0/1")

        retry = next(
            item
            for item in self.fixture_reports["retry-completion"]["criteria"]
            if item["criterion_id"] == "C5"
        )
        self.assertEqual(retry["status"], "PASS")
        self.assertEqual(retry["exact_ratio"], "1/1")
        self.assertEqual(retry["denominator_count"], 1)

    def test_c6_and_c7_debt_remain_independently_visible(self) -> None:
        corrupt = self.fixture_reports["evidence-corruption"]
        debt = self.fixture_reports["reconciliation-debt"]
        self.assertEqual(
            next(item for item in corrupt["criteria"] if item["criterion_id"] == "C6")["status"],
            "FAIL",
        )
        self.assertEqual(
            next(item for item in debt["criteria"] if item["criterion_id"] == "C7")["status"],
            "FAIL",
        )
        self.assertEqual(
            {item["status"] for item in corrupt["criteria"] if item["criterion_id"] != "C6"},
            {"PASS"},
        )
        self.assertEqual(
            {item["status"] for item in debt["criteria"] if item["criterion_id"] != "C7"},
            {"PASS"},
        )

    def test_c7_certified_empty_requires_a_completed_evidenced_detection_manifest(self) -> None:
        result = next(
            item
            for item in self.fixture_reports["certified-empty-reconciliation"]["criteria"]
            if item["criterion_id"] == "C7"
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["exact_ratio"], "0/0")
        self.assertIn("measurement", result["admitted_derivation_classes_used"])

    def test_c1_split_preserves_predecessor_and_validates_successor_graph(self) -> None:
        valid = next(
            item
            for item in self.fixture_reports["valid-split-disposition"]["criteria"]
            if item["criterion_id"] == "C1"
        )
        invalid = next(
            item
            for item in self.fixture_reports["invalid-split-lineage"]["criteria"]
            if item["criterion_id"] == "C1"
        )
        self.assertEqual(valid["status"], "PASS")
        self.assertEqual(valid["exact_ratio"], "3/3")
        self.assertEqual(invalid["status"], "FAIL")
        self.assertIn("invalid-candidate-lineage", {item["code"] for item in invalid["diagnostics"]})

    def test_stale_digest_bound_inputs_fail_closed(self) -> None:
        stale = deepcopy(self.current_input)
        stale["source_artifacts"][0]["sha256"] = "f" * 64
        stale = _finalize_input(
            ROOT,
            {key: value for key, value in stale.items() if key not in {"input_set_id", "input_set_digest_sha256"}},
        )
        with self.assertRaisesRegex(ConformanceDataError, "stale-certification-source"):
            validate_input_set(ROOT, self.contract, stale)

    def test_supersession_and_revocation_change_authority_not_historical_reports(self) -> None:
        fixture = self.fixtures["supersession_fixture"]
        self.assertEqual(fixture["historical_report_digest_before"], fixture["historical_report_digest_after"])
        validate_authority_index(ROOT, fixture["authority_index"])

        revoked = deepcopy(fixture["authority_index"])
        revoked["certifications"][0]["status"] = "revoked"
        revoked["actions"][0]["kind"] = "revoke"
        revoked["actions"][0]["successor_certification_id"] = None
        revoked["actions"][0]["reason"] = "Referenced fixture evidence was invalidated."
        revoked["authority_index_sha256"] = _authority_digest(revoked)
        validate_authority_index(ROOT, revoked)

    def test_materialization_preserves_append_only_authority_history(self) -> None:
        prior = self.fixtures["supersession_fixture"]["authority_index"]
        rebuilt = build_current_authority(self.contract, self.current_report, prior)
        self.assertEqual(rebuilt["certifications"], prior["certifications"])
        self.assertEqual(rebuilt["actions"], prior["actions"])
        self.assertEqual(rebuilt["current_certification_id"], prior["current_certification_id"])
        self.assertEqual(
            rebuilt["current_evaluation"]["report_digest_sha256"],
            self.current_report["report_digest_sha256"],
        )
        validate_authority_index(ROOT, rebuilt)

    def test_current_repository_reports_incomplete_state_without_gate_weakening(self) -> None:
        states = {item["criterion_id"]: item for item in self.current_report["criteria"]}
        self.assertEqual(self.current_report["final_state"], "FAIL")
        self.assertFalse(self.current_report["certification_eligible"])
        self.assertEqual(states["C4"]["status"], "FAIL")
        self.assertEqual(states["C4"]["exact_ratio"], "0/9506")
        self.assertEqual(
            {criterion for criterion, result in states.items() if result["status"] == "BLOCKED"},
            {"C1", "C2", "C3", "C5", "C6", "C7"},
        )
        self.assertEqual(self.authority["current_certification_id"], None)
        self.assertEqual(self.current_report["input_artifacts"], self.current_input["source_artifacts"])
        self.assertTrue(all(item["sha256"] for item in self.current_report["input_artifacts"]))

    def test_repository_artifacts_recompute_deterministically(self) -> None:
        self.assertEqual(
            verify_repository_certification(ROOT),
            {
                "generated_assertion_artifacts": 64,
                "generated_assertion_groups": 255,
                "generated_assertion_occurrences": 1034993,
                "generated_count_contracts": 88,
                "certification_contracts": 1,
                "certification_criteria": 7,
                "certification_fixtures": 17,
                "current_certification_state": "FAIL",
            },
        )


if __name__ == "__main__":
    unittest.main()
