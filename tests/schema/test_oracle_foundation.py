from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.errors import ConformanceDataError  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.oracle import (  # noqa: E402
    AUTHORITY_PATH,
    CONTRACT_PATH,
    FIXTURE_PATH,
    ORACLE_CLASSES,
    REPORT_PATH,
    _dependency,
    finalize_oracle_record,
    validate_contract,
    validate_fixtures,
    validate_oracle_collection,
    validate_oracle_record,
    validate_vector_binding,
    verify_current,
)


class OracleFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_strict(ROOT / CONTRACT_PATH)
        cls.fixture = load_strict(ROOT / FIXTURE_PATH)
        cls.records = {item["oracle_class"]: item for item in cls.fixture["valid_oracles"]}

    def _refresh(self, record: dict) -> dict:
        return finalize_oracle_record(ROOT, record)

    def _assert_rejected(self, record: dict, code: str) -> None:
        with self.assertRaisesRegex(ConformanceDataError, code):
            validate_oracle_record(ROOT, self.contract, self._refresh(record))

    def test_committed_foundation_is_deterministic_and_complete(self) -> None:
        validate_contract(ROOT, self.contract)
        self.assertEqual(
            validate_fixtures(ROOT, self.contract, self.fixture),
            {"valid_oracle_classes": 8, "prohibited_cases_rejected": 10},
        )
        result = verify_current(ROOT, broad_foundations=False)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["requirements"], 3378)
        self.assertTrue((ROOT / AUTHORITY_PATH).is_file())
        self.assertTrue((ROOT / REPORT_PATH).is_file())

    def test_o1_through_o8_are_epistemic_functions_not_a_ladder(self) -> None:
        self.assertEqual(list(ORACLE_CLASSES), [f"O{index}" for index in range(1, 9)])
        self.assertEqual(self.contract["selection_and_conflict"]["class_precedence"], "none")
        self.assertTrue(self.contract["selection_and_conflict"]["numeric_rank_forbidden"])
        for record in self.records.values():
            validate_oracle_record(ROOT, self.contract, record)

    def test_majority_vote_cannot_be_expected_output(self) -> None:
        changed = deepcopy(self.records["O1"])
        changed["dependency_graph"]["nodes"][0]["kind"] = "empirical-consensus"
        self._assert_rejected(changed, "consensus-oracle-forbidden")

    def test_target_output_cannot_oracle_itself(self) -> None:
        changed = deepcopy(self.records["O1"])
        profile = "rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7"
        changed["independence"]["evaluated_profile_ids"] = [profile]
        node = changed["dependency_graph"]["nodes"][0]
        node["kind"] = "target-implementation-output"
        node["subject_profile_ids"] = [profile]
        self._assert_rejected(changed, "target-self-oracle")

    def test_generator_evaluator_same_authority_domain_is_rejected(self) -> None:
        changed = deepcopy(self.records["O2"])
        node = changed["dependency_graph"]["nodes"][0]
        node.update(kind="generator", semantic_evaluator=True, authority_domain_id=changed["independence"]["stimulus_generator_authority_domain_ids"][0])
        self._assert_rejected(changed, "generator-self-oracle")

    def test_observation_promotion_needs_separate_independent_basis(self) -> None:
        changed = deepcopy(self.records["O1"])
        observation = _dependency("test-promotion", "empirical-observation", "promotion-source")
        changed["dependency_graph"]["nodes"].append(observation)
        changed["dependency_graph"]["root_dependency_ids"].append(observation["dependency_id"])
        changed["promotion_event"] = {
            "source_observation_id": observation["dependency_id"],
            "promoter_id": "reviewer-a",
            "reviewer_id": "reviewer-b",
            "promoted_at": "2026-09-10",
            "justification": "Independent normative authority was subsequently established.",
            "independent_oracle_basis_dependency_ids": [observation["dependency_id"]],
            "target_expectation_revision_id": "rcid:v1:expectation-projection:h:jcs-sha256-v1:" + "8" * 64,
        }
        self._assert_rejected(changed, "observation-promotion-without-independent-authority")
        expected_root = changed["dependency_graph"]["nodes"][0]["dependency_id"]
        changed["promotion_event"]["independent_oracle_basis_dependency_ids"] = [expected_root]
        validate_oracle_record(ROOT, self.contract, self._refresh(changed))

    def test_indirect_observation_claim_expectation_is_rejected(self) -> None:
        changed = deepcopy(self.records["O1"])
        observation = _dependency("test-indirect", "empirical-observation", "context-only")
        changed["dependency_graph"]["nodes"].append(observation)
        root = changed["dependency_graph"]["nodes"][0]
        root["kind"] = "research-claim"
        root["upstream_dependency_ids"] = [observation["dependency_id"]]
        self._assert_rejected(changed, "observation-as-expectation")

    def test_reference_profile_cannot_be_universal_truth(self) -> None:
        changed = deepcopy(self.records["O5"])
        changed["scope"]["kind"] = "external-normative"
        changed["scope"]["profile_family_id"] = None
        self._assert_rejected(changed, "oracle-scope-class-mismatch")

    def test_silence_cannot_imply_unsupported(self) -> None:
        changed = deepcopy(self.records["O1"])
        changed["dependency_graph"]["nodes"][0]["kind"] = "absence-of-authority"
        changed["expected_result"]["value"] = {"unsupported": True}
        self._assert_rejected(changed, "negative-inference-from-silence")

    def test_historical_observation_cannot_be_normative_truth(self) -> None:
        changed = deepcopy(self.records["O7"])
        changed["permitted_judgments"] = ["normative-conformant"]
        self._assert_rejected(changed, "oracle-judgment-escalation")

    def test_class_specific_version_and_provenance_are_required(self) -> None:
        changed = deepcopy(self.records["O3"])
        changed["provenance"].pop("data_version")
        self._assert_rejected(changed, "oracle-provenance-fields")

    def test_source_identity_and_version_must_be_canonical_and_pinned(self) -> None:
        changed = deepcopy(self.records["O1"])
        changed["provenance"]["source_identity"] = "unregistered-summary"
        self._assert_rejected(changed, "oracle-source-authority")
        changed = deepcopy(self.records["O1"])
        changed["provenance"]["source_version"] = "latest"
        self._assert_rejected(changed, "mutable-oracle-version")

    def test_dependency_cycle_is_rejected(self) -> None:
        changed = deepcopy(self.records["O2"])
        node = changed["dependency_graph"]["nodes"][0]
        node["upstream_dependency_ids"] = [node["dependency_id"]]
        self._assert_rejected(changed, "oracle-dependency-cycle")

    def test_under_specification_is_not_failure(self) -> None:
        changed = deepcopy(self.records["O1"])
        changed["resolution_state"] = "expectation-under-specified"
        changed["expected_result"] = None
        validate_oracle_record(ROOT, self.contract, self._refresh(changed))

    def test_conflicting_legitimate_expectations_survive_without_winner(self) -> None:
        first = self.records["O1"]
        second = deepcopy(first)
        second["expected_result"]["value"] = {"match": False}
        second = self._refresh(second)
        with self.assertRaisesRegex(ConformanceDataError, "unrepresented-authority-conflict"):
            validate_oracle_collection(ROOT, self.contract, [first, second], [])
        conflict = {
            "conflict_id": "urn:strling:oracle-conflict:test",
            "requirement_scientific_id": first["requirement_scientific_id"],
            "oracle_ids": [first["oracle_id"], second["oracle_id"]],
            "resolution_state": "conflicting-authoritative-expectations",
            "selected_oracle_id": None,
            "scope_overlap_basis": "Both claims answer the same requirement over the same applicability scope.",
        }
        validate_oracle_collection(ROOT, self.contract, [first, second], [conflict])

    def test_different_profile_documentation_results_are_not_false_conflicts(self) -> None:
        first = self.records["O6"]
        second = deepcopy(first)
        profile = "rcid:v1:profile:u7:019ff984-a52e-746c-b7c9-7f82de44ebfd"
        second["scope"]["profile_ids"] = [profile]
        second["provenance"]["implementation_scope_id"] = profile
        second["dependency_graph"]["nodes"][0]["subject_profile_ids"] = [profile]
        second["expected_result"]["value"] = {"match": True}
        second = self._refresh(second)
        validate_oracle_collection(ROOT, self.contract, [first, second], [])

    def test_frozen_campaign_binding_detects_later_oracle_drift(self) -> None:
        binding = self.fixture["frozen_vector_binding"]
        validate_vector_binding(ROOT, self.contract, binding, self.fixture["valid_oracles"])
        changed = deepcopy(self.fixture["valid_oracles"])
        changed[0]["oracle_digest_sha256"] = "f" * 64
        with self.assertRaisesRegex(ConformanceDataError, "frozen-oracle-drift"):
            validate_vector_binding(ROOT, self.contract, binding, changed)

    def test_generated_artifacts_are_canonical_bytes(self) -> None:
        for path in (CONTRACT_PATH, FIXTURE_PATH, REPORT_PATH, AUTHORITY_PATH):
            value = load_strict(ROOT / path)
            self.assertEqual((ROOT / path).read_bytes(), canonical_bytes(value) + b"\n")


if __name__ == "__main__":
    unittest.main()
