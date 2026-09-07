from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.derivation import verify_catalog as verify_derivation_catalog
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.execution_provenance import (
    FIXTURE_PATH,
    POLICY_PATH,
    build_reference_fixture,
    lineage_set_sha256,
    observation_content_id,
    policy_revision,
    result_signature,
    validate_lineage_set,
    validate_policy,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.scientific_identity import verify_catalog as verify_identity_catalog


class ExecutionProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = load_strict(ROOT / POLICY_PATH)
        cls.fixture = load_strict(ROOT / FIXTURE_PATH)

    def _refresh(self, record: dict) -> dict:
        record["lineage_set_sha256"] = lineage_set_sha256(record)
        return record

    def test_reference_lineages_are_valid_and_population_explicit(self) -> None:
        self.assertEqual(
            validate_lineage_set(ROOT, self.fixture, self.policy),
            {
                "inconclusive_attempt_count": 3,
                "logical_execution_count": 5,
                "physical_attempt_count": 8,
                "recovered_attempt_count": 1,
                "repeat_measurement_attempt_count": 1,
                "retry_attempt_count": 2,
                "terminal_attempt_count": 5,
                "terminal_observation_count": 5,
            },
        )

    def test_policy_digest_and_closed_retry_rules_are_enforced(self) -> None:
        self.assertEqual(self.policy["policy_revision_sha256"], policy_revision(self.policy))
        validate_policy(ROOT, self.policy)
        changed = deepcopy(self.policy)
        changed["retry_rules"][0]["maximum_attempts"] = 2
        with self.assertRaisesRegex(ConformanceDataError, "execution-policy-digest-mismatch"):
            validate_policy(ROOT, changed)
        self.assertEqual(
            [item["schema_version"] for item in self.policy["compatibility"]["historical_contracts"]],
            [
                "evidence-pack-manifest.v2",
                "evidence-pack-manifest.v3",
                "observation-content.v1",
                "physical-attempt-evidence.v1",
            ],
        )
        self.assertFalse(self.policy["compatibility"]["historical_records_rewritten"])
        self.assertEqual(len(self.policy["retry_rules"]), 9)
        inconclusive = next(
            rule for rule in self.policy["retry_rules"]
            if rule["reason_code"] == "inconclusive-attribution"
        )
        self.assertFalse(inconclusive["retry_permitted"])
        self.assertEqual(inconclusive["exhausted_disposition"], "unresolved")

    def test_population_counts_bind_nonindependent_calculation_derivation(self) -> None:
        catalog = load_strict(
            ROOT / "registries/provenance/generated-assertion-derivations.v1.json"
        )
        derivation = next(
            item
            for item in catalog["derivations"]
            if item["derivation_revision_id"] == self.fixture["count_derivation_revision_id"]
        )
        self.assertEqual(derivation["derivation_class"], "calculation")
        self.assertFalse(derivation["independent_evidence"])

        changed = deepcopy(self.fixture)
        changed["count_derivation_revision_id"] = (
            "rcid:v1:assertion-derivation-revision:h:jcs-sha256-v1:" + "f" * 64
        )
        self._refresh(changed)
        with self.assertRaisesRegex(
            ConformanceDataError, "lineage-count-derivation-mismatch"
        ):
            validate_lineage_set(ROOT, changed, self.policy)

    def test_ordinary_compile_rejection_and_bounded_target_crash_are_terminal(self) -> None:
        by_logical = {item["logical_execution_id"]: item for item in self.fixture["lineages"]}
        ordinary = by_logical[sorted(by_logical)[0]]
        self.assertEqual(ordinary["disposition"]["status"], "satisfied")
        recovery = by_logical[sorted(by_logical)[1]]
        self.assertEqual(recovery["attempts"][1]["terminality"]["outcome_class"], "compile-rejection")
        self.assertEqual(recovery["disposition"]["satisfaction_attempt_id"], recovery["attempts"][1]["physical_run_id"])
        crash = by_logical[sorted(by_logical)[2]]
        self.assertEqual(crash["attempts"][0]["terminality"]["outcome_class"], "target-crash")
        self.assertIsNotNone(crash["attempts"][0]["terminality"]["fault_attribution"]["evidence_reference"])

    def test_process_symptom_without_attribution_is_inconclusive(self) -> None:
        changed = deepcopy(self.fixture)
        crash = changed["lineages"][2]["attempts"][0]
        crash["terminality"]["fault_attribution"]["evidence_reference"] = None
        self._refresh(changed)
        with self.assertRaisesRegex(ConformanceDataError, "unattributed-process-symptom"):
            validate_lineage_set(ROOT, changed, self.policy)

    def test_adapter_and_malformed_failures_cannot_become_target_behavior(self) -> None:
        changed = deepcopy(self.fixture)
        malformed = changed["lineages"][3]["attempts"][0]
        malformed["terminality"].update(
            disposition="terminal-scientific-observation",
            observation_complete=True,
            produced_observation_id="rcid:v1:observation:u7:019ffdee-0000-7000-8000-000000000099",
            semantic_result={"match": False},
            scientific_result_signature=result_signature("malformed-adapter-response", {"match": False}),
        )
        self._refresh(changed)
        with self.assertRaises(ConformanceDataError):
            validate_lineage_set(ROOT, changed, self.policy)

    def test_retry_preserves_predecessor_reset_policy_and_recovery_chain(self) -> None:
        recovery = self.fixture["lineages"][1]
        first, second = recovery["attempts"]
        self.assertEqual(first["terminality"]["disposition"], "inconclusive-attempt")
        self.assertEqual(second["predecessor_physical_run_id"], first["physical_run_id"])
        self.assertEqual(second["retry"]["reason_code"], "interrupted-target-invocation")
        self.assertEqual(second["reset"]["scope"], "target-process")
        self.assertEqual(second["checkpoint_context"]["recovery_action"], "retry")
        self.assertEqual(recovery["disposition"]["attempts_total"], 2)

    def test_retry_exhaustion_remains_unresolved(self) -> None:
        exhausted = self.fixture["lineages"][3]["disposition"]
        self.assertEqual(exhausted["status"], "unresolved")
        self.assertTrue(exhausted["retry_budget_exhausted"])
        self.assertEqual(exhausted["unresolved_reason"], "retry-budget-exhausted")
        self.assertEqual(exhausted["terminal_attempt_count"], 0)

    def test_terminal_result_cannot_be_laundered_by_retry(self) -> None:
        changed = deepcopy(self.fixture)
        repeated = changed["lineages"][4]
        second = repeated["attempts"][1]
        second["attempt_purpose"] = "automatic-retry"
        second["repeat"] = None
        second["retry"] = {
            "authorization_kind": "automatic",
            "policy_rule": "lost-unattributed-response",
            "policy_revision_sha256": self.policy["policy_revision_sha256"],
            "reason_code": "lost-unattributed-response",
        }
        second["checkpoint_context"]["recovery_action"] = "retry"
        self._refresh(changed)
        with self.assertRaisesRegex(ConformanceDataError, "retry-laundering"):
            validate_lineage_set(ROOT, changed, self.policy)

    def test_repeat_preserves_both_terminal_results_without_adjudicating_flakiness(self) -> None:
        repeated = self.fixture["lineages"][4]
        disposition = repeated["disposition"]
        self.assertEqual(disposition["terminal_attempt_count"], 2)
        self.assertEqual(disposition["distinct_terminal_result_signature_count"], 2)
        self.assertEqual(disposition["satisfaction_attempt_id"], repeated["attempts"][0]["physical_run_id"])
        self.assertNotIn("flaky", disposition)

    def test_repeat_binds_policy_and_same_environment(self) -> None:
        changed = deepcopy(self.fixture)
        repeat = changed["lineages"][4]["attempts"][1]
        repeat["repeat"]["policy_revision_sha256"] = "f" * 64
        self._refresh(changed)
        with self.assertRaisesRegex(ConformanceDataError, "repeat-policy-mismatch"):
            validate_lineage_set(ROOT, changed, self.policy)

        changed = deepcopy(self.fixture)
        repeat = changed["lineages"][4]["attempts"][1]
        repeat["execution_context"]["environment_realization_id"] = (
            "rcid:v1:environment-realization:u7:019ffdee-0000-7000-8000-000000000099"
        )
        self._refresh(changed)
        with self.assertRaisesRegex(ConformanceDataError, "repeat-environment-drift"):
            validate_lineage_set(ROOT, changed, self.policy)

    def test_dangling_observation_and_ordinal_mutation_fail(self) -> None:
        dangling = deepcopy(self.fixture)
        dangling["lineages"][0]["observations"][0]["terminal_attempt_id"] = dangling["lineages"][1]["attempts"][0]["physical_run_id"]
        dangling["lineages"][0]["observations"][0]["observation_content_id"] = observation_content_id(ROOT, dangling["lineages"][0]["observations"][0])
        self._refresh(dangling)
        with self.assertRaisesRegex(ConformanceDataError, "missing-terminal-observation|dangling-terminal-attempt"):
            validate_lineage_set(ROOT, dangling, self.policy)

        ordinal = deepcopy(self.fixture)
        ordinal["lineages"][1]["attempts"][1]["attempt_ordinal"] = 3
        self._refresh(ordinal)
        with self.assertRaisesRegex(ConformanceDataError, "noncontiguous-attempt-ordinals"):
            validate_lineage_set(ROOT, ordinal, self.policy)

    def test_regeneration_is_deterministic_and_prior_contracts_remain_green(self) -> None:
        first = build_reference_fixture(ROOT, self.policy)
        second = build_reference_fixture(ROOT, self.policy)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(canonical_bytes(first), canonical_bytes(self.fixture))
        self.assertEqual(
            verify_identity_catalog(ROOT),
            {"scientific_identities": 22427, "scientific_lineage_records": 0},
        )
        self.assertGreater(verify_derivation_catalog(ROOT)["generated_assertion_groups"], 0)


if __name__ == "__main__":
    unittest.main()
