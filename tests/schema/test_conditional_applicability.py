from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.applicability import (  # noqa: E402
    AUTHORITY_PATH,
    CONTRACT_PATH,
    FIXTURE_PATH,
    REPORT_PATH,
    _eval_node,
    _exercise_fixtures,
    _finalize,
    _finalize_fact,
    _fixture_basis,
    _predicate_id,
    audit_requirements,
    evaluate,
    validate_fact_snapshot,
    validate_predicate,
    verify_current,
)
from regex_conformance_schema.errors import ConformanceDataError  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402


class ConditionalApplicabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_strict(ROOT / CONTRACT_PATH)
        cls.fixture = load_strict(ROOT / FIXTURE_PATH)
        cls.requirement, cls.binding, cls.predicate = _fixture_basis(ROOT)
        cls.snapshots = {item["snapshot_id"]: item for item in cls.fixture["profile_fact_snapshots"]}
        cls.cases = {item["case_id"]: item for item in cls.fixture["valid_cases"]}
        cls.context = {"feature_scientific_id": cls.binding["feature_scientific_id"], "operation_scientific_ids": cls.binding["operation_scientific_ids"]}

    def test_committed_authority_closes_all_conditional_requirements(self) -> None:
        audit = audit_requirements(ROOT, self.contract)
        self.assertEqual(audit["semantic_requirements"], 3378)
        self.assertEqual(audit["unconditional_requirements"], 1406)
        self.assertEqual(audit["conditional_requirements"], 1972)
        self.assertEqual(audit["conditional_requirements_validated"], 1972)
        self.assertEqual(audit["unexplained_conditional_requirements"], 0)
        self.assertEqual(audit["required_intrinsic_modifier_scope_requirements"], 80)
        self.assertEqual(audit["required_unexplained_capability_dependencies"], 0)
        result = verify_current(ROOT, broad_foundations=False)
        self.assertEqual(result["result"], "PASS")

    def test_known_true_false_missing_and_conflict_are_distinct(self) -> None:
        outcomes = _exercise_fixtures(ROOT, self.contract, self.fixture)["outcomes"]
        self.assertEqual(outcomes["known-true"], "applicable")
        self.assertEqual(outcomes["known-false"], "not-applicable")
        self.assertEqual(outcomes["missing-open-world"], "unresolved")
        self.assertEqual(outcomes["conflicting-facts"], "unresolved")
        self.assertEqual(outcomes["explicit-absence"], "not-applicable")

    def test_scoped_field_closure_can_establish_absence_without_global_closed_world(self) -> None:
        missing = deepcopy(self.snapshots[self.cases["missing-open-world"]["snapshot_id"]])
        field = self.predicate["predicate"]["clauses"][0]["field"]
        field_spec = next(item for item in self.contract["field_registry"] if item["field"] == field)
        missing["field_closure_rules"] = [{
            "field_id": field_spec["field_id"], "field": field,
            "rule_id": "rcid:v1:applicability-rule-set:h:jcs-sha256-v1:" + "3" * 64,
            "scope": "exact-profile-revision-and-field",
            "authority_artifact_id": "rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:" + "4" * 64,
        }]
        body = {key: value for key, value in missing.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
        missing = _finalize(ROOT, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")
        result = evaluate(ROOT, self.contract, self.requirement, self.binding, self.predicate, missing)
        self.assertEqual(result["result"], "not-applicable")
        self.assertNotEqual(self.contract["world_semantics"]["default"], "closed")

    def test_nested_logic_and_negation_preserve_unknown(self) -> None:
        missing = self.snapshots[self.cases["missing-open-world"]["snapshot_id"]]
        expected = {"and-unknown-false": "false", "or-unknown-true": "true", "negated-unknown": "unknown"}
        for case_id, truth in expected.items():
            observed, trace, _ = _eval_node(self.cases[case_id]["predicate"], missing, self.context)
            self.assertEqual(observed, truth)
            self.assertEqual(trace["truth_value"], truth)

    def test_commutative_predicate_serialization_has_one_identity(self) -> None:
        first = self.predicate["predicate"]
        second = {"operator": "all", "clauses": list(reversed(first["clauses"]))}
        self.assertEqual(_predicate_id(ROOT, first), _predicate_id(ROOT, second))

    def test_invalid_capability_reference_is_rejected(self) -> None:
        bad = {"operator": "contains", "field": "profile.feature_scientific_ids", "value": "rcid:v1:feature:u7:00000000-0000-7000-8000-000000000000"}
        with self.assertRaisesRegex(ConformanceDataError, "applicability-invalid-capability-reference"):
            validate_predicate(ROOT, bad, self.context, self.contract)

    def test_type_invalid_and_unsupported_operators_are_rejected(self) -> None:
        bad_type = {"operator": "eq", "field": "profile.feature_scientific_ids", "value": self.binding["feature_scientific_id"]}
        with self.assertRaisesRegex(ConformanceDataError, "applicability-operator-type"):
            validate_predicate(ROOT, bad_type, self.context, self.contract)
        bad_operator = {"operator": "execute", "field": "profile.feature_scientific_ids", "value": self.binding["feature_scientific_id"]}
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation"):
            validate_predicate(ROOT, bad_operator, self.context, self.contract)
        ambiguous = {
            "operator": "contains", "field": "profile.feature_scientific_ids",
            "value": self.binding["feature_scientific_id"], "lower": 1,
        }
        with self.assertRaisesRegex(ConformanceDataError, "applicability-predicate-target"):
            validate_predicate(ROOT, ambiguous, self.context, self.contract)

    def test_fact_value_type_must_match_the_registered_field(self) -> None:
        snapshot = deepcopy(self.fixture["profile_fact_snapshots"][0])
        fact = deepcopy(snapshot["facts"][0])
        fact_body = {key: value for key, value in fact.items() if key not in {"fact_id", "fact_digest_sha256"}}
        fact_body["value_type"] = "string"
        fact = _finalize_fact(ROOT, fact_body)
        body = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
        body["facts"] = [fact]
        snapshot = _finalize(ROOT, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")
        with self.assertRaisesRegex(ConformanceDataError, "applicability-fact-type"):
            validate_fact_snapshot(ROOT, snapshot, self.contract)

    def test_target_observation_cannot_establish_applicability(self) -> None:
        snapshot = deepcopy(self.fixture["profile_fact_snapshots"][0])
        fact = deepcopy(snapshot["facts"][0])
        fact_body = {key: value for key, value in fact.items() if key not in {"fact_id", "fact_digest_sha256"}}
        fact_body["dependencies"] = [{"dependency_id": "rcid:v1:observation:h:jcs-sha256-v1:" + "a" * 64, "kind": "target-observation"}]
        fact = _finalize_fact(ROOT, fact_body)
        body = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
        body["facts"] = [fact]
        snapshot = _finalize(ROOT, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")
        with self.assertRaisesRegex(ConformanceDataError, "applicability-self-reference"):
            validate_fact_snapshot(ROOT, snapshot, self.contract)

    def test_capability_fact_dependency_cycle_is_rejected(self) -> None:
        snapshot = deepcopy(self.fixture["profile_fact_snapshots"][0])
        first = deepcopy(snapshot["facts"][0]); second = deepcopy(snapshot["facts"][0])
        first_id = "rcid:v1:trust-assessment:h:jcs-sha256-v1:" + "a" * 64
        second_id = "rcid:v1:trust-assessment:h:jcs-sha256-v1:" + "b" * 64
        first["fact_id"] = first_id; second["fact_id"] = second_id
        first["dependencies"] = [{"dependency_id": second_id, "kind": "capability-fact"}]
        second["dependencies"] = [{"dependency_id": first_id, "kind": "capability-fact"}]
        body = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
        body["facts"] = [first, second]
        snapshot = _finalize(ROOT, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")
        with self.assertRaisesRegex(ConformanceDataError, "applicability-dependency-cycle"):
            validate_fact_snapshot(ROOT, snapshot, self.contract)

    def test_ad_hoc_skip_is_not_an_applicability_input(self) -> None:
        snapshot = deepcopy(self.fixture["profile_fact_snapshots"][0])
        snapshot["skip"] = True
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation"):
            validate_fact_snapshot(ROOT, snapshot, self.contract)

    def test_snapshot_revision_changes_create_new_evaluation_identity(self) -> None:
        first = self.fixture["profile_fact_snapshots"][0]
        changed = deepcopy(first)
        changed["profile_revision_id"] = "rcid:v1:profile-revision:h:jcs-sha256-v1:" + "2" * 64
        body = {key: value for key, value in changed.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
        changed = _finalize(ROOT, body, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")
        self.assertNotEqual(first["snapshot_id"], changed["snapshot_id"])
        first_result = evaluate(ROOT, self.contract, self.requirement, self.binding, self.predicate, first)
        changed_result = evaluate(ROOT, self.contract, self.requirement, self.binding, self.predicate, changed)
        self.assertNotEqual(first_result["evaluation_id"], changed_result["evaluation_id"])
        self.assertEqual(first_result["capability_snapshot"]["artifact_id"], first["snapshot_id"])
        self.assertEqual(changed_result["capability_snapshot"]["artifact_id"], changed["snapshot_id"])

    def test_evaluation_trace_is_structured_and_provenance_bearing(self) -> None:
        snapshot = self.snapshots[self.cases["known-true"]["snapshot_id"]]
        result = evaluate(ROOT, self.contract, self.requirement, self.binding, self.predicate, snapshot)
        self.assertEqual(result["result"], "applicable")
        self.assertEqual(result["truth_value"], "true")
        self.assertEqual(result["trace"]["operator"], "all")
        self.assertTrue(result["facts_read"])
        self.assertEqual(result["requirement"]["artifact_id"], self.requirement["scientific_id"])
        self.assertEqual(result["profile"]["profile_revision_id"], snapshot["profile_revision_id"])
        self.assertFalse(result["semantic_boundary"]["determines_expected_result"])
        self.assertEqual(result["unresolved_dependencies"], [])

    def test_applicability_has_no_oracle_or_support_authority(self) -> None:
        boundary = self.contract["evaluation_contract"]["not_applicable_meaning"]
        self.assertIn("not", boundary.lower())
        authority = load_strict(ROOT / AUTHORITY_PATH)
        self.assertFalse(authority["governance"]["not_applicable_is_unsupported"])
        self.assertEqual(authority["governance"]["expected_result_owner"], "oracle/evidence authority, never applicability")

    def test_unconditional_requirements_remain_requirement_scope_not_extra_conditions(self) -> None:
        report = load_strict(ROOT / REPORT_PATH)
        self.assertEqual(report["coverage"]["unconditional_requirements"], 1406)
        self.assertEqual(report["denominator_boundary"]["requirements"], 3378)
        self.assertTrue(report["denominator_boundary"]["unchanged"])

    def test_profile_expanded_denominator_remains_deferred(self) -> None:
        self.assertIsNone(self.contract["prospective_profile_expansion"]["exact_profile_count"])
        self.assertIsNone(self.contract["prospective_profile_expansion"]["final_execution_denominator"])
        self.assertFalse(self.contract["prospective_profile_expansion"]["historical_multiplier_substituted"])
        self.assertFalse(self.fixture["synthetic_denominator_example"]["authoritative"])

    def test_generated_artifacts_are_canonical_bytes(self) -> None:
        for path in (CONTRACT_PATH, FIXTURE_PATH, REPORT_PATH, AUTHORITY_PATH):
            value = load_strict(ROOT / path)
            self.assertEqual((ROOT / path).read_bytes(), canonical_bytes(value) + b"\n")


if __name__ == "__main__":
    unittest.main()
