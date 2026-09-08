from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.obligation_derivation import (
    CONTRACT_PATH,
    DENOMINATOR_SHA256,
    DRY_RUN_PATH,
    FIXTURE_PATH,
    LEGACY_REPORT_PATH,
    SNAPSHOT_PATH,
    _validate_decisions,
    _validate_fixtures,
    applicable_operations,
    build_contract,
    build_dry_run,
    denominator_baseline,
    derive_feature,
    validate_contract,
)


class ObligationDerivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = load_strict(ROOT / SNAPSHOT_PATH)
        cls.contract = load_strict(ROOT / CONTRACT_PATH)
        cls.dry_run = load_strict(ROOT / DRY_RUN_PATH)
        cls.legacy = load_strict(ROOT / LEGACY_REPORT_PATH)
        cls.features = {item["feature_id"]: item for item in cls.snapshot["features"]}

    def decision(self, feature_id: str, facet_id: str, *, override: tuple[str, str, str] | None = None) -> dict:
        feature = deepcopy(self.features[feature_id])
        if override:
            field, state, scope = override
            feature["semantic_assertions"][field]["state"] = state
            feature["semantic_assertions"][field]["scope"] = scope
        return next(item for item in derive_feature(self.snapshot, self.contract, feature) if item["facet_id"] == facet_id)

    def test_contract_is_total_over_fifteen_facets_and_thirty_three_operations(self) -> None:
        validate_contract(ROOT, self.contract, self.snapshot)
        self.assertEqual(len(self.contract["facet_rules"]), 15)
        self.assertEqual(len(self.contract["operation_rules"]), 33)
        self.assertEqual(len(self.contract["obligation_archetypes"]), 16)
        self.assertIsNone(self.contract["explainability_contract"]["generic_fallback_rule"])

    def test_semantic_state_suppression_and_characterization_are_distinct(self) -> None:
        suppressed = self.decision("feature.absent-expression", "facet.capture")
        self.assertEqual(suppressed["decision"], "not-required-by-feature-semantics")
        self.assertEqual(suppressed["provisional_obligations"], [])

        not_applicable = self.decision("feature.linear-time-guarantee", "facet.syntax")
        self.assertEqual(not_applicable["decision"], "not-applicable")

        characterized = self.decision(
            "feature.absent-expression",
            "facet.capture",
            override=("capture_result", "intentionally-under-specified", "canonical-invariant"),
        )
        self.assertEqual(characterized["decision"], "required")
        self.assertEqual(characterized["question_type"], "characterization-only")

        blocked = self.decision(
            "feature.absent-expression",
            "facet.capture",
            override=("capture_result", "unresolved", "canonical-invariant"),
        )
        self.assertEqual(blocked["decision"], "blocked-by-unresolved-semantics")
        self.assertEqual(blocked["provisional_obligations"], [])

    def test_representative_feature_families_derive_different_shapes(self) -> None:
        cases = {
            ("feature.capture-history", "facet.capture"): ("required", {"archetype.host-result"}),
            ("feature.unicode-line-break-boundary", "facet.unicode-encoding"): ("required", {"archetype.alternative-semantic-mode", "archetype.boundary-behavior"}),
            ("feature.append-replacement-state", "facet.replacement"): ("required", {"archetype.repeated-iteration", "archetype.replacement-output"}),
            ("feature.atomic-group", "facet.capture"): ("conditionally-required", {"archetype.host-result"}),
            ("feature.numeric-escape-disambiguation", "facet.phase"): ("conditionally-required", {"archetype.phase-specific"}),
            ("feature.linear-time-guarantee", "facet.complexity-guarantee"): ("required", {"archetype.complexity-guarantee"}),
            ("feature.escaped-literal", "facet.security-context"): ("conditionally-required", {"archetype.security-boundary"}),
            ("feature.assertion-conditional", "facet.interaction-composition"): ("required", {"archetype.interaction-specific"}),
        }
        for (feature_id, facet_id), (decision, archetypes) in cases.items():
            with self.subTest(feature_id=feature_id, facet_id=facet_id):
                result = self.decision(feature_id, facet_id)
                self.assertEqual(result["decision"], decision)
                self.assertEqual({item["archetype_id"] for item in result["provisional_obligations"]}, archetypes)

    def test_operation_rules_use_canonical_operations_and_explicit_conditions(self) -> None:
        rules = {item["operation_id"]: item for item in self.contract["operation_rules"]}
        self.assertEqual(rules["operation.escape-pattern"]["feature_selector"]["kind"], "feature-id-set")
        self.assertEqual(rules["operation.serialize-pattern"]["feature_selector"]["kind"], "all-compilable")
        self.assertEqual(rules["operation.stream-reset"]["feature_selector"]["kind"], "stream-capable")
        self.assertEqual(rules["operation.compile"]["profile_capability_predicate"]["clauses"][0]["field"], "profile.operation_scientific_ids")
        operations, conditional = applicable_operations(
            self.features["feature.escaped-literal"],
            self.contract,
            ["operation-family.construction"],
        )
        self.assertIn("operation.escape-pattern", operations)
        self.assertFalse(conditional)

    def test_differential_is_analysis_only_and_interactions_are_not_cartesian(self) -> None:
        differential = self.decision("feature.capture-history", "facet.version-platform-differential")
        self.assertEqual(differential["decision"], "not-required-by-feature-semantics")
        self.assertEqual(differential["provisional_obligations"], [])
        no_interaction = self.decision("feature.absent-expression", "facet.interaction-composition")
        self.assertEqual(no_interaction["provisional_obligations"], [])

        interaction = self.decision("feature.assertion-conditional", "facet.interaction-composition")["provisional_obligations"][0]
        self.assertTrue(interaction["interaction_basis"]["target_scientific_id"].startswith("rcid:v1:feature:u7:"))
        self.assertIn(
            interaction["interaction_basis"]["target_scientific_id"],
            [clause.get("value") for clause in interaction["profile_condition"]["clauses"]],
        )

    def test_semantic_variants_are_conditional_and_scientifically_identified(self) -> None:
        result = self.decision("feature.approximate-cost-model", "facet.core-match")
        variants = [item for item in result["provisional_obligations"] if item["semantic_variant_basis"]]
        self.assertEqual(len(variants), len(self.features["feature.approximate-cost-model"]["semantic_variants"]))
        self.assertTrue(all(item["requirement_state"] == "conditionally-required" for item in variants))
        self.assertTrue(all(item["semantic_variant_basis"]["variant_scientific_id"].startswith("rcid:v1:semantic-variant:u7:") for item in variants))
        self.assertTrue(all("operation_ids" not in item["prospective_identity_basis"] for item in variants))

    def test_unknown_state_and_rule_identity_drift_fail_closed(self) -> None:
        feature = deepcopy(self.features["feature.absent-expression"])
        feature["semantic_assertions"]["capture_result"]["state"] = "plausible"
        with self.assertRaisesRegex(ConformanceDataError, "unknown-semantic-state"):
            derive_feature(self.snapshot, self.contract, feature)

        changed = deepcopy(self.contract)
        changed["facet_rules"][0]["rationale"] += " changed"
        with self.assertRaisesRegex(ConformanceDataError, "obligation-rule-identity"):
            validate_contract(ROOT, changed, self.snapshot)

        stale = deepcopy(self.contract)
        stale["semantic_authority"]["snapshot_id"] = "rcid:v1:semantic-snapshot:h:stale"
        with self.assertRaisesRegex(ConformanceDataError, "stale-obligation-semantic-authority"):
            validate_contract(ROOT, stale, self.snapshot)

        mutable_predicate = deepcopy(self.contract)
        mutable_predicate["operation_rules"][0]["profile_capability_predicate"]["clauses"][0]["value"] = "operation.analyze"
        with self.assertRaisesRegex(ConformanceDataError, "mutable-label-in-obligation-predicate"):
            validate_contract(ROOT, mutable_predicate, self.snapshot)

    def test_duplicate_decision_owner_fails_closed(self) -> None:
        _, decisions = build_dry_run(ROOT, self.contract)
        duplicate = [*decisions, deepcopy(decisions[0])]
        with self.assertRaisesRegex(ConformanceDataError, "obligation-decision-totality|obligation-decision-conflict"):
            _validate_decisions(self.snapshot, duplicate, self.contract)

    def test_hand_enumerated_fixtures_close(self) -> None:
        fixture = load_strict(ROOT / FIXTURE_PATH)
        self.assertEqual(_validate_fixtures(ROOT, self.snapshot, self.contract), len(fixture["cases"]))
        self.assertGreaterEqual(len(fixture["cases"]), 11)

    def test_dry_run_is_deterministic_non_authoritative_and_non_uniform(self) -> None:
        first, first_decisions = build_dry_run(ROOT, self.contract)
        second, second_decisions = build_dry_run(ROOT, self.contract)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(first_decisions, second_decisions)
        self.assertEqual((ROOT / DRY_RUN_PATH).read_bytes(), canonical_bytes(first) + b"\n")
        self.assertFalse(first["classification"]["authoritative_denominator"])
        self.assertEqual(first["summary"]["facet_decisions"], 269 * 15)
        self.assertEqual(first["summary"]["blocked_decisions"], 0)
        self.assertGreater(first["summary"]["distinct_feature_shapes"], 10)
        self.assertLess(first["summary"]["most_common_feature_shape_count"], 269)

    def test_legacy_report_reconstructs_every_predecessor_case(self) -> None:
        self.assertEqual(self.legacy["summary"]["obligations_audited"], 12048)
        self.assertEqual(len(self.legacy["obligation_cases"]), 12048)
        self.assertGreater(self.legacy["summary"]["by_analysis_classification"]["uniform-template-without-feature-specific-trigger"], 0)
        self.assertGreater(self.legacy["summary"]["underrepresented_current_feature_facet_pairs"], 0)

    def test_predecessor_denominator_is_byte_locked(self) -> None:
        baseline = denominator_baseline(ROOT)
        self.assertTrue(baseline["artifacts_unchanged"])
        self.assertEqual(baseline["artifact_sha256"], DENOMINATOR_SHA256)
        for key, relative in {
            "obligation_projection": "ontology/projections/regex-semantic-projection-2026-08-22.v1.json",
            "vector_requirements": "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json",
            "denominator_forecast": "reports/scale/regex-semantic-denominator-forecast.json",
        }.items():
            self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), DENOMINATOR_SHA256[key])

    def test_contract_regenerates_byte_identically(self) -> None:
        built = build_contract(ROOT)
        self.assertEqual((ROOT / CONTRACT_PATH).read_bytes(), canonical_bytes(built) + b"\n")


if __name__ == "__main__":
    unittest.main()
