from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from support import ROOT
from regex_conformance_schema.denominator_audit import (
    AUDIT_AUTHORITY_PATH,
    CONTRACT_PATH,
    HANDOFF_PATH,
    LEGACY_FORECAST_PATH,
    LEGACY_PROJECTION_PATH,
    LEGACY_REQUIREMENTS_PATH,
    REPORT_PATH,
    _compare_counts,
    build_audit_authority,
    build_contract,
    build_handoff,
    build_report,
    reconcile_obligation_bases,
    validate_profile_condition,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.obligation_derivation import DENOMINATOR_SHA256, DRY_RUN_PATH
from regex_conformance_schema.obligation_snapshots import OBLIGATION_PATH, REQUIREMENT_PATH


class DenominatorAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_strict(ROOT / CONTRACT_PATH)
        cls.handoff = load_strict(ROOT / HANDOFF_PATH)
        cls.report = load_strict(ROOT / REPORT_PATH)
        cls.authority = load_strict(ROOT / AUDIT_AUTHORITY_PATH)
        cls.recomputed = cls.report["independent_recomputation"]
        cls.obligations = load_strict(ROOT / OBLIGATION_PATH)["obligations"]
        cls.requirements = load_strict(ROOT / REQUIREMENT_PATH)["requirements"]

    def test_exact_populations_are_recomputed_and_accounted(self) -> None:
        self.assertEqual(len(self.obligations), self.recomputed["obligations"]["total"])
        self.assertEqual(len(self.requirements), self.recomputed["requirements"]["total"])
        self.assertEqual(self.recomputed["obligations"]["total"], 2390)
        self.assertEqual(self.recomputed["requirements"]["total"], 3378)
        self.assertEqual(
            sum(self.recomputed["base_partitions"]["semantic_applicability"]["counts"].values()),
            len(self.requirements),
        )
        for axis in ("scientific_purpose", "execution_disposition", "evidence_role"):
            self.assertEqual(self.recomputed["base_partitions"][axis]["cross_sum"], len(self.requirements))

    def test_scenario_accounting_is_explicit_and_profile_safe(self) -> None:
        scenarios = self.recomputed["scenario_accounting"]["requirements"]
        required = sum(item["requirement_state"] == "required" for item in self.requirements)
        conditional = sum(item["requirement_state"] == "conditionally-required" for item in self.requirements)
        self.assertEqual(scenarios["lower"], required)
        self.assertIsNone(scenarios["expected"]["numeric_total"])
        self.assertEqual((scenarios["expected"]["lower_bound"], scenarios["expected"]["upper_bound"]), (required, required + conditional))
        self.assertEqual(scenarios["conservative"], required + conditional)
        self.assertIsNone(self.handoff["counts"]["exact_profiles"])
        self.assertIsNone(self.handoff["counts"]["final_logical_execution_denominator"])
        self.assertFalse(self.handoff["deferral"]["historical_multiplier_substituted"])

    def test_execution_and_scientific_purpose_are_orthogonal(self) -> None:
        disposition = self.recomputed["base_partitions"]["execution_disposition"]["counts"]
        purpose = self.recomputed["base_partitions"]["scientific_purpose"]["counts"]
        self.assertEqual(sum(disposition.values()), len(self.requirements))
        self.assertEqual(sum(purpose.values()), len(self.requirements))
        self.assertEqual(disposition["prohibited"], 0)
        self.assertEqual(disposition["unresolved"], 0)
        self.assertEqual(purpose["characterization-only"], sum(item["requirement_type"] == "characterization-only" for item in self.requirements))
        terms = {item["term"]: item["definition"] for item in self.contract["population_definitions"]}
        self.assertNotEqual(terms["prohibited"], terms["unresolved"])
        self.assertIn("not synonymous with not-applicable", terms["prohibited"].lower())

    def test_conditional_predicates_are_closed_and_non_tautological(self) -> None:
        audit = self.recomputed["predicate_audit"]
        conditional = [item for item in self.requirements if item["requirement_state"] == "conditionally-required"]
        self.assertEqual(audit["conditional_requirements"], len(conditional))
        self.assertEqual(audit["tautologies"], 0)
        self.assertEqual(audit["contradictions"], 0)
        self.assertEqual(audit["invalid_or_unresolved_references"], 0)
        known = {clause.get("value") for clause in conditional[0]["profile_condition"]["clauses"] if clause.get("value")}
        empty = validate_profile_condition({"operator": "all", "clauses": []}, known)
        self.assertTrue(empty["tautology"])
        clause = next(item for item in conditional[0]["profile_condition"]["clauses"] if "value" in item)
        opposite = {**clause, "operator": "not-contains" if clause["operator"] == "contains" else "disjoint"}
        contradictory = validate_profile_condition({"operator": "all", "clauses": [clause, opposite]}, known)
        self.assertTrue(contradictory["contradiction"])

    def test_cardinality_expansion_is_archetype_derived(self) -> None:
        audit = self.recomputed["cardinality_audit"]
        expansion = sum(item["requirement_cardinality"]["minimum_requirements"] - 1 for item in self.obligations)
        self.assertEqual(audit["additional_independently_attributable_roles"], expansion)
        self.assertEqual(audit["requirements"], audit["minimum_one_per_obligation"] + expansion)
        self.assertEqual(audit["unjustified_expansions"], 0)

    def test_adversarial_samples_cover_inclusions_and_suppressions(self) -> None:
        samples = self.recomputed["sample_audit"]
        included_axes = {item["sample_axis"] for item in samples["included_reconstructions"]}
        excluded_axes = {item["sample_axis"] for item in samples["excluded_reconstructions"]}
        self.assertTrue({"facet", "operation", "semantic-applicability", "evidence-role", "feature-requirement-band", "semantic-successor-feature", "interaction-derived"}.issubset(included_axes))
        self.assertIn("suppressed-facet", excluded_axes)
        self.assertTrue(all(item["result"] == "PASS" for item in samples["included_reconstructions"] + samples["excluded_reconstructions"]))

    def test_independent_disagreement_is_fail_closed(self) -> None:
        declared = {"total": len(self.requirements) + 1}
        with self.assertRaises(ConformanceDataError):
            _compare_counts(declared, {"total": len(self.requirements)}, ["total"], "fixture")

    def test_over_and_under_count_fixtures_fail_closed(self) -> None:
        dry_run = load_strict(ROOT / DRY_RUN_PATH)
        with self.assertRaisesRegex(ConformanceDataError, "under-counted-obligation"):
            reconcile_obligation_bases(self.obligations[:-1], dry_run)
        extra = deepcopy(self.obligations[0])
        extra["scientific_id"] = extra["scientific_id"][:-1] + ("0" if extra["scientific_id"][-1] != "0" else "1")
        extra["obligation_key"] = "fixture.over-count"
        extra["identity_basis"] = {"fixture": "unjustified-extra-question"}
        with self.assertRaisesRegex(ConformanceDataError, "over-counted-obligation"):
            reconcile_obligation_bases([*self.obligations, extra], dry_run)

    def test_migration_and_multiplier_audits_close(self) -> None:
        migration = self.recomputed["migration_audit"]
        self.assertEqual(migration["obligation"]["predecessor_count"], 12048)
        self.assertEqual(migration["requirement"]["predecessor_count"], 9506)
        self.assertEqual(migration["obligation"]["current_origin_count"], len(self.obligations))
        self.assertEqual(migration["requirement"]["current_origin_count"], len(self.requirements))
        multiplier = self.recomputed["multiplier_audit"]
        self.assertEqual(multiplier["authoritative_unexplained_multiplier_count"], 0)
        self.assertFalse(multiplier["uniform_feature_shape"])
        self.assertFalse(any(item["feeds_current_authority"] for item in multiplier["mechanisms"] if item["classification"] == "historical-planning-only"))

    def test_report_regenerates_deterministically(self) -> None:
        contract = build_contract(ROOT)
        handoff = build_handoff(ROOT, contract)
        report = build_report(ROOT, contract, handoff)
        authority = build_audit_authority(ROOT, contract, handoff, report)
        for path, value in ((CONTRACT_PATH, contract), (HANDOFF_PATH, handoff), (REPORT_PATH, report), (AUDIT_AUTHORITY_PATH, authority)):
            self.assertEqual((ROOT / path).read_bytes(), canonical_bytes(value) + b"\n")

    def test_historical_denominator_bytes_are_unchanged(self) -> None:
        expected = {
            LEGACY_PROJECTION_PATH: DENOMINATOR_SHA256["obligation_projection"],
            LEGACY_REQUIREMENTS_PATH: DENOMINATOR_SHA256["vector_requirements"],
            LEGACY_FORECAST_PATH: DENOMINATOR_SHA256["denominator_forecast"],
        }
        for path, digest in expected.items():
            with self.subTest(path=path.as_posix()):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
