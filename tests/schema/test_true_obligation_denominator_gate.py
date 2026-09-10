from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.denominator_audit import independent_recompute, validate_profile_condition  # noqa: E402
from regex_conformance_schema.denominator_foundation import (  # noqa: E402
    ACCOUNTING_CONTRACT_PATH,
    HANDOFF_PATH,
    MANIFEST_PATH,
    REPORT_PATH,
    SNAPSHOT_PATH,
    DRY_RUN_PATH,
    OBLIGATION_PATH,
    REQUIREMENT_PATH,
    _condition_fixtures,
    _explainability_audit,
    _over_count_audit,
    _require_exact,
    _suppression_audit,
    _under_count_audit,
    _validate_c4_and_profile,
    _validate_migration_closure,
    validate_acceptance_report,
    validate_manifest,
    verify_history,
)
from regex_conformance_schema.errors import ConformanceDataError  # noqa: E402
from regex_conformance_schema.jsonio import load_strict  # noqa: E402


class TrueObligationDenominatorGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.semantic = load_strict(ROOT / SNAPSHOT_PATH)
        cls.obligations = load_strict(ROOT / OBLIGATION_PATH)["obligations"]
        cls.requirements = load_strict(ROOT / REQUIREMENT_PATH)["requirements"]
        cls.dry_run = load_strict(ROOT / DRY_RUN_PATH)
        cls.accounting = load_strict(ROOT / ACCOUNTING_CONTRACT_PATH)
        cls.handoff = load_strict(ROOT / HANDOFF_PATH)
        cls.fresh = independent_recompute(ROOT, cls.accounting, cls.handoff)
        cls.manifest = load_strict(ROOT / MANIFEST_PATH)
        cls.report = load_strict(ROOT / REPORT_PATH)

    def test_committed_gate_remains_valid_historical_evidence(self) -> None:
        self.assertEqual(verify_history(ROOT)["result"], "PASS")

    def test_over_count_injection_fails(self) -> None:
        injected = [*self.obligations, deepcopy(self.obligations[0])]
        with self.assertRaisesRegex(ConformanceDataError, "duplicate-scientific-question"):
            _over_count_audit(self.semantic, injected, self.requirements, self.fresh)

    def test_under_count_injection_fails(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "under-counted-obligation"):
            _under_count_audit(self.semantic, self.obligations[:-1], self.requirements, self.dry_run, self.fresh)

    def test_orphan_obligation_fails(self) -> None:
        orphan = self.obligations[0]["scientific_id"]
        filtered = [item for item in self.requirements if orphan not in item["obligation_scientific_ids"]]
        with self.assertRaisesRegex(ConformanceDataError, "orphan-obligation"):
            _under_count_audit(self.semantic, self.obligations, filtered, self.dry_run, self.fresh)

    def test_orphan_requirement_fails(self) -> None:
        injected = deepcopy(self.requirements)
        injected[0]["obligation_scientific_ids"] = ["rcid:v1:obligation:u7:019fffff-ffff-7fff-bfff-ffffffffffff"]
        with self.assertRaisesRegex(ConformanceDataError, "orphan-requirement"):
            _explainability_audit(self.semantic, self.obligations, injected, self.fresh)

    def test_unjustified_cardinality_role_fails(self) -> None:
        injected = deepcopy(self.requirements)
        injected[0]["evidence_role"] = "characterization"
        with self.assertRaisesRegex(ConformanceDataError, "requirement-explainability"):
            _explainability_audit(self.semantic, self.obligations, injected, self.fresh)

    def test_malformed_and_unknown_predicates_fail(self) -> None:
        known = {item["scientific_id"] for item in load_strict(ROOT / "registries/identity/scientific-identities.v1.json")["bindings"]}
        malformed = {"operator": "all", "clauses": []}
        unknown = {"operator": "all", "clauses": [{"field": "profile.unknown", "operator": "contains", "value": "missing"}]}
        self.assertFalse(validate_profile_condition(malformed, known)["valid"])
        self.assertFalse(validate_profile_condition(unknown, known)["valid"])

    def test_suppression_leak_fails(self) -> None:
        suppressed = next(item for item in self.dry_run["decisions"] if item["decision"] == "not-applicable")
        injected = [*self.obligations, {"feature_scientific_id": suppressed["feature_scientific_id"], "facet_id": suppressed["facet_id"]}]
        with self.assertRaisesRegex(ConformanceDataError, "suppression-leak"):
            _suppression_audit(self.dry_run, injected)

    def test_multiplier_leak_fails(self) -> None:
        injected = deepcopy(self.fresh)
        injected["multiplier_audit"]["authoritative_unexplained_multiplier_count"] = 1
        with self.assertRaisesRegex(ConformanceDataError, "hidden-uniform-multiplier"):
            _over_count_audit(self.semantic, self.obligations, self.requirements, injected)

    def test_migration_mismatch_fails(self) -> None:
        injected = deepcopy(self.fresh)
        injected["migration_audit"]["obligation"]["predecessor_count"] -= 1
        with self.assertRaisesRegex(ConformanceDataError, "migration-disagreement"):
            _validate_migration_closure(injected)

    def test_stale_c4_denominator_fails(self) -> None:
        certification = load_strict(ROOT / "certification/reports/current-repository-2026-09-08.v2.json")
        injected = deepcopy(certification)
        next(item for item in injected["criteria"] if item["criterion_id"] == "C4")["denominator_count"] = 9506
        with self.assertRaisesRegex(ConformanceDataError, "stale-c4-denominator"):
            _validate_c4_and_profile(injected, self.handoff)

    def test_profile_count_before_freeze_fails(self) -> None:
        certification = load_strict(ROOT / "certification/reports/current-repository-2026-09-08.v2.json")
        injected = deepcopy(self.handoff)
        injected["counts"]["exact_profiles"] = 1
        with self.assertRaisesRegex(ConformanceDataError, "premature-profile-count"):
            _validate_c4_and_profile(certification, injected)

    def test_independent_recomputation_disagreement_fails(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "true-denominator-count"):
            _require_exact("requirements", 3377, 3378)

    def test_conditional_predicate_has_three_valued_boundary(self) -> None:
        conditional = min((item for item in self.requirements if item["requirement_state"] == "conditionally-required"), key=lambda item: item["scientific_id"])
        fixtures = _condition_fixtures(conditional)
        self.assertEqual([item["observed"] for item in fixtures], ["applicable", "not-applicable", "unresolved"])

    def test_explainability_closes_for_every_object(self) -> None:
        result = _explainability_audit(self.semantic, self.obligations, self.requirements, self.fresh)
        self.assertEqual(result["obligations_with_complete_chain"], 2390)
        self.assertEqual(result["requirements_with_complete_chain"], 3378)


if __name__ == "__main__":
    unittest.main()
