from __future__ import annotations

import hashlib
import unittest

from support import ROOT
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.obligation_derivation import DENOMINATOR_SHA256, DRY_RUN_PATH
from regex_conformance_schema.obligation_snapshots import (
    AUTHORITY_PATH,
    MIGRATION_PATH,
    OBLIGATION_PATH,
    PROJECTION_PATH,
    REPORT_PATH,
    REQUIREMENT_PATH,
    build_core,
    explain,
)
from regex_conformance_schema.scientific_identity import verify_catalog


class ObligationSnapshotMaterializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.obligations = load_strict(ROOT / OBLIGATION_PATH)
        cls.requirements = load_strict(ROOT / REQUIREMENT_PATH)
        cls.migration = load_strict(ROOT / MIGRATION_PATH)
        cls.projection = load_strict(ROOT / PROJECTION_PATH)
        cls.report = load_strict(ROOT / REPORT_PATH)
        cls.authority = load_strict(ROOT / AUTHORITY_PATH)

    def test_canonical_populations_and_question_types_close(self) -> None:
        self.assertEqual(self.obligations["counts"]["total"], 2390)
        self.assertEqual(self.obligations["counts"]["required"], 1058)
        self.assertEqual(self.obligations["counts"]["conditional"], 1332)
        self.assertEqual(self.obligations["counts"]["characterization"], 79)
        self.assertEqual(self.requirements["counts"]["total"], 3378)
        self.assertEqual(self.requirements["counts"]["required"], 1406)
        self.assertEqual(self.requirements["counts"]["conditional"], 1972)
        self.assertEqual(self.requirements["counts"]["characterization"], 79)
        self.assertEqual(self.requirements["counts"]["missing_vector_definitions"], 3378)
        self.assertTrue(all(not item["existing_vector_ids"] for item in self.requirements["requirements"]))

    def test_conditionality_and_cardinality_remain_explicit(self) -> None:
        conditional = [item for item in self.obligations["obligations"] if item["requirement_state"] == "conditionally-required"]
        self.assertEqual(len(conditional), 1332)
        self.assertTrue(all(item["profile_condition"]["clauses"] for item in conditional))
        cardinalities = {item["requirement_cardinality"]["minimum_requirements"] for item in self.obligations["obligations"]}
        self.assertGreater(len(cardinalities), 1)
        requirement_refs = {
            item["scientific_id"]: sum(item["scientific_id"] in requirement["obligation_scientific_ids"] for requirement in self.requirements["requirements"])
            for item in self.obligations["obligations"]
        }
        self.assertTrue(all(requirement_refs[item["scientific_id"]] == item["requirement_cardinality"]["minimum_requirements"] for item in self.obligations["obligations"]))

    def test_migration_is_total_and_non_one_to_one(self) -> None:
        self.assertEqual(len(self.migration["obligation_migrations"]), 12048)
        self.assertEqual(len(self.migration["requirement_migrations"]), 9506)
        obligation_dispositions = self.migration["counts"]["obligation_by_disposition"]
        requirement_dispositions = self.migration["counts"]["requirement_by_disposition"]
        for disposition in (
            "retained-scientific-identity",
            "semantically-equivalent-successor",
            "split-into-successors",
            "merged-into-successor",
            "retired-no-researched-trigger",
            "historical-only-unmapped",
        ):
            self.assertGreater(obligation_dispositions[disposition], 0)
            self.assertGreater(requirement_dispositions[disposition], 0)
        self.assertEqual(sum(obligation_dispositions.values()), 12048)
        self.assertEqual(sum(requirement_dispositions.values()), 9506)

    def test_every_object_has_a_complete_explanation_chain(self) -> None:
        obligation = self.obligations["obligations"][0]
        obligation_trace = explain(ROOT, obligation["scientific_id"])
        self.assertEqual(obligation_trace["obligation"]["scientific_id"], obligation["scientific_id"])
        self.assertGreaterEqual(len(obligation_trace["obligation"]["explanation"]["chain"]), 6)
        requirement = self.requirements["requirements"][0]
        requirement_trace = explain(ROOT, requirement["scientific_id"])
        self.assertEqual(requirement_trace["requirement"]["scientific_id"], requirement["scientific_id"])
        self.assertEqual(requirement_trace["obligation"]["scientific_id"], requirement["obligation_scientific_ids"][0])

    def test_dry_run_matches_obligations_and_authority_advances_only_successors(self) -> None:
        dry_run = load_strict(ROOT / DRY_RUN_PATH)
        self.assertEqual(dry_run["summary"]["provisional_obligations"], self.obligations["counts"]["total"])
        self.assertEqual(self.report["dry_run_comparison"]["obligation_delta"], 0)
        current = self.authority["current"]
        self.assertEqual(current["obligation_snapshot"]["artifact_id"], self.obligations["snapshot_id"])
        self.assertEqual(current["requirement_snapshot"]["artifact_id"], self.requirements["snapshot_id"])
        self.assertEqual(self.authority["profile_expanded_denominator"]["status"], "deferred")
        self.assertFalse(self.authority["governance"]["production_vectors_generated"])

    def test_identity_lock_contains_active_successors_and_reserved_history(self) -> None:
        self.assertEqual(verify_catalog(ROOT), {"scientific_identities": 28016, "scientific_lineage_records": 3162})
        self.assertEqual(self.report["derivations"]["identity_count"], 28016)
        self.assertEqual(self.report["derivations"]["lineage_record_count"], 3162)

    def test_historical_denominator_bytes_remain_immutable(self) -> None:
        paths = {
            "obligation_projection": "ontology/projections/regex-semantic-projection-2026-08-22.v1.json",
            "vector_requirements": "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json",
            "denominator_forecast": "reports/scale/regex-semantic-denominator-forecast.json",
        }
        for key, relative in paths.items():
            with self.subTest(relative=relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), DENOMINATOR_SHA256[key])

    def test_successor_snapshots_regenerate_deterministically(self) -> None:
        built = build_core(ROOT)
        for relative, value in zip((OBLIGATION_PATH, REQUIREMENT_PATH, MIGRATION_PATH, PROJECTION_PATH), built, strict=True):
            self.assertEqual((ROOT / relative).read_bytes(), canonical_bytes(value) + b"\n")


if __name__ == "__main__":
    unittest.main()
