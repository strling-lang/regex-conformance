from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

from support import ROOT
from regex_conformance_schema.derivation import (
    CATALOG_PATH,
    find_binding,
    require_assertion_gate,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance
from regex_conformance_schema.scientific_identity import verify_catalog as verify_identity_catalog
from regex_conformance_schema.scientific_identity import lineage_record_id, validate_lineage_records
from regex_conformance_schema.errors import ConformanceDataError


SCRIPT = ROOT / "tools/semantics/compile_researched_semantics.py"
SPEC = importlib.util.spec_from_file_location("compile_researched_semantics", SCRIPT)
assert SPEC and SPEC.loader
compiler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compiler)


class ResearchedFeatureSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ledger, cls.snapshot, cls.report = compiler.build_all()
        cls.predecessor = load_strict(ROOT / compiler.PREDECESSOR_PATH)
        cls.catalog = load_strict(ROOT / CATALOG_PATH)
        cls.identity_catalog = load_strict(ROOT / compiler.IDENTITY_PATH)

    def test_exact_feature_by_feature_research_coverage(self) -> None:
        predecessor_ids = {item["feature_id"] for item in self.predecessor["features"]}
        successor_ids = {item["feature_id"] for item in self.snapshot["features"]}
        ledger_ids = {item["feature_id"] for item in self.ledger["feature_research"]}
        self.assertEqual(predecessor_ids, successor_ids)
        self.assertEqual(successor_ids, ledger_ids)
        self.assertEqual(len(successor_ids), 251)
        self.assertEqual(self.report["completion"]["features_researched"], 251)
        self.assertEqual(self.report["completion"]["fields_audited"], 2510)
        self.assertEqual(self.report["completion"]["legacy_dimensions_audited"], 4769)
        self.assertTrue(
            all(len(item["legacy_field_audit"]) == 19 for item in self.ledger["feature_research"])
        )

    def test_every_substantive_assertion_is_source_and_derivation_bound(self) -> None:
        known_sources = {item["source_id"] for item in self.snapshot["sources"]}
        for feature in self.snapshot["features"]:
            with self.subTest(feature=feature["feature_id"]):
                self.assertEqual(set(feature["semantic_assertions"]), set(compiler.SEMANTIC_FIELDS))
                for assertion in feature["semantic_assertions"].values():
                    self.assertTrue(assertion["source_ids"])
                    self.assertLessEqual(set(assertion["source_ids"]), known_sources)
                    self.assertEqual(assertion["derivation_id"], compiler.RESEARCH_DERIVATION_ID)
                    self.assertEqual(assertion["derivation_class"], "research-derived")
        require_assertion_gate(
            self.catalog,
            compiler.SNAPSHOT_PATH.as_posix(),
            "/features/0/semantic_assertions/definition/statement",
            "independent-evidence",
        )

    def test_structured_semantic_states_remain_distinct(self) -> None:
        observed = {
            assertion["state"]
            for feature in self.snapshot["features"]
            for assertion in feature["semantic_assertions"].values()
        }
        self.assertTrue(
            {"known", "not-applicable", "no-feature-specific-implication", "implementation-defined"}.issubset(observed)
        )
        schema = load_strict(ROOT / compiler.SNAPSHOT_SCHEMA_PATH)
        for state in ("intentionally-under-specified", "unresolved"):
            fixture = deepcopy(self.snapshot)
            fixture["features"][0]["semantic_assertions"]["capture_result"]["state"] = state
            validate_instance(fixture, schema, source=f"state-{state}")

    def test_accepted_scientific_ids_are_reused_exactly(self) -> None:
        actual = {item["feature_id"]: item["scientific_id"] for item in self.snapshot["features"]}
        expected = {
            item["canonical_key"]: item["scientific_id"]
            for item in self.identity_catalog["bindings"]
            if item["entity_class"] == "feature" and item["canonical_key"] in actual
        }
        self.assertEqual(expected, actual)
        self.assertEqual(self.snapshot["counts"]["retained_feature_identities"], 251)
        self.assertEqual(self.snapshot["counts"]["successor_feature_identities"], 0)
        self.assertGreaterEqual(verify_identity_catalog(ROOT)["scientific_identities"], 22359)

    def test_variants_and_manifestations_cannot_redefine_canonical_semantics(self) -> None:
        variants = [
            variant
            for feature in self.snapshot["features"]
            for variant in feature["semantic_variants"]
        ]
        self.assertEqual(len(variants), 88)
        self.assertTrue(all(item["semantic_assertion"]["scope"] == "variant-specific" for item in variants))
        self.assertTrue(all("A documented semantic variant" not in item["semantic_assertion"]["statement"] for item in variants))
        feature_ids = {item["scientific_id"] for item in self.snapshot["features"]}
        self.assertEqual(len(self.snapshot["manifestations"]), 304)
        for manifestation in self.snapshot["manifestations"]:
            self.assertEqual(manifestation["semantic_scope"], "manifestation-specific")
            self.assertIn(manifestation["canonical_semantics_owner"], feature_ids)

    def test_legacy_templates_cannot_repopulate_successor_fields(self) -> None:
        legacy_values = {
            feature[field]
            for feature in self.predecessor["features"]
            for field in compiler.LEGACY_TEMPLATE_FIELDS
        }
        statements = {
            assertion["statement"]
            for feature in self.snapshot["features"]
            for assertion in feature["semantic_assertions"].values()
        }
        self.assertTrue(legacy_values.isdisjoint(statements))
        self.assertEqual(self.report["completion"]["template_derived_assertions_remaining"], 0)

    def test_artifact_identity_changes_with_semantic_content(self) -> None:
        changed = deepcopy(self.snapshot)
        changed["features"][0]["semantic_assertions"]["definition"]["statement"] += " Material change."
        body = {
            key: value
            for key, value in changed.items()
            if key not in {"snapshot_id", "snapshot_digest_sha256"}
        }
        successor = compiler._finalize(
            body,
            namespace="ontology-snapshot",
            schema_family_id=compiler.SCHEMA_FAMILIES["snapshot"],
            id_field="snapshot_id",
            digest_field="snapshot_digest_sha256",
        )
        self.assertNotEqual(successor["snapshot_id"], self.snapshot["snapshot_id"])
        self.assertEqual(successor["features"][0]["scientific_id"], self.snapshot["features"][0]["scientific_id"])

    def test_material_semantic_replacement_requires_successor_lineage(self) -> None:
        feature_ids = [
            item["scientific_id"]
            for item in self.identity_catalog["bindings"]
            if item["entity_class"] == "feature"
        ][:2]
        valid = {
            "change_kind": "supersedes",
            "current_fingerprints": [],
            "current_keys": ["feature.successor"],
            "effective_date": "2026-09-07",
            "identity_effect": "new-identity",
            "prior_fingerprints": [],
            "prior_keys": ["feature.predecessor"],
            "rationale": "Synthetic material semantic correction requires a successor.",
            "source_ids": [feature_ids[0]],
            "target_ids": [feature_ids[1]],
        }
        valid["lineage_record_id"] = lineage_record_id(ROOT, valid)
        validate_lineage_records(ROOT, [valid], set(feature_ids))
        invalid = deepcopy(valid)
        invalid["identity_effect"] = "retained"
        invalid["lineage_record_id"] = lineage_record_id(ROOT, invalid)
        with self.assertRaisesRegex(ConformanceDataError, "invalid-supersession-lineage"):
            validate_lineage_records(ROOT, [invalid], set(feature_ids))

    def test_deterministic_build_matches_tracked_bytes(self) -> None:
        second = compiler.build_all()
        for first_artifact, second_artifact, path in zip(
            (self.ledger, self.snapshot, self.report),
            second,
            (compiler.LEDGER_PATH, compiler.SNAPSHOT_PATH, compiler.REPORT_PATH),
            strict=True,
        ):
            self.assertEqual(canonical_bytes(first_artifact), canonical_bytes(second_artifact))
            self.assertEqual((ROOT / path).read_bytes(), canonical_bytes(first_artifact) + b"\n")

    def test_pre_redesign_projection_requirements_and_denominator_are_still_bound(self) -> None:
        compatibility = self.report["legacy_artifact_compatibility"]
        self.assertTrue(compatibility["artifacts_unchanged"])
        self.assertEqual(compatibility["obligation_templates"], 12048)
        self.assertEqual(compatibility["vector_requirements"], 9506)
        self.assertEqual(
            find_binding(
                self.catalog,
                compiler.REPORT_PATH.as_posix(),
                "/legacy_artifact_compatibility/artifact_sha256/semantic_snapshot",
            )["evidence_role"],
            "independent-measurement",
        )


if __name__ == "__main__":
    unittest.main()
