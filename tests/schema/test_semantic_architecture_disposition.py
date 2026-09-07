from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import unittest

from support import ROOT
from regex_conformance_schema.derivation import (
    CATALOG_PATH as DERIVATION_CATALOG_PATH,
    require_assertion_gate,
    verify_catalog as verify_derivation_catalog,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.foundation import verify_foundation_history
from regex_conformance_schema.scientific_identity import verify_catalog as verify_identity_catalog


SCRIPT = ROOT / "tools/semantics/compile_semantic_architecture.py"
SPEC = importlib.util.spec_from_file_location("compile_semantic_architecture", SCRIPT)
assert SPEC and SPEC.loader
compiler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compiler)


class SemanticArchitectureDispositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.allocation = load_strict(ROOT / compiler.ALLOCATION_PATH)
        cls.ledger, cls.snapshot, cls.report = compiler.build_all(cls.allocation)
        cls.predecessor = load_strict(ROOT / compiler.PREDECESSOR_PATH)
        cls.derivations = load_strict(ROOT / DERIVATION_CATALOG_PATH)

    def test_every_candidate_has_one_terminal_disposition(self) -> None:
        candidates = self.ledger["candidates"]
        self.assertEqual(len(candidates), 73)
        self.assertEqual(len({item["candidate_id"] for item in candidates}), 73)
        self.assertEqual(len({item["candidate_key"] for item in candidates}), 73)
        self.assertEqual(self.ledger["counts"]["blocking_unresolved"], 0)
        self.assertTrue(all(item["rationale"] and item["downstream_consequence"] for item in candidates))

    def test_accepted_entities_are_typed_source_and_derivation_bound(self) -> None:
        source_ids = {item["source_id"] for item in self.snapshot["sources"]}
        allocated_ids = {item["assigned_id"] for item in self.allocation["allocations"]}
        catalog_ids = {
            binding["scientific_id"]
            for binding in load_strict(ROOT / compiler.IDENTITY_PATH)["bindings"]
        }
        for collection in (
            self.snapshot["semantic_facets"],
            self.snapshot["operations"],
            [item for item in self.snapshot["features"] if item["identity_disposition"]["kind"] == "new"],
        ):
            for entity in collection:
                with self.subTest(entity=entity.get("feature_id", entity.get("operation_id", entity.get("facet_id")))):
                    self.assertIn(entity["scientific_id"], allocated_ids | catalog_ids)
                    self.assertEqual(entity["derivation_id"], compiler.DERIVATION_ID)
                    self.assertLessEqual(set(entity["source_ids"] if "source_ids" in entity else []), source_ids)

    def test_facets_have_closed_nonconflating_domains(self) -> None:
        facets = {item["facet_id"]: item for item in self.snapshot["semantic_facets"]}
        self.assertEqual(len(facets), 15)
        self.assertIn("compile", facets["facet.phase"]["domain"])
        self.assertIn("worst-case-time", facets["facet.complexity-guarantee"]["domain"])
        self.assertIn("untrusted-pattern", facets["facet.security-context"]["domain"])
        self.assertNotIn("timeout-observed", facets["facet.complexity-guarantee"]["domain"])

    def test_operations_are_canonical_not_vendor_method_names(self) -> None:
        operation_ids = {item["operation_id"] for item in self.snapshot["operations"]}
        self.assertEqual(len(operation_ids), 33)
        self.assertTrue({
            "operation.escape-pattern", "operation.escape-replacement",
            "operation.serialize-pattern", "operation.deserialize-pattern",
            "operation.inspect-pattern", "operation.stream-open",
            "operation.stream-close", "operation.stream-reset",
            "operation.stream-copy", "operation.stream-compress",
            "operation.stream-expand",
        }.issubset(operation_ids))
        self.assertFalse(any("pcre2_" in key or "hs_" in key for key in operation_ids))

    def test_confusion_boundaries_remain_distinct(self) -> None:
        features = {item["feature_id"]: item for item in self.snapshot["features"]}
        self.assertIn("feature.expression-intersection", features)
        self.assertIn("character-class", " ".join(
            assertion["statement"]
            for assertion in features["feature.expression-intersection"]["semantic_assertions"].values()
        ))
        complexity = next(item for item in self.snapshot["semantic_facets"] if item["facet_id"] == "facet.complexity-guarantee")
        self.assertIn("never an observed timeout", complexity["applicability"])
        complement = features["feature.expression-complement"]["semantic_assertions"]["unicode_encoding"]["statement"]
        self.assertIn("alphabet", complement)

    def test_existing_feature_identities_are_stable_and_additions_are_locked(self) -> None:
        before = {item["feature_id"]: item["scientific_id"] for item in self.predecessor["features"]}
        after = {item["feature_id"]: item["scientific_id"] for item in self.snapshot["features"]}
        self.assertEqual(before, {key: after[key] for key in before})
        self.assertEqual(len(after) - len(before), 17)
        self.assertEqual(
            verify_identity_catalog(ROOT),
            {"scientific_identities": 22427, "scientific_lineage_records": 0},
        )

    def test_predecessor_denominator_artifacts_are_byte_identical(self) -> None:
        expected = {
            "ontology/projections/regex-semantic-projection-2026-08-22.v1.json":
                "b25fbeaf80fc8e77f92fb5b36a094896bf30e86d4550ad62982f80a028b605b2",
            "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json":
                "a03feacf51bf3af241a7ab4fe0ea74bd29981670de93ec3d880a27516232cca7",
            "reports/scale/regex-semantic-denominator-forecast.json":
                "dab61b42376d757eadada26c31d8fb5c173a508bb6ce780e98a220449ce6e871",
        }
        for path, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)
        self.assertEqual(self.report["denominator_boundary"]["obligation_templates"], 12048)
        self.assertEqual(self.report["denominator_boundary"]["vector_requirements"], 9506)

    def test_derivation_is_independent_and_inventory_bound(self) -> None:
        counts = verify_derivation_catalog(ROOT)
        self.assertGreaterEqual(counts["generated_assertion_artifacts"], 48)
        require_assertion_gate(
            self.derivations,
            compiler.SNAPSHOT_PATH.as_posix(),
            "/features/251/semantic_assertions/definition/statement",
            "semantic-completeness",
        )
        require_assertion_gate(
            self.derivations,
            compiler.LEDGER_PATH.as_posix(),
            "/candidates/0/rationale",
            "independent-evidence",
        )

    def test_accepted_scientific_foundation_remains_historically_valid(self) -> None:
        self.assertEqual(verify_foundation_history(ROOT)["foundation_acceptance"], "PASS")

    def test_regeneration_is_deterministic_and_matches_tracked_bytes(self) -> None:
        second = compiler.build_all(self.allocation)
        for first, again, path in zip(
            (self.ledger, self.snapshot, self.report),
            second,
            (compiler.LEDGER_PATH, compiler.SNAPSHOT_PATH, compiler.REPORT_PATH),
            strict=True,
        ):
            self.assertEqual(canonical_bytes(first), canonical_bytes(again))
            self.assertEqual((ROOT / path).read_bytes(), canonical_bytes(first) + b"\n")


if __name__ == "__main__":
    unittest.main()
