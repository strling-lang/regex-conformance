from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from support import ROOT
from regex_conformance_schema.derivation import (
    CATALOG_PATH,
    CountSpec,
    build_catalog,
    find_binding,
    require_assertion_gate,
    validate_catalog_integrity,
    validate_count_contract,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance
from regex_conformance_schema.scientific_identity import verify_catalog as verify_identity_catalog


SEMANTIC_SNAPSHOT = "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json"
SEMANTIC_PROJECTION = "ontology/projections/regex-semantic-projection-2026-08-22.v1.json"


class GeneratedAssertionDerivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_strict(ROOT / CATALOG_PATH)
        cls.derivations = {
            record["derivation_id"]: record for record in cls.catalog["derivations"]
        }
        cls.schema = load_strict(
            ROOT / "schemas/json/generated-assertion-derivation-catalog.schema.json"
        )

    def _class_for(self, artifact: str, assertion: str) -> str:
        binding = find_binding(self.catalog, artifact, assertion)
        return self.derivations[binding["derivation_id"]]["derivation_class"]

    def test_representative_assertions_have_their_true_classes(self) -> None:
        self.assertEqual(
            self._class_for(SEMANTIC_SNAPSHOT, "/discovery_scans/0/result"),
            "constant-by-construction",
        )
        self.assertEqual(
            self._class_for(SEMANTIC_SNAPSHOT, "/counts/features"), "calculation"
        )
        self.assertEqual(
            self._class_for(
                "reports/scale/100k-execution.json", "/record_count"
            ),
            "measurement",
        )
        self.assertEqual(
            self._class_for(
                "registries/universe/full-known-universe-2026-08-15.v1.json",
                "/discovery_coverage/0/status",
            ),
            "research-derived",
        )
        self.assertEqual(
            self._class_for(
                "registries/universe/full-known-universe-2026-08-15.v1.json",
                "/forecast_policy/hard_limit_bytes",
            ),
            "manual-decision",
        )
        self.assertEqual(
            self._class_for(
                "adapters/manifests/pcre2-ordinary.v1.json",
                "/certification/status",
            ),
            "manual-decision",
        )

    def test_inventory_summary_is_itself_bound_to_calculation(self) -> None:
        summary = self.catalog["coverage_summary"]
        derivation = self.derivations[summary["derivation_id"]]
        self.assertEqual(derivation["derivation_class"], "calculation")
        self.assertEqual(summary["derivation_revision_id"], derivation["derivation_revision_id"])
        self.assertEqual(summary["inventoried_artifacts"], 41)
        self.assertEqual(summary["assertion_groups"], 178)
        self.assertEqual(summary["assertion_occurrences"], 512768)
        self.assertEqual(summary["count_contracts"], 53)

    def test_each_class_has_required_nonempty_metadata(self) -> None:
        records = {record["derivation_class"]: record for record in self.catalog["derivations"]}
        self.assertEqual(
            set(records),
            {
                "measurement",
                "calculation",
                "research-derived",
                "external-evidence",
                "inference",
                "constant-by-construction",
                "manual-decision",
            },
        )
        self.assertTrue(records["measurement"]["metadata"]["measured_inputs"])
        self.assertTrue(records["measurement"]["metadata"]["procedure_ref"])
        self.assertTrue(records["calculation"]["metadata"]["input_references"])
        self.assertTrue(records["calculation"]["metadata"]["formula"])
        self.assertTrue(records["research-derived"]["metadata"]["source_references"])
        self.assertTrue(records["research-derived"]["metadata"]["research_artifact_ref"])
        self.assertTrue(records["external-evidence"]["metadata"]["source_references"])
        self.assertTrue(records["inference"]["metadata"]["supporting_evidence_references"])
        self.assertTrue(records["constant-by-construction"]["metadata"]["constructor_ref"])
        self.assertTrue(records["manual-decision"]["metadata"]["governing_decision_ref"])

    def test_schema_rejects_unknown_class_and_missing_required_metadata(self) -> None:
        unknown = deepcopy(self.catalog)
        unknown["derivations"][0]["derivation_class"] = "asserted"
        with self.assertRaises(ConformanceDataError):
            validate_instance(unknown, self.schema, source="unknown-class")

        missing_source = deepcopy(self.catalog)
        research = next(
            record
            for record in missing_source["derivations"]
            if record["derivation_class"] == "research-derived"
        )
        research["metadata"]["source_references"] = []
        with self.assertRaises(ConformanceDataError):
            validate_instance(missing_source, self.schema, source="missing-research-source")

        missing_decision = deepcopy(self.catalog)
        manual = next(
            record
            for record in missing_decision["derivations"]
            if record["derivation_class"] == "manual-decision"
        )
        manual["metadata"].pop("governing_decision_ref")
        with self.assertRaises(ConformanceDataError):
            validate_instance(missing_decision, self.schema, source="missing-decision")

    def test_construction_and_inference_cannot_satisfy_independent_gates(self) -> None:
        guarded = (
            (SEMANTIC_SNAPSHOT, "/adversarial_audit/major_category_omission_count"),
            (SEMANTIC_SNAPSHOT, "/discovery_scans/0/result"),
            (SEMANTIC_SNAPSHOT, "/facility_family_reconciliations/0/result"),
            (SEMANTIC_PROJECTION, "/semantic_obligation_templates/0/facet"),
        )
        for artifact, assertion in guarded:
            with self.subTest(assertion=assertion), self.assertRaisesRegex(
                ConformanceDataError, "inappropriate-evidence-strength"
            ):
                require_assertion_gate(
                    self.catalog, artifact, assertion, "independent-evidence"
                )
        require_assertion_gate(
            self.catalog,
            SEMANTIC_PROJECTION,
            "/semantic_obligation_templates/0/facet",
            "structural-integrity",
        )
        with self.assertRaisesRegex(
            ConformanceDataError, "inappropriate-evidence-strength"
        ):
            require_assertion_gate(
                self.catalog,
                SEMANTIC_SNAPSHOT,
                "/adversarial_audit/category_sparsity/0/note",
                "independent-evidence",
            )
        require_assertion_gate(
            self.catalog,
            SEMANTIC_SNAPSHOT,
            "/adversarial_audit/category_sparsity/0/note",
            "advisory-inference",
        )
        with self.assertRaisesRegex(
            ConformanceDataError, "inappropriate-evidence-strength"
        ):
            require_assertion_gate(
                self.catalog,
                "adapters/manifests/pcre2-ordinary.v1.json",
                "/certification/status",
                "certification-evidence",
            )

    def test_dangling_stale_duplicate_and_incompatible_bindings_fail(self) -> None:
        dangling = deepcopy(self.catalog)
        dangling["artifacts"][0]["assertion_bindings"][0]["derivation_id"] = (
            "rcid:v1:assertion-derivation:u7:01a07849-ffff-7fff-8fff-ffffffffffff"
        )
        with self.assertRaisesRegex(ConformanceDataError, "dangling-derivation-reference"):
            validate_catalog_integrity(ROOT, dangling)

        stale = deepcopy(self.catalog)
        stale["artifacts"][0]["assertion_bindings"][0]["derivation_revision_id"] = (
            "rcid:v1:assertion-derivation-revision:h:jcs-sha256-v1:" + "f" * 64
        )
        with self.assertRaisesRegex(ConformanceDataError, "stale-derivation-revision"):
            validate_catalog_integrity(ROOT, stale)

        duplicate = deepcopy(self.catalog)
        duplicate["derivations"].append(deepcopy(duplicate["derivations"][0]))
        with self.assertRaisesRegex(ConformanceDataError, "duplicate-derivation-id"):
            validate_catalog_integrity(ROOT, duplicate)

        incompatible = {
            "artifacts": [
                {
                    "path": "generated.json",
                    "assertion_bindings": [
                        {"selector": "/result", "derivation_id": "left"},
                        {"selector": "/result", "derivation_id": "right"},
                    ],
                }
            ]
        }
        with self.assertRaisesRegex(
            ConformanceDataError, "incompatible-derivation-bindings"
        ):
            find_binding(incompatible, "generated.json", "/result")

    def test_count_contract_detects_mismatch_and_self_validation(self) -> None:
        spec = CountSpec(
            declared="/count",
            rule="collection-length",
            inputs=("/items",),
            population="item rows",
            resolution="Exact collection length.",
        )
        self.assertEqual(validate_count_contract({"count": 2, "items": [1, 2]}, spec), 2)
        with self.assertRaisesRegex(ConformanceDataError, "generated-count-mismatch"):
            validate_count_contract({"count": 3, "items": [1, 2]}, spec)
        self_validating = CountSpec(
            declared="/count",
            rule="sum-integer-values",
            inputs=("/count",),
            population="count itself",
            resolution="Invalid by definition.",
        )
        with self.assertRaisesRegex(ConformanceDataError, "self-validating-count"):
            validate_count_contract({"count": 1}, self_validating)

    def test_ambiguous_discovery_scan_count_names_its_full_population(self) -> None:
        artifact = next(
            item for item in self.catalog["artifacts"] if item["path"] == SEMANTIC_SNAPSHOT
        )
        contract = next(
            item
            for item in artifact["count_contracts"]
            if item["declared_count_selector"] == "/counts/discovery_scans"
        )
        self.assertTrue(contract["legacy_name_ambiguous"])
        self.assertEqual(contract["calculation_rule"], "sum-collection-lengths")
        self.assertEqual(
            contract["input_selectors"],
            ["/discovery_scans", "/facility_family_reconciliations", "/adversarial_audit/passes"],
        )
        self.assertIn("source scans", contract["counted_population"])
        self.assertIn("facility", contract["counted_population"])

    def test_identity_lock_and_semantic_artifact_bytes_are_unchanged(self) -> None:
        self.assertEqual(
            verify_identity_catalog(ROOT),
            {"scientific_identities": 22359, "scientific_lineage_records": 0},
        )
        expected = {
            SEMANTIC_SNAPSHOT: "a1a684abea7cc5a5224b4f94004ee21f05efd2cf5306ce4711dcbe437ff84645",
            SEMANTIC_PROJECTION: "b25fbeaf80fc8e77f92fb5b36a094896bf30e86d4550ad62982f80a028b605b2",
            "vectors/requirements/regex-semantic-vector-requirements-2026-08-22.v1.json": "a03feacf51bf3af241a7ab4fe0ea74bd29981670de93ec3d880a27516232cca7",
            "reports/scale/regex-semantic-denominator-forecast.json": "dab61b42376d757eadada26c31d8fb5c173a508bb6ce780e98a220449ce6e871",
        }
        for path, digest in expected.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)

    def test_inventory_regeneration_is_deterministic(self) -> None:
        first = build_catalog(ROOT)
        second = build_catalog(ROOT)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertEqual(canonical_bytes(first), canonical_bytes(self.catalog))


if __name__ == "__main__":
    unittest.main()
