from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.schema import validate_instance, validate_repository
from regex_conformance_schema.selection import validate_vertical_slice_selection


class VerticalSliceSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = ROOT / "registries" / "profiles" / "vertical-slice-archetypes.v1.json"
        cls.schema = load_strict(ROOT / "schemas" / "json" / "vertical-slice-selection.schema.json")
        cls.record = load_strict(cls.source)

    def test_governed_selection_is_repository_validated_and_conserves_seed_scope(self) -> None:
        counts = validate_repository(ROOT)
        self.assertEqual(counts["vertical_slice_selections"], 1)
        selected = {item["seed_handle"] for item in self.record["selected_archetypes"]}
        deferred = {item["seed_handle"] for item in self.record["deferred_candidates"]}
        self.assertEqual(
            selected,
            {"seed:p04:pcre2", "seed:p04:python-re", "seed:p04:mysql-regex"},
        )
        self.assertEqual(len(selected | deferred), 19)
        self.assertFalse(selected & deferred)
        self.assertTrue(
            all(item["registry_disposition"] == "in-scope" for item in self.record["selected_archetypes"])
        )
        self.assertFalse(self.record["selection_policy"]["execution_eligible"])

    def test_selection_covers_required_surface_and_environment_archetypes(self) -> None:
        by_key = {item["selection_key"]: item for item in self.record["selected_archetypes"]}
        self.assertEqual(
            {item["surface_class"] for item in by_key.values()},
            {"standalone-library-api", "host-runtime-api", "database-sql-api"},
        )
        self.assertEqual(
            {item["required_environment_strategy"] for item in by_key.values()},
            {"native-source-build", "native-runtime", "oci-service"},
        )
        self.assertIn("engine-backend", by_key["mysql-regex"]["required_node_roles"])
        self.assertIn("error-result-adapter", by_key["python-re"]["required_node_roles"])
        self.assertIn("matching-backend", by_key["pcre2-ordinary"]["required_node_roles"])

    def test_pending_or_convenience_selected_target_fails_closed(self) -> None:
        pending = deepcopy(self.record)
        pending["selected_archetypes"][0]["registry_disposition"] = "pending-investigation"
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            validate_instance(pending, self.schema, source=str(self.source))

        convenience = deepcopy(self.record)
        convenience["selection_policy"]["installed_runtime_preference"] = True
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            validate_instance(convenience, self.schema, source=str(self.source))

    def test_collisions_unknown_coverage_and_missing_strategy_diversity_fail_closed(self) -> None:
        collision = deepcopy(self.record)
        collision["selected_archetypes"][1]["selection_key"] = collision["selected_archetypes"][0][
            "selection_key"
        ]
        with self.assertRaisesRegex(ConformanceDataError, "selection-identity-collision"):
            validate_vertical_slice_selection(collision, source=str(self.source))

        unknown = deepcopy(self.record)
        unknown["coverage_claims"]["standalone"] = ["missing-target"]
        with self.assertRaisesRegex(ConformanceDataError, "selection-reference-unknown"):
            validate_vertical_slice_selection(unknown, source=str(self.source))

        duplicate_strategy = deepcopy(self.record)
        duplicate_strategy["selected_archetypes"][2]["required_environment_strategy"] = "native-runtime"
        with self.assertRaisesRegex(ConformanceDataError, "selection-environment-diversity-missing"):
            validate_vertical_slice_selection(duplicate_strategy, source=str(self.source))

    def test_seed_accounting_overlap_and_false_in_scope_deferral_fail_closed(self) -> None:
        overlap = deepcopy(self.record)
        overlap["deferred_candidates"][0]["seed_handle"] = overlap["selected_archetypes"][0]["seed_handle"]
        with self.assertRaisesRegex(ConformanceDataError, "selection-accounting-overlap"):
            validate_vertical_slice_selection(overlap, source=str(self.source))

        false_deferral = deepcopy(self.record)
        false_deferral["deferred_candidates"][0]["registry_disposition"] = "in-scope"
        with self.assertRaisesRegex(ConformanceDataError, "selection-deferral-mismatch"):
            validate_vertical_slice_selection(false_deferral, source=str(self.source))

        wrong_normative_reason = deepcopy(self.record)
        normative = next(
            item
            for item in wrong_normative_reason["deferred_candidates"]
            if item["registry_disposition"] == "normative-only-authority"
        )
        normative["reason_code"] = "pending-investigation"
        with self.assertRaisesRegex(ConformanceDataError, "selection-deferral-mismatch"):
            validate_vertical_slice_selection(wrong_normative_reason, source=str(self.source))

    def test_candidate_order_is_deterministic(self) -> None:
        selected_reordered = deepcopy(self.record)
        selected_reordered["selected_archetypes"][0], selected_reordered["selected_archetypes"][1] = (
            selected_reordered["selected_archetypes"][1],
            selected_reordered["selected_archetypes"][0],
        )
        with self.assertRaisesRegex(ConformanceDataError, "selection-order-nondeterministic"):
            validate_vertical_slice_selection(selected_reordered, source=str(self.source))

        reordered = deepcopy(self.record)
        reordered["deferred_candidates"][0], reordered["deferred_candidates"][1] = (
            reordered["deferred_candidates"][1],
            reordered["deferred_candidates"][0],
        )
        with self.assertRaisesRegex(ConformanceDataError, "selection-order-nondeterministic"):
            validate_vertical_slice_selection(reordered, source=str(self.source))


if __name__ == "__main__":
    unittest.main()
