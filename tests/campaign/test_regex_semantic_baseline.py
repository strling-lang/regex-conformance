from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "tools" / "semantics",
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    sys.path.insert(0, str(source))

import compile_semantic_baseline as baseline  # noqa: E402
from regex_conformance_schema.derivation import (  # noqa: E402
    CATALOG_PATH as DERIVATION_CATALOG_PATH,
    require_assertion_gate,
)
from regex_conformance_schema.errors import ConformanceDataError  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes  # noqa: E402
from regex_conformance_schema.jsonio import load_strict  # noqa: E402


class RegexSemanticBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus, cls.projection, cls.vectors, cls.denominator = baseline.build_all()

    def test_tracked_artifacts_are_deterministic(self) -> None:
        for value, path in (
            (self.corpus, baseline.CORPUS_PATH),
            (self.projection, baseline.PROJECTION_PATH),
            (self.vectors, baseline.VECTOR_REQUIREMENTS_PATH),
            (self.denominator, baseline.DENOMINATOR_PATH),
        ):
            self.assertEqual(path.read_bytes(), canonical_bytes(value) + b"\n")

    def test_candidate_conservation_and_identity_granularity(self) -> None:
        feature_ids = {feature["feature_id"] for feature in self.corpus["features"]}
        self.assertEqual(len(feature_ids), 251)
        self.assertTrue(
            {
                "feature.fixed-positive-lookbehind",
                "feature.bounded-variable-positive-lookbehind",
                "feature.unbounded-positive-lookbehind",
                "feature.atomic-group",
                "feature.possessive-quantifier",
                "feature.numeric-subroutine-call",
                "feature.whole-pattern-recursion",
                "feature.leftmost-longest-match",
                "feature.approximate-edit-distance",
                "feature.streaming-match",
            }.issubset(feature_ids)
        )
        self.assertEqual(self.corpus["counts"]["unresolved_semantic_candidates"], 9)
        self.assertEqual(set(self.corpus["candidate_disposition_counts"]), baseline.ALLOWED_DISPOSITIONS)
        legacy = next(
            candidate
            for candidate in self.corpus["candidates"]
            if candidate["candidate_id"] == "candidate.legacy-bridge.feature-assertion-lookbehind-positive"
        )
        self.assertEqual(legacy["canonical_feature_id"], "feature.fixed-positive-lookbehind")

    def test_syntax_manifestations_do_not_allocate_feature_identity(self) -> None:
        feature_ids = {feature["feature_id"] for feature in self.corpus["features"]}
        for manifestation in self.corpus["manifestations"]:
            self.assertIn(manifestation["semantic_feature_id"], feature_ids)
            self.assertIn("does not allocate", manifestation["identity_note"])

    def test_all_features_close_the_declared_facet_template_structurally(self) -> None:
        facets_by_feature: dict[str, set[str]] = {}
        for obligation in self.projection["semantic_obligation_templates"]:
            facets_by_feature.setdefault(obligation["feature_id"], set()).add(obligation["facet"])
        self.assertEqual(len(self.projection["semantic_obligation_templates"]), 12048)
        self.assertTrue(all(facets == set(baseline.FACET_CASES) for facets in facets_by_feature.values()))
        catalog = load_strict(ROOT / DERIVATION_CATALOG_PATH)
        assertion = "/semantic_obligation_templates/0/facet"
        require_assertion_gate(
            catalog,
            "ontology/projections/regex-semantic-projection-2026-08-22.v1.json",
            assertion,
            "structural-integrity",
        )
        with self.assertRaisesRegex(
            ConformanceDataError, "inappropriate-evidence-strength"
        ):
            require_assertion_gate(
                catalog,
                "ontology/projections/regex-semantic-projection-2026-08-22.v1.json",
                assertion,
                "semantic-completeness",
            )

    def test_vector_gap_is_explicit_and_attributable(self) -> None:
        counts = self.vectors["counts"]
        self.assertEqual(counts["minimum_vector_definitions"], 9506)
        self.assertEqual(counts["missing_vector_definitions"], 9506)
        self.assertEqual(counts["reusable_vector_definitions"], 0)
        obligation_ids = {item["obligation_id"] for item in self.projection["semantic_obligation_templates"]}
        self.assertTrue(all(item["obligation_id"] in obligation_ids for item in self.vectors["requirements"]))

    def test_profile_allocations_and_denominator_close_independently(self) -> None:
        units = self.denominator["coordinate_units_per_profile_by_archetype"]
        for case in ("lower", "expected", "conservative"):
            allocation = self.denominator["profile_bounds_and_allocations"][case]
            current = sum(units[name] * count for name, count in allocation["current_by_archetype"].items())
            historical = sum(units[name] * count for name, count in allocation["historical_by_archetype"].items())
            parts = self.denominator["logical_execution_denominator"][case]
            self.assertEqual(current, parts["current_stable_logical_executions"])
            self.assertEqual(historical, parts["historical_stable_logical_executions"])
            self.assertEqual(
                sum(
                    parts[key]
                    for key in (
                        "current_stable_logical_executions",
                        "historical_stable_logical_executions",
                        "platform_canary_logical_executions",
                        "targeted_platform_expansion_reserve",
                        "qualification_rehearsal_logical_executions",
                    )
                ),
                parts["total_logical_executions"],
            )

    def test_v3_capacity_passes_after_minimal_retention_change(self) -> None:
        capacity = self.denominator["compact_evidence_pack_v3"]
        self.assertEqual(
            capacity["restored_baseline"]["conservative_retained_bytes"],
            14_559_081_529,
        )
        self.assertEqual(capacity["capacity_status"], "PASS")
        self.assertFalse(capacity["stop_rule_applied"])
        self.assertEqual(capacity["conservative_soft_stop_overage_bytes"], 0)
        self.assertEqual(capacity["conservative_hard_cap_overage_bytes"], 0)
        self.assertEqual(
            capacity["forecast_cases"]["conservative"]["total_retained_bytes"],
            7_452_076_843,
        )
        self.assertEqual(
            capacity["retention_optimization"]["total_savings_bytes"],
            7_107_004_686,
        )
        self.assertEqual(
            capacity["retention_optimization"]["soft_stop_margin_bytes"],
            547_923_157,
        )
        self.assertFalse(self.denominator["classification"]["full_campaign_executed"])

    def test_report_is_plain_json_and_contains_no_execution_credit(self) -> None:
        tracked = json.loads(baseline.DENOMINATOR_PATH.read_text(encoding="utf-8"))
        self.assertTrue(tracked["classification"]["design_only"])
        self.assertFalse(tracked["classification"]["exact_coordinate_materialization_available"])


if __name__ == "__main__":
    unittest.main()
