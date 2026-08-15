from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator, FormatChecker
import rfc8785


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    sys.path.insert(0, str(source))

from regex_conformance_scale.universe_forecast import (  # noqa: E402
    FullUniverseForecastError,
    build_full_known_universe_forecast,
    verify_full_known_universe_forecast,
)


INDEX = ROOT / "registries/universe/full-known-universe-2026-08-15.v1.json"
INDEX_SCHEMA = ROOT / "schemas/json/full-known-universe-index.schema.json"
REPORT = ROOT / "reports/scale/full-known-universe-corpus-forecast.json"
REPORT_SCHEMA = ROOT / "schemas/json/full-known-universe-forecast.schema.json"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class FullKnownUniverseForecastTests(unittest.TestCase):
    def test_index_and_report_validate_and_rebuild_exactly(self) -> None:
        index = load(INDEX)
        report = load(REPORT)
        for instance, schema_path in ((index, INDEX_SCHEMA), (report, REPORT_SCHEMA)):
            errors = list(
                Draft202012Validator(
                    load(schema_path), format_checker=FormatChecker()
                ).iter_errors(instance)
            )
            self.assertEqual(errors, [])
        self.assertEqual(report, build_full_known_universe_forecast(ROOT))
        verify_full_known_universe_forecast(ROOT, report)
        digest_input = deepcopy(report)
        claimed = digest_input.pop("report_digest_sha256")
        self.assertEqual(hashlib.sha256(rfc8785.dumps(digest_input)).hexdigest(), claimed)

    def test_candidate_dispositions_and_primary_sources_are_closed(self) -> None:
        index = load(INDEX)
        report = load(REPORT)
        facilities = index["facilities"]
        candidates = index["other_candidates"]
        keys = [item["key"] for item in facilities + candidates]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(index["discovery_coverage"]["applied_source_classes"]), 13)
        self.assertTrue(all(item["source"].startswith("https://") for item in facilities + candidates))
        facility_keys = {item["key"] for item in facilities}
        self.assertTrue(
            all(
                item.get("target") in facility_keys
                for item in candidates
                if item["disposition"] == "alias-to-facility"
            )
        )
        self.assertEqual(report["index_summary"]["facility_count"], len(facilities))
        self.assertEqual(report["index_summary"]["total_candidate_count"], len(keys))
        self.assertEqual(report["index_summary"]["canonical_c1_c2_status"], "provisional-until-p21-registry-and-scanners")

    def test_denominators_recompute_independently(self) -> None:
        index = load(INDEX)
        report = load(REPORT)

        def calculate(historical: bool) -> dict[str, int]:
            result = {"lower": 0, "expected": 0, "upper": 0}
            for facility in index["facilities"]:
                archetype = index["obligation_archetypes"][facility["archetype"]]
                profile_band = (
                    facility["historical_profiles"]
                    if historical
                    else {key: facility["current_profiles"] for key in result}
                )
                for key in result:
                    result[key] += profile_band[key] * archetype[key]
            return result

        current = calculate(False)
        historical = calculate(True)
        self.assertEqual(report["denominators"]["current_stable"]["logical_executions"], current)
        self.assertEqual(report["denominators"]["full_historical_stable"]["logical_executions"], historical)
        final = report["denominators"]["final_stable_certification"]["logical_executions"]
        self.assertEqual(final["lower"], (historical["lower"] * 125 + 99) // 100)
        self.assertEqual(final["expected"], historical["expected"] * 2)
        self.assertEqual(final["upper"], historical["upper"] * 3)
        self.assertTrue(
            all(
                stage["physical_attempts"][key] >= stage["logical_executions"][key]
                for stage in report["denominators"].values()
                if "physical_attempts" in stage
                for key in ("lower", "expected", "upper")
            )
        )

    def test_raw_only_storage_and_request_gate_is_fail_closed(self) -> None:
        report = load(REPORT)
        basis = report["measured_basis"]
        self.assertEqual(basis["uncompressed_raw_only_bytes"], 386_855_397)
        self.assertEqual(basis["independent_gzip9_bytes"], 31_926_001)
        self.assertEqual(basis["deterministic_tar_gzip9"]["packed_bytes"], 31_742_126)
        self.assertTrue(basis["deterministic_tar_gzip9"]["reconstruction_verified"])
        classification = report["classification"]
        self.assertFalse(
            set(classification["permitted_remote_classes"])
            & set(classification["forbidden_remote_classes"])
        )
        self.assertIn("warehouse", classification["forbidden_remote_classes"])
        self.assertIn("lossless-raw-record-pack", classification["permitted_remote_classes"])
        gate = report["decision_gate"]
        self.assertTrue(gate["decision_required"])
        self.assertGreater(gate["lower_bound_final_packed_bytes_without_reserves"], 10_000_000_000)
        self.assertGreater(gate["expected_final_packed_bytes"], 8_000_000_000)
        self.assertGreater(gate["conservative_final_packed_bytes"], 10_000_000_000)
        self.assertLess(gate["expected_class_a_requests"], 1_000_000)
        self.assertLess(gate["conservative_class_a_requests"], 1_000_000)
        self.assertTrue(gate["p20_t02_must_remain_planned"])
        self.assertFalse(classification["r2_accessed"])
        self.assertFalse(classification["production_publication_performed"])

        final_bytes = report["raw_corpus_forecast"]["final_stable_certification"]["bytes"]
        final_requests = report["raw_corpus_forecast"]["final_stable_certification"][
            "objects_and_requests"
        ]
        qualification = report["raw_corpus_forecast"][
            "qualification_campaign_evidence_separate"
        ]
        retained = report["raw_corpus_forecast"]["final_retained_totals"]
        expected = final_bytes["expected"]
        conservative = final_bytes["conservative"]
        self.assertEqual(qualification["uncompressed_raw_only_bytes"], 386_855_397)
        self.assertEqual(qualification["packed_gzip9_raw_only_bytes"], 31_742_126)
        self.assertEqual(qualification["raw_member_count"], 807)
        self.assertEqual(qualification["lossless_pack_objects_including_manifest"], 2)
        self.assertEqual(qualification["class_a_puts"], 2)
        self.assertEqual(qualification["class_b_readbacks"], 2)
        self.assertEqual(expected["physical_attempts"], 130_363_801)
        self.assertEqual(conservative["physical_attempts"], 378_738_112)
        self.assertEqual(
            expected["packed_gzip9_raw_only_bytes_with_diagnostics_reserve"],
            sum(expected["packed_gzip9_raw_class_projection_bytes_before_diagnostics"].values())
            + expected["packed_gzip9_required_raw_diagnostics_reserve_bytes"],
        )
        self.assertEqual(
            conservative["packed_gzip9_raw_only_bytes_with_reserves"],
            sum(conservative["packed_gzip9_raw_class_projection_bytes_before_reserves"].values())
            + conservative["packed_gzip9_required_raw_diagnostics_reserve_bytes"]
            + conservative["fixed_reserve_bytes"],
        )
        self.assertEqual(
            expected["retry_overhead"]["additional_physical_attempts"],
            expected["physical_attempts"]
            - report["denominators"]["final_stable_certification"]["logical_executions"]["expected"],
        )
        self.assertGreater(
            conservative["retry_overhead"]["packed_raw_result_and_attempt_bytes"],
            expected["retry_overhead"]["packed_raw_result_and_attempt_bytes"],
        )
        self.assertEqual(
            retained["lower"]["packed_gzip9_raw_only_bytes_without_reserves"],
            final_bytes["lower"]["packed_gzip9_raw_only_bytes_without_reserves"]
            + qualification["packed_gzip9_raw_only_bytes"],
        )
        for case, retained_byte_key, uncompressed_byte_key in (
            (
                "expected",
                "packed_gzip9_raw_only_bytes_with_diagnostics_reserve",
                "uncompressed_raw_only_bytes_with_diagnostics_reserve",
            ),
            (
                "conservative",
                "packed_gzip9_raw_only_bytes_with_reserves",
                "uncompressed_raw_only_bytes_with_reserves",
            ),
        ):
            self.assertEqual(
                retained[case][retained_byte_key],
                final_bytes[case][retained_byte_key]
                + qualification["packed_gzip9_raw_only_bytes"],
            )
            self.assertEqual(
                retained[case][uncompressed_byte_key],
                final_bytes[case][uncompressed_byte_key]
                + qualification["uncompressed_raw_only_bytes"],
            )
            self.assertEqual(
                retained[case]["lossless_pack_objects_including_manifests"],
                final_requests[case]["lossless_pack_objects_including_manifest"]
                + qualification["lossless_pack_objects_including_manifest"],
            )
            self.assertEqual(
                retained[case]["class_a_puts"],
                final_requests[case]["class_a_puts"] + qualification["class_a_puts"],
            )
            self.assertEqual(
                retained[case]["class_b_readbacks"],
                final_requests[case]["class_b_readbacks"]
                + qualification["class_b_readbacks"],
            )
        self.assertEqual(
            gate["expected_final_packed_bytes"],
            retained["expected"][
                "packed_gzip9_raw_only_bytes_with_diagnostics_reserve"
            ],
        )
        self.assertEqual(
            gate["conservative_final_packed_bytes"],
            retained["conservative"]["packed_gzip9_raw_only_bytes_with_reserves"],
        )
        self.assertEqual(gate["expected_remaining_soft_reserve_bytes"], 0)
        self.assertEqual(gate["conservative_remaining_hard_reserve_bytes"], 0)

    def test_contributor_effects_reconcile(self) -> None:
        report = load(REPORT)
        analysis = report["contributor_analysis"]
        historical = report["denominators"]["full_historical_stable"]["logical_executions"]
        current = report["denominators"]["current_stable"]["logical_executions"]
        final = report["denominators"]["final_stable_certification"]["logical_executions"]
        self.assertEqual(
            sum(
                item["expected_historical_logical_executions"]
                for item in analysis["expected_historical_archetype_contributors"]
            ),
            historical["expected"],
        )
        self.assertEqual(
            analysis["expected_effects"]["historical_stable_increment_before_platform_expansion"],
            historical["expected"] - current["expected"],
        )
        self.assertEqual(
            analysis["expected_effects"]["platform_architecture_increment"],
            final["expected"] - historical["expected"],
        )
        self.assertEqual(analysis["d101"]["superseded_patch_execution_credit"], 0)

    def test_verifier_rejects_authority_and_gate_forgery(self) -> None:
        report = load(REPORT)
        for mutation in ("r2", "decision", "p20"):
            forged = deepcopy(report)
            if mutation == "r2":
                forged["classification"]["r2_accessed"] = True
            elif mutation == "decision":
                forged["decision_gate"]["decision_required"] = False
            else:
                forged["decision_gate"]["p20_t02_must_remain_planned"] = False
            with self.assertRaises(FullUniverseForecastError):
                verify_full_known_universe_forecast(ROOT, forged)


if __name__ == "__main__":
    unittest.main()
