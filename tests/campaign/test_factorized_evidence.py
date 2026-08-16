from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    sys.path.insert(0, str(source))

import regex_conformance_scale.factorized_evidence as factorized  # noqa: E402


REPORT = ROOT / "reports" / "scale" / "factorized-raw-evidence-forecast.json"
SCHEMA = ROOT / "schemas" / "json" / "factorized-evidence-forecast.schema.json"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


class TokenTableTests(unittest.TestCase):
    def test_typed_binary_tables_round_trip_deterministically(self) -> None:
        value = {
            "digest": "a" * 64,
            "identity": "rcid:v1:logical-execution:h:jcs-sha256-v1:" + "b" * 64,
            "uuid": "019ffffd-0128-790a-bca6-6d904a803283",
            "timestamp": "2026-08-14T11:16:38.824Z",
            "values": [None, False, True, -7, 42, "python-re"],
        }
        first = factorized.TokenTables.build([value])
        second = factorized.TokenTables.build([deepcopy(value)])
        self.assertEqual(first.encode_tables(), second.encode_tables())
        encoded = first.encode_tables() + first.encode_value(value)
        decoded, offset = factorized.TokenTables.decode_tables(encoded)
        result, end = decoded.decode_value(encoded, offset)
        self.assertEqual(result, value)
        self.assertEqual(end, len(encoded))

    def test_indexed_logical_lookup_inflates_one_payload_block(self) -> None:
        context = factorized._logical_identity_context(ROOT)
        template = {
            "base_logical_execution_id": "rcid:v1:logical-execution:h:jcs-sha256-v1:" + "1" * 64,
            "profile_id": "rcid:v1:profile:u7:019ffc57-9ad1-7be2-8067-73fce0a50770",
            "request_template_sha256": "2" * 64,
            "selection_key": "python-re",
            "target_release_id": "rcid:v1:release:u7:019ff984-a52e-737a-8353-17af9584dc6f",
            "vector_revision_id": "rcid:v1:vector-revision:h:jcs-sha256-v1:" + "3" * 64,
        }
        shard_id = "rcid:v1:shard:h:jcs-sha256-v1:" + "4" * 64
        model = {
            "schema_version": "logical-execution-segment.v1",
            "selection_key": "python-re",
            "shard_id": shard_id,
            "template_indexes": [0],
            "planned_repetitions": [1],
        }
        global_model = {
            "schema_version": factorized.MODEL_SCHEMA,
            "archive_schema_version": factorized.ARCHIVE_SCHEMA,
            "identity_context": context,
            "logical_templates": [template],
            "result_templates": [],
            "provenance_templates": [],
            "manifest": {
                "campaign_manifest_id": context["campaign_manifest_id"],
                "interruptions": [],
                "segment_catalog": {
                    "attempt_counts": [], "attempt_numbers": [],
                    "logical_execution_counts": [], "observation_counts": [],
                    "result_segment_ids": [], "segment_kinds": [], "sha256s": [],
                    "shard_ids": [], "size_bytes": []
                },
                "schema_version": "scale-evidence-manifest.v1",
            },
            "logical_member_by_shard": {},
            "source_binding": {
                "evidence_manifest_sha256": "5" * 64,
                "logical_member_count": 1,
                "manifest_member_count": 1,
                "raw_result_member_count": 0,
            },
        }
        ids = factorized._ContentIds(ROOT)
        payload, _ = factorized._logical_payload(ids, global_model, model)
        expected = factorized.canonical_bytes(payload) + b"\n"
        relative = f"logical/logical-execution-segments/sha256/{hashlib.sha256(expected).hexdigest()}.json"
        global_model["logical_member_by_shard"][shard_id] = relative
        semantic = factorized.SemanticCorpus(
            global_model=global_model,
            logical_members=(factorized.SemanticMember(relative, "canonical_logical_input", model),),
            result_members=(),
            manifest_member=factorized.SemanticMember(
                "evidence/scale-manifests/sha256/" + "5" * 64 + ".json",
                "minimal_manifest_integrity",
                {"derive_from_segment_catalog": True},
            ),
            statistics={},
        )
        first = factorized.encode_semantic_archive(semantic)
        second = factorized.encode_semantic_archive(semantic)
        self.assertEqual(first.data, second.data)
        lookup = factorized.lookup_archive_member(ROOT, first.data, relative)
        self.assertEqual(lookup.data, expected)
        self.assertEqual(lookup.payload_blocks_decompressed, 1)
        corrupted = bytearray(first.data)
        corrupted[len(corrupted) // 2] ^= 1
        with self.assertRaises(factorized.FactorizedEvidenceError):
            factorized.decode_semantic_archive(bytes(corrupted))


class FactorizedForecastTests(unittest.TestCase):
    def test_report_validates_and_preserves_authority_boundaries(self) -> None:
        report = load(REPORT)
        errors = list(
            Draft202012Validator(
                load(SCHEMA), format_checker=FormatChecker()
            ).iter_errors(report)
        )
        self.assertEqual(errors, [])
        factorized.verify_factorized_forecast(report)
        classification = report["classification"]
        self.assertTrue(classification["source_corpus_read_only"])
        self.assertFalse(classification["material_r2_publication_performed"])
        self.assertFalse(classification["authoritative_raw_evidence_changed"])
        self.assertFalse(classification["storage_limits_changed"])

    def test_measured_factorization_reconstructs_and_reforecasts_exact_denominators(self) -> None:
        report = load(REPORT)
        strongest = report["representations"]["factorized_deterministic_binary_xz9"]
        baseline = report["representations"]["p20_t01a_certified_tar_gzip9"]
        self.assertLess(strongest["retained_bytes"], baseline["retained_bytes"])
        self.assertLess(Decimal(strongest["bytes_per_logical_execution"]), Decimal(100))
        self.assertEqual(
            sum(strongest["bytes_by_evidence_class"].values()),
            strongest["retained_bytes"],
        )
        factoring = report["factoring_measurements"]
        self.assertEqual(factoring["content_addressed_diagnostic_value_count"], 2)
        self.assertEqual(factoring["infrastructure_failure_attempt_count"], 500)
        self.assertEqual(factoring["raw_performance_sample_count"], 4_249)
        self.assertEqual(factoring["result_template_count"], 26)
        certification = report["certification"]
        self.assertTrue(certification["byte_complete_reconstruction_verified"])
        self.assertTrue(certification["corruption_injection_detected"])
        self.assertLessEqual(certification["maximum_payload_blocks_per_random_lookup"], 2)
        for key, expected in factorized.DENOMINATORS.items():
            actual = report["forecast"]["cases"][key]
            self.assertEqual(actual["logical_executions"], expected["logical_executions"])
            self.assertEqual(actual["physical_attempts"], expected["physical_attempts"])
        self.assertFalse(report["forecast"]["cases"]["expected"]["exceeds_hard_limit"])
        self.assertTrue(report["forecast"]["cases"]["conservative"]["exceeds_hard_limit"])

    def test_required_trimming_review_is_quantified_but_not_applied(self) -> None:
        report = load(REPORT)
        gate = report["decision_gate"]
        self.assertTrue(gate["second_stage_trimming_review_required"])
        self.assertTrue(gate["p20_t02_must_remain_planned"])
        self.assertFalse(gate["material_r2_publication_authorized"])
        review = report["second_stage_trimming_review"]
        options = review["options_ranked_by_storage_and_scientific_tradeoff"]
        self.assertEqual(
            [item["owner_review_rank"] for item in options],
            list(range(1, len(options) + 1)),
        )
        savings_order = sorted(options, key=lambda item: item["storage_savings_bytes"], reverse=True)
        self.assertEqual(
            [item["storage_savings_rank"] for item in savings_order],
            list(range(1, len(options) + 1)),
        )
        self.assertTrue(all(item["requires_program_owner_approval"] for item in options))
        self.assertTrue(all(not item["implemented"] for item in options))
        by_key = {item["key"]: item for item in options}
        self.assertEqual(
            by_key["transition-directed-historical-testing-break-even"]["owner_review_rank"],
            1,
        )
        self.assertTrue(by_key["platform-canary-triggered-expansion"]["scenario"]["fits_hard_cap"])
        self.assertFalse(by_key["routine-diagnostics-reserve-to-anomaly-only"]["scenario"]["fits_hard_cap"])
        self.assertEqual(by_key["derive-logical-inputs-from-immutable-definitions"]["storage_savings_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
