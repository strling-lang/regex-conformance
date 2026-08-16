from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
import sys
import unittest

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    sys.path.insert(0, str(source))

import regex_conformance_scale.evidence_pack_v2 as pack_v2  # noqa: E402
import regex_conformance_scale.factorized_evidence as factorized  # noqa: E402


REPORT = ROOT / "reports" / "scale" / "evidence-pack-v2-certification.json"
REPORT_SCHEMA = ROOT / "schemas" / "json" / "evidence-pack-v2-certification.schema.json"
DIAGNOSTIC_SCHEMA = ROOT / "schemas" / "json" / "attempt-diagnostic-envelope-v2.schema.json"
PERFORMANCE_SCHEMA = ROOT / "schemas" / "json" / "raw-performance-samples-v2.schema.json"
MANIFEST_SCHEMA = ROOT / "schemas" / "json" / "evidence-pack-v2-manifest.schema.json"


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def diagnostic_envelope() -> dict:
    facts = {
        field: {"availability": "observed-absence-or-not-applicable"}
        for field in pack_v2.DIAGNOSTIC_FIELDS
    }
    facts["operation"] = {"availability": "observed", "value": "search"}
    facts["wall-duration"] = {
        "availability": "observed",
        "value": {"unit": "nanoseconds", "value": 4129},
    }
    return {
        "facts": facts,
        "physical_run_id": "rcid:v1:physical-run:u7:019ffffd-0128-790a-bca6-6d904a803283",
        "schema_version": pack_v2.DIAGNOSTIC_ENVELOPE_SCHEMA,
    }


def performance_record() -> dict:
    return {
        "claim_scope": "governed-benchmark",
        "methodology_id": "warm-search-v1",
        "physical_run_id": "rcid:v1:physical-run:u7:019ffffd-0128-790a-bca6-6d904a803283",
        "samples": {
            "compile-duration": {"unit": "nanoseconds", "values": [104, 99, 101]},
            "peak-rss": {"unit": "bytes", "values": [8192, 8192, 12288]},
        },
        "schema_version": pack_v2.PERFORMANCE_SAMPLES_SCHEMA,
    }


class ExpandedEvidenceContractTests(unittest.TestCase):
    def test_diagnostic_envelope_has_exact_ordered_availability_contract(self) -> None:
        value = diagnostic_envelope()
        pack_v2.validate_attempt_diagnostic_envelope(value)
        self.assertEqual(list(value["facts"]), list(pack_v2.DIAGNOSTIC_FIELDS))
        self.assertEqual(
            list(Draft202012Validator(load(DIAGNOSTIC_SCHEMA)).iter_errors(value)),
            [],
        )
        encoded = pack_v2._pack_availability(
            [[pack_v2.AVAILABILITY_CODES[item["availability"]] for item in value["facts"].values()]]
        )
        self.assertEqual(
            pack_v2.unpack_availability(encoded, 1)[0],
            [item["availability"] for item in value["facts"].values()],
        )

    def test_diagnostic_contract_rejects_value_on_absent_fact(self) -> None:
        value = diagnostic_envelope()
        value["facts"]["stderr"] = {
            "availability": "observed-absence-or-not-applicable",
            "value": "",
        }
        with self.assertRaises(pack_v2.EvidencePackError):
            pack_v2.validate_attempt_diagnostic_envelope(value)

    def test_raw_performance_samples_are_typed_arrays_not_derived_statistics(self) -> None:
        value = performance_record()
        pack_v2.validate_performance_samples(value)
        self.assertEqual(
            list(Draft202012Validator(load(PERFORMANCE_SCHEMA)).iter_errors(value)),
            [],
        )
        invalid = deepcopy(value)
        invalid["samples"]["compile-duration"]["values"] = [10.5]
        with self.assertRaises(pack_v2.EvidencePackError):
            pack_v2.validate_performance_samples(invalid)

    def test_token_tables_preserve_compact_binary_diagnostic_bitmaps(self) -> None:
        bitmap = bytes(range(9))
        tables = factorized.TokenTables.build([bitmap])
        encoded = tables.encode_tables() + tables.encode_value(bitmap)
        decoded, offset = factorized.TokenTables.decode_tables(encoded)
        value, end = decoded.decode_value(encoded, offset)
        self.assertEqual(value, bitmap)
        self.assertEqual(end, len(encoded))

    def test_repeated_exact_diagnostic_blobs_are_content_deduplicated(self) -> None:
        cas = pack_v2._Cas()
        payload = {
            "captured_bytes": 11,
            "content": "same stderr",
            "original_bytes": 11,
            "sha256": "a" * 64,
            "truncated": False,
        }
        first = pack_v2._extract_diagnostic_payloads(
            {"stderr": payload, "attempt": 1}, cas
        )
        second = pack_v2._extract_diagnostic_payloads(
            {"stderr": deepcopy(payload), "attempt": 2}, cas
        )
        self.assertEqual(
            first["stderr"]["evidence_pack_diagnostic_cas_sha256"],
            second["stderr"]["evidence_pack_diagnostic_cas_sha256"],
        )
        self.assertEqual(len(cas.objects), 1)

    def test_identical_fact_bytes_are_stored_once_with_independent_bindings(self) -> None:
        model = {"schema_version": pack_v2.PACK_MODEL_SCHEMA}
        fact_value = [{"availability": "absent"}]
        tables = factorized.TokenTables.build([model, fact_value])
        first = pack_v2._fact_object(
            pack_v2._FactBlock(
                "diagnostics",
                "diagnostic-facts",
                ("evidence/result-a.json",),
                fact_value,
            ),
            tables,
        )
        second = pack_v2._fact_object(
            pack_v2._FactBlock(
                "diagnostics",
                "diagnostic-facts",
                ("evidence/result-b.json",),
                fact_value,
            ),
            tables,
        )
        self.assertEqual(first.stored_sha256, second.stored_sha256)
        objects, aliases = pack_v2._deduplicate_physical_objects([first, second])
        self.assertEqual(len(objects), 1)
        self.assertEqual(len(aliases), 1)
        self.assertEqual(aliases[0]["member_paths"], ["evidence/result-b.json"])

        dictionary_raw = tables.encode_tables() + tables.encode_value(model)
        dictionary_stored = pack_v2._xz(dictionary_raw)
        dictionary = pack_v2.PackObject(
            evidence_class="shared_dictionary_cas",
            role="pack-dictionary",
            member_paths=(),
            raw_sha256=pack_v2._sha256(dictionary_raw),
            raw_size_bytes=len(dictionary_raw),
            stored_sha256=pack_v2._sha256(dictionary_stored),
            stored_size_bytes=len(dictionary_stored),
            data=dictionary_stored,
        )
        objects, aliases = pack_v2._deduplicate_physical_objects(
            [dictionary, first, second]
        )
        body = {
            "authority": {
                "analytics_authoritative": False,
                "independent_observations_preserved": True,
                "independent_physical_attempts_preserved": True,
                "raw_empirical_evidence": True,
            },
            "fact_aliases": aliases,
            "format": {
                "compression": "xz-crc64-sha256-preset9",
                "content_addressed_objects": True,
                "deterministic": True,
                "manifest_published_last": True,
                "normal_list_requests": 0,
                "version": 2,
            },
            "objects": [item.descriptor(index) for index, item in enumerate(objects)],
            "schema_version": pack_v2.PACK_SCHEMA,
            "source_binding": {
                "evidence_manifest_sha256": "a" * 64,
                "logical_execution_count": 2,
                "member_count": 2,
                "physical_attempt_count": 2,
                "source_raw_bytes": 2,
            },
        }
        manifest = {
            **body,
            "pack_digest_sha256": pack_v2._sha256(pack_v2.canonical_bytes(body)),
        }
        self.assertEqual(
            list(Draft202012Validator(load(MANIFEST_SCHEMA)).iter_errors(manifest)),
            [],
        )
        decoded = pack_v2._decode_pack(
            manifest,
            {item.stored_sha256: item.data for item in objects},
            roles={"diagnostic-facts"},
        )
        self.assertEqual(
            set(pack_v2._role_values(decoded)["diagnostic-facts"]),
            {"evidence/result-a.json", "evidence/result-b.json"},
        )


class PlatformCanaryPolicyTests(unittest.TestCase):
    def test_only_exact_semantic_scope_triggers_expansion(self) -> None:
        results = [
            pack_v2.PlatformCanaryResult("linux-arm64", "p1", "lookbehind", "search", "jit", "semantic", 40),
            pack_v2.PlatformCanaryResult("linux-arm64", "p1", "lookbehind", "search", "jit", "semantic", 35),
            pack_v2.PlatformCanaryResult("windows-arm64", "p2", "unicode", "match", "native", "diagnostic"),
            pack_v2.PlatformCanaryResult("macos-arm64", "p3", "replace", "replace", "native", "performance-only"),
            pack_v2.PlatformCanaryResult("linux-riscv64", "p4", "split", "split", "native", "infrastructure-noise"),
        ]
        plan = pack_v2.plan_platform_expansion(
            results,
            retained_bytes=1_000,
            bytes_per_logical_execution=Decimal("33.2"),
        )
        self.assertEqual(plan["outcome"], "admitted")
        self.assertEqual(plan["incremental_retained_bytes"], 1328)
        self.assertEqual(len(plan["targeted_scopes"]), 1)
        self.assertEqual(plan["targeted_scopes"][0]["affected_logical_executions"], 40)

    def test_canaries_fail_closed_at_capacity_boundaries(self) -> None:
        result = pack_v2.PlatformCanaryResult(
            "linux-arm64", "p1", "backtracking", "search", "jit", "semantic", 100
        )
        soft = pack_v2.plan_platform_expansion(
            [result], retained_bytes=pack_v2.SOFT_LIMIT_BYTES - 50,
            bytes_per_logical_execution=Decimal("1"),
        )
        hard = pack_v2.plan_platform_expansion(
            [result], retained_bytes=pack_v2.HARD_LIMIT_BYTES - 50,
            bytes_per_logical_execution=Decimal("1"),
        )
        self.assertEqual(soft["outcome"], "soft-stop-owner-review-required")
        self.assertEqual(hard["outcome"], "hard-cap-rejected")


class CertificationReportTests(unittest.TestCase):
    def test_tracked_report_validates_and_preserves_d103(self) -> None:
        report = load(REPORT)
        self.assertEqual(
            list(Draft202012Validator(load(REPORT_SCHEMA)).iter_errors(report)),
            [],
        )
        pack_v2.verify_certification_report(report)
        conservative = report["forecast"]["cases"]["conservative"]
        self.assertLess(conservative["total_retained_bytes"], 8_000_000_000)
        self.assertGreater(
            report["forecast"]["conservative_operating_reserve_below_soft_stop_bytes"],
            0,
        )
        self.assertTrue(report["decision_gate"]["p20_t02_entry_capacity_gate_passed"])
        self.assertFalse(report["decision_gate"]["program_owner_review_required"])


if __name__ == "__main__":
    unittest.main()
