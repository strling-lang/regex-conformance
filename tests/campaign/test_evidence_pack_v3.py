from __future__ import annotations

from copy import deepcopy
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

import regex_conformance_scale.evidence_pack_v3 as pack_v3  # noqa: E402
from regex_conformance_scale.factorized_evidence import TokenTables  # noqa: E402


REPORT = ROOT / "reports" / "scale" / "evidence-pack-v3-capacity-certification.json"
REPORT_SCHEMA = ROOT / "schemas" / "json" / "evidence-pack-v3-capacity-certification.schema.json"
MANIFEST_SCHEMA = ROOT / "schemas" / "json" / "evidence-pack-v3-manifest.schema.json"
CAMPAIGN_SHA = "8" * 64


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def sample_blocks() -> list[pack_v3.RetainedBlock]:
    values = {
        "canonical_inputs": {"definitions": ["probe-a"], "rows": 2},
        "diagnostics": {
            "anomaly": "native-error",
            "native_error": {"code": 9, "message": "bad group", "position": 4},
            "stderr": "exact diagnostic",
        },
        "manifests_integrity": {"interruption_count": 1},
        "performance_resource_samples": {"nanoseconds": [41, 39, 40]},
        "physical_attempt_facts": {
            "attempt_numbers": [1, 1, 2],
            "logical_indexes": [0, 1, 1],
        },
        "profile_environment_release_provenance": {
            "environment": "linux-x86-64",
            "profile": "unicode",
            "release": "1.2.3",
        },
        "semantic_results": {
            "observation_count": 2,
            "results": [{"matched": True}, {"matched": False}],
        },
        "shared_dictionary_cas": {"values": ["same", "same"]},
    }
    return [
        pack_v3.RetainedBlock(name, name.replace("_", "-"), 0, value)
        for name, value in values.items()
    ]


class TokenTableTests(unittest.TestCase):
    def test_uuidv7_bit_packing_reconstructs_exact_token_table(self) -> None:
        values = [
            "rcid:v1:physical-run:u7:019ffffd-0128-790a-bca6-6d904a803283",
            "rcid:v1:physical-run:u7:019ffffd-0129-790a-bca6-6d904a803284",
            "rcid:v1:observation:h:jcs-sha256-v1:" + "a" * 64,
            "2026-08-20T12:34:56.789Z",
        ]
        tables = TokenTables.build([values])
        encoded = pack_v3.encode_token_tables(tables)
        decoded, offset = pack_v3.decode_token_tables(encoded)
        self.assertEqual(decoded, tables)
        self.assertEqual(offset, len(encoded))


class ProductionPackTests(unittest.TestCase):
    def test_deterministic_pack_round_trip_and_bounded_lookup(self) -> None:
        blocks = sample_blocks()
        arguments = {
            "campaign_manifest_sha256": CAMPAIGN_SHA,
            "counts": {
                "logical_executions": 2,
                "observations": 2,
                "physical_attempts": 3,
            },
            "canonical_input_derivation": "fixture-compiler-v1",
        }
        first = pack_v3.build_evidence_pack(blocks, **arguments)
        second = pack_v3.build_evidence_pack(blocks, **arguments)
        self.assertEqual(first.manifest_bytes, second.manifest_bytes)
        self.assertEqual(first.objects, second.objects)
        self.assertEqual(
            list(Draft202012Validator(load(MANIFEST_SCHEMA)).iter_errors(first.manifest)),
            [],
        )
        self.assertEqual(
            pack_v3.decode_evidence_pack(first.manifest, first.objects),
            sorted(
                blocks,
                key=lambda item: (item.evidence_class, item.role, item.lookup_group),
            ),
        )
        value, reads = pack_v3.lookup_block(
            first.manifest,
            first.objects,
            role="diagnostics",
            lookup_group=0,
        )
        self.assertEqual(value, blocks[1].value)
        self.assertLessEqual(reads, 3)

    def test_corruption_is_detected_before_decode(self) -> None:
        pack = pack_v3.build_evidence_pack(
            sample_blocks(),
            campaign_manifest_sha256=CAMPAIGN_SHA,
            counts={"logical_executions": 2, "observations": 2, "physical_attempts": 3},
            canonical_input_derivation="fixture-compiler-v1",
        )
        damaged = dict(pack.objects)
        digest = sorted(damaged)[0]
        value = bytearray(damaged[digest])
        value[len(value) // 2] ^= 1
        damaged[digest] = bytes(value)
        with self.assertRaises(pack_v3.EvidencePackV3Error):
            pack_v3.decode_evidence_pack(pack.manifest, damaged)

    def test_coordinate_identities_are_stable_and_attempts_cannot_collapse(self) -> None:
        observation = pack_v3.derive_observation_identity(CAMPAIGN_SHA, 2, 41, 9)
        same = pack_v3.derive_observation_identity(CAMPAIGN_SHA, 2, 41, 9)
        first = pack_v3.derive_physical_attempt_identity(CAMPAIGN_SHA, 2, 41, 9, 1)
        retry = pack_v3.derive_physical_attempt_identity(CAMPAIGN_SHA, 2, 41, 9, 2)
        self.assertEqual(observation, same)
        self.assertNotEqual(observation, first)
        self.assertNotEqual(first, retry)

    def test_omission_rule_preserves_anomalous_empirical_payload(self) -> None:
        value = {
            "anomaly": "native-error",
            "diagnostic": {"message": "exact", "offset": 7},
            "observation_id": "rcid:v1:observation:u7:019ffffd-0128-790a-bca6-6d904a803283",
            "physical_run_id": "rcid:v1:physical-run:u7:019ffffd-0128-790a-bca6-6d904a803284",
            "result": {"matched": False},
        }
        stripped, counts = pack_v3.strip_legacy_assigned_identities(value)
        self.assertEqual(stripped["anomaly"], value["anomaly"])
        self.assertEqual(stripped["diagnostic"], value["diagnostic"])
        self.assertEqual(stripped["result"], value["result"])
        self.assertEqual(counts["observation_uuidv7_labels"], 1)
        self.assertEqual(counts["physical_attempt_uuidv7_labels"], 1)
        invalid = deepcopy(value)
        invalid["observation_id"] = "semantic-name"
        with self.assertRaises(pack_v3.EvidencePackV3Error):
            pack_v3.strip_legacy_assigned_identities(invalid)

    def test_routine_process_summary_reconstructs_and_commitment_verifies(self) -> None:
        stdout = b'{"outcome":"match"}\n'
        original = {
            "canonical_authority": False,
            "diagnostic": None,
            "exit_code": 0,
            "outcome": "completed",
            "provider_plan": {
                "canonical_authority": False,
                "enforced_limits": ["stderr", "stdout", "wall-time"],
                "launch_arguments": [],
                "process_tree_containment": True,
                "provider": "native",
                "semantic_authority": False,
            },
            "semantic_authority": False,
            "stderr_sha256": pack_v3.hashlib.sha256(b"").hexdigest(),
            "stderr_total_bytes": 0,
            "stdout_sha256": pack_v3.hashlib.sha256(stdout).hexdigest(),
            "stdout_total_bytes": len(stdout),
        }
        removed = pack_v3.Counter()
        commitment = pack_v3._RoutineProcessCommitment()
        summary = pack_v3._retain_process_diagnostic(
            original, removed, commitment
        )
        self.assertEqual(
            pack_v3.reconstruct_routine_process_diagnostic(summary, stdout),
            original,
        )
        pack_v3.verify_routine_process_stdout_commitment(
            [original], commitment.value()
        )
        self.assertEqual(removed["routine_success_process_diagnostic_records"], 1)

    def test_nonroutine_process_diagnostic_is_never_summarized(self) -> None:
        value = {
            "canonical_authority": False,
            "diagnostic": {"message": "compile error"},
            "exit_code": 2,
            "outcome": "completed",
            "provider_plan": {"provider": "native"},
            "semantic_authority": False,
            "stderr_sha256": "a" * 64,
            "stderr_total_bytes": 13,
            "stdout_sha256": "b" * 64,
            "stdout_total_bytes": 1,
        }
        commitment = pack_v3._RoutineProcessCommitment()
        self.assertEqual(
            pack_v3._retain_process_diagnostic(value, pack_v3.Counter(), commitment),
            value,
        )
        self.assertEqual(commitment.record_count, 0)

        unknown = deepcopy(value)
        unknown.update(
            {
                "diagnostic": None,
                "exit_code": 0,
                "stderr_sha256": pack_v3.hashlib.sha256(b"").hexdigest(),
                "stderr_total_bytes": 0,
                "unexpected_telemetry": {"must_survive": True},
            }
        )
        self.assertEqual(
            pack_v3._retain_process_diagnostic(
                unknown, pack_v3.Counter(), commitment
            ),
            unknown,
        )
        self.assertEqual(commitment.record_count, 0)

    def test_summary_without_commitment_fails_closed(self) -> None:
        blocks = sample_blocks()
        blocks[1] = pack_v3.RetainedBlock(
            "diagnostics",
            "diagnostic-facts",
            0,
            {"provider_plan": {"provider": "native"}, "routine_success": True},
        )
        with self.assertRaises(pack_v3.EvidencePackV3Error):
            pack_v3.build_evidence_pack(
                blocks,
                campaign_manifest_sha256=CAMPAIGN_SHA,
                counts={
                    "logical_executions": 2,
                    "observations": 2,
                    "physical_attempts": 3,
                },
                canonical_input_derivation="fixture-compiler-v1",
            )

    def test_malformed_commitment_fails_closed(self) -> None:
        blocks = sample_blocks()
        blocks[1] = pack_v3.RetainedBlock(
            "diagnostics",
            "diagnostic-facts",
            0,
            {"provider_plan": {"provider": "native"}, "routine_success": True},
        )
        commitment = pack_v3._RoutineProcessCommitment()
        commitment.add(
            {
                "stdout_sha256": "b" * 64,
                "stdout_total_bytes": 1,
            }
        )
        malformed = commitment.value()
        malformed["unexpected"] = True
        blocks.append(
            pack_v3.RetainedBlock(
                "diagnostics",
                "routine-process-stdout-commitment",
                0,
                malformed,
            )
        )
        with self.assertRaises(pack_v3.EvidencePackV3Error):
            pack_v3.build_evidence_pack(
                blocks,
                campaign_manifest_sha256=CAMPAIGN_SHA,
                counts={
                    "logical_executions": 2,
                    "observations": 2,
                    "physical_attempts": 3,
                },
                canonical_input_derivation="fixture-compiler-v1",
            )


class CapacityCertificationTests(unittest.TestCase):
    def test_tracked_report_recomputes_and_clears_both_capacity_limits(self) -> None:
        report = load(REPORT)
        self.assertEqual(
            list(Draft202012Validator(load(REPORT_SCHEMA)).iter_errors(report)),
            [],
        )
        pack_v3.verify_certification_report(report)
        conservative = report["final_forecast"]["cases"]["conservative"]
        self.assertEqual(conservative["total_retained_bytes"], 4_234_896_306)
        self.assertEqual(conservative["soft_stop_delta_bytes"], 3_765_103_694)
        self.assertEqual(conservative["hard_cap_delta_bytes"], 5_765_103_694)

    def test_forecast_verification_fails_closed_above_soft_stop(self) -> None:
        report = load(REPORT)
        forecast = deepcopy(report["final_forecast"]["cases"])
        measurement = deepcopy(report["future_contract_measurement"]["bytes_by_evidence_class"])
        measurement["diagnostics"] *= 10
        with self.assertRaises(pack_v3.EvidencePackV3Error):
            pack_v3.verify_capacity_forecast(
                measurement,
                report["declared_cutoff_denominators"],
                forecast,
                measured_logical_executions=1_000_000,
                measured_physical_attempts=1_016_750,
                qualification_corpus_bytes=report["final_forecast"]["qualification_corpus_bytes"],
            )


if __name__ == "__main__":
    unittest.main()
