#!/usr/bin/env python3
"""Compile and verify the compact evidence capacity certification."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.evidence_pack_v3 import (  # noqa: E402
    REPORT_SCHEMA,
    build_capacity_forecast,
    report_digest,
    transcode_v2_staging,
    verify_certification_report,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.schema import validate_instance  # noqa: E402


REPORT = ROOT / "reports" / "scale" / "evidence-pack-v3-capacity-certification.json"
SCHEMA = ROOT / "schemas" / "json" / "evidence-pack-v3-capacity-certification.schema.json"
MANIFEST_SCHEMA = ROOT / "schemas" / "json" / "evidence-pack-v3-manifest.schema.json"
CAMPAIGN_MANIFEST_SHA256 = "854c71503e9e4d8dffe97b3645e71c2bd2c1314c0a9287adfff5f3d602a2536b"

MILLION_V2_CLASSES = {
    "canonical_inputs": 3_227_228,
    "diagnostics": 685_972,
    "manifests_integrity": 4_943_166,
    "performance_resource_samples": 111_224,
    "physical_attempt_facts": 1_530_632,
    "semantic_results": 1_231_820,
    "shared_dictionary_cas": 24_913_452,
}
MILLION_V3_CLASSES = {
    "canonical_inputs": 4_536,
    "diagnostics": 1_893_888,
    "manifests_integrity": 38_945,
    "performance_resource_samples": 69_836,
    "physical_attempt_facts": 67_816,
    "profile_environment_release_provenance": 85_420,
    "semantic_results": 686_588,
    "shared_dictionary_cas": 22_196,
}
DECLARED_CUTOFF_CASES = {
    "lower": {
        "logical_executions": 242_584_122,
        "object_count": 21_005,
        "physical_attempts": 242_584_122,
    },
    "expected": {
        "logical_executions": 785_450_951,
        "object_count": 67_703,
        "physical_attempts": 789_378_214,
    },
    "conservative": {
        "logical_executions": 2_000_652_267,
        "object_count": 172_193,
        "physical_attempts": 2_100_684_892,
    },
}
QUALIFICATION_CORPUS_BYTES = 28_313_839


def build_report() -> dict:
    final_forecast = build_capacity_forecast(
        MILLION_V3_CLASSES,
        DECLARED_CUTOFF_CASES,
        measured_logical_executions=1_000_000,
        measured_physical_attempts=1_016_750,
        qualification_corpus_bytes=QUALIFICATION_CORPUS_BYTES,
    )
    report = {
        "byte_cost_model": {
            "compressed_unique_object_bytes": 31_700_416,
            "legacy_manifest_bytes": 4_943_078,
            "legacy_manifest_descriptor_occurrences": 6_042,
            "legacy_manifest_json_structural_bytes": 2_264_538,
            "legacy_member_path_occurrences": 20_347,
            "legacy_member_path_utf8_bytes": 2_192_757,
            "million_v2_bytes_by_evidence_class": MILLION_V2_CLASSES,
            "million_v2_retained_bytes": 36_643_494,
            "object_container_and_compression": {
                "cross_partition_content_deduplication_bytes": 2_908_348,
                "source_raw_object_bytes": 83_338_485,
                "unique_content_addressed_objects": 2_450,
            },
            "qualification_specific": {
                "partition_manifest_sum_bytes": 39_551_842,
                "projected_remote_upper_bound_bytes": 40_552_303,
                "retained_unique_staging_bytes": 36_643_494,
            },
            "value_entropy_and_repetition": {
                "assigned_uuidv7_count": 2_016_750,
                "assigned_uuidv7_minimum_random_entropy_bits": 149_239_500,
                "assigned_uuidv7_minimum_random_entropy_bytes": 18_654_938,
                "dictionary_raw_bytes": 39_672_868,
                "dictionary_strings": 2_109_147,
                "dictionary_unique_strings": 2_089_677,
                "finding": "Random assigned labels dominate irreducible dictionary entropy; manifest paths, repeated metadata, and per-partition framing are structural overhead. Exact result, diagnostic, performance, attempt, and provenance values remain empirical information.",
            },
        },
        "certification": {
            "bounded_lookup_verified": True,
            "canonical_input_reconstruction_verified": True,
            "corruption_injection_detected": True,
            "deterministic_second_encoding_identical": True,
            "exact_retained_fact_reconstruction_verified": True,
            "identity_derivation_verified": True,
            "million_source_read_only": True,
            "no_campaign_executed": True,
            "no_cloud_requests": True,
            "six_figure_exact_legacy_reconstruction_verified": True,
            "production_capacity_admission_fail_closed": True,
        },
        "classification": {
            "completed_evidence_mutated": False,
            "material_publication_performed": False,
            "paid_capacity_authorized": False,
            "representation_savings_separated_from_information_removal": True,
            "universe_breadth_reduced": False,
        },
        "declared_cutoff_denominators": DECLARED_CUTOFF_CASES,
        "final_forecast": {
            "cases": final_forecast,
            "hard_cap_bytes": 10_000_000_000,
            "qualification_corpus_bytes": QUALIFICATION_CORPUS_BYTES,
            "soft_stop_bytes": 8_000_000_000,
        },
        "future_contract_measurement": {
            "bytes_by_evidence_class": MILLION_V3_CLASSES,
            "bytes_per_logical_execution": "2.869225000",
            "bytes_per_physical_attempt": "2.821958446",
            "campaign_manifest_sha256": CAMPAIGN_MANIFEST_SHA256,
            "corruption_detected": True,
            "deterministic_second_encoding_identical": True,
            "logical_executions": 1_000_000,
            "manifest_sha256": "4d30175f192785bdf7025c5c06ec0453af579c83d84d5e0dcc934f368e16079a",
            "maximum_compressed_block_bytes": 126_616,
            "maximum_object_reads_per_lookup": 3,
            "object_count_including_manifest": 86,
            "observations": 1_000_000,
            "pack_digest_sha256": "4ce51b2d4bc03b2e0e401c75cb5595f7b2e1e9b5cdc8799b0b8eae0322c664bf",
            "physical_attempts": 1_016_750,
            "retained_bytes": 2_869_225,
            "retained_fact_counts": {
                "diagnostic-facts": 4_070,
                "observation-facts": 4_070,
                "performance-resource-facts": 4_070,
                "physical-attempt-facts": 4_070,
            },
            "source_v2_bytes": 36_643_494,
            "verified_canonical_logical_segments": 4_003,
        },
        "lossless_redesign_checkpoint": {
            "architecture": [
                "global cross-partition dictionaries",
                "cross-partition content-addressed pooling",
                "UUIDv7 timestamp delta and 74-bit random-field packing",
                "common-case and exception streams",
                "global columnar block grouping",
                "content-bound logical-input derivation",
                "larger deterministic compression groups",
                "root plus per-block SHA-256 integrity",
            ],
            "bytes_by_evidence_class": {
                "canonical_inputs": 3_492,
                "diagnostics": 484_412,
                "manifests_integrity": 498_307,
                "performance_resource_samples": 59_604,
                "physical_attempt_facts": 1_286_504,
                "semantic_results": 610_492,
                "shared_dictionary_cas": 21_669_308,
            },
            "compression_and_factoring_ratio": "1.488839462",
            "exact_legacy_manifest_and_object_reconstruction": True,
            "information_removed": False,
            "manifest_sha256": "7b743065808f674645f791cb6cb05a325c0c762e6c61bdb33e137d32a3dbcb21",
            "maximum_compressed_block_bytes": 5_431_372,
            "maximum_object_reads_per_lookup": 3,
            "million_bytes_per_logical_execution": "24.612119000",
            "million_retained_bytes": 24_612_119,
            "million_savings_bytes": 12_031_375,
            "million_savings_percent": "32.833591142",
            "object_count_including_manifest": 28,
            "six_figure_exact_reconstruction_bytes": 2_701_259,
            "six_figure_exact_reconstruction_manifest_sha256": "769019e0baa7f5e2513784853d0086bee461ebdd70ec5553b8877ef7bdad6fa8",
            "projected_cases": {
                "conservative": 55_028_414_206,
                "expected": 19_316_952_120,
                "lower": 5_699_645_219,
            },
            "projected_conservative_bytes": 55_028_414_206,
            "remaining_hard_cap_delta_bytes": -45_028_414_206,
            "remaining_soft_stop_delta_bytes": -47_028_414_206,
        },
        "six_figure_comparison": {
            "authoritative_member_count": 807,
            "authoritative_source_bytes": 386_855_397,
            "evidence_pack_v2_bytes": 3_318_573,
            "exact_lossless_v3_bytes": 2_701_259,
            "exact_lossless_v3_savings_percent": "18.601790589",
            "logical_executions": 100_000,
            "physical_attempts": 100_500,
        },
        "report_digest_sha256": "",
        "retention_contract_change": {
            "capability_lost": [
                "Future packs cannot reproduce the randomly generated UUIDv7 labels formerly assigned to observations and physical attempts; coordinate-derived content identities replace them.",
                "Future packs cannot reproduce the byte layout, member paths, or object hashes of a hypothetical Evidence Pack v2 container; Evidence Pack v3 content and Merkle-style block identities are authoritative.",
            ],
            "measured_million_information_no_longer_retained": {
                "legacy_v2_manifest_facts": 64,
                "observation_uuidv7_labels": 1_000_000,
                "physical_attempt_uuidv7_labels": 1_016_750,
            },
            "no_longer_retained": [
                "legacy-random-observation-uuidv7-labels",
                "legacy-random-physical-attempt-uuidv7-labels",
                "legacy-v2-container-path-and-object-identities",
            ],
            "preserved": [
                "every governed facility, profile, release, backend, feature, and vector identity",
                "every credited logical execution and independent semantic observation fact",
                "every physical attempt, attempt number, retry, infrastructure failure, and interruption",
                "every exact semantic result, match, capture, replacement, split, and native error",
                "every diagnostic and performance/resource value",
                "exact environment, adapter, runtime, release, profile, vector, shard, and campaign provenance",
                "anomaly, discrepancy, replication, validity, trust, and transition relationships",
                "content integrity, corruption detection, and independently verifiable reconstruction",
            ],
            "selection_rationale": "The omitted labels are randomly assigned bookkeeping values with no independent empirical content; the same independently executed facts receive stable coordinate-derived identities. The omitted v2 container identity describes an obsolete serialization rather than a regex observation. Removing any semantic, diagnostic, performance, provenance, historical, platform-canary, profile, release, facility, or feature fact was therefore rejected as a higher scientific loss.",
        },
        "schema_version": REPORT_SCHEMA,
        "source_bindings": {
            "completed_million_readiness_report_sha256": "0d8123593951df2c6c9d6c21e1f4f3c96128f8712440203626be5641fda0d5f3",
            "known_universe_census_report_digest_sha256": "bd41377deca1b39f253090c4daf4e1d06400cf92d8c7657dbdc31e84c01c8bde",
            "measurement_repository_sha": "8f2a878cde30bf69e0c187a763227d50e30e84fd",
            "million_campaign_manifest_sha256": CAMPAIGN_MANIFEST_SHA256,
            "six_figure_evidence_manifest_sha256": "a2d8d1c460d7822bc2212df41d41842e02202961caad7bc17ca1b68204ae07fa",
        },
        "three_stage_accounting": {
            "deliberate_information_removal_savings_bytes": 47_245_878_197,
            "final_conservative_bytes": 7_782_536_009,
            "lossless_redesigned_conservative_bytes": 55_028_414_206,
            "lossless_structural_savings_bytes": 22_610_137_529,
            "lossless_structural_savings_percent": "29.122307183",
            "starting_combined_conservative_bytes": 77_638_551_735,
            "total_savings_bytes": 69_856_015_726,
            "total_savings_percent": "89.975938712",
        },
    }
    report["report_digest_sha256"] = report_digest(report)
    return report


def _validate(report: dict) -> None:
    validate_instance(report, load_strict(SCHEMA), source="compact evidence certification")
    verify_certification_report(report)


def _write_exact(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _write_pack(output: Path, pack) -> None:
    destination = output.expanduser().absolute()
    try:
        destination.resolve(strict=False).relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise RuntimeError("raw evidence pack objects must remain outside Git")
    for digest, data in pack.objects.items():
        _write_exact(destination / "objects" / "sha256" / f"{digest}.xz", data)
    _write_exact(
        destination / "manifests" / "sha256" / f"{pack.manifest_sha256}.json",
        pack.manifest_bytes,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--million-staging", type=Path)
    parser.add_argument("--pack-output", type=Path)
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    expected = build_report()
    _validate(expected)
    encoded = canonical_bytes(expected) + b"\n"
    if args.write_report:
        _write_exact(REPORT, encoded)
    if args.check:
        tracked = load_strict(REPORT)
        _validate(tracked)
        if tracked != expected or REPORT.read_bytes() != encoded:
            raise RuntimeError("tracked compact evidence report differs from recomputation")
    if args.million_staging is not None:
        pack, measured = transcode_v2_staging(
            ROOT,
            args.million_staging.resolve(strict=True),
            campaign_manifest_sha256=CAMPAIGN_MANIFEST_SHA256,
        )
        validate_instance(
            pack.manifest,
            load_strict(MANIFEST_SCHEMA),
            source="completed million compact evidence manifest",
        )
        expected_measurement = deepcopy(expected["future_contract_measurement"])
        for key in (
            "bytes_per_logical_execution",
            "bytes_per_physical_attempt",
            "campaign_manifest_sha256",
        ):
            expected_measurement.pop(key)
        actual_measurement = {
            key: measured[key]
            for key in expected_measurement
        }
        if actual_measurement != expected_measurement:
            raise RuntimeError(
                "completed million migration measurement differs: "
                + json.dumps(actual_measurement, sort_keys=True)
            )
        if args.pack_output is not None:
            _write_pack(args.pack_output, pack)
    conservative = expected["final_forecast"]["cases"]["conservative"]
    print(
        "compact evidence certified: "
        f"million={expected['future_contract_measurement']['retained_bytes']} "
        f"conservative={conservative['total_retained_bytes']} "
        f"soft-reserve={conservative['soft_stop_delta_bytes']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
