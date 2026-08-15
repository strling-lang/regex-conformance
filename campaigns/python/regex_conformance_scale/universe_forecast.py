"""Deterministic P20-T01A universe denominator and raw-corpus forecast."""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785


class FullUniverseForecastError(ValueError):
    """Raised when the universe index or forecast fails closed."""


_INDEX_PATH = "registries/universe/full-known-universe-2026-08-15.v1.json"
_SOURCE_PATHS = (
    _INDEX_PATH,
    "registries/profiles/vertical-slice-coordinates.v1.json",
    "registries/profiles/small-scale-qualification.v1.json",
    "reports/scale/million-scale-capacity-plan.json",
    "campaigns/python/regex_conformance_scale/universe_forecast.py",
    "schemas/json/full-known-universe-index.schema.json",
    "schemas/json/full-known-universe-forecast.schema.json",
    "tools/campaigns/compile_full_known_universe_forecast.py",
)

_P19_RAW = {
    "canonical_logical_input": {"files": 402, "raw_bytes": 69_698_118, "gzip9_bytes": 5_588_247},
    "raw_result_and_attempt": {"files": 404, "raw_bytes": 316_912_761, "gzip9_bytes": 26_282_967},
    "minimal_manifest_integrity": {"files": 1, "raw_bytes": 244_518, "gzip9_bytes": 54_787},
}
_P19_LOGICAL_EXECUTIONS = 100_000
_P19_PHYSICAL_ATTEMPTS = 100_500
_P19_PACKED_BYTES = 31_742_126
_P19_PACKED_MEMBERS = 807


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FullUniverseForecastError(f"{path} is not a JSON object")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _ceil_decimal(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _band(value: dict[str, Any]) -> tuple[int, int, int]:
    result = tuple(int(value[key]) for key in ("lower", "expected", "upper"))
    if not result[0] <= result[1] <= result[2]:
        raise FullUniverseForecastError(f"unordered band: {value!r}")
    return result


def _source_bindings(root: Path) -> list[dict[str, str]]:
    return [
        {"path": path, "sha256": _sha256((root / path).read_bytes())}
        for path in _SOURCE_PATHS
    ]


def _validate_index(index: dict[str, Any]) -> None:
    if index.get("schema_version") != "full-known-universe-index.v1":
        raise FullUniverseForecastError("unexpected universe index schema")
    if index.get("snapshot", {}).get("canonical_registry_authority") is not False:
        raise FullUniverseForecastError("planning index cannot claim canonical authority")
    if index.get("snapshot", {}).get("discovery_exhaustion_claimed") is not False:
        raise FullUniverseForecastError("planning index cannot claim discovery exhaustion")
    if any(index.get("classification", {}).values()):
        raise FullUniverseForecastError("planning index cannot authorize execution or mutation")

    facilities = index.get("facilities")
    candidates = index.get("other_candidates")
    if not isinstance(facilities, list) or len(facilities) < 60:
        raise FullUniverseForecastError("facility breadth floor is not met")
    if not isinstance(candidates, list) or len(candidates) < 12:
        raise FullUniverseForecastError("candidate disposition breadth floor is not met")
    facility_keys = [item.get("key") for item in facilities]
    candidate_keys = [item.get("key") for item in candidates]
    if len(set(facility_keys + candidate_keys)) != len(facility_keys) + len(candidate_keys):
        raise FullUniverseForecastError("candidate/facility keys are not unique")
    facility_key_set = set(facility_keys)
    archetypes = index.get("obligation_archetypes", {})
    for value in archetypes.values():
        _band(value)
    for facility in facilities:
        if facility.get("archetype") not in archetypes:
            raise FullUniverseForecastError(f"unknown archetype for {facility.get('key')}")
        current = facility.get("current_profiles")
        lower, _, _ = _band(facility.get("historical_profiles", {}))
        if not isinstance(current, int) or current < 0 or current > lower:
            raise FullUniverseForecastError(f"invalid current profile count for {facility.get('key')}")
        if current and not facility.get("current_representatives"):
            raise FullUniverseForecastError(f"active facility lacks representative selector: {facility.get('key')}")
        if not str(facility.get("source", "")).startswith("https://"):
            raise FullUniverseForecastError(f"facility lacks an HTTPS primary source: {facility.get('key')}")
    for candidate in candidates:
        if candidate.get("disposition") == "alias-to-facility" and candidate.get("target") not in facility_key_set:
            raise FullUniverseForecastError(f"dangling alias: {candidate.get('key')}")
        if not str(candidate.get("source", "")).startswith("https://"):
            raise FullUniverseForecastError(f"candidate lacks an HTTPS source: {candidate.get('key')}")

    classes = index.get("discovery_coverage", {}).get("applied_source_classes", [])
    if len(classes) != 13 or len(set(classes)) != 13:
        raise FullUniverseForecastError("all thirteen discovery source classes must be dispositioned")


def _logical_denominator(index: dict[str, Any], *, historical: bool) -> dict[str, int]:
    totals = [0, 0, 0]
    archetypes = index["obligation_archetypes"]
    for facility in index["facilities"]:
        profiles = (
            _band(facility["historical_profiles"])
            if historical
            else (facility["current_profiles"],) * 3
        )
        obligations = _band(archetypes[facility["archetype"]])
        for ordinal in range(3):
            totals[ordinal] += profiles[ordinal] * obligations[ordinal]
    return dict(zip(("lower", "expected", "upper"), totals, strict=True))


def _multiply_band(band: dict[str, int], multiplier: dict[str, str]) -> dict[str, int]:
    return {
        key: _ceil_decimal(Decimal(band[key]) * Decimal(multiplier[key]))
        for key in ("lower", "expected", "upper")
    }


def _attempts(logical: dict[str, int], policy: dict[str, Any]) -> dict[str, int]:
    expected_rate = Decimal(policy["expected_retry_rate"])
    conservative_rate = Decimal(policy["conservative_retry_rate"])
    return {
        "lower": logical["lower"],
        "expected": _ceil_decimal(Decimal(logical["expected"]) * (Decimal(1) + expected_rate)),
        "upper": _ceil_decimal(Decimal(logical["upper"]) * (Decimal(1) + conservative_rate)),
    }


def _object_envelope(logical: dict[str, int], policy: dict[str, Any]) -> dict[str, Any]:
    shard = int(policy["result_shard_size"])
    pack_members = int(policy["raw_members_per_lossless_pack"])
    retry_expected = Decimal(policy["expected_retry_rate"])
    retry_upper = Decimal(policy["conservative_retry_rate"])

    def counts(n: int, retry: Decimal) -> dict[str, int]:
        logical_shards = (n + shard - 1) // shard
        attempt_only = (_ceil_decimal(Decimal(n) * retry) + shard - 1) // shard
        raw_members = logical_shards * 2 + attempt_only + 3
        packed_objects = (raw_members + pack_members - 1) // pack_members + 1
        return {
            "logical_segment_objects": logical_shards,
            "result_segment_objects": logical_shards,
            "attempt_only_objects": attempt_only,
            "minimal_control_objects": 3,
            "unpacked_raw_objects": raw_members,
            "lossless_pack_objects_including_manifest": packed_objects,
            "class_a_puts": packed_objects,
            "class_b_readbacks": packed_objects,
        }

    return {
        "expected": counts(logical["expected"], retry_expected),
        "conservative": counts(logical["upper"], retry_upper),
        "raw_members_per_pack": pack_members,
        "normal_list_requests": 0,
    }


def _project_raw_classes(
    logical_executions: int,
    physical_attempts: int,
    *,
    byte_field: str,
) -> dict[str, int]:
    """Scale logical and attempt-bearing P19 raw classes on their proper units."""

    return {
        "canonical_logical_input": _ceil_decimal(
            Decimal(logical_executions)
            * Decimal(_P19_RAW["canonical_logical_input"][byte_field])
            / Decimal(_P19_LOGICAL_EXECUTIONS)
        ),
        "raw_result_and_attempt": _ceil_decimal(
            Decimal(physical_attempts)
            * Decimal(_P19_RAW["raw_result_and_attempt"][byte_field])
            / Decimal(_P19_PHYSICAL_ATTEMPTS)
        ),
        "minimal_manifest_integrity": _ceil_decimal(
            Decimal(logical_executions)
            * Decimal(_P19_RAW["minimal_manifest_integrity"][byte_field])
            / Decimal(_P19_LOGICAL_EXECUTIONS)
        ),
    }


def _packed_projection(gzip_classes: dict[str, int]) -> dict[str, int]:
    """Allocate the measured deterministic packing gain proportionally by class."""

    gzip_total = sum(item["gzip9_bytes"] for item in _P19_RAW.values())
    ratio = Decimal(_P19_PACKED_BYTES) / Decimal(gzip_total)
    return {
        key: _ceil_decimal(Decimal(value) * ratio)
        for key, value in gzip_classes.items()
    }


def _retry_overhead_bytes(
    logical_executions: int,
    physical_attempts: int,
) -> dict[str, int]:
    no_retry = _project_raw_classes(
        logical_executions,
        logical_executions,
        byte_field="gzip9_bytes",
    )
    with_retry = _project_raw_classes(
        logical_executions,
        physical_attempts,
        byte_field="gzip9_bytes",
    )
    no_retry_packed = _packed_projection(no_retry)
    with_retry_packed = _packed_projection(with_retry)
    return {
        "additional_physical_attempts": physical_attempts - logical_executions,
        "packed_raw_result_and_attempt_bytes": (
            with_retry_packed["raw_result_and_attempt"]
            - no_retry_packed["raw_result_and_attempt"]
        ),
    }


def _bytes_for(logical: dict[str, int], policy: dict[str, Any]) -> dict[str, Any]:
    expected_reserve = Decimal(policy["expected_diagnostics_reserve_rate"])
    conservative_reserve = Decimal(policy["conservative_diagnostics_reserve_rate"])
    fixed_reserve = int(policy["conservative_fixed_reserve_bytes"])
    physical = _attempts(logical, policy)

    lower_raw_classes = _project_raw_classes(
        logical["lower"], physical["lower"], byte_field="raw_bytes"
    )
    lower_gzip_classes = _project_raw_classes(
        logical["lower"], physical["lower"], byte_field="gzip9_bytes"
    )
    lower_packed_classes = _packed_projection(lower_gzip_classes)

    expected_raw_classes = _project_raw_classes(
        logical["expected"], physical["expected"], byte_field="raw_bytes"
    )
    expected_gzip_classes = _project_raw_classes(
        logical["expected"], physical["expected"], byte_field="gzip9_bytes"
    )
    expected_packed_classes = _packed_projection(expected_gzip_classes)
    expected_raw_base = sum(expected_raw_classes.values())
    expected_individual_base = sum(expected_gzip_classes.values())
    expected_packed_base = sum(expected_packed_classes.values())
    expected_raw_diagnostics = _ceil_decimal(Decimal(expected_raw_base) * expected_reserve)
    expected_individual_diagnostics = _ceil_decimal(
        Decimal(expected_individual_base) * expected_reserve
    )
    expected_packed_diagnostics = _ceil_decimal(
        Decimal(expected_packed_base) * expected_reserve
    )

    conservative_raw_classes = _project_raw_classes(
        logical["upper"], physical["upper"], byte_field="raw_bytes"
    )
    conservative_gzip_classes = _project_raw_classes(
        logical["upper"], physical["upper"], byte_field="gzip9_bytes"
    )
    conservative_packed_classes = _packed_projection(conservative_gzip_classes)
    conservative_raw_base = sum(conservative_raw_classes.values())
    conservative_individual_base = sum(conservative_gzip_classes.values())
    conservative_packed_base = sum(conservative_packed_classes.values())
    conservative_raw_diagnostics = _ceil_decimal(
        Decimal(conservative_raw_base) * conservative_reserve
    )
    conservative_individual_diagnostics = _ceil_decimal(
        Decimal(conservative_individual_base) * conservative_reserve
    )
    conservative_packed_diagnostics = _ceil_decimal(
        Decimal(conservative_packed_base) * conservative_reserve
    )

    return {
        "lower": {
            "packed_gzip9_raw_only_bytes_without_reserves": sum(lower_packed_classes.values()),
            "physical_attempts": physical["lower"],
        },
        "expected": {
            "physical_attempts": physical["expected"],
            "uncompressed_raw_class_projection_bytes_before_diagnostics": expected_raw_classes,
            "uncompressed_required_raw_diagnostics_reserve_bytes": expected_raw_diagnostics,
            "uncompressed_raw_only_bytes_with_diagnostics_reserve": (
                expected_raw_base + expected_raw_diagnostics
            ),
            "independent_gzip9_raw_class_projection_bytes_before_diagnostics": expected_gzip_classes,
            "independent_gzip9_required_raw_diagnostics_reserve_bytes": expected_individual_diagnostics,
            "independent_gzip9_raw_only_bytes_with_diagnostics_reserve": (
                expected_individual_base + expected_individual_diagnostics
            ),
            "packed_gzip9_raw_class_projection_bytes_before_diagnostics": expected_packed_classes,
            "packed_gzip9_required_raw_diagnostics_reserve_bytes": expected_packed_diagnostics,
            "packed_gzip9_raw_only_bytes_with_diagnostics_reserve": (
                expected_packed_base + expected_packed_diagnostics
            ),
            "retry_overhead": _retry_overhead_bytes(
                logical["expected"], physical["expected"]
            ),
        },
        "conservative": {
            "physical_attempts": physical["upper"],
            "uncompressed_raw_class_projection_bytes_before_reserves": conservative_raw_classes,
            "uncompressed_required_raw_diagnostics_reserve_bytes": conservative_raw_diagnostics,
            "uncompressed_raw_only_bytes_with_reserves": (
                conservative_raw_base + conservative_raw_diagnostics + fixed_reserve
            ),
            "independent_gzip9_raw_class_projection_bytes_before_reserves": conservative_gzip_classes,
            "independent_gzip9_required_raw_diagnostics_reserve_bytes": conservative_individual_diagnostics,
            "independent_gzip9_raw_only_bytes_with_reserves": (
                conservative_individual_base
                + conservative_individual_diagnostics
                + fixed_reserve
            ),
            "packed_gzip9_raw_class_projection_bytes_before_reserves": conservative_packed_classes,
            "packed_gzip9_required_raw_diagnostics_reserve_bytes": conservative_packed_diagnostics,
            "packed_gzip9_raw_only_bytes_with_reserves": (
                conservative_packed_base + conservative_packed_diagnostics + fixed_reserve
            ),
            "fixed_reserve_bytes": fixed_reserve,
            "retry_overhead": _retry_overhead_bytes(
                logical["upper"], physical["upper"]
            ),
        },
    }


def _contributor_analysis(
    index: dict[str, Any],
    current: dict[str, int],
    historical: dict[str, int],
    final_stable: dict[str, int],
) -> dict[str, Any]:
    archetypes = index["obligation_archetypes"]
    facilities = []
    archetype_totals: dict[str, int] = {}
    one_profile_per_current_representative = 0
    for facility in index["facilities"]:
        obligation = int(archetypes[facility["archetype"]]["expected"])
        contribution = int(facility["historical_profiles"]["expected"]) * obligation
        facilities.append(
            {
                "facility_key": facility["key"],
                "expected_historical_logical_executions": contribution,
            }
        )
        archetype = facility["archetype"]
        archetype_totals[archetype] = archetype_totals.get(archetype, 0) + contribution
        one_profile_per_current_representative += (
            len(facility["current_representatives"]) * obligation
        )
    facilities.sort(
        key=lambda item: (-item["expected_historical_logical_executions"], item["facility_key"])
    )
    archetype_rows = [
        {
            "archetype": key,
            "expected_historical_logical_executions": value,
        }
        for key, value in sorted(
            archetype_totals.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    return {
        "largest_expected_historical_facility_contributors": facilities[:10],
        "expected_historical_archetype_contributors": archetype_rows,
        "d101": {
            "active_current_release_line_representatives": sum(
                len(item["current_representatives"]) for item in index["facilities"]
            ),
            "active_unit": "latest stable patch or update per governed release line",
            "superseded_patch_execution_credit": 0,
            "avoided_servicing_patch_executions": "not quantified because the P21 canonical supersession ledger does not yet exist",
        },
        "expected_effects": {
            "current_profile_multiplicity_increment_over_one_profile_per_current_representative": (
                current["expected"] - one_profile_per_current_representative
            ),
            "historical_stable_increment_before_platform_expansion": (
                historical["expected"] - current["expected"]
            ),
            "platform_architecture_increment": (
                final_stable["expected"] - historical["expected"]
            ),
        },
    }


def build_full_known_universe_forecast(root: Path) -> dict[str, Any]:
    """Build the bounded final-corpus forecast from the reviewed planning index."""

    index = _load(root / _INDEX_PATH)
    _validate_index(index)
    capacity = _load(root / "reports/scale/million-scale-capacity-plan.json")
    basis = capacity.get("p19_measured_basis", {})
    if basis.get("artifact_bytes", {}).get("evidence") != 317_157_279:
        raise FullUniverseForecastError("P19 evidence byte basis changed")
    if basis.get("artifact_bytes", {}).get("logical_segments") != 69_698_118:
        raise FullUniverseForecastError("P19 logical byte basis changed")
    if basis.get("attempts", {}).get("physical_attempts") != 100_500:
        raise FullUniverseForecastError("P19 retry basis changed")

    policy = index["forecast_policy"]
    current = _logical_denominator(index, historical=False)
    historical = _logical_denominator(index, historical=True)
    final_stable = _multiply_band(historical, policy["final_platform_architecture_multiplier"])
    platform_increment = {
        key: final_stable[key] - historical[key]
        for key in ("lower", "expected", "upper")
    }
    prerelease_profiles = _band(policy["optional_prerelease_profile_count"])
    prerelease = {
        "lower": prerelease_profiles[0] * 11_538,
        "expected": prerelease_profiles[1] * 25_000,
        "upper": prerelease_profiles[2] * 60_000,
    }
    denominators = {
        "current_stable": {"logical_executions": current, "physical_attempts": _attempts(current, policy)},
        "full_historical_stable": {"logical_executions": historical, "physical_attempts": _attempts(historical, policy)},
        "material_platform_architecture_increment": {"logical_executions": platform_increment},
        "final_stable_certification": {"logical_executions": final_stable, "physical_attempts": _attempts(final_stable, policy)},
        "optional_prerelease_separate": {"logical_executions": prerelease, "physical_attempts": _attempts(prerelease, policy)},
    }

    raw_corpus = {
        stage: {
            "bytes": _bytes_for(value["logical_executions"], policy),
            "objects_and_requests": _object_envelope(value["logical_executions"], policy),
        }
        for stage, value in denominators.items()
        if stage in {"current_stable", "full_historical_stable", "final_stable_certification", "optional_prerelease_separate"}
    }
    qualification_retention = {
        "campaign": "P19 Session 05 100K qualification",
        "logical_executions": _P19_LOGICAL_EXECUTIONS,
        "physical_attempts": _P19_PHYSICAL_ATTEMPTS,
        "raw_member_count": _P19_PACKED_MEMBERS,
        "uncompressed_raw_only_bytes": sum(
            item["raw_bytes"] for item in _P19_RAW.values()
        ),
        "packed_gzip9_raw_only_bytes": _P19_PACKED_BYTES,
        "lossless_pack_objects_including_manifest": 2,
        "class_a_puts": 2,
        "class_b_readbacks": 2,
        "normal_list_requests": 0,
    }
    final_bytes = raw_corpus["final_stable_certification"]["bytes"]
    final_requests = raw_corpus["final_stable_certification"][
        "objects_and_requests"
    ]
    lower_production_packed = final_bytes["lower"][
        "packed_gzip9_raw_only_bytes_without_reserves"
    ]
    expected_production_packed = final_bytes["expected"][
        "packed_gzip9_raw_only_bytes_with_diagnostics_reserve"
    ]
    conservative_production_packed = final_bytes["conservative"][
        "packed_gzip9_raw_only_bytes_with_reserves"
    ]
    lower_packed = lower_production_packed + _P19_PACKED_BYTES
    expected_packed = expected_production_packed + _P19_PACKED_BYTES
    conservative_packed = conservative_production_packed + _P19_PACKED_BYTES
    expected_a = (
        final_requests["expected"]["class_a_puts"]
        + qualification_retention["class_a_puts"]
    )
    conservative_a = (
        final_requests["conservative"]["class_a_puts"]
        + qualification_retention["class_a_puts"]
    )
    retained_totals = {
        "lower": {
            "packed_gzip9_raw_only_bytes_without_reserves": lower_packed,
        },
        "expected": {
            "uncompressed_raw_only_bytes_with_diagnostics_reserve": (
                final_bytes["expected"][
                    "uncompressed_raw_only_bytes_with_diagnostics_reserve"
                ]
                + qualification_retention["uncompressed_raw_only_bytes"]
            ),
            "packed_gzip9_raw_only_bytes_with_diagnostics_reserve": expected_packed,
            "lossless_pack_objects_including_manifests": (
                final_requests["expected"][
                    "lossless_pack_objects_including_manifest"
                ]
                + qualification_retention[
                    "lossless_pack_objects_including_manifest"
                ]
            ),
            "class_a_puts": expected_a,
            "class_b_readbacks": (
                final_requests["expected"]["class_b_readbacks"]
                + qualification_retention["class_b_readbacks"]
            ),
        },
        "conservative": {
            "uncompressed_raw_only_bytes_with_reserves": (
                final_bytes["conservative"][
                    "uncompressed_raw_only_bytes_with_reserves"
                ]
                + qualification_retention["uncompressed_raw_only_bytes"]
            ),
            "packed_gzip9_raw_only_bytes_with_reserves": conservative_packed,
            "lossless_pack_objects_including_manifests": (
                final_requests["conservative"][
                    "lossless_pack_objects_including_manifest"
                ]
                + qualification_retention[
                    "lossless_pack_objects_including_manifest"
                ]
            ),
            "class_a_puts": conservative_a,
            "class_b_readbacks": (
                final_requests["conservative"]["class_b_readbacks"]
                + qualification_retention["class_b_readbacks"]
            ),
        },
    }
    raw_corpus["qualification_campaign_evidence_separate"] = qualification_retention
    raw_corpus["final_retained_totals"] = retained_totals
    soft = int(policy["soft_limit_bytes"])
    hard = int(policy["hard_limit_bytes"])
    decision_required = (
        lower_packed > hard
        or expected_packed > soft
        or conservative_packed > hard
        or expected_a > 1_000_000
        or conservative_a > 1_000_000
    )

    reps = [
        representative
        for facility in index["facilities"]
        for representative in facility["current_representatives"]
    ]
    selector_markers = ("latest", "official", "source-resolved", "current", "supported")
    selector_count = sum(any(marker in value for marker in selector_markers) for value in reps)
    dispositions: dict[str, int] = {"in-scope": len(index["facilities"])}
    for candidate in index["other_candidates"]:
        disposition = candidate["disposition"]
        dispositions[disposition] = dispositions.get(disposition, 0) + 1

    body: dict[str, Any] = {
        "schema_version": "full-known-universe-forecast.v1",
        "classification": {
            "canonical_registry_authority": False,
            "docker_authorized": False,
            "external_evidence_mutated": False,
            "normative_authority": False,
            "p20_t02_authorized": False,
            "planning_only": True,
            "production_publication_performed": False,
            "r2_accessed": False,
            "semantic_authority": False,
            "permitted_remote_classes": [
                "canonical-logical-input",
                "raw-result-and-attempt-evidence",
                "required-raw-diagnostics",
                "minimal-manifest-and-integrity",
                "lossless-raw-record-pack",
            ],
            "forbidden_remote_classes": [
                "analytical-cache",
                "compatibility-dataset",
                "derived-index",
                "normalized-observation",
                "parquet",
                "public-site-artifact",
                "report",
                "summary",
                "warehouse",
            ],
        },
        "cutoff_date": "2026-08-15",
        "source_bindings": _source_bindings(root),
        "index_summary": {
            "facility_count": len(index["facilities"]),
            "other_candidate_count": len(index["other_candidates"]),
            "total_candidate_count": len(index["facilities"]) + len(index["other_candidates"]),
            "disposition_counts": dispositions,
            "current_profile_count": sum(item["current_profiles"] for item in index["facilities"]),
            "historical_profile_count": {
                key: sum(item["historical_profiles"][key] for item in index["facilities"])
                for key in ("lower", "expected", "upper")
            },
            "current_representative_count": len(reps),
            "exact_literal_current_representative_count": len(reps) - selector_count,
            "governed_selector_current_representative_count": selector_count,
            "release_history_status": "exact-where-primary-history-is-complete-otherwise-bounded",
            "canonical_c1_c2_status": "provisional-until-p21-registry-and-scanners",
        },
        "contributor_analysis": _contributor_analysis(
            index,
            current,
            historical,
            final_stable,
        ),
        "measured_basis": {
            "campaign": "P19 Session 05 100K qualification",
            "logical_executions": _P19_LOGICAL_EXECUTIONS,
            "physical_attempts": _P19_PHYSICAL_ATTEMPTS,
            "retry_rate": "0.005",
            "raw_classes": _P19_RAW,
            "uncompressed_raw_only_bytes": sum(item["raw_bytes"] for item in _P19_RAW.values()),
            "independent_gzip9_bytes": sum(item["gzip9_bytes"] for item in _P19_RAW.values()),
            "deterministic_tar_gzip9": {
                "member_count": _P19_PACKED_MEMBERS,
                "packed_bytes": _P19_PACKED_BYTES,
                "reconstruction_verified": True,
                "tar_metadata": "sorted paths; mtime=0; uid=gid=0; empty owner names; mode=0644",
            },
            "compression_ratios": {
                "independent_gzip9_over_raw": str(
                    (Decimal(sum(item["gzip9_bytes"] for item in _P19_RAW.values())) / Decimal(sum(item["raw_bytes"] for item in _P19_RAW.values()))).quantize(Decimal("0.000000001"))
                ),
                "packed_gzip9_over_raw": str(
                    (Decimal(_P19_PACKED_BYTES) / Decimal(sum(item["raw_bytes"] for item in _P19_RAW.values()))).quantize(Decimal("0.000000001"))
                ),
            },
        },
        "denominators": denominators,
        "raw_corpus_forecast": raw_corpus,
        "service_envelope": {
            "provider": "Cloudflare R2 Standard",
            "official_limits_retrieved_on": "2026-08-15",
            "provider_bucket_storage_limit": "unlimited",
            "provider_object_count_limit": "unlimited",
            "provider_single_part_upload_limit": "4.995 GiB",
            "free_tier": {
                "storage_gb_month_decimal": 10,
                "class_a_requests_per_month": 1_000_000,
                "class_b_requests_per_month": 10_000_000,
                "applies_to_standard_storage_only": True,
            },
            "program_limits": {"soft_bytes": soft, "hard_bytes": hard},
            "sources": [
                "https://developers.cloudflare.com/r2/pricing/",
                "https://developers.cloudflare.com/r2/platform/limits/",
            ],
        },
        "decision_gate": {
            "decision_required": decision_required,
            "outcome": "stop-and-request-program-owner-decision" if decision_required else "safe-to-continue",
            "lower_bound_final_packed_bytes_without_reserves": lower_packed,
            "lower_bound_production_packed_bytes_without_reserves": lower_production_packed,
            "qualification_campaign_packed_bytes": _P19_PACKED_BYTES,
            "lower_bound_exceeds_hard_by_bytes": max(0, lower_packed - hard),
            "lower_bound_remaining_hard_reserve_bytes": max(0, hard - lower_packed),
            "expected_final_packed_bytes": expected_packed,
            "expected_production_packed_bytes": expected_production_packed,
            "conservative_final_packed_bytes": conservative_packed,
            "conservative_production_packed_bytes": conservative_production_packed,
            "expected_exceeds_soft_by_bytes": max(0, expected_packed - soft),
            "expected_remaining_soft_reserve_bytes": max(0, soft - expected_packed),
            "conservative_exceeds_hard_by_bytes": max(0, conservative_packed - hard),
            "conservative_remaining_hard_reserve_bytes": max(
                0, hard - conservative_packed
            ),
            "expected_class_a_requests": expected_a,
            "conservative_class_a_requests": conservative_a,
            "scope_reduction_permitted": False,
            "retention_weakening_permitted": False,
            "paid_storage_authorized": False,
            "p20_t02_must_remain_planned": True,
        },
    }
    body["report_digest_sha256"] = _sha256(rfc8785.dumps(body))
    return body


def verify_full_known_universe_forecast(root: Path, report: dict[str, Any]) -> None:
    """Recompute every identity, denominator, storage class, and decision gate."""

    digest_input = deepcopy(report)
    claimed = digest_input.pop("report_digest_sha256", None)
    if claimed != _sha256(rfc8785.dumps(digest_input)):
        raise FullUniverseForecastError("forecast digest differs")
    rebuilt = build_full_known_universe_forecast(root)
    if report != rebuilt:
        raise FullUniverseForecastError("forecast differs from deterministic rebuild")

    classification = report["classification"]
    if classification["r2_accessed"] or classification["production_publication_performed"]:
        raise FullUniverseForecastError("forecast cannot access or publish to R2")
    if set(classification["permitted_remote_classes"]) & set(classification["forbidden_remote_classes"]):
        raise FullUniverseForecastError("remote artifact classes overlap")
    denominators = report["denominators"]
    for value in denominators.values():
        logical = value["logical_executions"]
        if not logical["lower"] <= logical["expected"] <= logical["upper"]:
            raise FullUniverseForecastError("logical denominator band is unordered")
        attempts = value.get("physical_attempts")
        if attempts and not (
            logical["lower"] <= attempts["lower"]
            and logical["expected"] <= attempts["expected"]
            and logical["upper"] <= attempts["upper"]
        ):
            raise FullUniverseForecastError("physical attempts do not cover logical executions")
    raw_corpus = report["raw_corpus_forecast"]
    qualification = raw_corpus["qualification_campaign_evidence_separate"]
    retained = raw_corpus["final_retained_totals"]
    final_bytes = raw_corpus["final_stable_certification"]["bytes"]
    final_requests = raw_corpus["final_stable_certification"][
        "objects_and_requests"
    ]
    if qualification["uncompressed_raw_only_bytes"] != sum(
        item["raw_bytes"] for item in _P19_RAW.values()
    ) or qualification["packed_gzip9_raw_only_bytes"] != _P19_PACKED_BYTES:
        raise FullUniverseForecastError("qualification retention differs from measured basis")
    retained_byte_keys = {
        "expected": (
            "uncompressed_raw_only_bytes_with_diagnostics_reserve",
            "packed_gzip9_raw_only_bytes_with_diagnostics_reserve",
        ),
        "conservative": (
            "uncompressed_raw_only_bytes_with_reserves",
            "packed_gzip9_raw_only_bytes_with_reserves",
        ),
    }
    for case, (uncompressed_key, packed_key) in retained_byte_keys.items():
        if retained[case][uncompressed_key] != (
            final_bytes[case][uncompressed_key]
            + qualification["uncompressed_raw_only_bytes"]
        ) or retained[case][packed_key] != (
            final_bytes[case][packed_key]
            + qualification["packed_gzip9_raw_only_bytes"]
        ):
            raise FullUniverseForecastError("retained storage does not reconcile")
        if retained[case]["lossless_pack_objects_including_manifests"] != (
            final_requests[case]["lossless_pack_objects_including_manifest"]
            + qualification["lossless_pack_objects_including_manifest"]
        ):
            raise FullUniverseForecastError("retained object forecast does not reconcile")
        if retained[case]["class_a_puts"] != (
            final_requests[case]["class_a_puts"] + qualification["class_a_puts"]
        ) or retained[case]["class_b_readbacks"] != (
            final_requests[case]["class_b_readbacks"]
            + qualification["class_b_readbacks"]
        ):
            raise FullUniverseForecastError("retained request forecast does not reconcile")
    gate = report["decision_gate"]
    if (
        gate["lower_bound_final_packed_bytes_without_reserves"]
        != retained["lower"]["packed_gzip9_raw_only_bytes_without_reserves"]
        or gate["expected_final_packed_bytes"]
        != retained["expected"][
            "packed_gzip9_raw_only_bytes_with_diagnostics_reserve"
        ]
        or gate["conservative_final_packed_bytes"]
        != retained["conservative"]["packed_gzip9_raw_only_bytes_with_reserves"]
        or gate["expected_class_a_requests"]
        != retained["expected"]["class_a_puts"]
        or gate["conservative_class_a_requests"]
        != retained["conservative"]["class_a_puts"]
    ):
        raise FullUniverseForecastError("decision gate omits retained evidence")
    if report["decision_gate"]["decision_required"] is not True:
        raise FullUniverseForecastError("current forecast must stop at the owner decision gate")
    if report["decision_gate"]["p20_t02_must_remain_planned"] is not True:
        raise FullUniverseForecastError("P20-T02 gate was weakened")
