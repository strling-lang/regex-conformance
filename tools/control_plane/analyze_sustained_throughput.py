#!/usr/bin/env python3
"""Reconstruct sustained-envelope throughput and telemetry without mutation."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from fractions import Fraction
import json
import math
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
if str(CONTROL_PLANE) not in sys.path:
    sys.path.insert(0, str(CONTROL_PLANE))

from regex_conformance_control_plane.operating_envelope import (  # noqa: E402
    STABILITY_PHASES,
    build_report,
    canonical_artifact_bytes,
    load_checkpoint_chain,
    load_plan,
    load_workload_binding,
    verify_plan_source_bindings,
)


DEFAULT_PLAN = ROOT / "control-plane" / "qualification" / "sustained-operating-envelope.v1.json"
REPORT_NAME = "operating-envelope-report.json"
WORKLOAD_BINDING_NAME = "workload-binding.json"
RATE_SCALE = 1_000_000_000


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _ceil_fraction(value: Fraction) -> int:
    return (value.numerator + value.denominator - 1) // value.denominator


def _rate(window: Mapping[str, Any]) -> Fraction:
    return Fraction(window["completed_work_count"] * 1_000, window["duration_ms"])


def _scaled_rate(rate: Fraction) -> int:
    return _ceil_fraction(rate * RATE_SCALE)


def _lower_median(values: Sequence[Fraction]) -> Fraction:
    ordered = sorted(values)
    return ordered[(len(ordered) - 1) // 2]


def _degradation(reference: Fraction, observed: Fraction) -> int:
    if reference <= 0:
        return 0
    return _ceil_fraction(max(Fraction(0), reference - observed) * 10_000 / reference)


def _measurement_map(window: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        item["measurement"]: {
            "diagnostic": item["diagnostic"],
            "last": item["last"],
            "maximum": item["maximum"],
            "minimum": item["minimum"],
            "sample_count": item["sample_count"],
            "status": item["status"],
            "unit": item["unit"],
        }
        for item in window["measurement_summaries"]
    }


def _recovery_effects(
    checkpoints: Sequence[Mapping[str, Any]], rates_by_sequence: Mapping[int, Fraction]
) -> list[dict[str, Any]]:
    effects: list[dict[str, Any]] = []
    for index, checkpoint in enumerate(checkpoints):
        if checkpoint["phase"] != "recovery":
            continue
        previous = next(
            (
                candidate
                for candidate in reversed(checkpoints[:index])
                if candidate["phase"] in STABILITY_PHASES
            ),
            None,
        )
        following = None
        superseded = False
        for candidate in checkpoints[index + 1 :]:
            if candidate["phase"] == "interruption":
                superseded = True
                break
            if candidate["phase"] in STABILITY_PHASES:
                following = candidate
                break
        item: dict[str, Any] = {
            "recovery_sequence": checkpoint["sequence"],
            "session_index": checkpoint["session_index"],
            "superseded_before_next_window": superseded,
        }
        if previous is not None:
            item["previous_window_sequence"] = previous["sequence"]
            item["previous_rate_count_per_second_nano"] = _scaled_rate(
                rates_by_sequence[previous["sequence"]]
            )
        else:
            item["previous_window_sequence"] = None
            item["previous_rate_count_per_second_nano"] = None
        if following is not None:
            before = rates_by_sequence[previous["sequence"]] if previous is not None else Fraction(0)
            after = rates_by_sequence[following["sequence"]]
            item["next_window_sequence"] = following["sequence"]
            item["next_rate_count_per_second_nano"] = _scaled_rate(after)
            item["degradation_from_previous_basis_points"] = _degradation(before, after)
        else:
            item["next_window_sequence"] = None
            item["next_rate_count_per_second_nano"] = None
            item["degradation_from_previous_basis_points"] = None
        effects.append(item)
    return effects


def build_analysis(
    plan: Mapping[str, Any], checkpoints: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    stability = [item for item in checkpoints if item["phase"] in STABILITY_PHASES]
    rates = [_rate(item["window"]) for item in stability]
    rates_by_sequence = {
        item["sequence"]: rate for item, rate in zip(stability, rates, strict=True)
    }
    median_rate = _lower_median(rates)
    minimum_rate = min(rates)
    maximum_rate = max(rates)
    rows: list[dict[str, Any]] = []
    for offset, (checkpoint, rate) in enumerate(zip(stability, rates, strict=True), start=1):
        window = checkpoint["window"]
        observed_at = _parse_timestamp(checkpoint["observed_at"])
        rolling = rates[max(0, offset - 6) : offset]
        rows.append(
            {
                "attempt_id": checkpoint["attempt_id"],
                "checkpoint_sequence": checkpoint["sequence"],
                "completed_work_count": window["completed_work_count"],
                "duration_ms": window["duration_ms"],
                "measurements": _measurement_map(window),
                "observed_at": checkpoint["observed_at"],
                "phase": checkpoint["phase"],
                "reported_throughput_count_per_second_milli": (
                    window["completed_work_count"] * 1_000_000
                    + window["duration_ms"]
                    - 1
                )
                // window["duration_ms"],
                "rolling_six_window_median_count_per_second_nano": (
                    _scaled_rate(_lower_median(rolling)) if len(rolling) == 6 else None
                ),
                "sampling_overhead_ms": window["sampling_overhead_ms"],
                "session_index": checkpoint["session_index"],
                "throughput_count_per_second_nano": _scaled_rate(rate),
                "window_end_basis": "checkpoint-observed-at",
                "window_start_at_derived": (
                    observed_at - timedelta(milliseconds=window["duration_ms"])
                ).isoformat().replace("+00:00", "Z"),
                "window_index": offset,
            }
        )

    first_crossing = None
    for offset in range(1, len(rows) + 1):
        prefix = sorted(
            item["reported_throughput_count_per_second_milli"] for item in rows[:offset]
        )
        reference = prefix[(len(prefix) - 1) // 2]
        degradation = (
            math.ceil((reference - prefix[0]) * 10_000 / reference) if reference else 0
        )
        if degradation > plan["maximum_throughput_degradation_basis_points"]:
            first_crossing = {
                "checkpoint_sequence": rows[offset - 1]["checkpoint_sequence"],
                "degradation_basis_points": degradation,
                "stability_window_count": offset,
            }
            break

    original_report = build_report(plan, checkpoints)
    report_rates = sorted(
        item["reported_throughput_count_per_second_milli"] for item in rows
    )
    report_median = report_rates[(len(report_rates) - 1) // 2]
    report_minimum = report_rates[0]
    independent_report_degradation = math.ceil(
        (report_median - report_minimum) * 10_000 / report_median
    )
    early = rates[:12]
    late = rates[-12:]
    pre_recovery = [
        rates_by_sequence[item["sequence"]]
        for item in stability
        if item["phase"] == "steady-load"
    ]
    post_recovery = [
        rates_by_sequence[item["sequence"]]
        for item in stability
        if item["phase"] == "post-recovery"
    ]
    return {
        "events": [
            {
                "attempt_id": item["attempt_id"],
                "observed_at": item["observed_at"],
                "phase": item["phase"],
                "sequence": item["sequence"],
                "session_index": item["session_index"],
            }
            for item in checkpoints
            if item["phase"] in {"interruption", "recovery", "complete"}
        ],
        "recovery_effects": _recovery_effects(checkpoints, rates_by_sequence),
        "summary": {
            "baseline_throughput_status": "unavailable-idle-resource-baseline",
            "checkpoint_count": len(checkpoints),
            "early_twelve_lower_median_count_per_second_nano": _scaled_rate(
                _lower_median(early)
            ),
            "exact_minimum_to_lower_median_degradation_basis_points": _degradation(
                median_rate, minimum_rate
            ),
            "first_governed_running_threshold_crossing": first_crossing,
            "independent_report_degradation_basis_points": independent_report_degradation,
            "independent_report_reproduction": (
                independent_report_degradation
                == original_report["summary"]["throughput_degradation_basis_points"]
            ),
            "late_twelve_lower_median_count_per_second_nano": _scaled_rate(
                _lower_median(late)
            ),
            "lower_median_throughput_count_per_second_nano": _scaled_rate(median_rate),
            "maximum_throughput_count_per_second_nano": _scaled_rate(maximum_rate),
            "minimum_throughput_count_per_second_nano": _scaled_rate(minimum_rate),
            "post_recovery_lower_median_count_per_second_nano": _scaled_rate(
                _lower_median(post_recovery)
            ),
            "pre_recovery_lower_median_count_per_second_nano": _scaled_rate(
                _lower_median(pre_recovery)
            ),
            "reported_degradation_basis_points": original_report["summary"][
                "throughput_degradation_basis_points"
            ],
            "reported_status": original_report["summary"]["status"],
            "stability_window_count": len(stability),
        },
        "windows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruct every sustained-envelope throughput window read-only."
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--checkpoint-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    plan = load_plan(arguments.plan)
    verify_plan_source_bindings(ROOT, plan)
    checkpoints = load_checkpoint_chain(arguments.checkpoint_root, plan)
    binding_path = arguments.checkpoint_root / WORKLOAD_BINDING_NAME
    binding = load_workload_binding(binding_path)
    if binding["plan_digest_sha256"] != plan["plan_digest_sha256"]:
        parser.error("workload binding plan digest differs")
    if binding["workload_digest_sha256"] != checkpoints[-1]["workload_digest_sha256"]:
        parser.error("workload binding digest differs from checkpoint chain")
    report_path = arguments.checkpoint_root / REPORT_NAME
    if report_path.is_file() and report_path.read_bytes() != canonical_artifact_bytes(
        build_report(plan, checkpoints)
    ):
        parser.error("operating-envelope report differs from deterministic reconstruction")
    result = build_analysis(plan, checkpoints)
    result["plan_digest_sha256"] = plan["plan_digest_sha256"]
    result["qualification_id"] = checkpoints[-1]["qualification_id"]
    result["source_revision"] = binding["source_revision"]
    result["workload_digest_sha256"] = binding["workload_digest_sha256"]
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
