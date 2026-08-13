"""Fail-closed attribution of controlled execution faults.

The classifier consumes bounded supervisor/protocol/environment facts.  It
never infers target behavior from a process symptom alone.
"""

from __future__ import annotations

import re
from typing import Any

from .state_models import canonical_object


TOKEN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
INJECTION_POINTS = frozenset(
    {
        "adapter-process",
        "evidence-storage",
        "network-acquisition",
        "target-invocation",
        "worker-process",
    }
)
CONTAINMENT_OUTCOMES = frozenset(
    {
        "completed",
        "cpu-time-limit",
        "launch-failed",
        "not-run",
        "stderr-limit",
        "stdout-limit",
        "wall-time-limit",
    }
)
PROTOCOL_CHECKPOINTS = frozenset(
    {"not-applicable", "target-invocation-started", "target-not-started", "target-response-complete"}
)
ADAPTER_RESPONSE_STATES = frozenset({"malformed", "missing", "not-applicable", "valid"})
HEALTH_STATES = frozenset({"healthy", "unhealthy", "unknown"})
FAULT_STIMULUS_SCHEMA_VERSION = "deliberate-fault-stimulus.v1"
FAULT_ASSESSMENT_SCHEMA_VERSION = "fault-attribution-assessment.v1"


class FaultAttributionError(ValueError):
    """Fault facts are malformed, contradictory, or outside the closed vocabulary."""


def _require_enum(value: Any, allowed: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise FaultAttributionError(f"{label} is outside the closed vocabulary")
    return value


def validate_stimulus(value: dict[str, Any]) -> None:
    if not isinstance(value, dict) or set(value) != {
        "adapter_response_state",
        "containment",
        "environment_health_after",
        "environment_health_before",
        "fault_key",
        "injection_point",
        "network_observation",
        "protocol_checkpoint",
        "schema_version",
        "storage_observation",
        "supervisor_health",
    }:
        raise FaultAttributionError("fault stimulus requires the exact bounded fact set")
    if value["schema_version"] != FAULT_STIMULUS_SCHEMA_VERSION:
        raise FaultAttributionError("unsupported deliberate-fault stimulus schema")
    key = value["fault_key"]
    if not isinstance(key, str) or TOKEN.fullmatch(key) is None:
        raise FaultAttributionError("fault key must be a canonical token")
    _require_enum(value["injection_point"], INJECTION_POINTS, "injection point")
    _require_enum(value["protocol_checkpoint"], PROTOCOL_CHECKPOINTS, "protocol checkpoint")
    _require_enum(value["adapter_response_state"], ADAPTER_RESPONSE_STATES, "adapter response state")
    _require_enum(value["environment_health_before"], HEALTH_STATES, "pre-fault environment health")
    _require_enum(value["environment_health_after"], HEALTH_STATES, "post-fault environment health")
    _require_enum(value["supervisor_health"], HEALTH_STATES, "supervisor health")
    _require_enum(value["network_observation"], frozenset({"none", "transport-failed"}), "network observation")
    _require_enum(value["storage_observation"], frozenset({"none", "publication-failed"}), "storage observation")
    containment = value["containment"]
    if not isinstance(containment, dict) or set(containment) != {"exit_code", "outcome"}:
        raise FaultAttributionError("containment fact requires exact outcome and exit code")
    outcome = _require_enum(containment["outcome"], CONTAINMENT_OUTCOMES, "containment outcome")
    exit_code = containment["exit_code"]
    if exit_code is not None and (isinstance(exit_code, bool) or not isinstance(exit_code, int)):
        raise FaultAttributionError("containment exit code must be an integer or null")
    if outcome in {"launch-failed", "not-run"} and exit_code is not None:
        raise FaultAttributionError("a process that did not run cannot have an exit code")
    if outcome not in {"launch-failed", "not-run"} and exit_code is None:
        raise FaultAttributionError("a launched process requires an exit code")
    canonical_object(value)


def _result(
    stimulus: dict[str, Any],
    *,
    outcome_class: str,
    attribution_layer: str,
    reason_code: str,
    eligible: bool,
) -> dict[str, Any]:
    digest = canonical_object(stimulus)[1]
    result = {
        "attribution_layer": attribution_layer,
        "c5_terminal_eligible": eligible,
        "canonical_authority": False,
        "completion_disposition": "accepted-terminal-observation" if eligible else "inconclusive-attempt",
        "fault_key": stimulus["fault_key"],
        "logical_execution_satisfied": eligible,
        "normative_authority": False,
        "outcome_class": outcome_class,
        "reason_code": reason_code,
        "schema_version": FAULT_ASSESSMENT_SCHEMA_VERSION,
        "semantic_authority": False,
        "stimulus_sha256": digest,
    }
    canonical_object(result)
    return result


def classify_fault(stimulus: dict[str, Any]) -> dict[str, Any]:
    """Classify one deliberate fault without converting ambiguity into target behavior."""

    validate_stimulus(stimulus)
    point = stimulus["injection_point"]
    containment = stimulus["containment"]

    if stimulus["storage_observation"] == "publication-failed":
        return _result(
            stimulus,
            outcome_class="storage-publication-failure",
            attribution_layer="storage",
            reason_code="publication-failed-before-evidence-commit",
            eligible=False,
        )
    if stimulus["network_observation"] == "transport-failed":
        return _result(
            stimulus,
            outcome_class="network-failure",
            attribution_layer="network",
            reason_code="transport-failed-before-target-invocation",
            eligible=False,
        )
    if point == "worker-process":
        return _result(
            stimulus,
            outcome_class="worker-failure",
            attribution_layer="worker",
            reason_code="worker-terminated-without-target-attribution",
            eligible=False,
        )
    if stimulus["adapter_response_state"] == "malformed" or point == "adapter-process":
        return _result(
            stimulus,
            outcome_class="adapter-protocol-failure",
            attribution_layer="adapter-protocol",
            reason_code=(
                "malformed-adapter-response"
                if stimulus["adapter_response_state"] == "malformed"
                else "adapter-process-terminated"
            ),
            eligible=False,
        )

    target_proven = (
        point == "target-invocation"
        and stimulus["protocol_checkpoint"] == "target-invocation-started"
        and stimulus["adapter_response_state"] == "missing"
        and stimulus["environment_health_before"] == "healthy"
        and stimulus["environment_health_after"] == "healthy"
        and stimulus["supervisor_health"] == "healthy"
        and stimulus["network_observation"] == "none"
        and stimulus["storage_observation"] == "none"
    )
    if target_proven and containment["outcome"] == "wall-time-limit":
        return _result(
            stimulus,
            outcome_class="target-timeout",
            attribution_layer="target",
            reason_code="verified-target-wall-time-limit",
            eligible=True,
        )
    if (
        target_proven
        and containment["outcome"] == "completed"
        and isinstance(containment["exit_code"], int)
        and containment["exit_code"] < 0
    ):
        return _result(
            stimulus,
            outcome_class="target-crash",
            attribution_layer="target",
            reason_code="verified-target-signal",
            eligible=True,
        )
    return _result(
        stimulus,
        outcome_class="inconclusive",
        attribution_layer="unknown",
        reason_code="insufficient-or-contradictory-attribution",
        eligible=False,
    )


def reference_stimuli() -> tuple[dict[str, Any], ...]:
    """Return the canonical closed fault set in deterministic key order."""

    common = {
        "adapter_response_state": "missing",
        "containment": {"exit_code": -15, "outcome": "wall-time-limit"},
        "environment_health_after": "healthy",
        "environment_health_before": "healthy",
        "network_observation": "none",
        "protocol_checkpoint": "target-invocation-started",
        "schema_version": FAULT_STIMULUS_SCHEMA_VERSION,
        "storage_observation": "none",
        "supervisor_health": "healthy",
    }
    values = [
        {**common, "fault_key": "adapter-process-crash", "injection_point": "adapter-process", "containment": {"exit_code": -6, "outcome": "completed"}, "protocol_checkpoint": "target-not-started"},
        {**common, "fault_key": "malformed-adapter-response", "injection_point": "adapter-process", "adapter_response_state": "malformed", "containment": {"exit_code": 0, "outcome": "completed"}, "protocol_checkpoint": "target-response-complete"},
        {**common, "fault_key": "network-acquisition-failure", "injection_point": "network-acquisition", "adapter_response_state": "not-applicable", "containment": {"exit_code": None, "outcome": "not-run"}, "network_observation": "transport-failed", "protocol_checkpoint": "not-applicable"},
        {**common, "fault_key": "storage-publication-failure", "injection_point": "evidence-storage", "adapter_response_state": "valid", "containment": {"exit_code": 0, "outcome": "completed"}, "protocol_checkpoint": "target-response-complete", "storage_observation": "publication-failed"},
        {**common, "fault_key": "target-process-crash", "injection_point": "target-invocation", "containment": {"exit_code": -6, "outcome": "completed"}},
        {**common, "fault_key": "target-timeout", "injection_point": "target-invocation"},
        {**common, "fault_key": "worker-kill", "injection_point": "worker-process", "containment": {"exit_code": -9, "outcome": "completed"}, "protocol_checkpoint": "target-not-started"},
    ]
    result = tuple(sorted(values, key=lambda item: item["fault_key"]))
    for item in result:
        validate_stimulus(item)
    return result


def build_reference_report() -> dict[str, Any]:
    cases = [
        {"assessment": classify_fault(stimulus), "stimulus": stimulus}
        for stimulus in reference_stimuli()
    ]
    report = {
        "cases": cases,
        "classification": {
            "normative_authority": False,
            "operational_qualification_only": True,
            "semantic_authority": False,
        },
        "schema_version": "fault-classification-report.v1",
        "summary": {
            "accepted_terminal_count": sum(
                1 for item in cases if item["assessment"]["c5_terminal_eligible"]
            ),
            "case_count": len(cases),
            "inconclusive_attempt_count": sum(
                1 for item in cases if not item["assessment"]["c5_terminal_eligible"]
            ),
        },
    }
    canonical_object(report)
    return report
