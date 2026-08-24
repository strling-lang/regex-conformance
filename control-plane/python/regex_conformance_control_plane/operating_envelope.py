"""Resumable, non-canonical sustained operating-envelope qualification."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from pathlib import PurePosixPath
import re
from typing import Any, Mapping, Sequence

from .state_models import OPERATIONAL_ID_PATTERN, SAFE_INTEGER_MAX, canonical_json, parse_canonical_object


PLAN_SCHEMA_VERSION = "sustained-operating-envelope-plan.v1"
CHECKPOINT_SCHEMA_VERSION = "sustained-operating-envelope-checkpoint.v1"
REPORT_SCHEMA_VERSION = "sustained-operating-envelope-report.v1"
CLASSIFICATION = {
    "canonical_authority": False,
    "normative_authority": False,
    "operational_qualification_only": True,
    "semantic_authority": False,
    "target_behavior": False,
}
PHASES = frozenset(
    {"baseline", "steady-load", "interruption", "recovery", "post-recovery", "complete"}
)
WINDOW_PHASES = frozenset({"baseline", "steady-load", "post-recovery"})
STABILITY_PHASES = frozenset({"steady-load", "post-recovery"})
MEASUREMENT_UNITS = frozenset({"basis_points", "bytes", "millidegrees_celsius"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class OperatingEnvelopeError(ValueError):
    """An operating-envelope artifact violates the resumable qualification contract."""


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _reject_linked_ancestors(path: Path, label: str) -> None:
    candidate = path.expanduser().absolute()
    for current in (candidate, *candidate.parents):
        if current.exists() and _is_link(current):
            raise OperatingEnvelopeError(f"{label} must not traverse a symlink or junction")


def _object(label: str, value: object, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise OperatingEnvelopeError(f"{label} fields are incomplete or unexpected")
    return value


def _array(label: str, value: object, *, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        raise OperatingEnvelopeError(f"{label} must contain at least {minimum} items")
    return value


def _integer(label: str, value: object, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= SAFE_INTEGER_MAX:
        raise OperatingEnvelopeError(f"{label} must be a safe integer of at least {minimum}")
    return value


def _sha256(label: str, value: object) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise OperatingEnvelopeError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _operational_id(label: str, value: object, namespace: str) -> str:
    if (
        not isinstance(value, str)
        or OPERATIONAL_ID_PATTERN.fullmatch(value) is None
        or not value.startswith(f"opid:v1:{namespace}:u7:")
    ):
        raise OperatingEnvelopeError(f"{label} must use the {namespace} operational UUIDv7 namespace")
    return value


def _timestamp(label: str, value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise OperatingEnvelopeError(f"{label} must be a bounded RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise OperatingEnvelopeError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise OperatingEnvelopeError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _classification(value: object) -> None:
    if value != CLASSIFICATION:
        raise OperatingEnvelopeError("operating-envelope artifacts cannot claim scientific authority")


def _digest_without(record: Mapping[str, Any], field: str) -> str:
    payload = dict(record)
    payload.pop(field, None)
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _load_canonical(path: Path) -> dict[str, Any]:
    _reject_linked_ancestors(path, "operating-envelope artifact")
    if _is_link(path) or not path.is_file():
        raise OperatingEnvelopeError(f"operating-envelope artifact must be a regular non-link file: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise OperatingEnvelopeError(f"operating-envelope artifact must be strict UTF-8: {path}") from error
    if not text.endswith("\n") or "\r" in text:
        raise OperatingEnvelopeError(f"operating-envelope artifact must use canonical bytes plus one LF: {path}")
    try:
        record = parse_canonical_object(text[:-1])
    except ValueError as error:
        raise OperatingEnvelopeError(f"operating-envelope artifact is not canonical JSON: {path}") from error
    if raw != canonical_json(record) + b"\n":
        raise OperatingEnvelopeError(f"operating-envelope artifact bytes are not canonical: {path}")
    return record


def load_plan(path: Path) -> dict[str, Any]:
    plan = _load_canonical(path)
    validate_plan(plan)
    return plan


def validate_plan(value: Mapping[str, Any]) -> None:
    plan = _object(
        "operating-envelope plan",
        value,
        {
            "classification",
            "maximum_sampling_overhead_basis_points",
            "maximum_throughput_degradation_basis_points",
            "measurement_policy",
            "minimum_post_recovery_duration_ms",
            "minimum_recovery_count",
            "minimum_stability_duration_ms",
            "minimum_stability_window_count",
            "plan_digest_sha256",
            "record_type",
            "schema_version",
            "source_bindings",
        },
    )
    if plan["schema_version"] != PLAN_SCHEMA_VERSION or plan["record_type"] != "plan":
        raise OperatingEnvelopeError("unsupported operating-envelope plan schema")
    _classification(plan["classification"])
    minimum_duration = _integer(
        "minimum stability duration", plan["minimum_stability_duration_ms"], minimum=1
    )
    post_duration = _integer(
        "minimum post-recovery duration", plan["minimum_post_recovery_duration_ms"], minimum=1
    )
    if post_duration > minimum_duration:
        raise OperatingEnvelopeError("post-recovery duration cannot exceed total stability duration")
    _integer("minimum stability window count", plan["minimum_stability_window_count"], minimum=2)
    _integer("minimum recovery count", plan["minimum_recovery_count"], minimum=1)
    overhead = _integer(
        "maximum sampling overhead", plan["maximum_sampling_overhead_basis_points"]
    )
    degradation = _integer(
        "maximum throughput degradation", plan["maximum_throughput_degradation_basis_points"]
    )
    if overhead > 10_000 or degradation > 10_000:
        raise OperatingEnvelopeError("basis-point thresholds cannot exceed 100 percent")

    policies = _array("measurement policy", plan["measurement_policy"], minimum=1)
    names: list[str] = []
    for index, raw in enumerate(policies):
        policy = _object(
            f"measurement policy {index}", raw, {"measurement", "required", "unit"}
        )
        name = policy["measurement"]
        if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", name) is None:
            raise OperatingEnvelopeError("measurement names must be lowercase canonical tokens")
        if policy["unit"] not in MEASUREMENT_UNITS:
            raise OperatingEnvelopeError("measurement policy uses an unsupported unit")
        if not isinstance(policy["required"], bool):
            raise OperatingEnvelopeError("measurement required flag must be boolean")
        names.append(name)
    if names != sorted(names) or len(names) != len(set(names)):
        raise OperatingEnvelopeError("measurement policies must be unique and sorted by name")
    required_names = {item["measurement"] for item in policies if item["required"]}
    expected = {
        "cpu-utilization",
        "environment-cache-size",
        "execution-scratch-size",
        "persistent-disk-available",
        "ram-working-set",
        "result-spool-size",
    }
    if required_names != expected:
        raise OperatingEnvelopeError("operating-envelope plan must require every portable resource measurement")
    thermal = next((item for item in policies if item["measurement"] == "processor-temperature"), None)
    if thermal is None or thermal["required"] or thermal["unit"] != "millidegrees_celsius":
        raise OperatingEnvelopeError("processor temperature must be present as an optional explicit measurement")
    bindings = _array("operating-envelope source bindings", plan["source_bindings"], minimum=1)
    paths: list[str] = []
    for index, raw in enumerate(bindings):
        binding = _object(f"source binding {index}", raw, {"path", "sha256"})
        path = binding["path"]
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
        ):
            raise OperatingEnvelopeError("source binding paths must be safe repository-relative POSIX paths")
        _sha256("source binding digest", binding["sha256"])
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise OperatingEnvelopeError("source bindings must be unique and sorted by path")
    claimed = _sha256("operating-envelope plan digest", plan["plan_digest_sha256"])
    if claimed != _digest_without(plan, "plan_digest_sha256"):
        raise OperatingEnvelopeError("operating-envelope plan digest does not match its contents")


def verify_plan_source_bindings(root: Path, plan: Mapping[str, Any]) -> None:
    validate_plan(plan)
    repository = root.resolve(strict=True)
    for binding in plan["source_bindings"]:
        path = repository.joinpath(*PurePosixPath(binding["path"]).parts)
        _reject_linked_ancestors(path, "source binding")
        try:
            path.resolve(strict=True).relative_to(repository)
        except ValueError as error:
            raise OperatingEnvelopeError("source binding escapes the repository") from error
        if _is_link(path) or not path.is_file():
            raise OperatingEnvelopeError("source bindings must identify regular non-link files")
        if hashlib.sha256(path.read_bytes()).hexdigest() != binding["sha256"]:
            raise OperatingEnvelopeError(f"source binding digest changed: {binding['path']}")


def _measurement_summaries(
    raw: object, policies: Sequence[Mapping[str, Any]], checkpoint_label: str
) -> dict[str, Mapping[str, Any]]:
    values = _array(f"{checkpoint_label} measurement summaries", raw, minimum=1)
    expected = {item["measurement"]: item for item in policies}
    result: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(values):
        summary = _object(
            f"{checkpoint_label} measurement {index}",
            item,
            {"diagnostic", "last", "maximum", "measurement", "minimum", "sample_count", "status", "unit"},
        )
        name = summary["measurement"]
        if name not in expected or name in result:
            raise OperatingEnvelopeError(f"{checkpoint_label} contains an unknown or duplicate measurement")
        if summary["unit"] != expected[name]["unit"]:
            raise OperatingEnvelopeError(f"{checkpoint_label} measurement unit differs from the plan")
        status = summary["status"]
        count = _integer(f"{checkpoint_label} measurement sample count", summary["sample_count"])
        numeric = (summary["minimum"], summary["maximum"], summary["last"])
        if status == "observed":
            if count < 1 or any(isinstance(item_value, bool) or not isinstance(item_value, int) for item_value in numeric):
                raise OperatingEnvelopeError(f"{checkpoint_label} observed measurements require numeric samples")
            minimum, maximum, last = numeric
            if not 0 <= minimum <= last <= maximum <= SAFE_INTEGER_MAX:
                raise OperatingEnvelopeError(f"{checkpoint_label} observed measurement bounds are inconsistent")
            if summary["diagnostic"] is not None:
                raise OperatingEnvelopeError(f"{checkpoint_label} observed measurements cannot carry unavailable diagnostics")
        elif status == "unavailable":
            if count != 0 or any(item_value is not None for item_value in numeric):
                raise OperatingEnvelopeError(f"{checkpoint_label} unavailable measurements must remain null")
            diagnostic = summary["diagnostic"]
            if not isinstance(diagnostic, str) or not diagnostic or len(diagnostic) > 512:
                raise OperatingEnvelopeError(f"{checkpoint_label} unavailable measurements require a diagnostic")
            if expected[name]["required"]:
                raise OperatingEnvelopeError(f"{checkpoint_label} required measurement {name} is unavailable")
        else:
            raise OperatingEnvelopeError(f"{checkpoint_label} measurement status is unsupported")
        result[name] = summary
    if set(result) != set(expected):
        raise OperatingEnvelopeError(f"{checkpoint_label} must explicitly account for every planned measurement")
    return result


COUNTER_FIELDS = {
    "completed_work_count",
    "containment_failure_count",
    "duplicate_completion_count",
    "integrity_failure_count",
    "interruption_count",
    "logical_completion_count",
    "post_recovery_duration_ms",
    "resource_floor_breach_count",
    "sampler_overhead_ms",
    "stability_duration_ms",
    "stability_window_count",
    "successful_resume_count",
}
FAILURE_FIELDS = {
    "containment_failure_count",
    "duplicate_completion_count",
    "integrity_failure_count",
    "resource_floor_breach_count",
}


def _counters(label: str, value: object) -> dict[str, int]:
    raw = _object(label, value, COUNTER_FIELDS)
    return {key: _integer(f"{label} {key}", raw[key]) for key in sorted(COUNTER_FIELDS)}


def _checkpoint_digest(checkpoint: Mapping[str, Any]) -> str:
    return _digest_without(checkpoint, "checkpoint_digest_sha256")


def finalize_checkpoint(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a checkpoint with its deterministic content digest populated."""

    result = dict(value)
    result["checkpoint_digest_sha256"] = "0" * 64
    result["checkpoint_digest_sha256"] = _checkpoint_digest(result)
    return result


def validate_checkpoint_chain(
    plan: Mapping[str, Any], checkpoints: Sequence[Mapping[str, Any]]
) -> tuple[dict[str, Any], ...]:
    validate_plan(plan)
    if not checkpoints:
        raise OperatingEnvelopeError("operating-envelope checkpoint chain is empty")
    policies = tuple(plan["measurement_policy"])
    validated: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    previous_time: datetime | None = None
    previous_counters = {key: 0 for key in COUNTER_FIELDS}
    previous_attempt: str | None = None
    previous_session = 0
    checkpoint_ids: set[str] = set()
    attempt_ids: set[str] = set()
    qualification_id: str | None = None
    logical_execution_id: str | None = None
    allowed_transitions = {
        "baseline": {"baseline", "steady-load", "interruption"},
        "steady-load": {"steady-load", "interruption", "complete"},
        "interruption": {"recovery"},
        "recovery": {"post-recovery", "interruption"},
        "post-recovery": {"post-recovery", "interruption", "complete"},
        "complete": set(),
    }

    for offset, raw_value in enumerate(checkpoints, start=1):
        checkpoint = dict(
            _object(
                f"operating-envelope checkpoint {offset}",
                raw_value,
                {
                    "attempt_id",
                    "checkpoint_digest_sha256",
                    "checkpoint_id",
                    "classification",
                    "counters",
                    "failure_increments",
                    "logical_execution_id",
                    "observed_at",
                    "phase",
                    "plan_digest_sha256",
                    "previous_checkpoint_digest_sha256",
                    "qualification_id",
                    "record_type",
                    "schema_version",
                    "sequence",
                    "session_index",
                    "window",
                },
            )
        )
        if checkpoint["schema_version"] != CHECKPOINT_SCHEMA_VERSION or checkpoint["record_type"] != "checkpoint":
            raise OperatingEnvelopeError("unsupported operating-envelope checkpoint schema")
        _classification(checkpoint["classification"])
        sequence = _integer("checkpoint sequence", checkpoint["sequence"], minimum=1)
        if sequence != offset:
            raise OperatingEnvelopeError("operating-envelope checkpoint sequence must be contiguous")
        checkpoint_id = _operational_id(
            "checkpoint ID", checkpoint["checkpoint_id"], "operating-envelope-checkpoint"
        )
        if checkpoint_id in checkpoint_ids:
            raise OperatingEnvelopeError("checkpoint identities must be unique")
        checkpoint_ids.add(checkpoint_id)
        current_qualification = _operational_id(
            "qualification ID", checkpoint["qualification_id"], "operating-envelope"
        )
        current_logical = _operational_id(
            "logical execution ID", checkpoint["logical_execution_id"], "logical-execution"
        )
        attempt = _operational_id("attempt ID", checkpoint["attempt_id"], "execution-attempt")
        qualification_id = current_qualification if qualification_id is None else qualification_id
        logical_execution_id = current_logical if logical_execution_id is None else logical_execution_id
        if current_qualification != qualification_id or current_logical != logical_execution_id:
            raise OperatingEnvelopeError("checkpoint chain changed qualification or logical-execution identity")
        if checkpoint["plan_digest_sha256"] != plan["plan_digest_sha256"]:
            raise OperatingEnvelopeError("checkpoint plan digest differs from the qualification plan")
        claimed_digest = _sha256("checkpoint digest", checkpoint["checkpoint_digest_sha256"])
        if claimed_digest != _checkpoint_digest(checkpoint):
            raise OperatingEnvelopeError("checkpoint digest does not match its content")
        predecessor = checkpoint["previous_checkpoint_digest_sha256"]
        expected_predecessor = None if previous is None else previous["checkpoint_digest_sha256"]
        if predecessor != expected_predecessor:
            raise OperatingEnvelopeError("checkpoint predecessor digest does not match the prior checkpoint")
        observed = _timestamp("checkpoint observation", checkpoint["observed_at"])
        if previous_time is not None and observed < previous_time:
            raise OperatingEnvelopeError("checkpoint observation times cannot move backward")
        previous_time = observed
        phase = checkpoint["phase"]
        if phase not in PHASES:
            raise OperatingEnvelopeError("checkpoint phase is unsupported")
        if previous is None:
            if phase != "baseline":
                raise OperatingEnvelopeError("the first operating-envelope checkpoint must be baseline")
        elif phase not in allowed_transitions[previous["phase"]]:
            raise OperatingEnvelopeError("operating-envelope phase transition is invalid")

        session_index = _integer("checkpoint session index", checkpoint["session_index"], minimum=1)
        if previous is None:
            if session_index != 1:
                raise OperatingEnvelopeError("the first operating-envelope session index must be one")
            attempt_ids.add(attempt)
        elif phase == "recovery":
            if session_index != previous_session + 1 or attempt == previous_attempt:
                raise OperatingEnvelopeError("recovery requires the next session and a new physical attempt")
            if attempt in attempt_ids:
                raise OperatingEnvelopeError("a recovery cannot reuse an earlier physical attempt identity")
            attempt_ids.add(attempt)
        elif session_index != previous_session or attempt != previous_attempt:
            raise OperatingEnvelopeError("physical attempt identity may change only at an explicit recovery")

        counters = _counters(f"checkpoint {offset} counters", checkpoint["counters"])
        failure_increments = _object(
            f"checkpoint {offset} failure increments",
            checkpoint["failure_increments"],
            FAILURE_FIELDS,
        )
        window = checkpoint["window"]
        increments = {key: 0 for key in COUNTER_FIELDS}
        for field in FAILURE_FIELDS:
            increments[field] = _integer(
                f"checkpoint {offset} {field} increment", failure_increments[field]
            )
        if phase in WINDOW_PHASES:
            window_object = _object(
                f"checkpoint {offset} window",
                window,
                {"completed_work_count", "duration_ms", "measurement_summaries", "sampling_overhead_ms"},
            )
            duration = _integer("window duration", window_object["duration_ms"], minimum=1)
            completed = _integer("window completed work", window_object["completed_work_count"])
            overhead_ms = _integer("window sampling overhead", window_object["sampling_overhead_ms"])
            if overhead_ms > duration:
                raise OperatingEnvelopeError("sampling overhead cannot exceed its observation window")
            _measurement_summaries(window_object["measurement_summaries"], policies, f"checkpoint {offset}")
            increments["completed_work_count"] = completed
            increments["sampler_overhead_ms"] = overhead_ms
            if phase in STABILITY_PHASES:
                increments["stability_duration_ms"] = duration
                increments["stability_window_count"] = 1
                if phase == "post-recovery":
                    increments["post_recovery_duration_ms"] = duration
        elif window is not None:
            raise OperatingEnvelopeError("event checkpoints cannot contain a measurement window")
        if phase == "interruption":
            increments["interruption_count"] = 1
        elif phase == "recovery":
            increments["successful_resume_count"] = 1
        elif phase == "complete":
            increments["logical_completion_count"] = 1

        for field in COUNTER_FIELDS:
            expected_value = previous_counters[field] + increments[field]
            if counters[field] != expected_value:
                raise OperatingEnvelopeError(f"checkpoint cumulative {field} does not reconcile")
        if counters["successful_resume_count"] > counters["interruption_count"]:
            raise OperatingEnvelopeError("successful resumes cannot exceed interruptions")
        if counters["logical_completion_count"] > 1:
            raise OperatingEnvelopeError("retries cannot add another logical completion")

        checkpoint["counters"] = counters
        validated.append(checkpoint)
        previous = checkpoint
        previous_counters = counters
        previous_attempt = attempt
        previous_session = session_index

    return tuple(validated)


def load_checkpoint_chain(root: Path, plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    _reject_linked_ancestors(root, "checkpoint root")
    if _is_link(root) or not root.is_dir():
        raise OperatingEnvelopeError("checkpoint root must be an existing non-link directory")
    files = sorted(root.glob("checkpoint-*.json"))
    if not files:
        raise OperatingEnvelopeError("checkpoint root contains no operating-envelope checkpoints")
    for offset, path in enumerate(files, start=1):
        if path.name != f"checkpoint-{offset:06d}.json":
            raise OperatingEnvelopeError("checkpoint filenames must be contiguous and canonical")
    return validate_checkpoint_chain(plan, tuple(_load_canonical(path) for path in files))


def _ceil_ratio(numerator: int, denominator: int, scale: int = 10_000) -> int:
    if denominator <= 0:
        return 0
    return (numerator * scale + denominator - 1) // denominator


def build_report(plan: Mapping[str, Any], checkpoints: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    chain = validate_checkpoint_chain(plan, checkpoints)
    final = chain[-1]
    counters = final["counters"]
    stability_windows: list[Mapping[str, Any]] = [
        checkpoint["window"] for checkpoint in chain if checkpoint["phase"] in STABILITY_PHASES
    ]
    rates = sorted(
        _integer(
            "stability-window throughput",
            _ceil_ratio(window["completed_work_count"], window["duration_ms"], 1_000_000),
        )
        for window in stability_windows
    )
    median_rate = rates[(len(rates) - 1) // 2] if rates else 0
    minimum_rate = rates[0] if rates else 0
    degradation = _ceil_ratio(max(0, median_rate - minimum_rate), median_rate)
    overhead = _ceil_ratio(counters["sampler_overhead_ms"], counters["stability_duration_ms"])

    policies = {item["measurement"]: item for item in plan["measurement_policy"]}
    coverage: list[dict[str, Any]] = []
    for name in sorted(policies):
        summaries = [
            item
            for checkpoint in chain
            if checkpoint["window"] is not None
            for item in checkpoint["window"]["measurement_summaries"]
            if item["measurement"] == name
        ]
        observed = [item for item in summaries if item["status"] == "observed"]
        unavailable = [item for item in summaries if item["status"] == "unavailable"]
        status = "observed" if observed and not unavailable else "partial" if observed else "unavailable"
        diagnostics = sorted({item["diagnostic"] for item in unavailable})
        coverage.append(
            {
                "diagnostics": diagnostics,
                "measurement": name,
                "sample_count": sum(item["sample_count"] for item in observed),
                "status": status,
                "unit": policies[name]["unit"],
            }
        )

    final_complete = final["phase"] == "complete" and counters["logical_completion_count"] == 1
    checks = {
        "completion": final_complete,
        "failure-free": all(counters[field] == 0 for field in FAILURE_FIELDS),
        "measurement-coverage": all(
            item["status"] == "observed"
            for item in coverage
            if policies[item["measurement"]]["required"]
        ),
        "post-recovery-duration": counters["post_recovery_duration_ms"]
        >= plan["minimum_post_recovery_duration_ms"],
        "recovery": counters["interruption_count"] >= plan["minimum_recovery_count"]
        and counters["successful_resume_count"] == counters["interruption_count"],
        "sampling-overhead": overhead <= plan["maximum_sampling_overhead_basis_points"],
        "stability-duration": counters["stability_duration_ms"]
        >= plan["minimum_stability_duration_ms"],
        "stability-windows": counters["stability_window_count"]
        >= plan["minimum_stability_window_count"],
        "throughput-stability": bool(rates)
        and minimum_rate > 0
        and degradation <= plan["maximum_throughput_degradation_basis_points"],
    }
    hard_failure = any(counters[field] > 0 for field in FAILURE_FIELDS)
    if final_complete:
        status = "passed" if all(checks.values()) else "failed"
    else:
        status = "failed" if hard_failure else "in-progress"
    criteria = [
        {
            "criterion": key,
            "status": "passed" if passed else "failed" if final_complete or hard_failure else "pending",
        }
        for key, passed in sorted(checks.items())
    ]
    attempt_ids = tuple(dict.fromkeys(checkpoint["attempt_id"] for checkpoint in chain))
    report: dict[str, Any] = {
        "checkpoint_digests": [checkpoint["checkpoint_digest_sha256"] for checkpoint in chain],
        "classification": dict(CLASSIFICATION),
        "criteria": criteria,
        "first_observed_at": chain[0]["observed_at"],
        "last_observed_at": final["observed_at"],
        "logical_execution_id": final["logical_execution_id"],
        "measurement_coverage": coverage,
        "plan_digest_sha256": plan["plan_digest_sha256"],
        "qualification_id": final["qualification_id"],
        "record_type": "report",
        "report_digest_sha256": "0" * 64,
        "schema_version": REPORT_SCHEMA_VERSION,
        "summary": {
            "checkpoint_count": len(chain),
            "completed_work_count": counters["completed_work_count"],
            "containment_failure_count": counters["containment_failure_count"],
            "duplicate_completion_count": counters["duplicate_completion_count"],
            "integrity_failure_count": counters["integrity_failure_count"],
            "interruption_count": counters["interruption_count"],
            "logical_completion_count": counters["logical_completion_count"],
            "median_throughput_count_per_second_milli": median_rate,
            "minimum_throughput_count_per_second_milli": minimum_rate,
            "physical_attempt_count": len(attempt_ids),
            "post_recovery_duration_ms": counters["post_recovery_duration_ms"],
            "resource_floor_breach_count": counters["resource_floor_breach_count"],
            "sampler_overhead_basis_points": overhead,
            "sampler_overhead_ms": counters["sampler_overhead_ms"],
            "stability_duration_ms": counters["stability_duration_ms"],
            "stability_window_count": counters["stability_window_count"],
            "status": status,
            "successful_resume_count": counters["successful_resume_count"],
            "throughput_degradation_basis_points": degradation,
        },
    }
    report["report_digest_sha256"] = _digest_without(report, "report_digest_sha256")
    return report


def validate_report(
    plan: Mapping[str, Any], checkpoints: Sequence[Mapping[str, Any]], report: Mapping[str, Any]
) -> None:
    expected = build_report(plan, checkpoints)
    if report != expected:
        raise OperatingEnvelopeError("operating-envelope report does not match its checkpoint chain")


def canonical_artifact_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json(value) + b"\n"
