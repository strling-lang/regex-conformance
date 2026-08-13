"""Non-canonical operational telemetry and deterministic calibration models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Any, Iterable, Mapping

from .resource_models import IDENTITY_PATTERN, RESOURCE_POOL_KINDS, SAFE_INTEGER_MAX, TOKEN_PATTERN
from .state_models import canonical_object


TELEMETRY_SCHEMA_VERSION = "operational-telemetry.v1"
TELEMETRY_ID_PATTERN = re.compile(
    r"^opid:v1:telemetry:u7:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
OPERATION_KINDS = frozenset({"environment", "campaign", "shard", "execution", "transfer", "provider"})
METRIC_KINDS = frozenset({"resource-usage", "transfer-volume", "transfer-rate", "wall-clock", "output-volume"})
METRIC_UNITS = frozenset({"bytes", "bytes_per_second", "logical_cpu", "milliseconds"})
SAMPLE_QUALITIES = frozenset({"complete", "partial"})


def _safe_integer(label: str, value: int, *, minimum: int = 0) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= SAFE_INTEGER_MAX:
        raise ValueError(f"{label} must be a safe integer of at least {minimum}")


def _token(label: str, value: str) -> None:
    if not isinstance(value, str) or TOKEN_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase canonical token")


def _timestamp(label: str, value: str) -> None:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError(f"{label} must be a bounded RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a UTC offset")


def _reference(label: str, value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 512 or any(not c.isprintable() for c in value):
        raise ValueError(f"{label} must be bounded printable text")
    canonical_object({"reference": value})


@dataclass(frozen=True)
class TelemetryMetric:
    """One numeric operational measurement; it cannot carry target semantics."""

    name: str
    metric_kind: str
    unit: str
    value: int
    pool_kind: str | None = None

    def __post_init__(self) -> None:
        _token("telemetry metric name", self.name)
        if not isinstance(self.metric_kind, str) or self.metric_kind not in METRIC_KINDS:
            raise ValueError("telemetry metric kind is unsupported")
        if not isinstance(self.unit, str) or self.unit not in METRIC_UNITS:
            raise ValueError("telemetry metric unit is unsupported")
        _safe_integer("telemetry metric value", self.value)
        if self.metric_kind == "resource-usage":
            if not isinstance(self.pool_kind, str) or self.pool_kind not in RESOURCE_POOL_KINDS:
                raise ValueError("resource telemetry requires a typed resource pool")
            expected_unit = "logical_cpu" if self.pool_kind == "cpu" else "bytes"
            if self.unit != expected_unit:
                raise ValueError("resource telemetry unit does not match its typed pool")
        elif self.pool_kind is not None:
            raise ValueError("non-resource telemetry cannot claim a resource pool")
        if self.metric_kind in {"transfer-volume", "output-volume"} and self.unit != "bytes":
            raise ValueError("volume telemetry must use bytes")
        if self.metric_kind == "transfer-rate" and self.unit != "bytes_per_second":
            raise ValueError("transfer-rate telemetry must use bytes_per_second")
        if self.metric_kind == "wall-clock" and self.unit != "milliseconds":
            raise ValueError("wall-clock telemetry must use milliseconds")

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_kind": self.metric_kind,
            "name": self.name,
            "pool_kind": self.pool_kind,
            "unit": self.unit,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TelemetryMetric":
        if set(value) != {"metric_kind", "name", "pool_kind", "unit", "value"}:
            raise ValueError("telemetry metric fields are incomplete or unexpected")
        return cls(
            name=value["name"],
            metric_kind=value["metric_kind"],
            unit=value["unit"],
            value=value["value"],
            pool_kind=value["pool_kind"],
        )


@dataclass(frozen=True)
class TelemetrySample:
    sample_id: str
    operation_kind: str
    calibration_key: str
    attempt_id: str
    observed_at: str
    quality: str
    source: str
    metrics: tuple[TelemetryMetric, ...]
    canonical_authority: bool = False
    semantic_authority: bool = False
    schema_version: str = TELEMETRY_SCHEMA_VERSION
    record_type: str = "telemetry-sample"

    def __post_init__(self) -> None:
        if TELEMETRY_ID_PATTERN.fullmatch(self.sample_id) is None:
            raise ValueError("telemetry sample ID must be an operational telemetry UUIDv7")
        if not isinstance(self.operation_kind, str) or self.operation_kind not in OPERATION_KINDS:
            raise ValueError("telemetry operation kind is unsupported")
        _reference("telemetry calibration key", self.calibration_key)
        if (
            not isinstance(self.attempt_id, str)
            or not self.attempt_id.startswith("opid:v1:")
            or IDENTITY_PATTERN.fullmatch(self.attempt_id) is None
        ):
            raise ValueError("telemetry attempt ID must be a canonical operational identity")
        _timestamp("telemetry observation time", self.observed_at)
        if not isinstance(self.quality, str) or self.quality not in SAMPLE_QUALITIES:
            raise ValueError("telemetry sample quality is unsupported")
        _token("telemetry source", self.source)
        if not isinstance(self.metrics, tuple) or not self.metrics:
            raise ValueError("telemetry samples require at least one metric")
        if len(self.metrics) > 128 or any(not isinstance(item, TelemetryMetric) for item in self.metrics):
            raise ValueError("telemetry samples require at most 128 typed metrics")
        names = tuple(item.name for item in self.metrics)
        if len(names) != len(set(names)):
            raise ValueError("telemetry samples cannot contain duplicate metric names")
        if not isinstance(self.canonical_authority, bool) or self.canonical_authority:
            raise ValueError("operational telemetry cannot claim canonical authority")
        if not isinstance(self.semantic_authority, bool) or self.semantic_authority:
            raise ValueError("operational telemetry cannot claim regex semantic authority")
        if self.schema_version != TELEMETRY_SCHEMA_VERSION or self.record_type != "telemetry-sample":
            raise ValueError("unsupported telemetry sample schema")
        canonical_object(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "calibration_key": self.calibration_key,
            "canonical_authority": False,
            "metrics": [item.to_dict() for item in sorted(self.metrics, key=lambda item: item.name)],
            "observed_at": self.observed_at,
            "operation_kind": self.operation_kind,
            "quality": self.quality,
            "record_type": self.record_type,
            "sample_id": self.sample_id,
            "schema_version": self.schema_version,
            "semantic_authority": False,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TelemetrySample":
        fields = {
            "attempt_id", "calibration_key", "canonical_authority", "metrics", "observed_at",
            "operation_kind", "quality", "record_type", "sample_id", "schema_version",
            "semantic_authority", "source",
        }
        if set(value) != fields or not isinstance(value["metrics"], list):
            raise ValueError("telemetry sample fields are incomplete or unexpected")
        return cls(
            sample_id=value["sample_id"],
            operation_kind=value["operation_kind"],
            calibration_key=value["calibration_key"],
            attempt_id=value["attempt_id"],
            observed_at=value["observed_at"],
            quality=value["quality"],
            source=value["source"],
            metrics=tuple(TelemetryMetric.from_dict(item) for item in value["metrics"]),
            canonical_authority=value["canonical_authority"],
            semantic_authority=value["semantic_authority"],
            schema_version=value["schema_version"],
            record_type=value["record_type"],
        )


@dataclass(frozen=True)
class CalibrationPolicy:
    minimum_samples: int = 3
    maximum_samples: int = 64
    expected_percentile_basis_points: int = 5000
    upper_percentile_basis_points: int = 9500
    headroom_basis_points: int = 2500

    def __post_init__(self) -> None:
        _safe_integer("minimum calibration samples", self.minimum_samples, minimum=1)
        _safe_integer("maximum calibration samples", self.maximum_samples, minimum=self.minimum_samples)
        if self.maximum_samples > 10_000:
            raise ValueError("calibration sample window cannot exceed 10000")
        for label, value in (
            ("expected calibration percentile", self.expected_percentile_basis_points),
            ("upper calibration percentile", self.upper_percentile_basis_points),
        ):
            _safe_integer(label, value, minimum=1)
            if value > 10_000:
                raise ValueError(f"{label} cannot exceed 100 percent")
        if self.expected_percentile_basis_points > self.upper_percentile_basis_points:
            raise ValueError("expected calibration percentile cannot exceed upper percentile")
        _safe_integer("calibration headroom basis points", self.headroom_basis_points)
        if self.headroom_basis_points > 100_000:
            raise ValueError("calibration headroom cannot exceed 1000 percent")

    def to_dict(self) -> dict[str, int]:
        return {
            "expected_percentile_basis_points": self.expected_percentile_basis_points,
            "headroom_basis_points": self.headroom_basis_points,
            "maximum_samples": self.maximum_samples,
            "minimum_samples": self.minimum_samples,
            "upper_percentile_basis_points": self.upper_percentile_basis_points,
        }


def _nearest_rank(values: tuple[int, ...], basis_points: int) -> int:
    rank = max(1, (len(values) * basis_points + 9_999) // 10_000)
    return values[rank - 1]


@dataclass(frozen=True)
class CalibrationSnapshot:
    operation_kind: str
    calibration_key: str
    metric_name: str
    pool_kind: str
    unit: str
    sample_ids: tuple[str, ...]
    sample_count: int
    minimum: int | None
    maximum: int | None
    expected: int | None
    upper_bound: int | None
    eligible: bool
    calibration_digest: str
    policy: CalibrationPolicy
    canonical_authority: bool = False
    semantic_authority: bool = False
    schema_version: str = TELEMETRY_SCHEMA_VERSION
    record_type: str = "calibration-snapshot"

    def __post_init__(self) -> None:
        if not isinstance(self.operation_kind, str) or self.operation_kind not in OPERATION_KINDS:
            raise ValueError("calibration operation kind is unsupported")
        _reference("calibration key", self.calibration_key)
        _token("calibration metric name", self.metric_name)
        if not isinstance(self.pool_kind, str) or self.pool_kind not in RESOURCE_POOL_KINDS:
            raise ValueError("calibration snapshot requires a typed resource pool")
        if not isinstance(self.unit, str) or self.unit not in {"bytes", "logical_cpu"}:
            raise ValueError("calibration snapshot unit is unsupported")
        if self.pool_kind == "cpu" and self.unit != "logical_cpu":
            raise ValueError("CPU calibration must use logical_cpu")
        if self.pool_kind != "cpu" and self.unit != "bytes":
            raise ValueError("non-CPU calibration must use bytes")
        _safe_integer("calibration sample count", self.sample_count)
        if not isinstance(self.sample_ids, tuple):
            raise ValueError("calibration sample IDs must be an immutable tuple")
        if self.sample_count != len(self.sample_ids) or len(self.sample_ids) != len(set(self.sample_ids)):
            raise ValueError("calibration sample IDs must be unique and match the sample count")
        if any(
            not isinstance(value, str) or TELEMETRY_ID_PATTERN.fullmatch(value) is None
            for value in self.sample_ids
        ):
            raise ValueError("calibration snapshot contains an invalid telemetry sample ID")
        for label, value in (
            ("calibration minimum", self.minimum), ("calibration maximum", self.maximum),
            ("calibration expected", self.expected), ("calibration upper bound", self.upper_bound),
        ):
            if value is not None:
                _safe_integer(label, value)
        if not isinstance(self.eligible, bool):
            raise ValueError("calibration eligibility must be boolean")
        if not isinstance(self.policy, CalibrationPolicy):
            raise ValueError("calibration snapshot requires a typed policy")
        if self.eligible:
            if None in {self.minimum, self.maximum, self.expected, self.upper_bound}:
                raise ValueError("eligible calibration snapshots require numeric bounds")
            if not self.minimum <= self.expected <= self.maximum <= self.upper_bound:  # type: ignore[operator]
                raise ValueError("eligible calibration bounds are inconsistent")
            if self.sample_count < self.policy.minimum_samples:
                raise ValueError("eligible calibration snapshots require the minimum sample count")
        elif any(value is not None for value in (self.minimum, self.maximum, self.expected, self.upper_bound)):
            raise ValueError("ineligible calibration snapshots cannot publish numeric recommendations")
        if not isinstance(self.calibration_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", self.calibration_digest):
            raise ValueError("calibration digest must be SHA-256")
        if (
            not isinstance(self.canonical_authority, bool)
            or not isinstance(self.semantic_authority, bool)
            or self.canonical_authority
            or self.semantic_authority
        ):
            raise ValueError("calibration snapshots are operational and non-semantic")
        if self.schema_version != TELEMETRY_SCHEMA_VERSION or self.record_type != "calibration-snapshot":
            raise ValueError("unsupported calibration snapshot schema")
        canonical_object(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "calibration_digest": self.calibration_digest,
            "calibration_key": self.calibration_key,
            "canonical_authority": False,
            "eligible": self.eligible,
            "expected": self.expected,
            "maximum": self.maximum,
            "metric_name": self.metric_name,
            "minimum": self.minimum,
            "operation_kind": self.operation_kind,
            "policy": self.policy.to_dict(),
            "pool_kind": self.pool_kind,
            "record_type": self.record_type,
            "sample_count": self.sample_count,
            "sample_ids": list(self.sample_ids),
            "schema_version": self.schema_version,
            "semantic_authority": False,
            "unit": self.unit,
            "upper_bound": self.upper_bound,
        }


def build_calibration(
    samples: Iterable[TelemetrySample],
    *,
    operation_kind: str,
    calibration_key: str,
    metric_name: str,
    pool_kind: str,
    unit: str,
    policy: CalibrationPolicy,
) -> CalibrationSnapshot:
    selected: list[tuple[TelemetrySample, TelemetryMetric]] = []
    for sample in samples:
        if (
            sample.operation_kind != operation_kind
            or sample.calibration_key != calibration_key
            or sample.quality != "complete"
        ):
            continue
        for metric in sample.metrics:
            if (
                metric.name == metric_name
                and metric.metric_kind == "resource-usage"
                and metric.pool_kind == pool_kind
                and metric.unit == unit
            ):
                selected.append((sample, metric))
    selected.sort(key=lambda item: (item[0].observed_at, item[0].sample_id))
    selected = selected[-policy.maximum_samples :]
    sample_ids = tuple(item[0].sample_id for item in selected)
    digest_payload = {
        "calibration_key": calibration_key,
        "metric_name": metric_name,
        "operation_kind": operation_kind,
        "policy": policy.to_dict(),
        "pool_kind": pool_kind,
        "sample_ids": list(sample_ids),
        "unit": unit,
        "values": [item[1].value for item in selected],
    }
    payload_json, digest = canonical_object(digest_payload)
    del payload_json
    if len(selected) < policy.minimum_samples:
        return CalibrationSnapshot(
            operation_kind, calibration_key, metric_name, pool_kind, unit, sample_ids, len(sample_ids),
            None, None, None, None, False, digest, policy,
        )
    values = tuple(sorted(item[1].value for item in selected))
    expected = _nearest_rank(values, policy.expected_percentile_basis_points)
    upper_observed = _nearest_rank(values, policy.upper_percentile_basis_points)
    upper_bound = (upper_observed * (10_000 + policy.headroom_basis_points) + 9_999) // 10_000
    if upper_bound > SAFE_INTEGER_MAX:
        upper_bound = SAFE_INTEGER_MAX
    return CalibrationSnapshot(
        operation_kind, calibration_key, metric_name, pool_kind, unit, sample_ids, len(sample_ids),
        values[0], values[-1], expected, max(values[-1], expected, upper_bound), True, digest, policy,
    )
