"""Operational telemetry collection without semantic or canonical authority."""

from __future__ import annotations

from datetime import datetime, timezone
import secrets
from typing import Protocol
import uuid

from .containment import ContainedExecutionResult
from .telemetry_models import TelemetryMetric, TelemetrySample
from .telemetry_store import TelemetryStore


class TelemetryClock(Protocol):
    def now(self) -> datetime: ...


class TelemetryIdGenerator(Protocol):
    def next_id(self) -> str: ...


class UtcTelemetryClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class Uuid7TelemetryIds:
    def next_id(self) -> str:
        milliseconds = int(datetime.now(timezone.utc).timestamp() * 1000)
        if not 0 <= milliseconds < 2**48:
            raise ValueError("telemetry UUIDv7 timestamp must fit in 48 bits")
        randomness = secrets.randbits(74)
        integer = (
            ((milliseconds & ((1 << 48) - 1)) << 80)
            | (0x7 << 76)
            | (((randomness >> 62) & 0xFFF) << 64)
            | (0b10 << 62)
            | (randomness & ((1 << 62) - 1))
        )
        return f"opid:v1:telemetry:u7:{uuid.UUID(int=integer)}"


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("telemetry clocks must return timezone-aware values")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class OperationalTelemetryCollector:
    """Build and optionally persist numeric measurements from trusted control-plane code."""

    def __init__(
        self,
        *,
        store: TelemetryStore | None = None,
        clock: TelemetryClock | None = None,
        id_generator: TelemetryIdGenerator | None = None,
    ) -> None:
        self._store = store
        self._clock = clock or UtcTelemetryClock()
        self._ids = id_generator or Uuid7TelemetryIds()

    def collect(
        self,
        *,
        operation_kind: str,
        calibration_key: str,
        attempt_id: str,
        source: str,
        metrics: tuple[TelemetryMetric, ...],
        quality: str = "complete",
    ) -> TelemetrySample:
        sample = TelemetrySample(
            sample_id=self._ids.next_id(),
            operation_kind=operation_kind,
            calibration_key=calibration_key,
            attempt_id=attempt_id,
            observed_at=_timestamp(self._clock.now()),
            quality=quality,
            source=source,
            metrics=metrics,
        )
        if self._store is not None:
            self._store.append(sample)
        return sample

    def collect_containment(
        self,
        result: ContainedExecutionResult,
        *,
        calibration_key: str,
        attempt_id: str,
        source: str = "contained-process",
    ) -> TelemetrySample:
        quality = "complete" if result.outcome == "completed" else "partial"
        return self.collect(
            operation_kind="execution",
            calibration_key=calibration_key,
            attempt_id=attempt_id,
            source=source,
            quality=quality,
            metrics=(
                TelemetryMetric("execution-wall-clock", "wall-clock", "milliseconds", result.wall_time_ms),
                TelemetryMetric("execution-stdout", "output-volume", "bytes", result.stdout_total_bytes),
                TelemetryMetric("execution-stderr", "output-volume", "bytes", result.stderr_total_bytes),
            ),
        )
