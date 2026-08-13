"""Provider-neutral lifecycle events and deterministic progress projections."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Mapping, Protocol

from .state_models import (
    OPERATIONAL_ID_PATTERN,
    SAFE_INTEGER_MAX,
    StateModelError,
    canonical_json,
    canonical_object,
    parse_canonical_object,
)


EVENT_TYPES = frozenset({"checkpoint", "diagnostic", "lifecycle", "metric", "progress"})
PROGRESS_UNITS = frozenset({"bytes", "environments", "executions", "items", "shards", "steps"})
TERMINAL_STATUSES = frozenset({"cancelled", "completed", "failed", "partial", "refused"})


class EventModelError(ValueError):
    """A lifecycle event violates the public event contract."""


class EventPublisher(Protocol):
    def publish(self, draft: "EventDraft", *, event_id: str | None = None) -> Any: ...


def _require_token(value: str, label: str) -> None:
    from .state_models import TOKEN_PATTERN

    if TOKEN_PATTERN.fullmatch(value) is None:
        raise EventModelError(f"{label} must be a lowercase hyphenated token")


def _require_safe_integer(value: int, label: str, *, positive: bool = False) -> None:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= SAFE_INTEGER_MAX:
        qualifier = "positive " if positive else "non-negative "
        raise EventModelError(f"{label} must be a {qualifier}safe integer")


def _require_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise EventModelError(f"{label} must be a lowercase SHA-256 digest")


def _timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise EventModelError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise EventModelError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _require_identifier(value: str, label: str, *, namespace: str | None = None) -> None:
    if OPERATIONAL_ID_PATTERN.fullmatch(value) is None:
        raise EventModelError(f"{label} must be an operational UUIDv7")
    if namespace is not None and not value.startswith(f"opid:v1:{namespace}:u7:"):
        raise EventModelError(f"{label} uses the wrong operational namespace")


@dataclass(frozen=True)
class EventDraft:
    """Producer-supplied content before journal identity and ordering are assigned."""

    stream_id: str
    operation_kind: str
    event_type: str
    phase: str
    status: str
    attempt: int = 1
    current: int | None = None
    total: int | None = None
    unit: str | None = None
    message: str = ""
    correlation_id: str | None = None
    causation_id: str | None = None
    attributes: Mapping[str, Any] | None = None
    terminal: bool = False

    def __post_init__(self) -> None:
        _require_identifier(self.stream_id, "event stream ID")
        _require_token(self.operation_kind, "event operation kind")
        if self.event_type not in EVENT_TYPES:
            raise EventModelError("event type is unsupported")
        _require_token(self.phase, "event phase")
        _require_token(self.status, "event status")
        _require_safe_integer(self.attempt, "event attempt", positive=True)
        if self.current is None:
            if self.total is not None or self.unit is not None:
                raise EventModelError("event progress total/unit require a current value")
            if self.event_type in {"checkpoint", "progress"}:
                raise EventModelError("checkpoint/progress events require progress coordinates")
        else:
            _require_safe_integer(self.current, "event current progress")
            if self.unit not in PROGRESS_UNITS:
                raise EventModelError("event progress unit is unsupported")
            if self.total is not None:
                _require_safe_integer(self.total, "event total progress")
                if self.current > self.total:
                    raise EventModelError("event current progress cannot exceed total")
        if not self.message or len(self.message) > 512 or any(c in self.message for c in "\r\n\x00"):
            raise EventModelError("event message must be bounded non-empty single-line text")
        try:
            canonical_json(self.message)
        except StateModelError as error:
            raise EventModelError("event message contains unsafe material") from error
        if self.correlation_id is not None:
            _require_identifier(self.correlation_id, "event correlation ID")
        if self.causation_id is not None:
            _require_identifier(self.causation_id, "event causation ID", namespace="lifecycle-event")
        if not isinstance(self.terminal, bool):
            raise EventModelError("event terminal flag must be boolean")
        if self.terminal != (self.status in TERMINAL_STATUSES):
            raise EventModelError("event terminal flag and status disagree")
        attributes_json, _ = canonical_object(self.attributes or {})
        if len(attributes_json.encode("utf-8")) > 16 * 1024:
            raise EventModelError("event attributes exceed the 16 KiB persistence limit")

    @property
    def attributes_object(self) -> dict[str, Any]:
        return dict(self.attributes or {})


@dataclass(frozen=True)
class LifecycleEvent:
    event_id: str
    stream_id: str
    stream_sequence: int
    operation_kind: str
    event_type: str
    phase: str
    status: str
    attempt: int
    occurred_at: str
    current: int | None
    total: int | None
    unit: str | None
    message: str
    correlation_id: str | None
    causation_id: str | None
    attributes_json: str
    attributes_sha256: str
    terminal: bool
    event_digest: str
    canonical_authority: bool = False
    schema_version: str = "lifecycle-event.v1"

    def __post_init__(self) -> None:
        _require_identifier(self.event_id, "event ID", namespace="lifecycle-event")
        draft = EventDraft(
            self.stream_id,
            self.operation_kind,
            self.event_type,
            self.phase,
            self.status,
            self.attempt,
            self.current,
            self.total,
            self.unit,
            self.message,
            self.correlation_id,
            self.causation_id,
            parse_canonical_object(self.attributes_json),
            self.terminal,
        )
        del draft
        _require_safe_integer(self.stream_sequence, "event stream sequence", positive=True)
        _timestamp(self.occurred_at, "event occurrence")
        _require_digest(self.attributes_sha256, "event attributes digest")
        if hashlib.sha256(self.attributes_json.encode("utf-8")).hexdigest() != self.attributes_sha256:
            raise EventModelError("event attributes digest does not match")
        _require_digest(self.event_digest, "event digest")
        if self.event_digest != self.calculate_digest(**self._digest_values()):
            raise EventModelError("event digest does not match its complete content")
        if self.canonical_authority is not False:
            raise EventModelError("local lifecycle events cannot claim canonical authority")
        if self.schema_version != "lifecycle-event.v1":
            raise EventModelError("unsupported lifecycle event schema")

    @classmethod
    def build(
        cls,
        *,
        event_id: str,
        stream_sequence: int,
        occurred_at: str,
        draft: EventDraft,
    ) -> "LifecycleEvent":
        attributes_json, attributes_sha256 = canonical_object(draft.attributes_object)
        values = {
            "event_id": event_id,
            "stream_id": draft.stream_id,
            "stream_sequence": stream_sequence,
            "operation_kind": draft.operation_kind,
            "event_type": draft.event_type,
            "phase": draft.phase,
            "status": draft.status,
            "attempt": draft.attempt,
            "occurred_at": occurred_at,
            "current": draft.current,
            "total": draft.total,
            "unit": draft.unit,
            "message": draft.message,
            "correlation_id": draft.correlation_id,
            "causation_id": draft.causation_id,
            "attributes_json": attributes_json,
            "attributes_sha256": attributes_sha256,
            "terminal": draft.terminal,
        }
        return cls(**values, event_digest=cls.calculate_digest(**values))

    def _digest_values(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "stream_id": self.stream_id,
            "stream_sequence": self.stream_sequence,
            "operation_kind": self.operation_kind,
            "event_type": self.event_type,
            "phase": self.phase,
            "status": self.status,
            "attempt": self.attempt,
            "occurred_at": self.occurred_at,
            "current": self.current,
            "total": self.total,
            "unit": self.unit,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "attributes_json": self.attributes_json,
            "attributes_sha256": self.attributes_sha256,
            "terminal": self.terminal,
        }

    @staticmethod
    def calculate_digest(**values: Any) -> str:
        projection = dict(values)
        projection["canonical_authority"] = False
        projection["schema_version"] = "lifecycle-event.v1"
        return hashlib.sha256(canonical_json(projection)).hexdigest()

    @property
    def attributes(self) -> dict[str, Any]:
        return parse_canonical_object(self.attributes_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "attributes": self.attributes,
            "attributes_sha256": self.attributes_sha256,
            "canonical_authority": False,
            "causation_id": self.causation_id,
            "correlation_id": self.correlation_id,
            "current": self.current,
            "event_digest": self.event_digest,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "message": self.message,
            "occurred_at": self.occurred_at,
            "operation_kind": self.operation_kind,
            "phase": self.phase,
            "schema_version": self.schema_version,
            "status": self.status,
            "stream_id": self.stream_id,
            "stream_sequence": self.stream_sequence,
            "terminal": self.terminal,
            "total": self.total,
            "unit": self.unit,
        }


@dataclass(frozen=True)
class StoredEvent:
    offset: int
    event: LifecycleEvent

    def __post_init__(self) -> None:
        _require_safe_integer(self.offset, "journal event offset", positive=True)

    def to_dict(self) -> dict[str, Any]:
        return {"event": self.event.to_dict(), "offset": self.offset}


@dataclass(frozen=True)
class EventCursor:
    journal_id: str
    offset: int
    schema_version: str = "event-cursor.v1"

    def __post_init__(self) -> None:
        _require_identifier(self.journal_id, "event journal ID", namespace="event-journal")
        _require_safe_integer(self.offset, "event cursor offset")
        if self.schema_version != "event-cursor.v1":
            raise EventModelError("unsupported event cursor schema")

    def to_dict(self) -> dict[str, Any]:
        return {"journal_id": self.journal_id, "offset": self.offset, "schema_version": self.schema_version}


@dataclass(frozen=True)
class EventBatch:
    cursor: EventCursor
    events: tuple[StoredEvent, ...]
    oldest_retained_offset: int | None
    newest_retained_offset: int | None
    has_more: bool
    schema_version: str = "event-batch.v1"

    def __post_init__(self) -> None:
        if (self.oldest_retained_offset is None) != (self.newest_retained_offset is None):
            raise EventModelError("event retention bounds must both be present or absent")
        if self.oldest_retained_offset is not None:
            _require_safe_integer(self.oldest_retained_offset, "oldest retained event offset", positive=True)
            _require_safe_integer(self.newest_retained_offset or 0, "newest retained event offset", positive=True)
            if self.oldest_retained_offset > (self.newest_retained_offset or 0):
                raise EventModelError("event retention bounds are reversed")
        if self.events:
            offsets = [item.offset for item in self.events]
            if offsets != list(range(offsets[0], offsets[0] + len(offsets))):
                raise EventModelError("event batch offsets are not contiguous")
            if self.cursor.offset != offsets[-1]:
                raise EventModelError("event batch cursor does not identify its last event")
        if not isinstance(self.has_more, bool):
            raise EventModelError("event batch has_more flag must be boolean")
        if self.schema_version != "event-batch.v1":
            raise EventModelError("unsupported event batch schema")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cursor": self.cursor.to_dict(),
            "events": [item.to_dict() for item in self.events],
            "has_more": self.has_more,
            "newest_retained_offset": self.newest_retained_offset,
            "oldest_retained_offset": self.oldest_retained_offset,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True)
class ProgressProjection:
    stream_id: str
    operation_kind: str
    phase: str
    status: str
    attempt: int
    current: int | None
    total: int | None
    unit: str | None
    percent_basis_points: int | None
    rate_milliunits_per_second: int | None
    eta_seconds: int | None
    updated_at: str
    terminal: bool
    history_complete: bool
    sample_count: int
    schema_version: str = "progress-projection.v1"

    def __post_init__(self) -> None:
        _require_identifier(self.stream_id, "progress stream ID")
        _require_token(self.operation_kind, "progress operation kind")
        _require_token(self.phase, "progress phase")
        _require_token(self.status, "progress status")
        _require_safe_integer(self.attempt, "progress attempt", positive=True)
        _timestamp(self.updated_at, "progress update")
        _require_safe_integer(self.sample_count, "progress sample count", positive=True)
        if self.current is None:
            if any(value is not None for value in (self.total, self.unit, self.percent_basis_points, self.rate_milliunits_per_second, self.eta_seconds)):
                raise EventModelError("non-quantified progress cannot expose quantitative projections")
        else:
            _require_safe_integer(self.current, "projected current progress")
            if self.unit not in PROGRESS_UNITS:
                raise EventModelError("projected progress unit is unsupported")
            if self.total is not None:
                _require_safe_integer(self.total, "projected total progress")
                if self.current > self.total:
                    raise EventModelError("projected current progress exceeds total")
            for value, label in (
                (self.percent_basis_points, "progress percentage"),
                (self.rate_milliunits_per_second, "progress rate"),
                (self.eta_seconds, "progress ETA"),
            ):
                if value is not None:
                    _require_safe_integer(value, label)
            if self.percent_basis_points is not None and self.percent_basis_points > 10_000:
                raise EventModelError("progress percentage exceeds 100 percent")
        if not isinstance(self.terminal, bool) or not isinstance(self.history_complete, bool):
            raise EventModelError("progress terminal/history flags must be boolean")
        if self.schema_version != "progress-projection.v1":
            raise EventModelError("unsupported progress projection schema")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "current": self.current,
            "eta_seconds": self.eta_seconds,
            "history_complete": self.history_complete,
            "operation_kind": self.operation_kind,
            "percent_basis_points": self.percent_basis_points,
            "phase": self.phase,
            "rate_milliunits_per_second": self.rate_milliunits_per_second,
            "sample_count": self.sample_count,
            "schema_version": self.schema_version,
            "status": self.status,
            "stream_id": self.stream_id,
            "terminal": self.terminal,
            "total": self.total,
            "unit": self.unit,
            "updated_at": self.updated_at,
        }


class ProgressAggregator:
    """Derive restart-aware status, integer rates, and ETA from events only."""

    @staticmethod
    def project(events: tuple[LifecycleEvent, ...]) -> ProgressProjection:
        if not events:
            raise EventModelError("progress projection requires at least one event")
        stream_id = events[0].stream_id
        operation_kind = events[0].operation_kind
        ordered = tuple(sorted(events, key=lambda item: item.stream_sequence))
        if any(item.stream_id != stream_id or item.operation_kind != operation_kind for item in ordered):
            raise EventModelError("progress projection cannot mix streams or operation kinds")
        history_complete = ordered[0].stream_sequence == 1
        expected = ordered[0].stream_sequence
        terminal_seen = False
        last_current: int | None = None
        last_total: int | None = None
        last_unit: str | None = None
        last_attempt = ordered[0].attempt
        attempt_samples: list[LifecycleEvent] = []
        for event in ordered:
            if event.stream_sequence != expected:
                raise EventModelError("progress event history contains a sequence gap")
            expected += 1
            if terminal_seen:
                raise EventModelError("progress event follows a terminal event")
            if event.attempt < last_attempt or event.attempt > last_attempt + 1:
                raise EventModelError("progress attempt sequence is not contiguous")
            if event.attempt > last_attempt:
                if event.status != "resumed":
                    raise EventModelError("a new progress attempt must begin with resumed status")
                if event.current != last_current:
                    raise EventModelError("resumed progress must start at the prior durable coordinate")
                attempt_samples = []
                last_attempt = event.attempt
            if event.current is not None:
                if last_current is not None and event.current < last_current:
                    raise EventModelError("progress current coordinate moved backward")
                if last_unit is not None and event.unit != last_unit:
                    raise EventModelError("progress unit changed within one stream")
                if last_total is not None and event.total not in {None, last_total}:
                    raise EventModelError("progress total changed within one stream")
                last_current = event.current
                last_total = event.total if event.total is not None else last_total
                last_unit = event.unit
                attempt_samples.append(event)
            terminal_seen = event.terminal
        latest = ordered[-1]
        percent = None
        if last_current is not None and last_total is not None:
            percent = 10_000 if last_total == 0 else (last_current * 10_000) // last_total
        rate = None
        eta = None
        quantitative = [item for item in attempt_samples if item.current is not None]
        if len(quantitative) >= 2:
            first = quantitative[0]
            last = quantitative[-1]
            elapsed = _timestamp(last.occurred_at, "progress sample") - _timestamp(first.occurred_at, "progress sample")
            elapsed_ms = elapsed.days * 86_400_000 + elapsed.seconds * 1_000 + elapsed.microseconds // 1_000
            delta = (last.current or 0) - (first.current or 0)
            if elapsed_ms > 0 and delta > 0:
                rate = min(SAFE_INTEGER_MAX, (delta * 1_000_000) // elapsed_ms)
                if last_total is not None and last_current is not None and rate > 0:
                    remaining = last_total - last_current
                    eta = min(SAFE_INTEGER_MAX, (remaining * 1_000 + rate - 1) // rate)
        return ProgressProjection(
            stream_id,
            operation_kind,
            latest.phase,
            latest.status,
            latest.attempt,
            last_current,
            last_total,
            last_unit,
            percent,
            rate,
            eta,
            latest.occurred_at,
            latest.terminal,
            history_complete,
            len(ordered),
        )
