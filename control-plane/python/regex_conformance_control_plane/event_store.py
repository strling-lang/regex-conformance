"""Bounded durable journal and cursor subscriptions for lifecycle events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from typing import Any, Protocol
import uuid

from .event_models import EventBatch, EventCursor, EventDraft, EventModelError, LifecycleEvent, StoredEvent
from .state_models import (
    OPERATIONAL_ID_PATTERN,
    SAFE_INTEGER_MAX,
    StateModelError,
    canonical_json,
    canonical_object,
    parse_canonical_object,
)
from .state_store import _ProcessLock, _validate_sqlite_sidecars, _validate_state_path


EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()
CURRENT_EVENT_DATABASE_VERSION = 1


class EventClock(Protocol):
    def now(self) -> datetime: ...


class EventIdGenerator(Protocol):
    def new_event_id(self) -> str: ...

    def new_journal_id(self) -> str: ...


class UtcEventClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class Uuid7EventIds:
    @staticmethod
    def _new(namespace: str) -> str:
        milliseconds = time.time_ns() // 1_000_000
        if milliseconds >= 1 << 48:
            raise RuntimeError("system time exceeds UUIDv7 timestamp domain")
        random_bits = secrets.randbits(74)
        value = (
            (milliseconds << 80)
            | (0x7 << 76)
            | (((random_bits >> 62) & 0xFFF) << 64)
            | (0b10 << 62)
            | (random_bits & ((1 << 62) - 1))
        )
        return f"opid:v1:{namespace}:u7:{uuid.UUID(int=value)}"

    def new_event_id(self) -> str:
        return self._new("lifecycle-event")

    def new_journal_id(self) -> str:
        return self._new("event-journal")


class EventJournalError(RuntimeError):
    pass


class EventJournalCorruptionError(EventJournalError):
    pass


class EventJournalConflictError(EventJournalError):
    pass


class EventCursorGapError(EventJournalError):
    def __init__(self, requested_offset: int, oldest_available_offset: int) -> None:
        self.requested_offset = requested_offset
        self.oldest_available_offset = oldest_available_offset
        super().__init__(
            f"event cursor {requested_offset} precedes oldest available offset {oldest_available_offset}"
        )


_SCHEMA = (
    """
    CREATE TABLE journal_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE lifecycle_events (
        event_offset INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        stream_id TEXT NOT NULL,
        stream_sequence INTEGER NOT NULL,
        draft_sha256 TEXT NOT NULL,
        event_json TEXT NOT NULL,
        event_digest TEXT NOT NULL,
        previous_chain_sha256 TEXT NOT NULL,
        chain_sha256 TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        UNIQUE (stream_id, stream_sequence)
    )
    """,
    """
    CREATE TABLE event_stream_heads (
        stream_id TEXT PRIMARY KEY,
        operation_kind TEXT NOT NULL,
        last_sequence INTEGER NOT NULL,
        attempt INTEGER NOT NULL,
        current_value INTEGER,
        total_value INTEGER,
        unit TEXT,
        terminal INTEGER NOT NULL CHECK (terminal IN (0, 1))
    )
    """,
    "CREATE INDEX idx_lifecycle_events_stream ON lifecycle_events (stream_id, stream_sequence)",
)
SCHEMA_SHA256 = hashlib.sha256("\n-- statement --\n".join(item.strip() for item in _SCHEMA).encode()).hexdigest()
_EXPECTED_COLUMNS = {
    "journal_metadata": ("key", "value"),
    "lifecycle_events": (
        "event_offset",
        "event_id",
        "stream_id",
        "stream_sequence",
        "draft_sha256",
        "event_json",
        "event_digest",
        "previous_chain_sha256",
        "chain_sha256",
        "occurred_at",
    ),
    "event_stream_heads": (
        "stream_id",
        "operation_kind",
        "last_sequence",
        "attempt",
        "current_value",
        "total_value",
        "unit",
        "terminal",
    ),
}


def _stamp(clock: EventClock) -> str:
    value = clock.now()
    if value.tzinfo is None:
        raise EventModelError("event clock must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _draft_digest(draft: EventDraft) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "attempt": draft.attempt,
                "attributes": draft.attributes_object,
                "causation_id": draft.causation_id,
                "correlation_id": draft.correlation_id,
                "current": draft.current,
                "event_type": draft.event_type,
                "message": draft.message,
                "operation_kind": draft.operation_kind,
                "phase": draft.phase,
                "status": draft.status,
                "stream_id": draft.stream_id,
                "terminal": draft.terminal,
                "total": draft.total,
                "unit": draft.unit,
            }
        )
    ).hexdigest()


def _snapshot_draft(draft: EventDraft) -> EventDraft:
    """Detach producer-owned mutable objects before digesting or persisting."""

    attributes_json, _ = canonical_object(draft.attributes_object)
    return EventDraft(
        stream_id=draft.stream_id,
        operation_kind=draft.operation_kind,
        event_type=draft.event_type,
        phase=draft.phase,
        status=draft.status,
        attempt=draft.attempt,
        current=draft.current,
        total=draft.total,
        unit=draft.unit,
        message=draft.message,
        correlation_id=draft.correlation_id,
        causation_id=draft.causation_id,
        attributes=parse_canonical_object(attributes_json),
        terminal=draft.terminal,
    )


def _draft_from_event(event: LifecycleEvent) -> EventDraft:
    return EventDraft(
        stream_id=event.stream_id,
        operation_kind=event.operation_kind,
        event_type=event.event_type,
        phase=event.phase,
        status=event.status,
        attempt=event.attempt,
        current=event.current,
        total=event.total,
        unit=event.unit,
        message=event.message,
        correlation_id=event.correlation_id,
        causation_id=event.causation_id,
        attributes=event.attributes,
        terminal=event.terminal,
    )


def _chain_digest(offset: int, previous: str, event: LifecycleEvent) -> str:
    return hashlib.sha256(
        canonical_json({"event": event.to_dict(), "offset": offset, "previous_chain_sha256": previous})
    ).hexdigest()


def _event_from_json(value: str) -> LifecycleEvent:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise EventJournalCorruptionError("stored lifecycle event is not JSON") from error
    try:
        if not isinstance(parsed, dict) or canonical_json(parsed).decode("utf-8") != value:
            raise EventJournalCorruptionError("stored lifecycle event is not canonical JSON")
        attributes_json = canonical_json(parsed["attributes"]).decode("utf-8")
        return LifecycleEvent(
            event_id=parsed["event_id"],
            stream_id=parsed["stream_id"],
            stream_sequence=parsed["stream_sequence"],
            operation_kind=parsed["operation_kind"],
            event_type=parsed["event_type"],
            phase=parsed["phase"],
            status=parsed["status"],
            attempt=parsed["attempt"],
            occurred_at=parsed["occurred_at"],
            current=parsed["current"],
            total=parsed["total"],
            unit=parsed["unit"],
            message=parsed["message"],
            correlation_id=parsed["correlation_id"],
            causation_id=parsed["causation_id"],
            attributes_json=attributes_json,
            attributes_sha256=parsed["attributes_sha256"],
            terminal=parsed["terminal"],
            event_digest=parsed["event_digest"],
            canonical_authority=parsed["canonical_authority"],
            schema_version=parsed["schema_version"],
        )
    except (KeyError, TypeError, EventModelError, StateModelError) as error:
        raise EventJournalCorruptionError("stored lifecycle event violates its model") from error


class EventJournal:
    """Single-process append journal with bounded retention and explicit cursor gaps."""

    def __init__(
        self,
        path: Path,
        connection: sqlite3.Connection,
        process_lock: _ProcessLock,
        *,
        clock: EventClock,
        ids: EventIdGenerator,
    ) -> None:
        self.path = path
        self._connection = connection
        self._process_lock = process_lock
        self._clock = clock
        self._ids = ids
        self._mutex = threading.RLock()
        self._changed = threading.Condition(self._mutex)
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path | str,
        *,
        maximum_events: int = 10_000,
        clock: EventClock | None = None,
        id_generator: EventIdGenerator | None = None,
    ) -> "EventJournal":
        if isinstance(maximum_events, bool) or not 1 <= maximum_events <= 1_000_000:
            raise ValueError("event retention must be between 1 and 1,000,000 events")
        selected_clock = clock or UtcEventClock()
        selected_ids = id_generator or Uuid7EventIds()
        state_path, new_database, expected_identity = _validate_state_path(Path(path))
        process_lock = _ProcessLock(Path(f"{state_path}.lock"))
        process_lock.acquire()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(state_path, timeout=30.0, isolation_level=None, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            opened = state_path.stat(follow_symlinks=False)
            if (int(opened.st_dev), int(opened.st_ino)) != expected_identity:
                raise EventJournalCorruptionError("event journal identity changed during open")
            discovered = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if discovered > CURRENT_EVENT_DATABASE_VERSION:
                raise EventJournalCorruptionError("event journal schema is newer than this controller")
            connection.execute("PRAGMA busy_timeout = 30000")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).casefold()
            if mode != "wal":
                raise EventJournalCorruptionError("event journal could not enable WAL")
            _validate_sqlite_sidecars(state_path)
            connection.execute("PRAGMA secure_delete = ON")
            if discovered == 0:
                connection.execute("BEGIN EXCLUSIVE")
                try:
                    for statement in _SCHEMA:
                        connection.execute(statement)
                    journal_id = selected_ids.new_journal_id()
                    if not journal_id.startswith("opid:v1:event-journal:u7:"):
                        raise EventModelError("event journal ID generator returned the wrong namespace")
                    metadata = {
                        "journal_id": journal_id,
                        "last_offset": "0",
                        "maximum_events": str(maximum_events),
                        "oldest_offset": "0",
                        "retained_anchor_sha256": EMPTY_DIGEST,
                        "schema_sha256": SCHEMA_SHA256,
                        "tail_chain_sha256": EMPTY_DIGEST,
                    }
                    connection.executemany("INSERT INTO journal_metadata (key, value) VALUES (?, ?)", metadata.items())
                    connection.execute(f"PRAGMA user_version = {CURRENT_EVENT_DATABASE_VERSION}")
                    connection.execute("COMMIT")
                except Exception:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
            elif new_database:
                raise EventJournalCorruptionError("non-new event journal has an empty database file")
            cls._verify(connection, maximum_events)
            return cls(state_path, connection, process_lock, clock=selected_clock, ids=selected_ids)
        except Exception:
            if connection is not None:
                connection.close()
            process_lock.release()
            raise

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        return {str(row[0]): str(row[1]) for row in connection.execute("SELECT key, value FROM journal_metadata")}

    @classmethod
    def _verify(cls, connection: sqlite3.Connection, requested_maximum: int | None = None) -> None:
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != CURRENT_EVENT_DATABASE_VERSION:
            raise EventJournalCorruptionError("event journal schema version is unsupported")
        if str(connection.execute("PRAGMA quick_check").fetchone()[0]).casefold() != "ok":
            raise EventJournalCorruptionError("event journal failed SQLite quick_check")
        objects = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('index', 'table')"
            )
        }
        if objects != {"event_stream_heads", "idx_lifecycle_events_stream", "journal_metadata", "lifecycle_events"}:
            raise EventJournalCorruptionError("event journal schema objects are missing or unexpected")
        for table, expected_columns in _EXPECTED_COLUMNS.items():
            actual_columns = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info('{table}')"))
            if actual_columns != expected_columns:
                raise EventJournalCorruptionError(f"event journal table {table} has an incompatible column layout")
        metadata = cls._metadata(connection)
        expected_keys = {
            "journal_id",
            "last_offset",
            "maximum_events",
            "oldest_offset",
            "retained_anchor_sha256",
            "schema_sha256",
            "tail_chain_sha256",
        }
        if set(metadata) != expected_keys or metadata["schema_sha256"] != SCHEMA_SHA256:
            raise EventJournalCorruptionError("event journal metadata or schema digest is invalid")
        if not metadata["journal_id"].startswith("opid:v1:event-journal:u7:") or OPERATIONAL_ID_PATTERN.fullmatch(metadata["journal_id"]) is None:
            raise EventJournalCorruptionError("event journal ID is invalid")
        try:
            maximum = int(metadata["maximum_events"])
            last_offset = int(metadata["last_offset"])
            oldest_offset = int(metadata["oldest_offset"])
        except ValueError as error:
            raise EventJournalCorruptionError("event journal numeric metadata is malformed") from error
        if not 1 <= maximum <= 1_000_000:
            raise EventJournalCorruptionError("event journal retention metadata is outside the supported domain")
        if requested_maximum is not None and maximum != requested_maximum:
            raise EventJournalConflictError("configured event retention differs from the durable journal policy")
        for value in (last_offset, oldest_offset):
            if not 0 <= value <= SAFE_INTEGER_MAX:
                raise EventJournalCorruptionError("event journal offset is outside the safe-integer domain")
        for key in ("retained_anchor_sha256", "tail_chain_sha256"):
            value = metadata[key]
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise EventJournalCorruptionError("event journal chain metadata is malformed")
        rows = list(connection.execute("SELECT * FROM lifecycle_events ORDER BY event_offset"))
        if len(rows) > maximum:
            raise EventJournalCorruptionError("event journal exceeds its retention policy")
        if not rows:
            if (
                last_offset != 0
                or oldest_offset != 0
                or metadata["tail_chain_sha256"] != EMPTY_DIGEST
                or metadata["retained_anchor_sha256"] != EMPTY_DIGEST
            ):
                raise EventJournalCorruptionError("empty event journal metadata is inconsistent")
            if connection.execute("SELECT 1 FROM event_stream_heads LIMIT 1").fetchone() is not None:
                raise EventJournalCorruptionError("empty event journal retains a stream head")
            return
        try:
            first_offset = int(rows[0]["event_offset"])
            final_offset = int(rows[-1]["event_offset"])
        except (TypeError, ValueError) as error:
            raise EventJournalCorruptionError("event journal row offset is malformed") from error
        if first_offset != oldest_offset or final_offset != last_offset:
            raise EventJournalCorruptionError("event retention bounds disagree with stored rows")
        previous = metadata["retained_anchor_sha256"]
        expected_offset = oldest_offset
        stream_sequences: dict[str, int] = {}
        for row in rows:
            try:
                offset = int(row["event_offset"])
                stored_stream_sequence = int(row["stream_sequence"])
            except (TypeError, ValueError) as error:
                raise EventJournalCorruptionError("event journal row coordinates are malformed") from error
            if offset != expected_offset:
                raise EventJournalCorruptionError("retained event offsets are not contiguous")
            expected_offset += 1
            event = _event_from_json(str(row["event_json"]))
            if event.event_id != str(row["event_id"]) or event.event_digest != str(row["event_digest"]):
                raise EventJournalCorruptionError("event row identity does not match serialized content")
            if event.stream_id != str(row["stream_id"]) or event.stream_sequence != stored_stream_sequence:
                raise EventJournalCorruptionError("event stream coordinates do not match serialized content")
            if str(row["occurred_at"]) != event.occurred_at:
                raise EventJournalCorruptionError("event occurrence column does not match serialized content")
            if str(row["draft_sha256"]) != _draft_digest(_draft_from_event(event)):
                raise EventJournalCorruptionError("event draft digest does not match serialized content")
            prior_sequence = stream_sequences.get(event.stream_id)
            if prior_sequence is not None and event.stream_sequence != prior_sequence + 1:
                raise EventJournalCorruptionError("retained event stream sequence is not contiguous")
            stream_sequences[event.stream_id] = event.stream_sequence
            if str(row["previous_chain_sha256"]) != previous:
                raise EventJournalCorruptionError("event chain predecessor is inconsistent")
            expected_chain = _chain_digest(offset, previous, event)
            if str(row["chain_sha256"]) != expected_chain:
                raise EventJournalCorruptionError("event journal chain digest is invalid")
            previous = expected_chain
        if previous != metadata["tail_chain_sha256"]:
            raise EventJournalCorruptionError("event journal tail digest is inconsistent")
        head_streams: set[str] = set()
        for row in connection.execute("SELECT * FROM event_stream_heads ORDER BY stream_id"):
            stream_id = str(row["stream_id"])
            head_streams.add(stream_id)
            if OPERATIONAL_ID_PATTERN.fullmatch(stream_id) is None:
                raise EventJournalCorruptionError("event stream head contains an invalid stream ID")
            try:
                last_sequence = int(row["last_sequence"])
                attempt = int(row["attempt"])
                terminal = int(row["terminal"])
            except (TypeError, ValueError) as error:
                raise EventJournalCorruptionError("event stream head contains malformed coordinates") from error
            if (
                not 1 <= last_sequence <= SAFE_INTEGER_MAX
                or not 1 <= attempt <= SAFE_INTEGER_MAX
                or terminal not in {0, 1}
            ):
                raise EventJournalCorruptionError("event stream head coordinates are outside the safe-integer domain")
            retained = connection.execute(
                "SELECT event_json FROM lifecycle_events WHERE stream_id = ? ORDER BY stream_sequence DESC LIMIT 1",
                (stream_id,),
            ).fetchone()
            if retained is None:
                if bool(row["terminal"]):
                    raise EventJournalCorruptionError("terminal event stream head survived complete retention eviction")
                continue
            event = _event_from_json(str(retained[0]))
            if (
                str(row["operation_kind"]) != event.operation_kind
                or last_sequence != event.stream_sequence
                or attempt != event.attempt
                or terminal != int(event.terminal)
                or (event.current is not None and row["current_value"] != event.current)
                or (event.total is not None and row["total_value"] != event.total)
                or (event.unit is not None and row["unit"] != event.unit)
            ):
                raise EventJournalCorruptionError("event stream head disagrees with its latest retained event")
        if not set(stream_sequences).issubset(head_streams):
            raise EventJournalCorruptionError("retained event stream is missing its durable head")

    def _ensure_open(self) -> None:
        if self._closed:
            raise EventJournalError("event journal is closed")

    def close(self) -> None:
        with self._changed:
            if self._closed:
                return
            self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._connection.close()
            self._process_lock.release()
            self._closed = True
            self._changed.notify_all()

    def __enter__(self) -> "EventJournal":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @property
    def journal_id(self) -> str:
        with self._mutex:
            self._ensure_open()
            return self._metadata(self._connection)["journal_id"]

    def cursor(self) -> EventCursor:
        with self._mutex:
            self._ensure_open()
            metadata = self._metadata(self._connection)
            return EventCursor(metadata["journal_id"], int(metadata["last_offset"]))

    def publish(self, draft: EventDraft, *, event_id: str | None = None) -> StoredEvent:
        draft = _snapshot_draft(draft)
        selected_id = event_id or self._ids.new_event_id()
        if not selected_id.startswith("opid:v1:lifecycle-event:u7:") or OPERATIONAL_ID_PATTERN.fullmatch(selected_id) is None:
            raise EventModelError("event ID generator returned the wrong namespace")
        request_digest = _draft_digest(draft)
        with self._changed:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT event_offset, draft_sha256, event_json FROM lifecycle_events WHERE event_id = ?",
                    (selected_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing["draft_sha256"]) != request_digest:
                        raise EventJournalConflictError("event ID was reused with different content")
                    event = _event_from_json(str(existing["event_json"]))
                    self._connection.execute("ROLLBACK")
                    return StoredEvent(int(existing["event_offset"]), event)
                metadata = self._metadata(self._connection)
                offset = int(metadata["last_offset"]) + 1
                if offset > SAFE_INTEGER_MAX:
                    raise EventJournalConflictError("event journal exhausted the safe-integer offset domain")
                head = self._connection.execute(
                    "SELECT * FROM event_stream_heads WHERE stream_id = ?",
                    (draft.stream_id,),
                ).fetchone()
                if head is None:
                    active_heads = int(
                        self._connection.execute("SELECT COUNT(*) FROM event_stream_heads WHERE terminal = 0").fetchone()[0]
                    )
                    if active_heads >= int(metadata["maximum_events"]):
                        raise EventJournalConflictError("active event streams reached the bounded journal policy")
                    if draft.attempt != 1:
                        raise EventJournalConflictError("a new event stream must begin with attempt one")
                    sequence = 1
                else:
                    if bool(head["terminal"]):
                        raise EventJournalConflictError("terminal event streams are immutable")
                    if str(head["operation_kind"]) != draft.operation_kind:
                        raise EventJournalConflictError("event stream operation kind changed")
                    prior_attempt = int(head["attempt"])
                    if draft.attempt not in {prior_attempt, prior_attempt + 1}:
                        raise EventJournalConflictError("event attempt sequence is not contiguous")
                    if draft.attempt == prior_attempt + 1:
                        if draft.status != "resumed" or draft.current != head["current_value"]:
                            raise EventJournalConflictError("a resumed attempt must bind the prior durable coordinate")
                    elif draft.status == "resumed":
                        raise EventJournalConflictError("resumed status requires a new attempt")
                    if draft.current is not None and head["current_value"] is not None and draft.current < int(head["current_value"]):
                        raise EventJournalConflictError("event progress moved backward")
                    if head["unit"] is not None and draft.unit != str(head["unit"]):
                        raise EventJournalConflictError("event progress unit changed")
                    if head["total_value"] is not None and draft.total not in {None, int(head["total_value"])}:
                        raise EventJournalConflictError("event progress total changed")
                    sequence = int(head["last_sequence"]) + 1
                    if sequence > SAFE_INTEGER_MAX:
                        raise EventJournalConflictError("event stream exhausted the safe-integer sequence domain")
                event = LifecycleEvent.build(
                    event_id=selected_id,
                    stream_sequence=sequence,
                    occurred_at=_stamp(self._clock),
                    draft=draft,
                )
                previous = metadata["tail_chain_sha256"]
                chain = _chain_digest(offset, previous, event)
                event_json = canonical_json(event.to_dict()).decode("utf-8")
                self._connection.execute(
                    "INSERT INTO lifecycle_events (event_offset, event_id, stream_id, stream_sequence, draft_sha256, "
                    "event_json, event_digest, previous_chain_sha256, chain_sha256, occurred_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        offset,
                        event.event_id,
                        event.stream_id,
                        event.stream_sequence,
                        request_digest,
                        event_json,
                        event.event_digest,
                        previous,
                        chain,
                        event.occurred_at,
                    ),
                )
                effective_current = draft.current if draft.current is not None else (None if head is None else head["current_value"])
                effective_total = draft.total if draft.total is not None else (None if head is None else head["total_value"])
                effective_unit = draft.unit if draft.unit is not None else (None if head is None else head["unit"])
                self._connection.execute(
                    "INSERT INTO event_stream_heads (stream_id, operation_kind, last_sequence, attempt, current_value, "
                    "total_value, unit, terminal) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(stream_id) DO UPDATE SET last_sequence = excluded.last_sequence, "
                    "attempt = excluded.attempt, current_value = excluded.current_value, "
                    "total_value = excluded.total_value, unit = excluded.unit, terminal = excluded.terminal",
                    (
                        draft.stream_id,
                        draft.operation_kind,
                        sequence,
                        draft.attempt,
                        effective_current,
                        effective_total,
                        effective_unit,
                        int(draft.terminal),
                    ),
                )
                oldest = int(metadata["oldest_offset"]) or offset
                anchor = metadata["retained_anchor_sha256"]
                maximum = int(metadata["maximum_events"])
                excess = int(self._connection.execute("SELECT COUNT(*) FROM lifecycle_events").fetchone()[0]) - maximum
                if excess > 0:
                    removed = list(
                        self._connection.execute(
                            "SELECT event_offset, chain_sha256 FROM lifecycle_events ORDER BY event_offset LIMIT ?",
                            (excess,),
                        )
                    )
                    anchor = str(removed[-1]["chain_sha256"])
                    cutoff = int(removed[-1]["event_offset"])
                    self._connection.execute("DELETE FROM lifecycle_events WHERE event_offset <= ?", (cutoff,))
                    self._connection.execute(
                        "DELETE FROM event_stream_heads WHERE terminal = 1 AND stream_id NOT IN "
                        "(SELECT DISTINCT stream_id FROM lifecycle_events)"
                    )
                    oldest = cutoff + 1
                self._connection.executemany(
                    "UPDATE journal_metadata SET value = ? WHERE key = ?",
                    ((str(offset), "last_offset"), (str(oldest), "oldest_offset"), (anchor, "retained_anchor_sha256"), (chain, "tail_chain_sha256")),
                )
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            self._changed.notify_all()
            return StoredEvent(offset, event)

    def read(self, cursor: EventCursor | None = None, *, maximum_events: int = 100) -> EventBatch:
        if isinstance(maximum_events, bool) or not 1 <= maximum_events <= 10_000:
            raise ValueError("event batch size must be between 1 and 10,000")
        with self._mutex:
            self._ensure_open()
            metadata = self._metadata(self._connection)
            journal_id = metadata["journal_id"]
            if cursor is not None and cursor.journal_id != journal_id:
                raise EventJournalConflictError("event cursor belongs to another journal")
            oldest = int(metadata["oldest_offset"])
            newest = int(metadata["last_offset"])
            requested = (oldest - 1 if oldest else 0) if cursor is None else cursor.offset
            if oldest and requested < oldest - 1:
                raise EventCursorGapError(requested, oldest)
            if requested > newest:
                raise EventJournalConflictError("event cursor is ahead of the journal tail")
            rows = list(
                self._connection.execute(
                    "SELECT event_offset, event_json FROM lifecycle_events WHERE event_offset > ? "
                    "ORDER BY event_offset LIMIT ?",
                    (requested, maximum_events + 1),
                )
            )
            has_more = len(rows) > maximum_events
            selected = rows[:maximum_events]
            events = tuple(StoredEvent(int(row["event_offset"]), _event_from_json(str(row["event_json"]))) for row in selected)
            next_offset = events[-1].offset if events else requested
            return EventBatch(
                EventCursor(journal_id, next_offset),
                events,
                oldest or None,
                newest or None,
                has_more,
            )

    def read_stream(self, stream_id: str) -> tuple[LifecycleEvent, ...]:
        if OPERATIONAL_ID_PATTERN.fullmatch(stream_id) is None:
            raise EventModelError("event stream ID must be an operational UUIDv7")
        with self._mutex:
            self._ensure_open()
            return tuple(
                _event_from_json(str(row[0]))
                for row in self._connection.execute(
                    "SELECT event_json FROM lifecycle_events WHERE stream_id = ? ORDER BY stream_sequence",
                    (stream_id,),
                )
            )

    def subscribe(self, cursor: EventCursor | None = None) -> "EventSubscription":
        return EventSubscription(self, cursor)

    def _wait_for_change(self, cursor: EventCursor | None, timeout_seconds: float | None) -> None:
        with self._changed:
            self._ensure_open()
            baseline = 0 if cursor is None else cursor.offset
            newest = int(self._metadata(self._connection)["last_offset"])
            if newest > baseline:
                return
            self._changed.wait(timeout_seconds)

    def health_check(self) -> dict[str, Any]:
        with self._mutex:
            self._ensure_open()
            self._verify(self._connection)
            metadata = self._metadata(self._connection)
            count = int(self._connection.execute("SELECT COUNT(*) FROM lifecycle_events").fetchone()[0])
            return {
                "canonical_authority": False,
                "journal_id": metadata["journal_id"],
                "last_offset": int(metadata["last_offset"]),
                "maximum_events": int(metadata["maximum_events"]),
                "oldest_offset": int(metadata["oldest_offset"]),
                "retained_event_count": count,
                "schema_sha256": SCHEMA_SHA256,
            }


@dataclass
class EventSubscription:
    journal: EventJournal
    cursor: EventCursor | None = None

    def next_batch(self, *, maximum_events: int = 100, timeout_seconds: float | None = None) -> EventBatch:
        if timeout_seconds is not None and (timeout_seconds < 0 or timeout_seconds > 300):
            raise ValueError("event subscription timeout must be between 0 and 300 seconds")
        batch = self.journal.read(self.cursor, maximum_events=maximum_events)
        if not batch.events and timeout_seconds != 0:
            self.journal._wait_for_change(self.cursor, timeout_seconds)
            batch = self.journal.read(self.cursor, maximum_events=maximum_events)
        self.cursor = batch.cursor
        return batch
