"""Restart-safe SQLite state, conservative reconciliation, and recoverable rebuild."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

from .state_models import (
    OPERATIONAL_ID_PATTERN,
    SAFE_INTEGER_MAX,
    STATE_RECORD_KINDS,
    OperationalStateRecord,
    ReconciliationAction,
    ReconciliationActionResult,
    ReconciliationIssue,
    ReconciliationObservation,
    ReconciliationPlan,
    ReconciliationReport,
    StateModelError,
    StateMutation,
    StateSnapshot,
    StateSourceReference,
    canonical_json,
)

CURRENT_DATABASE_SCHEMA_VERSION = 1
DEFAULT_BUSY_TIMEOUT_SECONDS = 5
DEFAULT_MAXIMUM_OBSERVATION_AGE_SECONDS = 300


class StateClock(Protocol):
    def now(self) -> datetime: ...


class StateIdGenerator(Protocol):
    def new_store_id(self) -> str: ...

    def new_session_id(self) -> str: ...

    def new_reconciliation_id(self) -> str: ...


class UtcStateClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class Uuid7StateIds:
    @staticmethod
    def _new(namespace: str) -> str:
        stamp = int(time.time() * 1000)
        if not 0 <= stamp < 2**48:
            raise StateModelError("UUIDv7 timestamp must fit in 48 bits")
        integer = (
            (stamp << 80)
            | (0x7 << 76)
            | (secrets.randbits(12) << 64)
            | (0b10 << 62)
            | secrets.randbits(62)
        )
        return f"opid:v1:{namespace}:u7:{uuid.UUID(int=integer)}"

    def new_store_id(self) -> str:
        return self._new("control-plane-state")

    def new_session_id(self) -> str:
        return self._new("control-plane-session")

    def new_reconciliation_id(self) -> str:
        return self._new("state-reconciliation")


class StateStoreError(RuntimeError):
    pass


class StateCorruptionError(StateStoreError):
    pass


class IncompatibleStateVersionError(StateStoreError):
    pass


class StateConflictError(StateStoreError):
    pass


class StateAdmissionError(StateStoreError):
    pass


class StateStoreBusyError(StateStoreError):
    pass


class StaleReconciliationPlanError(StateStoreError):
    pass


class UnsafeStatePathError(StateStoreError):
    pass


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]

    @property
    def sha256(self) -> str:
        encoded = "\n-- statement --\n".join(item.strip() for item in self.statements).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


MIGRATIONS = (
    Migration(
        1,
        "initial-durable-operational-state",
        (
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE operational_records (
                record_kind TEXT NOT NULL,
                record_id TEXT NOT NULL,
                generation INTEGER NOT NULL CHECK (generation >= 1),
                lifecycle_state TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sources_json TEXT NOT NULL,
                tombstoned INTEGER NOT NULL CHECK (tombstoned IN (0, 1)),
                PRIMARY KEY (record_kind, record_id)
            )
            """,
            """
            CREATE TABLE state_transitions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                command_id TEXT NOT NULL,
                record_kind TEXT NOT NULL,
                record_id TEXT NOT NULL,
                from_generation INTEGER,
                to_generation INTEGER NOT NULL,
                from_payload_sha256 TEXT,
                to_payload_sha256 TEXT NOT NULL,
                from_state_sha256 TEXT,
                to_state_sha256 TEXT NOT NULL,
                action TEXT NOT NULL,
                reason_code TEXT NOT NULL,
                committed_at TEXT NOT NULL,
                UNIQUE (command_id, record_kind, record_id)
            )
            """,
            """
            CREATE TABLE commands (
                command_id TEXT PRIMARY KEY,
                request_sha256 TEXT NOT NULL,
                committed_epoch INTEGER NOT NULL,
                committed_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE controller_sessions (
                session_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                termination TEXT NOT NULL,
                prior_session_id TEXT
            )
            """,
            """
            CREATE TABLE reconciliation_runs (
                plan_id TEXT PRIMARY KEY,
                plan_sha256 TEXT NOT NULL,
                report_json TEXT NOT NULL,
                completed_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX idx_transitions_record ON state_transitions (record_kind, record_id, sequence)",
            "CREATE INDEX idx_sessions_started ON controller_sessions (started_at, session_id)",
            """
            CREATE TRIGGER immutable_migrations_update
            BEFORE UPDATE ON schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migration history is immutable');
            END
            """,
            """
            CREATE TRIGGER immutable_migrations_delete
            BEFORE DELETE ON schema_migrations BEGIN
                SELECT RAISE(ABORT, 'schema migration history is immutable');
            END
            """,
            """
            CREATE TRIGGER immutable_transitions_update
            BEFORE UPDATE ON state_transitions BEGIN
                SELECT RAISE(ABORT, 'state transition history is immutable');
            END
            """,
            """
            CREATE TRIGGER immutable_transitions_delete
            BEFORE DELETE ON state_transitions BEGIN
                SELECT RAISE(ABORT, 'state transition history is immutable');
            END
            """,
            """
            CREATE TRIGGER immutable_commands_update
            BEFORE UPDATE ON commands BEGIN
                SELECT RAISE(ABORT, 'state command history is immutable');
            END
            """,
            """
            CREATE TRIGGER immutable_commands_delete
            BEFORE DELETE ON commands BEGIN
                SELECT RAISE(ABORT, 'state command history is immutable');
            END
            """,
            """
            CREATE TRIGGER immutable_reconciliations_update
            BEFORE UPDATE ON reconciliation_runs BEGIN
                SELECT RAISE(ABORT, 'reconciliation history is immutable');
            END
            """,
            """
            CREATE TRIGGER immutable_reconciliations_delete
            BEFORE DELETE ON reconciliation_runs BEGIN
                SELECT RAISE(ABORT, 'reconciliation history is immutable');
            END
            """,
        ),
    ),
)

_EXPECTED_OBJECTS = frozenset(
    {
        "commands",
        "controller_sessions",
        "idx_sessions_started",
        "idx_transitions_record",
        "immutable_commands_delete",
        "immutable_commands_update",
        "immutable_migrations_delete",
        "immutable_migrations_update",
        "immutable_reconciliations_delete",
        "immutable_reconciliations_update",
        "immutable_transitions_delete",
        "immutable_transitions_update",
        "metadata",
        "operational_records",
        "reconciliation_runs",
        "schema_migrations",
        "state_transitions",
    }
)
_EXPECTED_COLUMNS = {
    "schema_migrations": ("version", "name", "sha256", "applied_at"),
    "metadata": ("key", "value"),
    "operational_records": (
        "record_kind",
        "record_id",
        "generation",
        "lifecycle_state",
        "verification_status",
        "payload_json",
        "payload_sha256",
        "updated_at",
        "sources_json",
        "tombstoned",
    ),
    "state_transitions": (
        "sequence",
        "command_id",
        "record_kind",
        "record_id",
        "from_generation",
        "to_generation",
        "from_payload_sha256",
        "to_payload_sha256",
        "from_state_sha256",
        "to_state_sha256",
        "action",
        "reason_code",
        "committed_at",
    ),
    "commands": ("command_id", "request_sha256", "committed_epoch", "committed_at"),
    "controller_sessions": ("session_id", "started_at", "ended_at", "termination", "prior_session_id"),
    "reconciliation_runs": ("plan_id", "plan_sha256", "report_json", "completed_at"),
}

_ALLOWED_RECONCILIATION_SOURCES = {
    "cache-inventory": frozenset({"provider-reality"}),
    "campaign-assignment": frozenset({"immutable-evidence", "provider-reality", "repository-manifest"}),
    "environment-instance": frozenset({"provider-reality"}),
    "event-cursor": frozenset({"immutable-evidence", "provider-reality"}),
    "lease": frozenset({"provider-reality"}),
    "machine-inventory": frozenset({"provider-reality"}),
    "resource-measurement": frozenset({"provider-reality"}),
    "shard-checkpoint": frozenset({"immutable-evidence", "provider-reality"}),
    "spool-publication": frozenset({"immutable-evidence", "provider-reality"}),
    "transfer": frozenset({"immutable-evidence", "provider-reality"}),
    "worker-telemetry": frozenset({"provider-reality"}),
}


def _now(clock: StateClock) -> datetime:
    value = clock.now()
    if value.tzinfo is None:
        raise StateModelError("state clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise StateModelError("stored state timestamp is not RFC 3339") from error
    if parsed.tzinfo is None:
        raise StateModelError("stored state timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _require_token(value: str, label: str) -> None:
    from .state_models import TOKEN_PATTERN

    if TOKEN_PATTERN.fullmatch(value) is None:
        raise StateModelError(f"{label} must be a lowercase hyphenated token")


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _is_linklike(path: Path) -> bool:
    junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(junction is not None and junction())


def _prepare_state_parent(parent: Path) -> None:
    probe = parent
    missing: list[Path] = []
    while not probe.exists() and probe != probe.parent:
        missing.append(probe)
        probe = probe.parent
    while probe != probe.parent:
        if probe.exists() and _is_linklike(probe):
            raise UnsafeStatePathError("state database path cannot traverse a symbolic link")
        probe = probe.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    for created in reversed(missing):
        if _is_linklike(created):
            raise UnsafeStatePathError("state database parent changed into a link during creation")
    try:
        os.chmod(parent, 0o700)
    except OSError:
        if os.name != "nt":
            raise


def _sqlite_sidecars(path: Path) -> tuple[Path, ...]:
    return tuple(Path(f"{path}{suffix}") for suffix in ("-journal", "-shm", "-wal"))


def _validate_sqlite_sidecars(path: Path) -> None:
    for sidecar in _sqlite_sidecars(path):
        if _is_linklike(sidecar):
            raise UnsafeStatePathError("SQLite state sidecars cannot be symbolic links or junctions")
        if not sidecar.exists():
            continue
        details = sidecar.stat(follow_symlinks=False)
        if not stat.S_ISREG(details.st_mode) or getattr(details, "st_nlink", 1) != 1:
            raise UnsafeStatePathError("SQLite state sidecars must be singly linked regular files")


def _validate_state_path(path: Path) -> tuple[Path, bool, tuple[int, int]]:
    candidate = Path(path)
    if not candidate.name or candidate.name in {".", ".."}:
        raise UnsafeStatePathError("state database path must identify one file")
    parent = candidate.parent
    _prepare_state_parent(parent)
    if _is_linklike(candidate):
        raise UnsafeStatePathError("state database cannot be a symbolic link")
    sidecars = _sqlite_sidecars(candidate)
    _validate_sqlite_sidecars(candidate)
    existed = candidate.exists()
    if not existed and any(item.exists() for item in sidecars):
        raise StateCorruptionError("state database is missing while SQLite sidecars remain")
    if not existed:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(candidate, flags, 0o600)
        except FileExistsError as error:
            raise StateStoreBusyError("state database appeared concurrently before lock acquisition") from error
        try:
            details = os.fstat(descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    else:
        details = candidate.stat(follow_symlinks=False)
    if not stat.S_ISREG(details.st_mode):
        raise UnsafeStatePathError("state database must be a regular file")
    if getattr(details, "st_nlink", 1) != 1:
        raise UnsafeStatePathError("state database cannot be multiply linked")
    try:
        os.chmod(candidate, 0o600)
    except OSError:
        if os.name != "nt":
            raise
    return candidate, (not existed or details.st_size == 0), (int(details.st_dev), int(details.st_ino))


class _ProcessLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def acquire(self) -> None:
        if _is_linklike(self.path):
            raise UnsafeStatePathError("state lock cannot be a symbolic link or junction")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or getattr(details, "st_nlink", 1) != 1:
                raise UnsafeStatePathError("state lock must be a singly linked regular file")
            if details.st_size == 0:
                os.write(descriptor, b"0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                except OSError as error:
                    raise StateStoreBusyError("another controller holds the local state lock") from error
            else:
                import fcntl

                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    raise StateStoreBusyError("another controller holds the local state lock") from error
            self._descriptor = descriptor
            descriptor = -1
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def release(self) -> None:
        if self._descriptor is None:
            return
        descriptor = self._descriptor
        self._descriptor = None
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _decode_sources(value: str) -> tuple[StateSourceReference, ...]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise StateModelError("stored state sources are not strict JSON") from error
    if not isinstance(parsed, list) or canonical_json(parsed).decode("utf-8") != value:
        raise StateModelError("stored state sources are not a canonical JSON array")
    try:
        sources = tuple(StateSourceReference(**item) for item in parsed)
    except (TypeError, StateModelError) as error:
        raise StateModelError("stored state sources are malformed") from error
    return sources


def _record_from_row(row: sqlite3.Row) -> OperationalStateRecord:
    return OperationalStateRecord(
        record_kind=str(row["record_kind"]),
        record_id=str(row["record_id"]),
        generation=int(row["generation"]),
        lifecycle_state=str(row["lifecycle_state"]),
        verification_status=str(row["verification_status"]),
        payload_json=str(row["payload_json"]),
        payload_sha256=str(row["payload_sha256"]),
        updated_at=str(row["updated_at"]),
        sources=_decode_sources(str(row["sources_json"])),
        tombstoned=bool(row["tombstoned"]),
    )


class LocalStateStore:
    """Single-controller transactional projection of recoverable operational state."""

    def __init__(
        self,
        path: Path,
        connection: sqlite3.Connection,
        process_lock: _ProcessLock,
        *,
        clock: StateClock,
        ids: StateIdGenerator,
        prior_shutdown: str,
        session_id: str,
    ) -> None:
        self.path = path
        self._connection = connection
        self._process_lock = process_lock
        self._clock = clock
        self._ids = ids
        self._prior_shutdown = prior_shutdown
        self._session_id = session_id
        self._mutex = threading.RLock()
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path | str,
        *,
        clock: StateClock | None = None,
        id_generator: StateIdGenerator | None = None,
        busy_timeout_seconds: int = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> "LocalStateStore":
        selected_clock = clock or UtcStateClock()
        selected_ids = id_generator or Uuid7StateIds()
        if isinstance(busy_timeout_seconds, bool) or not 1 <= busy_timeout_seconds <= 300:
            raise ValueError("state busy timeout must be between 1 and 300 seconds")
        state_path, new_database, expected_identity = _validate_state_path(Path(path))
        process_lock = _ProcessLock(Path(f"{state_path}.lock"))
        process_lock.acquire()
        try:
            return cls._open_with_lock(
                state_path,
                process_lock,
                new_database=new_database,
                expected_identity=expected_identity,
                clock=selected_clock,
                ids=selected_ids,
                busy_timeout_seconds=busy_timeout_seconds,
            )
        except Exception:
            process_lock.release()
            raise

    @classmethod
    def _open_with_lock(
        cls,
        path: Path,
        process_lock: _ProcessLock,
        *,
        new_database: bool,
        expected_identity: tuple[int, int],
        clock: StateClock,
        ids: StateIdGenerator,
        busy_timeout_seconds: int,
    ) -> "LocalStateStore":
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                path,
                timeout=float(busy_timeout_seconds),
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            if _is_linklike(path):
                raise UnsafeStatePathError("state database became a link during open")
            opened_details = path.stat(follow_symlinks=False)
            opened_identity = (int(opened_details.st_dev), int(opened_details.st_ino))
            if opened_identity != expected_identity or not stat.S_ISREG(opened_details.st_mode):
                raise UnsafeStatePathError("state database identity changed during open")
            discovered_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if discovered_version > CURRENT_DATABASE_SCHEMA_VERSION:
                raise IncompatibleStateVersionError(
                    f"state schema version {discovered_version} is newer than supported version "
                    f"{CURRENT_DATABASE_SCHEMA_VERSION}"
                )
            connection.execute(f"PRAGMA busy_timeout = {busy_timeout_seconds * 1000}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).casefold()
            if mode != "wal":
                raise StateCorruptionError("state database could not enable durable WAL journaling")
            _validate_sqlite_sidecars(path)
            connection.execute("PRAGMA wal_autocheckpoint = 1000")
            connection.execute("PRAGMA secure_delete = ON")
            cls._apply_migrations(connection, clock)
            cls._verify_integrity(connection)
            stamp = _rfc3339(_now(clock))
            if new_database:
                cls._initialize_metadata(connection, ids.new_store_id())
            cls._verify_metadata(connection)
            cls._verify_records(connection)
            cls._verify_history(connection)
            prior_shutdown, session_id = cls._start_session(connection, clock, ids, stamp)
            try:
                os.chmod(path, 0o600)
            except OSError:
                if os.name != "nt":
                    raise
            return cls(
                path,
                connection,
                process_lock,
                clock=clock,
                ids=ids,
                prior_shutdown=prior_shutdown,
                session_id=session_id,
            )
        except IncompatibleStateVersionError:
            if connection is not None:
                connection.close()
            raise
        except StateStoreError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.DatabaseError, StateModelError, UnicodeError, ValueError) as error:
            if connection is not None:
                connection.close()
            raise StateCorruptionError("local state failed integrity or schema validation") from error

    @staticmethod
    def _apply_migrations(connection: sqlite3.Connection, clock: StateClock) -> None:
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current > CURRENT_DATABASE_SCHEMA_VERSION:
            raise IncompatibleStateVersionError(
                f"state schema version {current} is newer than supported version {CURRENT_DATABASE_SCHEMA_VERSION}"
            )
        for migration in MIGRATIONS:
            if migration.version <= current:
                continue
            if migration.version != current + 1:
                raise StateCorruptionError("state migrations are not contiguous")
            try:
                connection.execute("BEGIN EXCLUSIVE")
                for statement in migration.statements:
                    connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations (version, name, sha256, applied_at) VALUES (?, ?, ?, ?)",
                    (migration.version, migration.name, migration.sha256, _rfc3339(_now(clock))),
                )
                connection.execute(f"PRAGMA user_version = {migration.version}")
                connection.execute("COMMIT")
                current = migration.version
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _verify_integrity(connection: sqlite3.Connection) -> None:
        check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        if check != ["ok"]:
            raise StateCorruptionError("SQLite quick-check did not pass")
        if list(connection.execute("PRAGMA foreign_key_check")):
            raise StateCorruptionError("state database contains foreign-key violations")
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != CURRENT_DATABASE_SCHEMA_VERSION:
            raise IncompatibleStateVersionError("state database did not reach the supported schema version")
        rows = list(connection.execute("SELECT version, name, sha256 FROM schema_migrations ORDER BY version"))
        expected = [(item.version, item.name, item.sha256) for item in MIGRATIONS]
        actual = [(int(row[0]), str(row[1]), str(row[2])) for row in rows]
        if actual != expected:
            raise StateCorruptionError("state migration history does not match compiled migrations")
        objects = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'index', 'trigger')"
            )
        }
        if objects != _EXPECTED_OBJECTS:
            raise StateCorruptionError("state database schema objects do not match the supported schema")
        for table, columns in _EXPECTED_COLUMNS.items():
            actual_columns = tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info('{table}')"))
            if actual_columns != columns:
                raise StateCorruptionError(f"state table {table} has an incompatible column layout")

    @staticmethod
    def _initialize_metadata(connection: sqlite3.Connection, store_id: str) -> None:
        if OPERATIONAL_ID_PATTERN.fullmatch(store_id) is None:
            raise StateModelError("state store ID generator returned an invalid ID")
        if not store_id.startswith("opid:v1:control-plane-state:u7:"):
            raise StateModelError("state store ID generator returned the wrong namespace")
        connection.execute("BEGIN IMMEDIATE")
        try:
            existing = int(connection.execute("SELECT COUNT(*) FROM metadata").fetchone()[0])
            if existing:
                raise StateCorruptionError("new state database unexpectedly contains metadata")
            connection.executemany(
                "INSERT INTO metadata (key, value) VALUES (?, ?)",
                (
                    ("active_session_id", ""),
                    ("admission_state", "reconciliation-required"),
                    ("epoch", "0"),
                    ("store_id", store_id),
                ),
            )
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        return {str(row[0]): str(row[1]) for row in connection.execute("SELECT key, value FROM metadata")}

    @classmethod
    def _verify_metadata(cls, connection: sqlite3.Connection) -> None:
        values = cls._metadata(connection)
        if set(values) != {"active_session_id", "admission_state", "epoch", "store_id"}:
            raise StateCorruptionError("state metadata keys are missing or unexpected")
        if OPERATIONAL_ID_PATTERN.fullmatch(values["store_id"]) is None:
            raise StateCorruptionError("state store ID is invalid")
        if not values["store_id"].startswith("opid:v1:control-plane-state:u7:"):
            raise StateCorruptionError("state store ID uses the wrong namespace")
        try:
            epoch = int(values["epoch"])
        except ValueError as error:
            raise StateCorruptionError("state epoch is not an integer") from error
        if not 0 <= epoch <= SAFE_INTEGER_MAX:
            raise StateCorruptionError("state epoch is outside the safe-integer domain")
        if values["admission_state"] not in {"blocked", "ready", "reconciliation-required"}:
            raise StateCorruptionError("state admission metadata is invalid")
        active = values["active_session_id"]
        if active and OPERATIONAL_ID_PATTERN.fullmatch(active) is None:
            raise StateCorruptionError("active state session ID is invalid")
        if active and not active.startswith("opid:v1:control-plane-session:u7:"):
            raise StateCorruptionError("active state session ID uses the wrong namespace")

    @staticmethod
    def _verify_records(connection: sqlite3.Connection) -> None:
        for row in connection.execute("SELECT * FROM operational_records ORDER BY record_kind, record_id"):
            _record_from_row(row)

    @classmethod
    def _verify_history(cls, connection: sqlite3.Connection) -> None:
        command_ids: set[str] = set()
        metadata = cls._metadata(connection)
        current_epoch = int(metadata["epoch"])
        for row in connection.execute(
            "SELECT command_id, request_sha256, committed_epoch, committed_at FROM commands ORDER BY committed_epoch"
        ):
            command_id = str(row["command_id"])
            if OPERATIONAL_ID_PATTERN.fullmatch(command_id) is None:
                raise StateCorruptionError("state command history contains an invalid ID")
            digest = str(row["request_sha256"])
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise StateCorruptionError("state command history contains an invalid digest")
            epoch = int(row["committed_epoch"])
            if not 1 <= epoch <= SAFE_INTEGER_MAX:
                raise StateCorruptionError("state command history contains an invalid epoch")
            if epoch > current_epoch:
                raise StateCorruptionError("state command history claims a future epoch")
            _parse_timestamp(str(row["committed_at"]))
            command_ids.add(command_id)
        reconciliation_ids: set[str] = set()
        for row in connection.execute(
            "SELECT plan_id, plan_sha256, report_json, completed_at FROM reconciliation_runs ORDER BY completed_at, plan_id"
        ):
            plan_id = str(row["plan_id"])
            if OPERATIONAL_ID_PATTERN.fullmatch(plan_id) is None:
                raise StateCorruptionError("reconciliation history contains an invalid plan ID")
            if not plan_id.startswith("opid:v1:state-reconciliation:u7:"):
                raise StateCorruptionError("reconciliation history plan ID uses the wrong namespace")
            report = cls._parse_report(str(row["report_json"]))
            if report.plan_id != plan_id or report.plan_digest != str(row["plan_sha256"]):
                raise StateCorruptionError("reconciliation history does not bind its plan and report")
            if report.completed_at != str(row["completed_at"]):
                raise StateCorruptionError("reconciliation history completion time is inconsistent")
            reconciliation_ids.add(plan_id)
        known_transitions = command_ids | reconciliation_ids
        expected_sequence = 1
        transition_anchors: set[str] = set()
        latest: dict[tuple[str, str], tuple[int, str, str]] = {}
        for row in connection.execute("SELECT * FROM state_transitions ORDER BY sequence"):
            if int(row["sequence"]) != expected_sequence:
                raise StateCorruptionError("state transition sequence is not contiguous")
            expected_sequence += 1
            command_id = str(row["command_id"])
            if command_id not in known_transitions:
                raise StateCorruptionError("state transition is not anchored by a command or reconciliation")
            transition_anchors.add(command_id)
            record_kind = str(row["record_kind"])
            record_id = str(row["record_id"])
            if record_kind not in STATE_RECORD_KINDS:
                raise StateCorruptionError("state transition contains an invalid record kind")
            from_generation = row["from_generation"]
            to_generation = int(row["to_generation"])
            expected_generation = 1 if from_generation is None else int(from_generation) + 1
            if to_generation != expected_generation or not 1 <= to_generation <= SAFE_INTEGER_MAX:
                raise StateCorruptionError("state transition generation chain is invalid")
            previous = latest.get((record_kind, record_id))
            if previous is not None and from_generation != previous[0]:
                raise StateCorruptionError("state transition does not continue its record history")
            if previous is None and from_generation is not None:
                raise StateCorruptionError("first state transition cannot claim a previous generation")
            from_digest = row["from_payload_sha256"]
            if previous is not None and str(from_digest) != previous[1]:
                raise StateCorruptionError("state transition previous digest is inconsistent")
            if previous is None and from_digest is not None:
                raise StateCorruptionError("first state transition cannot claim a previous digest")
            to_digest = str(row["to_payload_sha256"])
            if len(to_digest) != 64 or any(character not in "0123456789abcdef" for character in to_digest):
                raise StateCorruptionError("state transition contains an invalid payload digest")
            from_state_digest = row["from_state_sha256"]
            if previous is not None and str(from_state_digest) != previous[2]:
                raise StateCorruptionError("state transition previous record digest is inconsistent")
            if previous is None and from_state_digest is not None:
                raise StateCorruptionError("first state transition cannot claim a previous record digest")
            to_state_digest = str(row["to_state_sha256"])
            if len(to_state_digest) != 64 or any(
                character not in "0123456789abcdef" for character in to_state_digest
            ):
                raise StateCorruptionError("state transition contains an invalid record digest")
            if str(row["action"]) not in {"create", "tombstone", "update"}:
                raise StateCorruptionError("state transition contains an invalid action")
            _require_token(str(row["reason_code"]), "state transition reason")
            _parse_timestamp(str(row["committed_at"]))
            latest[(record_kind, record_id)] = (to_generation, to_digest, to_state_digest)
        records = {
            record.key: (record.generation, record.payload_sha256, record.integrity_digest)
            for record in (
                _record_from_row(row)
                for row in connection.execute("SELECT * FROM operational_records ORDER BY record_kind, record_id")
            )
        }
        if records != latest:
            raise StateCorruptionError("current state records do not match append-only transition history")
        if not command_ids.issubset(transition_anchors):
            raise StateCorruptionError("state command history contains a mutation-free command")
        session_rows = list(connection.execute(
            "SELECT session_id, started_at, ended_at, termination, prior_session_id FROM controller_sessions "
            "ORDER BY started_at, session_id"
        ))
        session_ids = {str(row["session_id"]) for row in session_rows}
        active_ids: set[str] = set()
        for row in session_rows:
            session_id = str(row["session_id"])
            if OPERATIONAL_ID_PATTERN.fullmatch(session_id) is None:
                raise StateCorruptionError("controller session history contains an invalid ID")
            if not session_id.startswith("opid:v1:control-plane-session:u7:"):
                raise StateCorruptionError("controller session history contains an ID in the wrong namespace")
            _parse_timestamp(str(row["started_at"]))
            termination = str(row["termination"])
            if termination not in {"aborted", "active", "clean", "interrupted"}:
                raise StateCorruptionError("controller session history contains an invalid termination")
            if termination == "active":
                active_ids.add(session_id)
                if row["ended_at"] is not None:
                    raise StateCorruptionError("active controller session cannot have an end time")
            elif row["ended_at"] is None:
                raise StateCorruptionError("terminated controller session requires an end time")
            else:
                ended = _parse_timestamp(str(row["ended_at"]))
                if ended < _parse_timestamp(str(row["started_at"])):
                    raise StateCorruptionError("controller session ends before it starts")
            prior = row["prior_session_id"]
            if prior is not None and (
                OPERATIONAL_ID_PATTERN.fullmatch(str(prior)) is None
                or not str(prior).startswith("opid:v1:control-plane-session:u7:")
                or str(prior) not in session_ids
                or str(prior) == session_id
            ):
                raise StateCorruptionError("controller session history contains an invalid predecessor")
        if len(active_ids) > 1:
            raise StateCorruptionError("multiple controller sessions claim to be active")
        metadata_active = metadata["active_session_id"]
        if active_ids != ({metadata_active} if metadata_active else set()):
            raise StateCorruptionError("active session history and metadata disagree")

    @classmethod
    def _start_session(
        cls,
        connection: sqlite3.Connection,
        clock: StateClock,
        ids: StateIdGenerator,
        stamp: str,
    ) -> tuple[str, str]:
        connection.execute("BEGIN IMMEDIATE")
        try:
            metadata = cls._metadata(connection)
            active = metadata["active_session_id"]
            prior_session: str | None = None
            if active:
                row = connection.execute(
                    "SELECT session_id, termination FROM controller_sessions WHERE session_id = ?",
                    (active,),
                ).fetchone()
                if row is None or str(row["termination"]) != "active":
                    raise StateCorruptionError("active session metadata does not identify an active session")
                connection.execute(
                    "UPDATE controller_sessions SET ended_at = ?, termination = 'interrupted' WHERE session_id = ?",
                    (stamp, active),
                )
                prior_shutdown = "unclean"
                prior_session = active
            else:
                row = connection.execute(
                    "SELECT session_id, termination FROM controller_sessions ORDER BY started_at DESC, session_id DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    prior_shutdown = "new"
                else:
                    prior_session = str(row["session_id"])
                    prior_shutdown = "clean" if str(row["termination"]) == "clean" else "unclean"
            session_id = ids.new_session_id()
            if OPERATIONAL_ID_PATTERN.fullmatch(session_id) is None:
                raise StateModelError("state session ID generator returned an invalid ID")
            if not session_id.startswith("opid:v1:control-plane-session:u7:"):
                raise StateModelError("state session ID generator returned the wrong namespace")
            connection.execute(
                "INSERT INTO controller_sessions (session_id, started_at, ended_at, termination, prior_session_id) "
                "VALUES (?, ?, NULL, 'active', ?)",
                (session_id, stamp, prior_session),
            )
            connection.execute("UPDATE metadata SET value = ? WHERE key = 'active_session_id'", (session_id,))
            connection.execute(
                "UPDATE metadata SET value = 'reconciliation-required' WHERE key = 'admission_state'"
            )
            connection.execute("COMMIT")
            return prior_shutdown, session_id
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise StateStoreError("local state store is closed")

    def close(self, *, clean: bool = True) -> None:
        with self._mutex:
            if self._closed:
                return
            stamp = _rfc3339(_now(self._clock))
            termination = "clean" if clean else "aborted"
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                cursor = self._connection.execute(
                    "UPDATE controller_sessions SET ended_at = ?, termination = ? "
                    "WHERE session_id = ? AND termination = 'active'",
                    (stamp, termination, self._session_id),
                )
                if cursor.rowcount != 1:
                    raise StateCorruptionError("active state session disappeared before close")
                self._connection.execute("UPDATE metadata SET value = '' WHERE key = 'active_session_id'")
                self._connection.execute("COMMIT")
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            finally:
                self._connection.close()
                self._closed = True
                self._process_lock.release()

    def __enter__(self) -> "LocalStateStore":
        self._ensure_open()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close(clean=exc_type is None)

    def _snapshot_locked(self, *, observed_at: str | None = None) -> StateSnapshot:
        metadata = self._metadata(self._connection)
        records = tuple(
            _record_from_row(row)
            for row in self._connection.execute(
                "SELECT * FROM operational_records ORDER BY record_kind, record_id"
            )
        )
        return StateSnapshot.build(
            store_id=metadata["store_id"],
            database_schema_version=CURRENT_DATABASE_SCHEMA_VERSION,
            epoch=int(metadata["epoch"]),
            admission_state=metadata["admission_state"],
            prior_shutdown=self._prior_shutdown,
            observed_at=observed_at or _rfc3339(_now(self._clock)),
            records=records,
        )

    def snapshot(self) -> StateSnapshot:
        with self._mutex:
            self._ensure_open()
            return self._snapshot_locked()

    def require_ready(self) -> None:
        snapshot = self.snapshot()
        if snapshot.admission_state != "ready":
            raise StateAdmissionError(
                f"controller admission is {snapshot.admission_state}; startup reconciliation must pass first"
            )

    @staticmethod
    def _request_digest(
        *,
        expected_epoch: int,
        reason_code: str,
        mutations: tuple[StateMutation, ...],
    ) -> str:
        payload = {
            "expected_epoch": expected_epoch,
            "mutations": [item.to_dict() for item in mutations],
            "reason_code": reason_code,
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    def apply_batch(
        self,
        mutations: Iterable[StateMutation],
        *,
        command_id: str,
        reason_code: str,
        expected_epoch: int,
    ) -> StateSnapshot:
        ordered = tuple(sorted(tuple(mutations), key=lambda item: item.key))
        if not ordered:
            raise ValueError("state mutation batch cannot be empty")
        if len({item.key for item in ordered}) != len(ordered):
            raise StateConflictError("state mutation batch contains a duplicate record key")
        if OPERATIONAL_ID_PATTERN.fullmatch(command_id) is None:
            raise StateModelError("state command ID must be an operational UUIDv7")
        _require_token(reason_code, "state transition reason")
        if isinstance(expected_epoch, bool) or not 0 <= expected_epoch <= SAFE_INTEGER_MAX:
            raise StateModelError("expected state epoch must be a non-negative safe integer")
        request_digest = self._request_digest(
            expected_epoch=expected_epoch,
            reason_code=reason_code,
            mutations=ordered,
        )
        with self._mutex:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT request_sha256 FROM commands WHERE command_id = ?",
                    (command_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing[0]) != request_digest:
                        raise StateConflictError("state command ID was reused with different content")
                    self._connection.execute("ROLLBACK")
                    return self._snapshot_locked()
                metadata = self._metadata(self._connection)
                if metadata["admission_state"] != "ready":
                    raise StateAdmissionError("state mutations are blocked until reconciliation succeeds")
                current_epoch = int(metadata["epoch"])
                if current_epoch != expected_epoch:
                    raise StateConflictError(
                        f"state epoch changed from expected {expected_epoch} to {current_epoch}"
                    )
                stamp = _rfc3339(_now(self._clock))
                for mutation in ordered:
                    self._persist_mutation(
                        mutation,
                        command_id=command_id,
                        reason_code=reason_code,
                        committed_at=stamp,
                    )
                next_epoch = current_epoch + 1
                if next_epoch > SAFE_INTEGER_MAX:
                    raise StateConflictError("state epoch exhausted the safe-integer domain")
                self._connection.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'epoch'",
                    (str(next_epoch),),
                )
                self._connection.execute(
                    "INSERT INTO commands (command_id, request_sha256, committed_epoch, committed_at) "
                    "VALUES (?, ?, ?, ?)",
                    (command_id, request_digest, next_epoch, stamp),
                )
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            return self._snapshot_locked()

    def _persist_mutation(
        self,
        mutation: StateMutation,
        *,
        command_id: str,
        reason_code: str,
        committed_at: str,
    ) -> OperationalStateRecord:
        row = self._connection.execute(
            "SELECT * FROM operational_records WHERE record_kind = ? AND record_id = ?",
            mutation.key,
        ).fetchone()
        current = None if row is None else _record_from_row(row)
        if mutation.expected_generation is None:
            if current is not None:
                raise StateConflictError("state create expected no existing generation")
            generation = 1
        else:
            if current is None:
                raise StateConflictError("state update expected a record that is absent")
            if current.generation != mutation.expected_generation:
                raise StateConflictError(
                    f"state generation changed from expected {mutation.expected_generation} to {current.generation}"
                )
            generation = current.generation + 1
            if generation > SAFE_INTEGER_MAX:
                raise StateConflictError("state record generation exhausted the safe-integer domain")
        record = OperationalStateRecord(
            mutation.record_kind,
            mutation.record_id,
            generation,
            mutation.lifecycle_state,
            mutation.verification_status,
            mutation.payload_json,
            mutation.payload_sha256,
            committed_at,
            mutation.sources,
            mutation.tombstoned,
        )
        sources_json = canonical_json([item.to_dict() for item in record.sources]).decode("utf-8")
        self._connection.execute(
            "INSERT INTO operational_records (record_kind, record_id, generation, lifecycle_state, "
            "verification_status, payload_json, payload_sha256, updated_at, sources_json, tombstoned) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(record_kind, record_id) DO UPDATE SET generation = excluded.generation, "
            "lifecycle_state = excluded.lifecycle_state, verification_status = excluded.verification_status, "
            "payload_json = excluded.payload_json, payload_sha256 = excluded.payload_sha256, "
            "updated_at = excluded.updated_at, sources_json = excluded.sources_json, "
            "tombstoned = excluded.tombstoned",
            (
                record.record_kind,
                record.record_id,
                record.generation,
                record.lifecycle_state,
                record.verification_status,
                record.payload_json,
                record.payload_sha256,
                record.updated_at,
                sources_json,
                int(record.tombstoned),
            ),
        )
        action = "create" if current is None else ("tombstone" if record.tombstoned else "update")
        self._connection.execute(
            "INSERT INTO state_transitions (command_id, record_kind, record_id, from_generation, "
            "to_generation, from_payload_sha256, to_payload_sha256, from_state_sha256, to_state_sha256, "
            "action, reason_code, committed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                command_id,
                record.record_kind,
                record.record_id,
                None if current is None else current.generation,
                record.generation,
                None if current is None else current.payload_sha256,
                record.payload_sha256,
                None if current is None else current.integrity_digest,
                record.integrity_digest,
                action,
                reason_code,
                committed_at,
            ),
        )
        return record

    def apply_reconciliation(self, plan: ReconciliationPlan) -> ReconciliationReport:
        with self._mutex:
            self._ensure_open()
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._connection.execute(
                    "SELECT plan_sha256, report_json FROM reconciliation_runs WHERE plan_id = ?",
                    (plan.plan_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing["plan_sha256"]) != plan.plan_digest:
                        raise StateConflictError("reconciliation plan ID was reused with different content")
                    report = self._parse_report(str(existing["report_json"]))
                    self._connection.execute("ROLLBACK")
                    return report
                before = self._snapshot_locked()
                if before.snapshot_digest != plan.snapshot_digest:
                    raise StaleReconciliationPlanError("local state changed after reconciliation planning")
                stamp = _rfc3339(_now(self._clock))
                results: list[ReconciliationActionResult] = []
                for action in plan.actions:
                    record = self._persist_mutation(
                        action.to_mutation(),
                        command_id=plan.plan_id,
                        reason_code=action.reason_code,
                        committed_at=stamp,
                    )
                    results.append(
                        ReconciliationActionResult(
                            action.action,
                            action.record_kind,
                            action.record_id,
                            record.generation,
                            "applied",
                        )
                    )
                next_epoch = before.epoch + 1
                if next_epoch > SAFE_INTEGER_MAX:
                    raise StateConflictError("state epoch exhausted the safe-integer domain")
                resulting_status = "ready" if plan.ready_after_apply else "blocked"
                self._connection.execute("UPDATE metadata SET value = ? WHERE key = 'epoch'", (str(next_epoch),))
                self._connection.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'admission_state'",
                    (resulting_status,),
                )
                after = self._snapshot_locked(observed_at=stamp)
                report = ReconciliationReport.build(
                    plan_id=plan.plan_id,
                    plan_digest=plan.plan_digest,
                    before_snapshot_digest=before.snapshot_digest,
                    after_snapshot_digest=after.snapshot_digest,
                    completed_at=stamp,
                    status=resulting_status,
                    action_results=tuple(results),
                    issues=plan.issues,
                )
                report_json = canonical_json(report.to_dict()).decode("utf-8")
                self._connection.execute(
                    "INSERT INTO reconciliation_runs (plan_id, plan_sha256, report_json, completed_at) "
                    "VALUES (?, ?, ?, ?)",
                    (plan.plan_id, plan.plan_digest, report_json, stamp),
                )
                self._connection.execute("COMMIT")
                return report
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _parse_report(value: str) -> ReconciliationReport:
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise StateCorruptionError("stored reconciliation report is invalid JSON") from error
        if not isinstance(parsed, dict) or canonical_json(parsed).decode("utf-8") != value:
            raise StateCorruptionError("stored reconciliation report is not canonical JSON")
        try:
            issues = tuple(ReconciliationIssue(**item) for item in parsed["issues"])
            results = tuple(ReconciliationActionResult(**item) for item in parsed["action_results"])
            return ReconciliationReport(
                plan_id=parsed["plan_id"],
                plan_digest=parsed["plan_digest"],
                before_snapshot_digest=parsed["before_snapshot_digest"],
                after_snapshot_digest=parsed["after_snapshot_digest"],
                completed_at=parsed["completed_at"],
                status=parsed["status"],
                action_results=results,
                issues=issues,
                report_digest=parsed["report_digest"],
            )
        except (KeyError, TypeError, StateModelError) as error:
            raise StateCorruptionError("stored reconciliation report violates its model") from error

    def transition_history(self, record_kind: str, record_id: str) -> tuple[dict[str, Any], ...]:
        if record_kind not in STATE_RECORD_KINDS:
            raise ValueError("unknown state record kind")
        with self._mutex:
            self._ensure_open()
            rows = self._connection.execute(
                "SELECT sequence, command_id, from_generation, to_generation, from_payload_sha256, "
                "to_payload_sha256, action, reason_code, committed_at FROM state_transitions "
                "WHERE record_kind = ? AND record_id = ? ORDER BY sequence",
                (record_kind, record_id),
            )
            return tuple({key: row[key] for key in row.keys()} for row in rows)

    def health_check(self) -> dict[str, Any]:
        with self._mutex:
            self._ensure_open()
            self._verify_integrity(self._connection)
            self._verify_metadata(self._connection)
            self._verify_records(self._connection)
            self._verify_history(self._connection)
            snapshot = self._snapshot_locked()
            return {
                "admission_state": snapshot.admission_state,
                "canonical_authority": False,
                "database_schema_version": CURRENT_DATABASE_SCHEMA_VERSION,
                "migration_digests": [item.sha256 for item in MIGRATIONS],
                "quick_check": "ok",
                "record_count": len(snapshot.records),
                "store_id": snapshot.store_id,
            }


class StateReconciler:
    def __init__(
        self,
        *,
        clock: StateClock | None = None,
        id_generator: StateIdGenerator | None = None,
    ) -> None:
        self._clock = clock or UtcStateClock()
        self._ids = id_generator or Uuid7StateIds()

    def plan(
        self,
        snapshot: StateSnapshot,
        observations: Iterable[ReconciliationObservation],
        *,
        maximum_observation_age_seconds: int = DEFAULT_MAXIMUM_OBSERVATION_AGE_SECONDS,
    ) -> ReconciliationPlan:
        if (
            isinstance(maximum_observation_age_seconds, bool)
            or not 1 <= maximum_observation_age_seconds <= SAFE_INTEGER_MAX
        ):
            raise ValueError("maximum observation age must be a positive safe integer")
        ordered = tuple(
            sorted(
                tuple(observations),
                key=lambda item: (item.record_kind, item.record_id, item.source_kind, item.source_id),
            )
        )
        identities = [(item.key, item.source_identity) for item in ordered]
        if len(set(identities)) != len(identities):
            raise StateModelError("reconciliation observations duplicate a source identity for one record")
        observation_digest = hashlib.sha256(
            canonical_json([item.to_dict() for item in ordered])
        ).hexdigest()
        local = {item.key: item for item in snapshot.records}
        grouped: dict[tuple[str, str], list[ReconciliationObservation]] = {}
        for observation in ordered:
            grouped.setdefault(observation.key, []).append(observation)
        now = _now(self._clock)
        actions: list[ReconciliationAction] = []
        issues: list[ReconciliationIssue] = []
        for key in sorted(set(local) | set(grouped)):
            record = local.get(key)
            candidates = grouped.get(key, [])
            if not candidates:
                if record is not None:
                    issues.append(
                        ReconciliationIssue(*key, "missing-reality", "no fresh source accounted for local state")
                    )
                    action = self._quarantine(record, "missing-reality")
                    if action is not None:
                        actions.append(action)
                continue
            invalid_code: str | None = None
            for observation in candidates:
                allowed = _ALLOWED_RECONCILIATION_SOURCES[observation.record_kind]
                if observation.source_kind not in allowed:
                    invalid_code = invalid_code or "wrong-source-authority"
                elif not observation.verified:
                    invalid_code = invalid_code or "unverified-reality"
                else:
                    observed = _parse_timestamp(observation.observed_at)
                    if observed > now + timedelta(minutes=5):
                        invalid_code = invalid_code or "future-reality"
                    elif (now - observed).total_seconds() > maximum_observation_age_seconds:
                        invalid_code = invalid_code or "stale-reality"
            if invalid_code is not None:
                issues.append(
                    ReconciliationIssue(*key, invalid_code, "source facts cannot safely qualify local state")
                )
                if record is not None:
                    action = self._quarantine(record, invalid_code)
                    if action is not None:
                        actions.append(action)
                continue
            signatures = {item.state_signature for item in candidates}
            if len(signatures) != 1:
                issues.append(
                    ReconciliationIssue(*key, "source-conflict", "fresh verified sources disagree about state")
                )
                if record is not None:
                    action = self._quarantine(record, "source-conflict")
                    if action is not None:
                        actions.append(action)
                continue
            selected = candidates[0]
            sources = tuple(sorted((item.source_reference() for item in candidates), key=lambda item: item.identity))
            if not selected.exists:
                if record is None:
                    continue
                if record.tombstoned and record.sources == sources:
                    continue
                payload_json = "{}"
                payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
                actions.append(
                    ReconciliationAction(
                        "tombstone",
                        "verified-absent",
                        *key,
                        record.generation,
                        "absent",
                        "verified",
                        payload_json,
                        payload_sha256,
                        sources,
                        True,
                    )
                )
                continue
            if record is None:
                actions.append(
                    ReconciliationAction(
                        "create",
                        "source-rebuild",
                        *key,
                        None,
                        selected.lifecycle_state or "unknown",
                        "verified",
                        selected.payload_json,
                        selected.payload_sha256,
                        sources,
                        False,
                    )
                )
                continue
            matches = (
                not record.tombstoned
                and record.lifecycle_state == selected.lifecycle_state
                and record.payload_sha256 == selected.payload_sha256
            )
            if (
                matches
                and record.verification_status == "verified"
                and record.sources == sources
            ):
                continue
            actions.append(
                ReconciliationAction(
                    "verify" if matches else "replace",
                    "source-verified" if matches else "source-reconciled",
                    *key,
                    record.generation,
                    selected.lifecycle_state or "unknown",
                    "verified",
                    selected.payload_json,
                    selected.payload_sha256,
                    sources,
                    False,
                )
            )
        stamp = _rfc3339(now)
        return ReconciliationPlan.build(
            plan_id=self._ids.new_reconciliation_id(),
            snapshot_digest=snapshot.snapshot_digest,
            observation_digest=observation_digest,
            planned_at=stamp,
            maximum_observation_age_seconds=maximum_observation_age_seconds,
            actions=tuple(actions),
            issues=tuple(issues),
            ready_after_apply=not any(item.blocking for item in issues),
        )

    @staticmethod
    def _quarantine(record: OperationalStateRecord, reason_code: str) -> ReconciliationAction | None:
        if record.lifecycle_state == "quarantined" and record.verification_status == "quarantined":
            return None
        return ReconciliationAction(
            "quarantine",
            reason_code,
            record.record_kind,
            record.record_id,
            record.generation,
            "quarantined",
            "quarantined",
            record.payload_json,
            record.payload_sha256,
            record.sources,
            False,
        )


class DurableStateService:
    """Supervisor-ready service boundary over persistence and reconciliation."""

    def __init__(
        self,
        store: LocalStateStore,
        reconciler: StateReconciler,
        *,
        maximum_observation_age_seconds: int = DEFAULT_MAXIMUM_OBSERVATION_AGE_SECONDS,
    ) -> None:
        if (
            isinstance(maximum_observation_age_seconds, bool)
            or not 1 <= maximum_observation_age_seconds <= SAFE_INTEGER_MAX
        ):
            raise ValueError("maximum observation age must be a positive safe integer")
        self._store = store
        self._reconciler = reconciler
        self._maximum_observation_age_seconds = maximum_observation_age_seconds

    @classmethod
    def open(
        cls,
        path: Path | str,
        *,
        clock: StateClock | None = None,
        id_generator: StateIdGenerator | None = None,
        maximum_observation_age_seconds: int = DEFAULT_MAXIMUM_OBSERVATION_AGE_SECONDS,
    ) -> "DurableStateService":
        selected_clock = clock or UtcStateClock()
        selected_ids = id_generator or Uuid7StateIds()
        store = LocalStateStore.open(path, clock=selected_clock, id_generator=selected_ids)
        return cls(
            store,
            StateReconciler(clock=selected_clock, id_generator=selected_ids),
            maximum_observation_age_seconds=maximum_observation_age_seconds,
        )

    def snapshot(self) -> StateSnapshot:
        return self._store.snapshot()

    def plan_reconciliation(
        self,
        observations: Iterable[ReconciliationObservation],
    ) -> ReconciliationPlan:
        return self._reconciler.plan(
            self._store.snapshot(),
            observations,
            maximum_observation_age_seconds=self._maximum_observation_age_seconds,
        )

    def apply_reconciliation(self, plan: ReconciliationPlan) -> ReconciliationReport:
        return self._store.apply_reconciliation(plan)

    def reconcile(self, observations: Iterable[ReconciliationObservation]) -> ReconciliationReport:
        return self.apply_reconciliation(self.plan_reconciliation(observations))

    def apply_batch(
        self,
        mutations: Iterable[StateMutation],
        *,
        command_id: str,
        reason_code: str,
        expected_epoch: int,
    ) -> StateSnapshot:
        return self._store.apply_batch(
            mutations,
            command_id=command_id,
            reason_code=reason_code,
            expected_epoch=expected_epoch,
        )

    def require_ready(self) -> None:
        self._store.require_ready()

    def health_check(self) -> dict[str, Any]:
        return self._store.health_check()

    def close(self, *, clean: bool = True) -> None:
        self._store.close(clean=clean)


@dataclass(frozen=True)
class StateRebuildResult:
    store: LocalStateStore
    report: ReconciliationReport
    quarantine_manifest: Path | None


class StateRecovery:
    """Explicit, recoverable repair path; corrupt bytes are quarantined, never deleted."""

    @classmethod
    def rebuild(
        cls,
        path: Path | str,
        observations: Iterable[ReconciliationObservation],
        *,
        reason_code: str,
        clock: StateClock | None = None,
        id_generator: StateIdGenerator | None = None,
        maximum_observation_age_seconds: int = DEFAULT_MAXIMUM_OBSERVATION_AGE_SECONDS,
    ) -> StateRebuildResult:
        _require_token(reason_code, "state rebuild reason")
        selected_clock = clock or UtcStateClock()
        selected_ids = id_generator or Uuid7StateIds()
        state_path = Path(path)
        if not state_path.name or state_path.name in {".", ".."}:
            raise UnsafeStatePathError("state recovery path must identify one database file")
        _prepare_state_parent(state_path.parent)
        if _is_linklike(state_path):
            raise UnsafeStatePathError("state recovery refuses a linked database path")
        if state_path.exists():
            details = state_path.stat(follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode) or getattr(details, "st_nlink", 1) != 1:
                raise UnsafeStatePathError("state recovery requires a singly linked regular database file")
        process_lock = _ProcessLock(Path(f"{state_path}.lock"))
        process_lock.acquire()
        manifest_path: Path | None = None
        store: LocalStateStore | None = None
        try:
            files = tuple(
                item
                for item in (state_path, *_sqlite_sidecars(state_path))
                if item.exists() or _is_linklike(item)
            )
            if files:
                for source in files:
                    if _is_linklike(source) or not source.is_file():
                        raise UnsafeStatePathError("state recovery refuses non-regular database material")
                    source_details = source.stat(follow_symlinks=False)
                    if not stat.S_ISREG(source_details.st_mode) or getattr(source_details, "st_nlink", 1) != 1:
                        raise UnsafeStatePathError("state recovery requires singly linked regular database material")
                quarantine_root = state_path.parent / f"{state_path.name}.quarantine"
                if _is_linklike(quarantine_root):
                    raise UnsafeStatePathError("state quarantine root cannot be a symbolic link or junction")
                quarantine_root.mkdir(mode=0o700, exist_ok=True)
                suffix = selected_ids.new_session_id().rsplit(":", 1)[-1]
                quarantine = quarantine_root / suffix
                quarantine.mkdir(mode=0o700, exist_ok=False)
                entries: list[dict[str, Any]] = []
                for source in files:
                    # Recheck at the use boundary after the all-files preflight.
                    if _is_linklike(source) or not source.is_file():
                        raise UnsafeStatePathError("state recovery refuses non-regular database material")
                    source_details = source.stat(follow_symlinks=False)
                    if not stat.S_ISREG(source_details.st_mode) or getattr(source_details, "st_nlink", 1) != 1:
                        raise UnsafeStatePathError("state recovery requires singly linked regular database material")
                    destination = quarantine / source.name
                    os.replace(source, destination)
                    digest = hashlib.sha256()
                    with destination.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                    entries.append(
                        {"name": destination.name, "sha256": digest.hexdigest(), "size_bytes": destination.stat().st_size}
                    )
                    try:
                        os.chmod(destination, 0o600)
                    except OSError:
                        if os.name != "nt":
                            raise
                manifest = {
                    "canonical_authority": False,
                    "files": sorted(entries, key=lambda item: item["name"]),
                    "quarantined_at": _rfc3339(_now(selected_clock)),
                    "reason_code": reason_code,
                    "schema_version": "state-quarantine-manifest.v1",
                }
                manifest_path = quarantine / "quarantine-manifest.json"
                descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(descriptor, canonical_json(manifest))
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _fsync_directory(quarantine)
                _fsync_directory(quarantine_root)
                _fsync_directory(state_path.parent)
            state_path, new_database, expected_identity = _validate_state_path(state_path)
            store = LocalStateStore._open_with_lock(
                state_path,
                process_lock,
                new_database=new_database,
                expected_identity=expected_identity,
                clock=selected_clock,
                ids=selected_ids,
                busy_timeout_seconds=DEFAULT_BUSY_TIMEOUT_SECONDS,
            )
            process_lock = store._process_lock
            snapshot = store.snapshot()
            plan = StateReconciler(clock=selected_clock, id_generator=selected_ids).plan(
                snapshot,
                observations,
                maximum_observation_age_seconds=maximum_observation_age_seconds,
            )
            report = store.apply_reconciliation(plan)
            return StateRebuildResult(store, report, manifest_path)
        except Exception:
            if store is not None:
                try:
                    store.close(clean=False)
                except Exception:
                    process_lock.release()
            else:
                process_lock.release()
            raise
