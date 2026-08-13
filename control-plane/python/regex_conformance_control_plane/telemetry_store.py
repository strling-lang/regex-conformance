"""Append-only local telemetry storage and forecast calibration."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat
from typing import Iterable

from .resource_models import ResourceEstimate
from .state_models import canonical_object, parse_canonical_object
from .telemetry_models import (
    CalibrationPolicy,
    CalibrationSnapshot,
    TelemetrySample,
    build_calibration,
)


STORE_SCHEMA_VERSION = "operational-telemetry-store.v1"


class TelemetryStoreError(RuntimeError):
    """Base class for telemetry persistence failures."""


class TelemetryStoreConflictError(TelemetryStoreError):
    """An existing immutable sample ID was reused with different content."""


class TelemetryStoreCorruptionError(TelemetryStoreError):
    """Stored telemetry failed structural, digest, or database validation."""


class UnsafeTelemetryPathError(TelemetryStoreError):
    """The telemetry database path is link-backed or otherwise unsafe."""


def _path_identity(path: Path) -> tuple[int, int]:
    details = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(details.st_mode):
        raise UnsafeTelemetryPathError("telemetry database must be a regular file")
    if details.st_nlink != 1:
        raise UnsafeTelemetryPathError("telemetry database must not be hard-linked")
    if os.name != "nt" and details.st_mode & 0o077:
        raise UnsafeTelemetryPathError("telemetry database must not be accessible to group or other users")
    return (details.st_dev, details.st_ino)


def _reject_link(path: Path, label: str) -> None:
    if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
        raise UnsafeTelemetryPathError(f"{label} must not be a symlink or junction")


def _prepare_path(path: Path) -> tuple[Path, bool]:
    candidate = path.expanduser().absolute()
    parent = candidate.parent
    if not parent.exists():
        parent.mkdir(parents=True, mode=0o700)
    for ancestor in (parent, *parent.parents):
        if ancestor.exists():
            _reject_link(ancestor, "telemetry database ancestor")
    if not parent.is_dir():
        raise UnsafeTelemetryPathError("telemetry database parent must be a directory")
    existed = candidate.exists()
    if existed:
        _reject_link(candidate, "telemetry database")
        if not candidate.is_file():
            raise UnsafeTelemetryPathError("telemetry database must be a regular file")
        _path_identity(candidate)
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{candidate}{suffix}")
        if sidecar.exists():
            _reject_link(sidecar, "telemetry database sidecar")
            _path_identity(sidecar)
    return candidate, existed


class TelemetryStore:
    """A separate, local, non-canonical store for immutable measurements."""

    def __init__(self, path: Path, connection: sqlite3.Connection, identity: tuple[int, int]) -> None:
        self._path = path
        self._connection = connection
        self._identity = identity

    @classmethod
    def open(cls, path: str | os.PathLike[str]) -> "TelemetryStore":
        candidate, existed = _prepare_path(Path(path))
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(candidate, timeout=5, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            if not existed and os.name != "nt":
                os.chmod(candidate, 0o600)
            identity = _path_identity(candidate)
            store = cls(candidate, connection, identity)
            store._initialize_or_verify()
            store.verify()
            return store
        except (TelemetryStoreCorruptionError, UnsafeTelemetryPathError):
            if connection is not None:
                connection.close()
            raise
        except sqlite3.DatabaseError as error:
            if connection is not None:
                connection.close()
            raise TelemetryStoreCorruptionError("telemetry database cannot be initialized or verified") from error
        except Exception:
            if connection is not None:
                connection.close()
            raise

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "TelemetryStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _check_identity(self) -> None:
        _reject_link(self._path, "telemetry database")
        if _path_identity(self._path) != self._identity:
            raise UnsafeTelemetryPathError("telemetry database identity changed after opening")

    def _initialize_or_verify(self) -> None:
        self._connection.executescript(
            """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS samples (
                sample_id TEXT PRIMARY KEY NOT NULL,
                operation_kind TEXT NOT NULL,
                calibration_key TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
                    CHECK(length(payload_sha256) = 64)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS samples_calibration
                ON samples(operation_kind, calibration_key, observed_at, sample_id);
            COMMIT;
            """
        )
        row = self._connection.execute("SELECT value FROM metadata WHERE key = 'schema_version'").fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO metadata(key, value) VALUES ('schema_version', ?)",
                (STORE_SCHEMA_VERSION,),
            )
        elif row["value"] != STORE_SCHEMA_VERSION:
            raise TelemetryStoreCorruptionError("telemetry store schema version is incompatible")

    def verify(self) -> None:
        self._check_identity()
        integrity = self._connection.execute("PRAGMA integrity_check").fetchall()
        if [row[0] for row in integrity] != ["ok"]:
            raise TelemetryStoreCorruptionError("SQLite integrity validation failed")
        tables = {
            row["name"]
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != {"metadata", "samples", "samples_calibration"}:
            raise TelemetryStoreCorruptionError("telemetry store has an unexpected database structure")
        expected_columns = {
            "metadata": (("key", "TEXT", 1), ("value", "TEXT", 0)),
            "samples": (
                ("sample_id", "TEXT", 1),
                ("operation_kind", "TEXT", 0),
                ("calibration_key", "TEXT", 0),
                ("observed_at", "TEXT", 0),
                ("payload_json", "TEXT", 0),
                ("payload_sha256", "TEXT", 0),
            ),
        }
        for table, expected in expected_columns.items():
            actual = tuple(
                (row["name"], row["type"], row["pk"])
                for row in self._connection.execute(f"PRAGMA table_xinfo({table})")
            )
            if actual != expected:
                raise TelemetryStoreCorruptionError(f"telemetry store table {table!r} is incompatible")
        metadata = dict(self._connection.execute("SELECT key, value FROM metadata"))
        if metadata != {"schema_version": STORE_SCHEMA_VERSION}:
            raise TelemetryStoreCorruptionError("telemetry store metadata is missing or unexpected")
        for row in self._connection.execute(
            "SELECT sample_id, operation_kind, calibration_key, observed_at, payload_json, payload_sha256 FROM samples"
        ):
            sample = self._decode(row["payload_json"], row["payload_sha256"])
            if (
                row["sample_id"], row["operation_kind"], row["calibration_key"], row["observed_at"]
            ) != (sample.sample_id, sample.operation_kind, sample.calibration_key, sample.observed_at):
                raise TelemetryStoreCorruptionError("telemetry index columns do not match immutable payload")

    @staticmethod
    def _decode(payload_json: str, payload_sha256: str) -> TelemetrySample:
        try:
            payload = parse_canonical_object(payload_json)
            canonical, digest = canonical_object(payload)
            if canonical != payload_json or digest != payload_sha256:
                raise TelemetryStoreCorruptionError("telemetry sample digest does not match its payload")
            return TelemetrySample.from_dict(payload)
        except TelemetryStoreCorruptionError:
            raise
        except (TypeError, ValueError) as error:
            raise TelemetryStoreCorruptionError("stored telemetry sample is invalid") from error

    def append(self, sample: TelemetrySample) -> bool:
        """Append a sample; exact replay is idempotent, conflicting reuse is rejected."""

        self._check_identity()
        payload_json, digest = canonical_object(sample.to_dict())
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._connection.execute(
                "SELECT payload_json, payload_sha256 FROM samples WHERE sample_id = ?",
                (sample.sample_id,),
            ).fetchone()
            if existing is not None:
                if existing["payload_json"] == payload_json and existing["payload_sha256"] == digest:
                    self._connection.execute("COMMIT")
                    return False
                raise TelemetryStoreConflictError("immutable telemetry sample ID already has different content")
            self._connection.execute(
                """INSERT INTO samples(
                       sample_id, operation_kind, calibration_key, observed_at, payload_json, payload_sha256
                   ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    sample.sample_id,
                    sample.operation_kind,
                    sample.calibration_key,
                    sample.observed_at,
                    payload_json,
                    digest,
                ),
            )
            self._connection.execute("COMMIT")
            return True
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def samples(self, *, operation_kind: str, calibration_key: str) -> tuple[TelemetrySample, ...]:
        self._check_identity()
        rows = self._connection.execute(
            """SELECT payload_json, payload_sha256 FROM samples
               WHERE operation_kind = ? AND calibration_key = ?
               ORDER BY observed_at, sample_id""",
            (operation_kind, calibration_key),
        ).fetchall()
        return tuple(self._decode(row["payload_json"], row["payload_sha256"]) for row in rows)

    def calibration(
        self,
        *,
        operation_kind: str,
        calibration_key: str,
        metric_name: str,
        pool_kind: str,
        unit: str,
        policy: CalibrationPolicy | None = None,
    ) -> CalibrationSnapshot:
        return build_calibration(
            self.samples(operation_kind=operation_kind, calibration_key=calibration_key),
            operation_kind=operation_kind,
            calibration_key=calibration_key,
            metric_name=metric_name,
            pool_kind=pool_kind,
            unit=unit,
            policy=policy or CalibrationPolicy(),
        )

    def calibrate_estimate(
        self,
        estimate: ResourceEstimate,
        *,
        operation_kind: str,
        calibration_key: str,
        policy: CalibrationPolicy | None = None,
    ) -> ResourceEstimate:
        snapshot = self.calibration(
            operation_kind=operation_kind,
            calibration_key=calibration_key,
            metric_name=estimate.name,
            pool_kind=estimate.pool_kind,
            unit=estimate.unit,
            policy=policy,
        )
        if not snapshot.eligible:
            return estimate
        return ResourceEstimate(
            name=estimate.name,
            pool_kind=estimate.pool_kind,
            unit=estimate.unit,
            expected=snapshot.expected,
            upper_bound=snapshot.upper_bound,
            confidence="measured",
            source=f"telemetry-calibration:{snapshot.calibration_digest}",
            diagnostic=None,
        )

    def calibrate_all(
        self,
        estimates: Iterable[ResourceEstimate],
        *,
        operation_kind: str,
        calibration_key: str,
        policy: CalibrationPolicy | None = None,
    ) -> tuple[ResourceEstimate, ...]:
        return tuple(
            self.calibrate_estimate(
                estimate,
                operation_kind=operation_kind,
                calibration_key=calibration_key,
                policy=policy,
            )
            for estimate in estimates
        )
