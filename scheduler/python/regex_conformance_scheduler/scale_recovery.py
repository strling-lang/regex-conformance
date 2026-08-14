"""Durable local shard ledger for restartable scale campaigns.

The ledger is operational, recoverable state. Immutable evidence segments remain
the authority; a row is committed only after its referenced bytes have passed
read-after-write verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from regex_conformance_schema.jsonio import canonical_bytes, loads_strict


class ScaleRecoveryError(RuntimeError):
    """Scale campaign operational state is unsafe or contradictory."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class CommittedSegment:
    ordinal: int
    shard_id: str
    segment_kind: str
    attempt_number: int
    reference: dict[str, Any]
    commit_sha256: str


class ScaleRecoveryLedger:
    """SQLite hash-chain ledger for exact shard and interruption recovery."""

    SCHEMA_VERSION = "scale-recovery-ledger.v1"

    def __init__(self, path: Path, campaign_manifest_id: str) -> None:
        unresolved = path.expanduser().absolute()
        if unresolved.is_symlink():
            raise ScaleRecoveryError(
                "scale recovery database cannot be a symbolic link"
            )
        unresolved.parent.mkdir(parents=True, exist_ok=True)
        if unresolved.parent.is_symlink():
            raise ScaleRecoveryError("scale recovery database parent cannot be a link")
        self.path = unresolved.resolve(strict=False)
        if self.path.exists():
            metadata = self.path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ScaleRecoveryError(
                    "scale recovery database must be a private regular file"
                )
            if os.name != "nt" and metadata.st_mode & 0o077:
                raise ScaleRecoveryError("scale recovery database is not private")
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        try:
            self._create(campaign_manifest_id)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
            self.verify(campaign_manifest_id)
        except Exception:
            self._connection.close()
            raise

    def __enter__(self) -> "ScaleRecoveryLedger":
        return self

    def __exit__(self, *_arguments: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def _create(self, campaign_manifest_id: str) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                outcome TEXT CHECK (outcome IN ('completed', 'forced-interruption', 'failed'))
            );
            CREATE TABLE IF NOT EXISTS segment_commits (
                ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
                shard_id TEXT NOT NULL,
                segment_kind TEXT NOT NULL CHECK (segment_kind IN ('attempt', 'result')),
                attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
                reference_json BLOB NOT NULL,
                committed_at TEXT NOT NULL,
                previous_commit_sha256 TEXT,
                commit_sha256 TEXT NOT NULL UNIQUE,
                UNIQUE (shard_id, segment_kind, attempt_number)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_result_per_shard
                ON segment_commits(shard_id) WHERE segment_kind = 'result';
            CREATE TABLE IF NOT EXISTS interruptions (
                interruption_key TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                after_committed_shards INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                controller_session_id TEXT NOT NULL,
                worker_process TEXT,
                event_sha256 TEXT NOT NULL UNIQUE
            );
            """
        )
        existing = dict(self._connection.execute("SELECT key, value FROM metadata"))
        expected = {
            "campaign_manifest_id": campaign_manifest_id,
            "schema_version": self.SCHEMA_VERSION,
        }
        if not existing:
            self._connection.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)", expected.items()
            )
            self._connection.commit()
        elif existing != expected:
            raise ScaleRecoveryError(
                "scale recovery database belongs to another campaign or schema"
            )

    def begin_session(self, session_id: str) -> None:
        try:
            self._connection.execute(
                "INSERT INTO sessions(session_id, started_at) VALUES (?, ?)",
                (session_id, utc_now()),
            )
            self._connection.commit()
        except sqlite3.IntegrityError as error:
            raise ScaleRecoveryError(
                "controller session identity was reused"
            ) from error

    def recover_active_sessions(self) -> int:
        """Close sessions left active by abrupt controller termination."""

        ended_at = utc_now()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._connection.execute(
                "UPDATE sessions SET ended_at = ?, outcome = "
                "CASE WHEN EXISTS ("
                "SELECT 1 FROM interruptions "
                "WHERE interruptions.controller_session_id = sessions.session_id"
                ") THEN 'forced-interruption' ELSE 'failed' END "
                "WHERE ended_at IS NULL",
                (ended_at,),
            )
            self._connection.commit()
        except sqlite3.Error:
            self._connection.rollback()
            raise
        return int(cursor.rowcount)

    def end_session(self, session_id: str, outcome: str) -> None:
        if outcome not in {"completed", "forced-interruption", "failed"}:
            raise ScaleRecoveryError("controller session outcome is invalid")
        cursor = self._connection.execute(
            "UPDATE sessions SET ended_at = ?, outcome = ? "
            "WHERE session_id = ? AND ended_at IS NULL",
            (utc_now(), outcome, session_id),
        )
        if cursor.rowcount != 1:
            raise ScaleRecoveryError("controller session is absent or already terminal")
        self._connection.commit()

    @staticmethod
    def _commit_body(
        ordinal: int,
        shard_id: str,
        segment_kind: str,
        attempt_number: int,
        reference: dict[str, Any],
        committed_at: str,
        previous: str | None,
    ) -> dict[str, Any]:
        return {
            "attempt_number": attempt_number,
            "committed_at": committed_at,
            "ordinal": ordinal,
            "previous_commit_sha256": previous,
            "reference": reference,
            "schema_version": "scale-segment-commit.v1",
            "segment_kind": segment_kind,
            "shard_id": shard_id,
        }

    def commit_segment(
        self,
        shard_id: str,
        segment_kind: str,
        attempt_number: int,
        reference: dict[str, Any],
    ) -> str:
        if segment_kind not in {"attempt", "result"} or attempt_number < 1:
            raise ScaleRecoveryError("scale segment commit coordinates are invalid")
        encoded_reference = canonical_bytes(reference)
        committed_at = utc_now()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            previous_row = self._connection.execute(
                "SELECT ordinal, commit_sha256 FROM segment_commits "
                "ORDER BY ordinal DESC LIMIT 1"
            ).fetchone()
            ordinal = 1 if previous_row is None else previous_row["ordinal"] + 1
            previous = None if previous_row is None else previous_row["commit_sha256"]
            commit_sha256 = _digest(
                self._commit_body(
                    ordinal,
                    shard_id,
                    segment_kind,
                    attempt_number,
                    reference,
                    committed_at,
                    previous,
                )
            )
            self._connection.execute(
                "INSERT INTO segment_commits("
                "ordinal, shard_id, segment_kind, attempt_number, reference_json, "
                "committed_at, previous_commit_sha256, commit_sha256"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ordinal,
                    shard_id,
                    segment_kind,
                    attempt_number,
                    encoded_reference,
                    committed_at,
                    previous,
                    commit_sha256,
                ),
            )
            self._connection.commit()
        except (sqlite3.Error, ValueError):
            self._connection.rollback()
            raise
        return commit_sha256

    def record_interruption(
        self,
        *,
        interruption_key: str,
        action: str,
        after_committed_shards: int,
        controller_session_id: str,
        worker_process: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        observed_at = utc_now()
        body = {
            "action": action,
            "after_committed_shards": after_committed_shards,
            "controller_session_id": controller_session_id,
            "interruption_key": interruption_key,
            "observed_at": observed_at,
            "schema_version": "scale-interruption-event.v1",
            "worker_process": worker_process,
        }
        event_sha256 = _digest(body)
        try:
            self._connection.execute(
                "INSERT INTO interruptions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    interruption_key,
                    action,
                    after_committed_shards,
                    observed_at,
                    controller_session_id,
                    None if worker_process is None else canonical_bytes(worker_process),
                    event_sha256,
                ),
            )
            self._connection.commit()
        except sqlite3.IntegrityError as error:
            raise ScaleRecoveryError(
                "planned interruption was recorded twice"
            ) from error
        return {**body, "event_sha256": event_sha256}

    def interruptions(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row in self._connection.execute(
            "SELECT * FROM interruptions ORDER BY after_committed_shards, interruption_key"
        ):
            worker = (
                None
                if row["worker_process"] is None
                else loads_strict(bytes(row["worker_process"]).decode("utf-8"))
            )
            result.append(
                {
                    "action": row["action"],
                    "after_committed_shards": row["after_committed_shards"],
                    "controller_session_id": row["controller_session_id"],
                    "event_sha256": row["event_sha256"],
                    "interruption_key": row["interruption_key"],
                    "observed_at": row["observed_at"],
                    "schema_version": "scale-interruption-event.v1",
                    "worker_process": worker,
                }
            )
        return result

    def segments(self) -> list[CommittedSegment]:
        result: list[CommittedSegment] = []
        for row in self._connection.execute(
            "SELECT * FROM segment_commits ORDER BY ordinal"
        ):
            reference = loads_strict(bytes(row["reference_json"]).decode("utf-8"))
            if not isinstance(reference, dict):
                raise ScaleRecoveryError("segment reference is not an object")
            result.append(
                CommittedSegment(
                    ordinal=row["ordinal"],
                    shard_id=row["shard_id"],
                    segment_kind=row["segment_kind"],
                    attempt_number=row["attempt_number"],
                    reference=reference,
                    commit_sha256=row["commit_sha256"],
                )
            )
        return result

    def result_shard_ids(self) -> set[str]:
        return {
            row[0]
            for row in self._connection.execute(
                "SELECT shard_id FROM segment_commits WHERE segment_kind = 'result'"
            )
        }

    def attempt_number(self, shard_id: str) -> int:
        row = self._connection.execute(
            "SELECT COALESCE(MAX(attempt_number), 0) FROM segment_commits "
            "WHERE shard_id = ?",
            (shard_id,),
        ).fetchone()
        return int(row[0]) + 1

    def session_summary(self) -> dict[str, int]:
        rows = dict(
            self._connection.execute(
                "SELECT COALESCE(outcome, 'active'), COUNT(*) FROM sessions GROUP BY outcome"
            )
        )
        return {
            "active": int(rows.get("active", 0)),
            "completed": int(rows.get("completed", 0)),
            "failed": int(rows.get("failed", 0)),
            "forced_interruption": int(rows.get("forced-interruption", 0)),
            "total": sum(int(value) for value in rows.values()),
        }

    def verify(self, campaign_manifest_id: str) -> None:
        if self._connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ScaleRecoveryError("scale recovery SQLite integrity check failed")
        metadata = dict(self._connection.execute("SELECT key, value FROM metadata"))
        if metadata != {
            "campaign_manifest_id": campaign_manifest_id,
            "schema_version": self.SCHEMA_VERSION,
        }:
            raise ScaleRecoveryError("scale recovery metadata changed")
        invalid_session = self._connection.execute(
            "SELECT 1 FROM sessions WHERE "
            "(ended_at IS NULL AND outcome IS NOT NULL) OR "
            "(ended_at IS NOT NULL AND outcome IS NULL) LIMIT 1"
        ).fetchone()
        if invalid_session is not None:
            raise ScaleRecoveryError("scale controller session state is contradictory")

        previous: str | None = None
        for expected_ordinal, row in enumerate(
            self._connection.execute("SELECT * FROM segment_commits ORDER BY ordinal"),
            start=1,
        ):
            if row["ordinal"] != expected_ordinal:
                raise ScaleRecoveryError(
                    "scale segment commit ordinals are not contiguous"
                )
            try:
                reference = loads_strict(bytes(row["reference_json"]).decode("utf-8"))
            except (UnicodeError, ValueError) as error:
                raise ScaleRecoveryError(
                    "scale segment commit reference is not strict JSON"
                ) from error
            if canonical_bytes(reference) != bytes(row["reference_json"]):
                raise ScaleRecoveryError(
                    "scale segment commit reference is not canonical JSON"
                )
            body = self._commit_body(
                row["ordinal"],
                row["shard_id"],
                row["segment_kind"],
                row["attempt_number"],
                reference,
                row["committed_at"],
                previous,
            )
            if row["previous_commit_sha256"] != previous or row[
                "commit_sha256"
            ] != _digest(body):
                raise ScaleRecoveryError("scale segment commit hash chain is corrupt")
            previous = row["commit_sha256"]
        for event in self.interruptions():
            body = {key: value for key, value in event.items() if key != "event_sha256"}
            if event["event_sha256"] != _digest(body):
                raise ScaleRecoveryError("scale interruption event digest is corrupt")
