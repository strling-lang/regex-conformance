"""Transactional attempt checkpoints and conservative campaign recovery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Callable, Mapping

import rfc8785

from .safe_payload import UnsafeCheckpointPayloadError, validate_checkpoint_payload


CHECKPOINT_STATES = (
    "leased",
    "environment-ready",
    "running",
    "observation-finalized",
    "spooled",
    "segment-finalized",
    "uploaded",
    "verified",
    "manifest-committed",
    "acknowledged",
)
COMMITTED_STATES = frozenset({"manifest-committed", "acknowledged"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,2047}$")
TYPED_ID_PATTERNS = {
    "rcid:v1:campaign-manifest:h:": re.compile(
        r"^rcid:v1:campaign-manifest:h:jcs-sha256-v1:[0-9a-f]{64}$"
    ),
    "rcid:v1:logical-execution:h:": re.compile(
        r"^rcid:v1:logical-execution:h:jcs-sha256-v1:[0-9a-f]{64}$"
    ),
    "rcid:v1:physical-run:u7:": re.compile(
        r"^rcid:v1:physical-run:u7:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ),
}


class RecoveryError(RuntimeError):
    """Campaign recovery could not safely continue."""


class RecoveryConflictError(RecoveryError):
    """A caller proposed a contradictory transition or identity."""


class RecoveryIntegrityError(RecoveryError):
    """The durable recovery journal failed structural or hash verification."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError, UnicodeError, ValueError) as error:
        raise RecoveryConflictError("recovery material is not RFC 8785 canonicalizable") from error


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _require_identifier(label: str, value: str) -> None:
    if not isinstance(value, str) or SAFE_IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise RecoveryConflictError(f"{label} must be a bounded safe identifier")


def _require_sha256(label: str, value: str) -> None:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise RecoveryConflictError(f"{label} must be a lowercase SHA-256 digest")


def _require_typed_prefix(label: str, value: str, prefix: str) -> None:
    _require_identifier(label, value)
    pattern = TYPED_ID_PATTERNS.get(prefix)
    if pattern is None or pattern.fullmatch(value) is None:
        raise RecoveryConflictError(f"{label} has the wrong typed identity namespace")


def recovery_action_for_stage(stage: str, *, same_session: bool = False) -> str:
    """Return the D090 recovery action for one verified latest checkpoint."""

    if stage not in CHECKPOINT_STATES:
        return "quarantine"
    if same_session:
        return "committed" if stage in COMMITTED_STATES else "continue"
    if stage == "running":
        return "retry"
    if stage in COMMITTED_STATES:
        return "committed"
    return "continue"


@dataclass(frozen=True)
class RecoveryDecision:
    action: str
    logical_execution_id: str
    physical_run_id: str | None
    attempt_number: int | None
    resume_state: str | None
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "attempt_number": self.attempt_number,
            "logical_execution_id": self.logical_execution_id,
            "physical_run_id": self.physical_run_id,
            "reason_code": self.reason_code,
            "resume_state": self.resume_state,
        }


@dataclass(frozen=True)
class AttemptRecord:
    logical_execution_id: str
    physical_run_id: str
    attempt_number: int
    purpose: str
    disposition: str
    owner_session_id: str
    latest_state: str
    manifest_sha256: str | None
    commit_receipt_sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "commit_receipt_sha256": self.commit_receipt_sha256,
            "disposition": self.disposition,
            "latest_state": self.latest_state,
            "logical_execution_id": self.logical_execution_id,
            "manifest_sha256": self.manifest_sha256,
            "owner_session_id": self.owner_session_id,
            "physical_run_id": self.physical_run_id,
            "purpose": self.purpose,
        }


class RecoveryJournal:
    """SQLite-backed append-only attempt state with idempotent commit recovery."""

    SCHEMA_VERSION = "1"

    def __init__(
        self,
        database_path: Path,
        *,
        campaign_manifest_id: str,
        logical_execution_ids: tuple[str, ...],
        controller_session_id: str,
        physical_run_id_factory: Callable[[], str],
    ) -> None:
        _require_typed_prefix(
            "campaign manifest ID",
            campaign_manifest_id,
            "rcid:v1:campaign-manifest:h:",
        )
        _require_identifier("controller session ID", controller_session_id)
        if not logical_execution_ids:
            raise RecoveryConflictError("recovery plan requires at least one logical execution")
        for logical_id in logical_execution_ids:
            _require_typed_prefix(
                "logical execution ID",
                logical_id,
                "rcid:v1:logical-execution:h:",
            )
        if (
            tuple(sorted(logical_execution_ids)) != logical_execution_ids
            or len(set(logical_execution_ids)) != len(logical_execution_ids)
        ):
            raise RecoveryConflictError(
                "logical execution IDs must be unique and code-point ordered"
            )
        path = database_path.expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = path.parent.resolve(strict=True)
        if path.exists() and path.is_symlink():
            raise RecoveryIntegrityError("recovery journal refuses a symbolic-link database")
        if path.exists():
            status = path.stat()
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise RecoveryIntegrityError(
                    "recovery journal requires a singly linked regular database"
                )
        self.database_path = resolved_parent / path.name
        self.campaign_manifest_id = campaign_manifest_id
        self.logical_execution_ids = logical_execution_ids
        self.controller_session_id = controller_session_id
        self.physical_run_id_factory = physical_run_id_factory
        try:
            if not self.database_path.exists():
                descriptor = os.open(
                    self.database_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
                )
                os.close(descriptor)
            self._connection = sqlite3.connect(
                self.database_path,
                isolation_level=None,
                timeout=5.0,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._initialize()
            os.chmod(self.database_path, 0o600)
            self.audit()
        except RecoveryError:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise
        except (sqlite3.DatabaseError, OSError) as error:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise RecoveryIntegrityError("recovery journal could not be opened safely") from error

    def __enter__(self) -> "RecoveryJournal":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def _initialize(self) -> None:
        plan_sha256 = _sha256(list(self.logical_execution_ids))
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS attempts (
                physical_run_id TEXT PRIMARY KEY,
                logical_execution_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
                purpose TEXT NOT NULL CHECK (purpose IN ('initial', 'retry')),
                disposition TEXT NOT NULL CHECK (disposition IN ('active', 'interrupted', 'committed')),
                owner_session_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (logical_execution_id, attempt_number)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS checkpoints (
                physical_run_id TEXT NOT NULL REFERENCES attempts(physical_run_id),
                checkpoint_ordinal INTEGER NOT NULL CHECK (checkpoint_ordinal >= 1),
                state TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                manifest_sha256 TEXT,
                commit_receipt_sha256 TEXT,
                previous_checkpoint_sha256 TEXT,
                checkpoint_sha256 TEXT NOT NULL UNIQUE,
                controller_session_id TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY (physical_run_id, checkpoint_ordinal)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS logical_commits (
                logical_execution_id TEXT PRIMARY KEY,
                physical_run_id TEXT NOT NULL UNIQUE REFERENCES attempts(physical_run_id),
                manifest_sha256 TEXT NOT NULL,
                commit_receipt_sha256 TEXT NOT NULL UNIQUE
            ) STRICT;
            """
        )
        expected = {
            "campaign_manifest_id": self.campaign_manifest_id,
            "logical_plan_sha256": plan_sha256,
            "schema_version": self.SCHEMA_VERSION,
        }
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = {
                row["key"]: row["value"]
                for row in self._connection.execute("SELECT key, value FROM metadata")
            }
            if existing and existing != expected:
                raise RecoveryIntegrityError("recovery journal metadata contradicts the campaign plan")
            if not existing:
                self._connection.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)", sorted(expected.items())
                )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    def _latest_attempt_row(self, logical_execution_id: str) -> sqlite3.Row | None:
        return self._connection.execute(
            """
            SELECT a.*, c.state AS latest_state,
                   COALESCE(c.manifest_sha256, lc.manifest_sha256) AS manifest_sha256,
                   COALESCE(c.commit_receipt_sha256, lc.commit_receipt_sha256) AS commit_receipt_sha256
            FROM attempts AS a
            JOIN checkpoints AS c ON c.physical_run_id = a.physical_run_id
            LEFT JOIN logical_commits AS lc ON lc.physical_run_id = a.physical_run_id
            WHERE a.logical_execution_id = ?
              AND c.checkpoint_ordinal = (
                SELECT MAX(c2.checkpoint_ordinal)
                FROM checkpoints AS c2
                WHERE c2.physical_run_id = a.physical_run_id
              )
            ORDER BY a.attempt_number DESC
            LIMIT 1
            """,
            (logical_execution_id,),
        ).fetchone()

    def _insert_attempt(self, logical_execution_id: str, attempt_number: int, purpose: str) -> str:
        physical_run_id = self.physical_run_id_factory()
        _require_typed_prefix("physical run ID", physical_run_id, "rcid:v1:physical-run:u7:")
        try:
            self._connection.execute(
                """
                INSERT INTO attempts(
                    physical_run_id, logical_execution_id, attempt_number, purpose,
                    disposition, owner_session_id, created_at
                ) VALUES (?, ?, ?, ?, 'active', ?, ?)
                """,
                (
                    physical_run_id,
                    logical_execution_id,
                    attempt_number,
                    purpose,
                    self.controller_session_id,
                    _stamp(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise RecoveryConflictError("physical run identity or attempt ordinal collided") from error
        self._append_checkpoint(
            physical_run_id,
            "leased",
            {"attempt_number": attempt_number, "purpose": purpose},
        )
        return physical_run_id

    def start_or_resume(self, logical_execution_id: str) -> RecoveryDecision:
        if logical_execution_id not in self.logical_execution_ids:
            raise RecoveryConflictError("logical execution is outside the frozen campaign plan")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._audit_in_transaction()
            committed = self._connection.execute(
                "SELECT * FROM logical_commits WHERE logical_execution_id = ?",
                (logical_execution_id,),
            ).fetchone()
            if committed is not None:
                latest = self._latest_attempt_row(logical_execution_id)
                assert latest is not None
                self._connection.execute(
                    "UPDATE attempts SET owner_session_id = ? WHERE physical_run_id = ?",
                    (self.controller_session_id, latest["physical_run_id"]),
                )
                self._connection.execute("COMMIT")
                return RecoveryDecision(
                    "committed",
                    logical_execution_id,
                    latest["physical_run_id"],
                    latest["attempt_number"],
                    latest["latest_state"],
                    "verified-manifest-commit",
                )
            latest = self._latest_attempt_row(logical_execution_id)
            if latest is None:
                physical_run_id = self._insert_attempt(logical_execution_id, 1, "initial")
                self._connection.execute("COMMIT")
                return RecoveryDecision(
                    "start", logical_execution_id, physical_run_id, 1, "leased", "initial-attempt"
                )
            stage = latest["latest_state"]
            same_session = latest["owner_session_id"] == self.controller_session_id
            action = recovery_action_for_stage(stage, same_session=same_session)
            if action == "quarantine":
                raise RecoveryIntegrityError("latest attempt checkpoint has an unknown state")
            if action == "retry":
                if latest["disposition"] != "active":
                    raise RecoveryIntegrityError("retry source attempt is not active")
                self._connection.execute(
                    "UPDATE attempts SET disposition = 'interrupted' WHERE physical_run_id = ?",
                    (latest["physical_run_id"],),
                )
                attempt_number = latest["attempt_number"] + 1
                physical_run_id = self._insert_attempt(
                    logical_execution_id, attempt_number, "retry"
                )
                self._connection.execute("COMMIT")
                return RecoveryDecision(
                    "retry",
                    logical_execution_id,
                    physical_run_id,
                    attempt_number,
                    "leased",
                    "interrupted-target-invocation",
                )
            self._connection.execute(
                "UPDATE attempts SET owner_session_id = ? WHERE physical_run_id = ?",
                (self.controller_session_id, latest["physical_run_id"]),
            )
            self._connection.execute("COMMIT")
            reason = "duplicate-delivery" if same_session else "durable-checkpoint"
            return RecoveryDecision(
                action,
                logical_execution_id,
                latest["physical_run_id"],
                latest["attempt_number"],
                stage,
                reason,
            )
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def checkpoint(
        self,
        physical_run_id: str,
        state: str,
        payload: Mapping[str, Any] | None = None,
        *,
        manifest_sha256: str | None = None,
    ) -> str:
        _require_typed_prefix("physical run ID", physical_run_id, "rcid:v1:physical-run:u7:")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._audit_in_transaction()
            attempt = self._connection.execute(
                "SELECT * FROM attempts WHERE physical_run_id = ?", (physical_run_id,)
            ).fetchone()
            if attempt is None:
                raise RecoveryConflictError("physical run is unknown")
            if attempt["owner_session_id"] != self.controller_session_id:
                raise RecoveryConflictError("physical run is owned by another controller session")
            if attempt["disposition"] != "active":
                raise RecoveryConflictError("only an active physical run can advance")
            latest = self._connection.execute(
                """
                SELECT * FROM checkpoints WHERE physical_run_id = ?
                ORDER BY checkpoint_ordinal DESC LIMIT 1
                """,
                (physical_run_id,),
            ).fetchone()
            assert latest is not None
            expected_index = CHECKPOINT_STATES.index(latest["state"]) + 1
            if expected_index >= len(CHECKPOINT_STATES) or state != CHECKPOINT_STATES[expected_index]:
                raise RecoveryConflictError("checkpoint transition is not the exact next D090 state")
            if state == "manifest-committed":
                if manifest_sha256 is None:
                    raise RecoveryConflictError("manifest commit requires a verified manifest digest")
                _require_sha256("manifest digest", manifest_sha256)
            elif manifest_sha256 is not None:
                raise RecoveryConflictError("manifest digest is permitted only at manifest commit")
            digest = self._append_checkpoint(
                physical_run_id,
                state,
                {} if payload is None else dict(payload),
                manifest_sha256=manifest_sha256,
            )
            if state == "manifest-committed":
                self._connection.execute(
                    "UPDATE attempts SET disposition = 'committed' WHERE physical_run_id = ?",
                    (physical_run_id,),
                )
            self._connection.execute("COMMIT")
            return digest
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def acknowledge(self, physical_run_id: str) -> str:
        _require_typed_prefix("physical run ID", physical_run_id, "rcid:v1:physical-run:u7:")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._audit_in_transaction()
            attempt = self._connection.execute(
                "SELECT * FROM attempts WHERE physical_run_id = ?", (physical_run_id,)
            ).fetchone()
            if attempt is None or attempt["owner_session_id"] != self.controller_session_id:
                raise RecoveryConflictError("committed physical run is unknown or not reclaimed")
            if attempt["disposition"] != "committed":
                raise RecoveryConflictError("acknowledgment requires a committed physical run")
            latest = self._connection.execute(
                "SELECT state, checkpoint_sha256 FROM checkpoints WHERE physical_run_id = ? ORDER BY checkpoint_ordinal DESC LIMIT 1",
                (physical_run_id,),
            ).fetchone()
            assert latest is not None
            if latest["state"] == "acknowledged":
                self._connection.execute("COMMIT")
                return latest["checkpoint_sha256"]
            if latest["state"] != "manifest-committed":
                raise RecoveryIntegrityError("committed attempt lacks a manifest checkpoint")
            digest = self._append_checkpoint(physical_run_id, "acknowledged", {})
            self._connection.execute("COMMIT")
            return digest
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise

    def _append_checkpoint(
        self,
        physical_run_id: str,
        state: str,
        payload: Mapping[str, Any],
        *,
        manifest_sha256: str | None = None,
    ) -> str:
        payload_value = dict(payload)
        try:
            validate_checkpoint_payload(payload_value)
        except UnsafeCheckpointPayloadError as error:
            raise RecoveryConflictError(str(error)) from error
        payload_bytes = _canonical_bytes(payload_value)
        payload_json = payload_bytes.decode("utf-8")
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        previous = self._connection.execute(
            "SELECT * FROM checkpoints WHERE physical_run_id = ? ORDER BY checkpoint_ordinal DESC LIMIT 1",
            (physical_run_id,),
        ).fetchone()
        ordinal = 1 if previous is None else previous["checkpoint_ordinal"] + 1
        previous_digest = None if previous is None else previous["checkpoint_sha256"]
        attempt = self._connection.execute(
            "SELECT logical_execution_id, attempt_number FROM attempts WHERE physical_run_id = ?",
            (physical_run_id,),
        ).fetchone()
        assert attempt is not None
        receipt_sha256: str | None = None
        if state == "manifest-committed":
            assert manifest_sha256 is not None
            receipt_sha256 = _sha256(
                {
                    "campaign_manifest_id": self.campaign_manifest_id,
                    "logical_execution_id": attempt["logical_execution_id"],
                    "manifest_sha256": manifest_sha256,
                    "physical_run_id": physical_run_id,
                    "schema_version": "campaign-commit-receipt.v1",
                }
            )
        recorded_at = _stamp()
        body = {
            "attempt_number": attempt["attempt_number"],
            "campaign_manifest_id": self.campaign_manifest_id,
            "checkpoint_ordinal": ordinal,
            "commit_receipt_sha256": receipt_sha256,
            "controller_session_id": self.controller_session_id,
            "logical_execution_id": attempt["logical_execution_id"],
            "manifest_sha256": manifest_sha256,
            "payload_sha256": payload_sha256,
            "physical_run_id": physical_run_id,
            "previous_checkpoint_sha256": previous_digest,
            "schema_version": "attempt-checkpoint.v1",
            "state": state,
            "recorded_at": recorded_at,
        }
        checkpoint_sha256 = _sha256(body)
        self._connection.execute(
            """
            INSERT INTO checkpoints(
                physical_run_id, checkpoint_ordinal, state, payload_json, payload_sha256,
                manifest_sha256, commit_receipt_sha256, previous_checkpoint_sha256,
                checkpoint_sha256, controller_session_id, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                physical_run_id,
                ordinal,
                state,
                payload_json,
                payload_sha256,
                manifest_sha256,
                receipt_sha256,
                previous_digest,
                checkpoint_sha256,
                self.controller_session_id,
                recorded_at,
            ),
        )
        if state == "manifest-committed":
            try:
                self._connection.execute(
                    """
                    INSERT INTO logical_commits(
                        logical_execution_id, physical_run_id, manifest_sha256, commit_receipt_sha256
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        attempt["logical_execution_id"],
                        physical_run_id,
                        manifest_sha256,
                        receipt_sha256,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise RecoveryConflictError("logical execution already has a different commit") from error
        return checkpoint_sha256

    def latest_checkpoint_payload(self, physical_run_id: str) -> dict[str, Any]:
        """Return the verified canonical payload needed to continue recovery."""

        _require_typed_prefix(
            "physical run ID", physical_run_id, "rcid:v1:physical-run:u7:"
        )
        self.audit()
        row = self._connection.execute(
            "SELECT payload_json FROM checkpoints WHERE physical_run_id = ? "
            "ORDER BY checkpoint_ordinal DESC LIMIT 1",
            (physical_run_id,),
        ).fetchone()
        if row is None:
            raise RecoveryConflictError("physical run is unknown")
        payload = json.loads(row["payload_json"])
        assert isinstance(payload, dict)
        return payload

    def attempts(self, logical_execution_id: str | None = None) -> tuple[AttemptRecord, ...]:
        query = """
            SELECT a.*, c.state AS latest_state,
                   COALESCE(c.manifest_sha256, lc.manifest_sha256) AS manifest_sha256,
                   COALESCE(c.commit_receipt_sha256, lc.commit_receipt_sha256) AS commit_receipt_sha256
            FROM attempts AS a
            JOIN checkpoints AS c ON c.physical_run_id = a.physical_run_id
            LEFT JOIN logical_commits AS lc ON lc.physical_run_id = a.physical_run_id
            WHERE c.checkpoint_ordinal = (
                SELECT MAX(c2.checkpoint_ordinal) FROM checkpoints AS c2
                WHERE c2.physical_run_id = a.physical_run_id
            )
        """
        parameters: tuple[str, ...] = ()
        if logical_execution_id is not None:
            query += " AND a.logical_execution_id = ?"
            parameters = (logical_execution_id,)
        query += " ORDER BY a.logical_execution_id, a.attempt_number"
        return tuple(
            AttemptRecord(
                row["logical_execution_id"],
                row["physical_run_id"],
                row["attempt_number"],
                row["purpose"],
                row["disposition"],
                row["owner_session_id"],
                row["latest_state"],
                row["manifest_sha256"],
                row["commit_receipt_sha256"],
            )
            for row in self._connection.execute(query, parameters)
        )

    def audit(self) -> None:
        try:
            result = self._connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise RecoveryIntegrityError("SQLite integrity check failed")
            self._connection.execute("BEGIN")
            try:
                self._audit_in_transaction()
            finally:
                self._connection.execute("ROLLBACK")
        except sqlite3.DatabaseError as error:
            raise RecoveryIntegrityError("recovery journal is corrupt or incompatible") from error

    def _audit_in_transaction(self) -> None:
        metadata = {
            row["key"]: row["value"]
            for row in self._connection.execute("SELECT key, value FROM metadata")
        }
        expected_metadata = {
            "campaign_manifest_id": self.campaign_manifest_id,
            "logical_plan_sha256": _sha256(list(self.logical_execution_ids)),
            "schema_version": self.SCHEMA_VERSION,
        }
        if metadata != expected_metadata:
            raise RecoveryIntegrityError("recovery metadata failed exact reconciliation")
        by_logical: dict[str, list[sqlite3.Row]] = {}
        for attempt in self._connection.execute(
            "SELECT * FROM attempts ORDER BY logical_execution_id, attempt_number"
        ):
            logical_id = attempt["logical_execution_id"]
            if logical_id not in self.logical_execution_ids:
                raise RecoveryIntegrityError("attempt references unplanned logical execution")
            by_logical.setdefault(logical_id, []).append(attempt)
            checkpoints = list(
                self._connection.execute(
                    "SELECT * FROM checkpoints WHERE physical_run_id = ? ORDER BY checkpoint_ordinal",
                    (attempt["physical_run_id"],),
                )
            )
            if not checkpoints:
                raise RecoveryIntegrityError("attempt lacks its leased checkpoint")
            if [row["checkpoint_ordinal"] for row in checkpoints] != list(
                range(1, len(checkpoints) + 1)
            ):
                raise RecoveryIntegrityError("attempt checkpoint ordinals are not contiguous")
            if [row["state"] for row in checkpoints] != list(CHECKPOINT_STATES[: len(checkpoints)]):
                raise RecoveryIntegrityError("attempt checkpoints are not an exact D090 prefix")
            previous: str | None = None
            for row in checkpoints:
                try:
                    stored_payload = json.loads(
                        row["payload_json"],
                        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
                    )
                    stored_payload_bytes = _canonical_bytes(stored_payload)
                except (TypeError, ValueError, json.JSONDecodeError, RecoveryConflictError) as error:
                    raise RecoveryIntegrityError(
                        "attempt checkpoint payload is not strict canonical JSON"
                    ) from error
                if (
                    not isinstance(stored_payload, dict)
                    or stored_payload_bytes.decode("utf-8") != row["payload_json"]
                    or hashlib.sha256(stored_payload_bytes).hexdigest() != row["payload_sha256"]
                ):
                    raise RecoveryIntegrityError(
                        "attempt checkpoint payload failed canonical digest verification"
                    )
                body = {
                    "attempt_number": attempt["attempt_number"],
                    "campaign_manifest_id": self.campaign_manifest_id,
                    "checkpoint_ordinal": row["checkpoint_ordinal"],
                    "commit_receipt_sha256": row["commit_receipt_sha256"],
                    "controller_session_id": row["controller_session_id"],
                    "logical_execution_id": logical_id,
                    "manifest_sha256": row["manifest_sha256"],
                    "payload_sha256": row["payload_sha256"],
                    "physical_run_id": attempt["physical_run_id"],
                    "previous_checkpoint_sha256": previous,
                    "schema_version": "attempt-checkpoint.v1",
                    "state": row["state"],
                    "recorded_at": row["recorded_at"],
                }
                if row["previous_checkpoint_sha256"] != previous or row["checkpoint_sha256"] != _sha256(body):
                    raise RecoveryIntegrityError("attempt checkpoint hash chain failed verification")
                previous = row["checkpoint_sha256"]
            latest_state = checkpoints[-1]["state"]
            if attempt["disposition"] == "interrupted" and latest_state != "running":
                raise RecoveryIntegrityError("only a running attempt may become interrupted")
            if attempt["disposition"] == "committed" and latest_state not in COMMITTED_STATES:
                raise RecoveryIntegrityError("committed attempt lacks its durable commit checkpoint")
            if attempt["disposition"] == "active" and latest_state in COMMITTED_STATES:
                raise RecoveryIntegrityError("committed checkpoint cannot remain active")
        for logical_id, attempts in by_logical.items():
            if [row["attempt_number"] for row in attempts] != list(range(1, len(attempts) + 1)):
                raise RecoveryIntegrityError("physical attempt ordinals are not contiguous")
            if attempts[0]["purpose"] != "initial" or any(
                row["purpose"] != "retry" for row in attempts[1:]
            ):
                raise RecoveryIntegrityError("physical attempt purposes contradict their ordinals")
            if sum(row["disposition"] in {"active", "committed"} for row in attempts) != 1:
                raise RecoveryIntegrityError("logical execution has ambiguous active or committed attempts")
        commits = list(self._connection.execute("SELECT * FROM logical_commits"))
        committed_attempts = {
            row["physical_run_id"]
            for rows in by_logical.values()
            for row in rows
            if row["disposition"] == "committed"
        }
        if committed_attempts != {row["physical_run_id"] for row in commits}:
            raise RecoveryIntegrityError(
                "committed attempts and logical commit receipts do not reconcile"
            )
        for commit in commits:
            attempt = self._connection.execute(
                "SELECT * FROM attempts WHERE physical_run_id = ?", (commit["physical_run_id"],)
            ).fetchone()
            checkpoint = self._connection.execute(
                """
                SELECT * FROM checkpoints WHERE physical_run_id = ? AND state = 'manifest-committed'
                """,
                (commit["physical_run_id"],),
            ).fetchone()
            if (
                attempt is None
                or checkpoint is None
                or attempt["logical_execution_id"] != commit["logical_execution_id"]
                or attempt["disposition"] != "committed"
                or checkpoint["manifest_sha256"] != commit["manifest_sha256"]
                or checkpoint["commit_receipt_sha256"] != commit["commit_receipt_sha256"]
            ):
                raise RecoveryIntegrityError("logical commit does not reconcile its physical attempt")
            expected_receipt = _sha256(
                {
                    "campaign_manifest_id": self.campaign_manifest_id,
                    "logical_execution_id": commit["logical_execution_id"],
                    "manifest_sha256": commit["manifest_sha256"],
                    "physical_run_id": commit["physical_run_id"],
                    "schema_version": "campaign-commit-receipt.v1",
                }
            )
            if commit["commit_receipt_sha256"] != expected_receipt:
                raise RecoveryIntegrityError("logical commit receipt digest failed verification")


def build_restart_resume_reference_report() -> dict[str, Any]:
    cases = []
    for stage in CHECKPOINT_STATES:
        action = recovery_action_for_stage(stage)
        cases.append(
            {
                "case_key": f"restart-after-{stage}",
                "expected_action": action,
                "latest_checkpoint": stage,
                "preserve_physical_run": action != "retry",
                "requires_new_physical_run": action == "retry",
            }
        )
    cases.extend(
        [
            {
                "case_key": "corrupt-checkpoint-chain",
                "expected_action": "quarantine",
                "latest_checkpoint": None,
                "preserve_physical_run": False,
                "requires_new_physical_run": False,
            },
            {
                "case_key": "duplicate-active-delivery",
                "expected_action": "continue",
                "latest_checkpoint": "running",
                "preserve_physical_run": True,
                "requires_new_physical_run": False,
            },
            {
                "case_key": "repeated-running-restarts",
                "expected_action": "retry",
                "latest_checkpoint": "running",
                "preserve_physical_run": False,
                "requires_new_physical_run": True,
            },
            {
                "case_key": "uncommitted-transaction",
                "expected_action": "continue",
                "latest_checkpoint": "leased",
                "preserve_physical_run": True,
                "requires_new_physical_run": False,
            },
        ]
    )
    cases.sort(key=lambda item: item["case_key"])
    return {
        "cases": cases,
        "classification": {
            "canonical_authority": False,
            "normative_authority": False,
            "operational_qualification_only": True,
            "semantic_authority": False,
        },
        "schema_version": "restart-resume-qualification.v1",
        "summary": {
            "case_count": len(cases),
            "committed_case_count": sum(item["expected_action"] == "committed" for item in cases),
            "continue_case_count": sum(item["expected_action"] == "continue" for item in cases),
            "quarantine_case_count": sum(item["expected_action"] == "quarantine" for item in cases),
            "retry_case_count": sum(item["expected_action"] == "retry" for item in cases),
        },
    }
