"""Typed, deterministic records for non-canonical local operational state."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlsplit

import rfc8785

SAFE_INTEGER_MAX = 9_007_199_254_740_991
STATE_RECORD_KINDS = frozenset(
    {
        "cache-inventory",
        "campaign-assignment",
        "environment-instance",
        "event-cursor",
        "lease",
        "machine-inventory",
        "resource-measurement",
        "shard-checkpoint",
        "spool-publication",
        "transfer",
        "worker-telemetry",
    }
)
SOURCE_KINDS = frozenset(
    {"immutable-evidence", "local-operation", "provider-reality", "repository-manifest"}
)
RECONCILIATION_SOURCE_KINDS = SOURCE_KINDS - {"local-operation"}
VERIFICATION_STATES = frozenset({"provisional", "quarantined", "unverified", "verified"})
ADMISSION_STATES = frozenset({"blocked", "ready", "reconciliation-required"})
PRIOR_SHUTDOWN_STATES = frozenset({"clean", "new", "unclean"})

TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OPERATIONAL_ID_PATTERN = re.compile(
    r"^opid:v1:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:u7:"
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
RECORD_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,511}$")

_FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "accesstoken",
        "apikey",
        "authorization",
        "bearertoken",
        "clientsecret",
        "cookie",
        "credential",
        "credentials",
        "password",
        "passwd",
        "privatekey",
        "refreshtoken",
        "secret",
        "secretkey",
        "sessioncookie",
        "token",
    }
)
_FORBIDDEN_QUERY_NAMES = _FORBIDDEN_FIELD_NAMES | frozenset(
    {"awsaccesskeyid", "sig", "signature", "sharedaccesssignature", "xamzsignature", "xgoogsignature"}
)
_AUTHORIZATION_VALUE = re.compile(r"(?i)\b(?:basic|bearer)\s+[A-Za-z0-9+/_.=-]{8,}")


class StateModelError(ValueError):
    """A persisted or proposed state object violates the operational contract."""


class SecretMaterialError(StateModelError):
    """A record attempted to persist credential-bearing material."""


def _require_token(label: str, value: str) -> None:
    if TOKEN_PATTERN.fullmatch(value) is None:
        raise StateModelError(f"{label} must be a lowercase hyphenated token")


def _require_sha256(label: str, value: str) -> None:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise StateModelError(f"{label} must be a lowercase SHA-256 digest")


def _require_safe_integer(label: str, value: int, *, positive: bool = False) -> None:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= SAFE_INTEGER_MAX:
        qualifier = "positive " if positive else "non-negative "
        raise StateModelError(f"{label} must be a {qualifier}safe integer")


def _parse_timestamp(label: str, value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise StateModelError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise StateModelError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _normalized_field_name(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _string_contains_credentials(value: str) -> bool:
    if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
        return True
    if _AUTHORIZATION_VALUE.search(value) is not None:
        return True
    if "://" not in value:
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    if parsed.username is not None or parsed.password is not None:
        return True
    try:
        return any(_normalized_field_name(key) in _FORBIDDEN_QUERY_NAMES for key, _ in parse_qsl(parsed.query))
    except ValueError:
        return False


def _validate_json_tree(value: Any, *, field_name: str | None = None, seen: set[int] | None = None) -> None:
    if field_name is not None and _normalized_field_name(field_name) in _FORBIDDEN_FIELD_NAMES:
        raise SecretMaterialError("operational state cannot persist credential-bearing fields")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
            raise StateModelError("operational state integers must remain in the signed safe-integer domain")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StateModelError("operational state cannot contain non-finite numbers")
        return
    if isinstance(value, str):
        if _string_contains_credentials(value):
            raise SecretMaterialError("operational state cannot persist credential-bearing values")
        try:
            value.encode("utf-8", "strict")
        except UnicodeError as error:
            raise StateModelError("operational state strings must be valid Unicode scalar values") from error
        return
    if not isinstance(value, (dict, list, tuple)):
        raise StateModelError("operational state payloads must contain only JSON values")
    identity = id(value)
    current_seen = set() if seen is None else seen
    if identity in current_seen:
        raise StateModelError("operational state payloads cannot contain cycles")
    current_seen.add(identity)
    try:
        if isinstance(value, dict):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise StateModelError("operational state object keys must be strings")
                _validate_json_tree(item, field_name=key, seen=current_seen)
        else:
            for item in value:
                _validate_json_tree(item, seen=current_seen)
    finally:
        current_seen.remove(identity)


def canonical_json(value: Any) -> bytes:
    """Return JCS bytes after enforcing state-specific JSON and secret rules."""

    _validate_json_tree(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError, UnicodeError, ValueError) as error:
        raise StateModelError("operational state is not RFC 8785 canonicalizable") from error


def canonical_object(value: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(value, Mapping):
        raise StateModelError("operational state payload must be an object")
    materialized = dict(value)
    encoded = canonical_json(materialized)
    return encoded.decode("utf-8"), hashlib.sha256(encoded).hexdigest()


def parse_canonical_object(value: str) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise StateModelError("stored state JSON contains a duplicate object key")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            value,
            object_pairs_hook=unique_pairs,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                StateModelError(f"stored state JSON contains invalid constant {constant}")
            ),
        )
    except StateModelError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise StateModelError("stored state payload is not strict JSON") from error
    if not isinstance(parsed, dict):
        raise StateModelError("stored state payload must be a JSON object")
    encoded = canonical_json(parsed).decode("utf-8")
    if encoded != value:
        raise StateModelError("stored state payload is not in canonical JCS form")
    return parsed


def _validate_external_identifier(label: str, value: str) -> None:
    if not value or len(value) > 2048 or any(character in value for character in "\r\n\x00"):
        raise StateModelError(f"{label} must be a bounded single-line identifier")
    if _string_contains_credentials(value):
        raise SecretMaterialError(f"{label} cannot contain credentials")


@dataclass(frozen=True)
class StateSourceReference:
    source_kind: str
    source_id: str
    observed_at: str
    verified: bool

    def __post_init__(self) -> None:
        if self.source_kind not in SOURCE_KINDS:
            raise StateModelError("unknown operational state source kind")
        _validate_external_identifier("state source ID", self.source_id)
        _parse_timestamp("state source observation", self.observed_at)
        if not isinstance(self.verified, bool):
            raise StateModelError("state source verification must be boolean")

    @property
    def identity(self) -> tuple[str, str]:
        return (self.source_kind, self.source_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_at": self.observed_at,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "verified": self.verified,
        }


def _validate_sources(sources: tuple[StateSourceReference, ...], *, allow_empty: bool = False) -> None:
    if not sources and not allow_empty:
        raise StateModelError("operational records require at least one provenance source")
    if tuple(sorted(sources, key=lambda item: item.identity)) != sources:
        raise StateModelError("operational record sources must use deterministic identity order")
    identities = [item.identity for item in sources]
    if len(set(identities)) != len(identities):
        raise StateModelError("operational record sources must be unique by kind and ID")


@dataclass(frozen=True)
class OperationalStateRecord:
    record_kind: str
    record_id: str
    generation: int
    lifecycle_state: str
    verification_status: str
    payload_json: str
    payload_sha256: str
    updated_at: str
    sources: tuple[StateSourceReference, ...]
    tombstoned: bool = False
    canonical_authority: bool = False
    schema_version: str = "operational-state-record.v1"

    def __post_init__(self) -> None:
        if self.record_kind not in STATE_RECORD_KINDS:
            raise StateModelError("unknown operational state record kind")
        if RECORD_ID_PATTERN.fullmatch(self.record_id) is None:
            raise StateModelError("operational record ID contains unsupported characters")
        _require_safe_integer("operational record generation", self.generation, positive=True)
        _require_token("operational lifecycle state", self.lifecycle_state)
        if self.verification_status not in VERIFICATION_STATES:
            raise StateModelError("unknown operational verification status")
        payload = parse_canonical_object(self.payload_json)
        _require_sha256("operational payload digest", self.payload_sha256)
        if hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest() != self.payload_sha256:
            raise StateModelError("operational payload digest does not match the stored payload")
        _parse_timestamp("operational record update", self.updated_at)
        _validate_sources(self.sources)
        if self.verification_status == "verified" and (
            not all(item.verified for item in self.sources)
            or not any(item.source_kind != "local-operation" for item in self.sources)
        ):
            raise StateModelError("verified operational state requires verified external provenance")
        if not isinstance(self.tombstoned, bool):
            raise StateModelError("operational tombstone flag must be boolean")
        if self.tombstoned and (
            self.lifecycle_state != "absent"
            or self.verification_status != "verified"
            or payload
            or any(item.source_kind == "local-operation" for item in self.sources)
        ):
            raise StateModelError("operational tombstones must be verified absent records with an empty payload")
        if self.lifecycle_state == "quarantined" and self.verification_status != "quarantined":
            raise StateModelError("quarantined records require quarantined verification status")
        if self.verification_status == "quarantined" and self.lifecycle_state != "quarantined":
            raise StateModelError("quarantined verification status requires quarantined lifecycle state")
        if self.canonical_authority is not False:
            raise StateModelError("local operational state can never claim canonical authority")
        if self.schema_version != "operational-state-record.v1":
            raise StateModelError("unsupported operational state record schema")

    @classmethod
    def from_payload(
        cls,
        *,
        record_kind: str,
        record_id: str,
        generation: int,
        lifecycle_state: str,
        verification_status: str,
        payload: Mapping[str, Any],
        updated_at: str,
        sources: tuple[StateSourceReference, ...],
        tombstoned: bool = False,
    ) -> "OperationalStateRecord":
        payload_json, digest = canonical_object(payload)
        return cls(
            record_kind,
            record_id,
            generation,
            lifecycle_state,
            verification_status,
            payload_json,
            digest,
            updated_at,
            tuple(sorted(sources, key=lambda item: item.identity)),
            tombstoned,
        )

    @property
    def payload(self) -> dict[str, Any]:
        return parse_canonical_object(self.payload_json)

    @property
    def key(self) -> tuple[str, str]:
        return (self.record_kind, self.record_id)

    @property
    def integrity_digest(self) -> str:
        """Bind every serialized record field, not only its operational payload."""

        return hashlib.sha256(canonical_json(self.to_dict())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_authority": False,
            "generation": self.generation,
            "lifecycle_state": self.lifecycle_state,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "schema_version": self.schema_version,
            "sources": [item.to_dict() for item in self.sources],
            "tombstoned": self.tombstoned,
            "updated_at": self.updated_at,
            "verification_status": self.verification_status,
        }


@dataclass(frozen=True)
class StateMutation:
    record_kind: str
    record_id: str
    lifecycle_state: str
    verification_status: str
    payload_json: str
    payload_sha256: str
    sources: tuple[StateSourceReference, ...]
    expected_generation: int | None
    tombstoned: bool = False

    def __post_init__(self) -> None:
        if self.record_kind not in STATE_RECORD_KINDS or RECORD_ID_PATTERN.fullmatch(self.record_id) is None:
            raise StateModelError("state mutation has an invalid record key")
        _require_token("state mutation lifecycle", self.lifecycle_state)
        if self.verification_status not in VERIFICATION_STATES:
            raise StateModelError("state mutation has an invalid verification status")
        parse_canonical_object(self.payload_json)
        _require_sha256("state mutation payload digest", self.payload_sha256)
        if hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest() != self.payload_sha256:
            raise StateModelError("state mutation payload digest does not match")
        _validate_sources(self.sources)
        if self.verification_status == "verified" and (
            not all(item.verified for item in self.sources)
            or not any(item.source_kind != "local-operation" for item in self.sources)
        ):
            raise StateModelError("verified state mutations require verified external provenance")
        if self.expected_generation is not None:
            _require_safe_integer("expected state generation", self.expected_generation, positive=True)
        if self.tombstoned and (
            self.lifecycle_state != "absent"
            or self.verification_status != "verified"
            or self.payload_json != "{}"
            or any(item.source_kind == "local-operation" for item in self.sources)
        ):
            raise StateModelError("state mutation tombstones must be verified empty absent records")

    @classmethod
    def from_payload(
        cls,
        *,
        record_kind: str,
        record_id: str,
        lifecycle_state: str,
        verification_status: str,
        payload: Mapping[str, Any],
        sources: tuple[StateSourceReference, ...],
        expected_generation: int | None,
        tombstoned: bool = False,
    ) -> "StateMutation":
        payload_json, digest = canonical_object(payload)
        return cls(
            record_kind,
            record_id,
            lifecycle_state,
            verification_status,
            payload_json,
            digest,
            tuple(sorted(sources, key=lambda item: item.identity)),
            expected_generation,
            tombstoned,
        )

    @property
    def key(self) -> tuple[str, str]:
        return (self.record_kind, self.record_id)

    @property
    def payload(self) -> dict[str, Any]:
        return parse_canonical_object(self.payload_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_generation": self.expected_generation,
            "lifecycle_state": self.lifecycle_state,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "sources": [item.to_dict() for item in self.sources],
            "tombstoned": self.tombstoned,
            "verification_status": self.verification_status,
        }


@dataclass(frozen=True)
class StateSnapshot:
    store_id: str
    database_schema_version: int
    epoch: int
    admission_state: str
    prior_shutdown: str
    observed_at: str
    records: tuple[OperationalStateRecord, ...]
    snapshot_digest: str
    canonical_authority: bool = False
    schema_version: str = "local-operational-state.v1"

    def __post_init__(self) -> None:
        if OPERATIONAL_ID_PATTERN.fullmatch(self.store_id) is None:
            raise StateModelError("state store ID must be an operational UUIDv7")
        if not self.store_id.startswith("opid:v1:control-plane-state:u7:"):
            raise StateModelError("state store ID must use the control-plane-state namespace")
        _require_safe_integer("database schema version", self.database_schema_version, positive=True)
        _require_safe_integer("state store epoch", self.epoch)
        if self.admission_state not in ADMISSION_STATES:
            raise StateModelError("unknown state admission status")
        if self.prior_shutdown not in PRIOR_SHUTDOWN_STATES:
            raise StateModelError("unknown prior shutdown status")
        _parse_timestamp("state snapshot observation", self.observed_at)
        if tuple(sorted(self.records, key=lambda item: item.key)) != self.records:
            raise StateModelError("state snapshot records must use deterministic key order")
        keys = [item.key for item in self.records]
        if len(set(keys)) != len(keys):
            raise StateModelError("state snapshot records must have unique keys")
        _require_sha256("state snapshot digest", self.snapshot_digest)
        if self.snapshot_digest != self.calculate_digest(
            store_id=self.store_id,
            database_schema_version=self.database_schema_version,
            epoch=self.epoch,
            admission_state=self.admission_state,
            prior_shutdown=self.prior_shutdown,
            observed_at=self.observed_at,
            records=self.records,
        ):
            raise StateModelError("state snapshot digest does not match its contents")
        if self.canonical_authority is not False or self.schema_version != "local-operational-state.v1":
            raise StateModelError("unsupported or canonical-claiming state snapshot")

    @staticmethod
    def calculate_digest(
        *,
        store_id: str,
        database_schema_version: int,
        epoch: int,
        admission_state: str,
        prior_shutdown: str,
        observed_at: str,
        records: tuple[OperationalStateRecord, ...],
    ) -> str:
        payload = {
            "admission_state": admission_state,
            "canonical_authority": False,
            "database_schema_version": database_schema_version,
            "epoch": epoch,
            "prior_shutdown": prior_shutdown,
            "records": [item.to_dict() for item in records],
            "schema_version": "local-operational-state.v1",
            "store_id": store_id,
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    @classmethod
    def build(
        cls,
        *,
        store_id: str,
        database_schema_version: int,
        epoch: int,
        admission_state: str,
        prior_shutdown: str,
        observed_at: str,
        records: tuple[OperationalStateRecord, ...],
    ) -> "StateSnapshot":
        ordered = tuple(sorted(records, key=lambda item: item.key))
        digest = cls.calculate_digest(
            store_id=store_id,
            database_schema_version=database_schema_version,
            epoch=epoch,
            admission_state=admission_state,
            prior_shutdown=prior_shutdown,
            observed_at=observed_at,
            records=ordered,
        )
        return cls(
            store_id,
            database_schema_version,
            epoch,
            admission_state,
            prior_shutdown,
            observed_at,
            ordered,
            digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "admission_state": self.admission_state,
            "canonical_authority": False,
            "database_schema_version": self.database_schema_version,
            "epoch": self.epoch,
            "observed_at": self.observed_at,
            "prior_shutdown": self.prior_shutdown,
            "records": [item.to_dict() for item in self.records],
            "schema_version": self.schema_version,
            "snapshot_digest": self.snapshot_digest,
            "store_id": self.store_id,
        }


@dataclass(frozen=True)
class ReconciliationObservation:
    record_kind: str
    record_id: str
    exists: bool
    lifecycle_state: str | None
    payload_json: str
    payload_sha256: str
    observed_at: str
    source_kind: str
    source_id: str
    verified: bool

    def __post_init__(self) -> None:
        if self.record_kind not in STATE_RECORD_KINDS or RECORD_ID_PATTERN.fullmatch(self.record_id) is None:
            raise StateModelError("reconciliation observation has an invalid record key")
        if not isinstance(self.exists, bool) or not isinstance(self.verified, bool):
            raise StateModelError("reconciliation existence and verification must be boolean")
        payload = parse_canonical_object(self.payload_json)
        _require_sha256("reconciliation payload digest", self.payload_sha256)
        if hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest() != self.payload_sha256:
            raise StateModelError("reconciliation payload digest does not match")
        if self.exists:
            if self.lifecycle_state is None:
                raise StateModelError("present reconciliation observations require lifecycle state")
            _require_token("reconciliation lifecycle state", self.lifecycle_state)
        elif self.lifecycle_state is not None or payload:
            raise StateModelError("absent reconciliation observations require null state and empty payload")
        _parse_timestamp("reconciliation observation", self.observed_at)
        if self.source_kind not in RECONCILIATION_SOURCE_KINDS:
            raise StateModelError("reconciliation observations require an external reality or authority source")
        _validate_external_identifier("reconciliation source ID", self.source_id)

    @classmethod
    def present(
        cls,
        *,
        record_kind: str,
        record_id: str,
        lifecycle_state: str,
        payload: Mapping[str, Any],
        observed_at: str,
        source_kind: str,
        source_id: str,
        verified: bool = True,
    ) -> "ReconciliationObservation":
        payload_json, digest = canonical_object(payload)
        return cls(
            record_kind,
            record_id,
            True,
            lifecycle_state,
            payload_json,
            digest,
            observed_at,
            source_kind,
            source_id,
            verified,
        )

    @classmethod
    def absent(
        cls,
        *,
        record_kind: str,
        record_id: str,
        observed_at: str,
        source_kind: str,
        source_id: str,
        verified: bool = True,
    ) -> "ReconciliationObservation":
        payload_json, digest = canonical_object({})
        return cls(
            record_kind,
            record_id,
            False,
            None,
            payload_json,
            digest,
            observed_at,
            source_kind,
            source_id,
            verified,
        )

    @property
    def key(self) -> tuple[str, str]:
        return (self.record_kind, self.record_id)

    @property
    def source_identity(self) -> tuple[str, str]:
        return (self.source_kind, self.source_id)

    @property
    def payload(self) -> dict[str, Any]:
        return parse_canonical_object(self.payload_json)

    @property
    def state_signature(self) -> tuple[bool, str | None, str]:
        return (self.exists, self.lifecycle_state, self.payload_sha256)

    def source_reference(self) -> StateSourceReference:
        return StateSourceReference(self.source_kind, self.source_id, self.observed_at, self.verified)

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_authority": False,
            "exists": self.exists,
            "lifecycle_state": self.lifecycle_state,
            "observed_at": self.observed_at,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class ReconciliationIssue:
    record_kind: str
    record_id: str
    code: str
    detail: str
    blocking: bool = True

    def __post_init__(self) -> None:
        if self.record_kind not in STATE_RECORD_KINDS or RECORD_ID_PATTERN.fullmatch(self.record_id) is None:
            raise StateModelError("reconciliation issue has an invalid record key")
        _require_token("reconciliation issue code", self.code)
        if not self.detail or len(self.detail) > 512 or any(character in self.detail for character in "\r\n\x00"):
            raise StateModelError("reconciliation issue detail must be bounded single-line text")
        if _string_contains_credentials(self.detail):
            raise SecretMaterialError("reconciliation issue detail cannot contain credentials")
        if not isinstance(self.blocking, bool):
            raise StateModelError("reconciliation issue blocking flag must be boolean")

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.record_kind, self.record_id, self.code)

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocking": self.blocking,
            "code": self.code,
            "detail": self.detail,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
        }


@dataclass(frozen=True)
class ReconciliationAction:
    action: str
    reason_code: str
    record_kind: str
    record_id: str
    expected_generation: int | None
    lifecycle_state: str
    verification_status: str
    payload_json: str
    payload_sha256: str
    sources: tuple[StateSourceReference, ...]
    tombstoned: bool

    def __post_init__(self) -> None:
        if self.action not in {"create", "quarantine", "replace", "tombstone", "verify"}:
            raise StateModelError("unknown reconciliation action")
        _require_token("reconciliation action reason", self.reason_code)
        mutation = self.to_mutation()
        if self.action == "create" and mutation.expected_generation is not None:
            raise StateModelError("reconciliation create action cannot expect an existing generation")
        if self.action != "create" and mutation.expected_generation is None:
            raise StateModelError("reconciliation update action requires an expected generation")
        if self.action != "quarantine" and (
            not all(item.verified for item in self.sources)
            or any(item.source_kind == "local-operation" for item in self.sources)
        ):
            raise StateModelError("reconciliation actions require verified external sources")

    @property
    def key(self) -> tuple[str, str]:
        return (self.record_kind, self.record_id)

    @property
    def payload(self) -> dict[str, Any]:
        return parse_canonical_object(self.payload_json)

    def to_mutation(self) -> StateMutation:
        return StateMutation(
            self.record_kind,
            self.record_id,
            self.lifecycle_state,
            self.verification_status,
            self.payload_json,
            self.payload_sha256,
            self.sources,
            self.expected_generation,
            self.tombstoned,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "expected_generation": self.expected_generation,
            "lifecycle_state": self.lifecycle_state,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256,
            "reason_code": self.reason_code,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "sources": [item.to_dict() for item in self.sources],
            "tombstoned": self.tombstoned,
            "verification_status": self.verification_status,
        }


@dataclass(frozen=True)
class ReconciliationPlan:
    plan_id: str
    snapshot_digest: str
    observation_digest: str
    planned_at: str
    maximum_observation_age_seconds: int
    actions: tuple[ReconciliationAction, ...]
    issues: tuple[ReconciliationIssue, ...]
    ready_after_apply: bool
    plan_digest: str
    canonical_authority: bool = False
    schema_version: str = "state-reconciliation-plan.v1"

    def __post_init__(self) -> None:
        if OPERATIONAL_ID_PATTERN.fullmatch(self.plan_id) is None:
            raise StateModelError("reconciliation plan ID must be an operational UUIDv7")
        if not self.plan_id.startswith("opid:v1:state-reconciliation:u7:"):
            raise StateModelError("reconciliation plan ID must use the state-reconciliation namespace")
        _require_sha256("reconciliation snapshot digest", self.snapshot_digest)
        _require_sha256("reconciliation observation digest", self.observation_digest)
        _parse_timestamp("reconciliation plan time", self.planned_at)
        _require_safe_integer(
            "maximum reconciliation observation age", self.maximum_observation_age_seconds, positive=True
        )
        if tuple(sorted(self.actions, key=lambda item: item.key)) != self.actions:
            raise StateModelError("reconciliation actions must use deterministic key order")
        if len({item.key for item in self.actions}) != len(self.actions):
            raise StateModelError("reconciliation plan may mutate each key at most once")
        if tuple(sorted(self.issues, key=lambda item: item.key)) != self.issues:
            raise StateModelError("reconciliation issues must use deterministic order")
        if self.ready_after_apply and any(item.blocking for item in self.issues):
            raise StateModelError("reconciliation plan cannot claim readiness with blocking issues")
        _require_sha256("reconciliation plan digest", self.plan_digest)
        if self.plan_digest != self.calculate_digest(
            plan_id=self.plan_id,
            snapshot_digest=self.snapshot_digest,
            observation_digest=self.observation_digest,
            planned_at=self.planned_at,
            maximum_observation_age_seconds=self.maximum_observation_age_seconds,
            actions=self.actions,
            issues=self.issues,
            ready_after_apply=self.ready_after_apply,
        ):
            raise StateModelError("reconciliation plan digest does not match its contents")
        if self.canonical_authority is not False or self.schema_version != "state-reconciliation-plan.v1":
            raise StateModelError("unsupported or canonical-claiming reconciliation plan")

    @staticmethod
    def calculate_digest(**values: Any) -> str:
        payload = {
            "actions": [item.to_dict() for item in values["actions"]],
            "canonical_authority": False,
            "issues": [item.to_dict() for item in values["issues"]],
            "maximum_observation_age_seconds": values["maximum_observation_age_seconds"],
            "observation_digest": values["observation_digest"],
            "plan_id": values["plan_id"],
            "planned_at": values["planned_at"],
            "ready_after_apply": values["ready_after_apply"],
            "schema_version": "state-reconciliation-plan.v1",
            "snapshot_digest": values["snapshot_digest"],
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    @classmethod
    def build(cls, **values: Any) -> "ReconciliationPlan":
        actions = tuple(sorted(values["actions"], key=lambda item: item.key))
        issues = tuple(sorted(values["issues"], key=lambda item: item.key))
        digest = cls.calculate_digest(
            plan_id=values["plan_id"],
            snapshot_digest=values["snapshot_digest"],
            observation_digest=values["observation_digest"],
            planned_at=values["planned_at"],
            maximum_observation_age_seconds=values["maximum_observation_age_seconds"],
            actions=actions,
            issues=issues,
            ready_after_apply=values["ready_after_apply"],
        )
        return cls(
            values["plan_id"],
            values["snapshot_digest"],
            values["observation_digest"],
            values["planned_at"],
            values["maximum_observation_age_seconds"],
            actions,
            issues,
            values["ready_after_apply"],
            digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "actions": [item.to_dict() for item in self.actions],
            "canonical_authority": False,
            "issues": [item.to_dict() for item in self.issues],
            "maximum_observation_age_seconds": self.maximum_observation_age_seconds,
            "observation_digest": self.observation_digest,
            "plan_digest": self.plan_digest,
            "plan_id": self.plan_id,
            "planned_at": self.planned_at,
            "ready_after_apply": self.ready_after_apply,
            "schema_version": self.schema_version,
            "snapshot_digest": self.snapshot_digest,
        }


@dataclass(frozen=True)
class ReconciliationActionResult:
    action: str
    record_kind: str
    record_id: str
    resulting_generation: int
    code: str

    def __post_init__(self) -> None:
        if self.action not in {"create", "quarantine", "replace", "tombstone", "verify"}:
            raise StateModelError("unknown reconciliation result action")
        if self.record_kind not in STATE_RECORD_KINDS or RECORD_ID_PATTERN.fullmatch(self.record_id) is None:
            raise StateModelError("reconciliation result has invalid record key")
        _require_safe_integer("reconciliation result generation", self.resulting_generation, positive=True)
        _require_token("reconciliation result code", self.code)

    @property
    def key(self) -> tuple[str, str]:
        return (self.record_kind, self.record_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "code": self.code,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "resulting_generation": self.resulting_generation,
        }


@dataclass(frozen=True)
class ReconciliationReport:
    plan_id: str
    plan_digest: str
    before_snapshot_digest: str
    after_snapshot_digest: str
    completed_at: str
    status: str
    action_results: tuple[ReconciliationActionResult, ...]
    issues: tuple[ReconciliationIssue, ...]
    report_digest: str
    canonical_authority: bool = False
    schema_version: str = "state-reconciliation-report.v1"

    def __post_init__(self) -> None:
        if OPERATIONAL_ID_PATTERN.fullmatch(self.plan_id) is None:
            raise StateModelError("reconciliation report plan ID must be an operational UUIDv7")
        if not self.plan_id.startswith("opid:v1:state-reconciliation:u7:"):
            raise StateModelError("reconciliation report must identify a state-reconciliation plan")
        for label, value in (
            ("plan", self.plan_digest),
            ("before snapshot", self.before_snapshot_digest),
            ("after snapshot", self.after_snapshot_digest),
            ("report", self.report_digest),
        ):
            _require_sha256(f"reconciliation {label} digest", value)
        _parse_timestamp("reconciliation completion", self.completed_at)
        if self.status not in {"blocked", "ready"}:
            raise StateModelError("unknown reconciliation report status")
        if tuple(sorted(self.action_results, key=lambda item: item.key)) != self.action_results:
            raise StateModelError("reconciliation results must use deterministic order")
        if tuple(sorted(self.issues, key=lambda item: item.key)) != self.issues:
            raise StateModelError("reconciliation report issues must use deterministic order")
        if self.status == "ready" and any(item.blocking for item in self.issues):
            raise StateModelError("ready reconciliation report cannot contain blocking issues")
        if self.report_digest != self.calculate_digest(
            plan_id=self.plan_id,
            plan_digest=self.plan_digest,
            before_snapshot_digest=self.before_snapshot_digest,
            after_snapshot_digest=self.after_snapshot_digest,
            completed_at=self.completed_at,
            status=self.status,
            action_results=self.action_results,
            issues=self.issues,
        ):
            raise StateModelError("reconciliation report digest does not match its contents")
        if self.canonical_authority is not False or self.schema_version != "state-reconciliation-report.v1":
            raise StateModelError("unsupported or canonical-claiming reconciliation report")

    @staticmethod
    def calculate_digest(**values: Any) -> str:
        payload = {
            "action_results": [item.to_dict() for item in values["action_results"]],
            "after_snapshot_digest": values["after_snapshot_digest"],
            "before_snapshot_digest": values["before_snapshot_digest"],
            "canonical_authority": False,
            "completed_at": values["completed_at"],
            "issues": [item.to_dict() for item in values["issues"]],
            "plan_digest": values["plan_digest"],
            "plan_id": values["plan_id"],
            "schema_version": "state-reconciliation-report.v1",
            "status": values["status"],
        }
        return hashlib.sha256(canonical_json(payload)).hexdigest()

    @classmethod
    def build(cls, **values: Any) -> "ReconciliationReport":
        results = tuple(sorted(values["action_results"], key=lambda item: item.key))
        issues = tuple(sorted(values["issues"], key=lambda item: item.key))
        digest = cls.calculate_digest(
            plan_id=values["plan_id"],
            plan_digest=values["plan_digest"],
            before_snapshot_digest=values["before_snapshot_digest"],
            after_snapshot_digest=values["after_snapshot_digest"],
            completed_at=values["completed_at"],
            status=values["status"],
            action_results=results,
            issues=issues,
        )
        return cls(
            values["plan_id"],
            values["plan_digest"],
            values["before_snapshot_digest"],
            values["after_snapshot_digest"],
            values["completed_at"],
            values["status"],
            results,
            issues,
            digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_results": [item.to_dict() for item in self.action_results],
            "after_snapshot_digest": self.after_snapshot_digest,
            "before_snapshot_digest": self.before_snapshot_digest,
            "canonical_authority": False,
            "completed_at": self.completed_at,
            "issues": [item.to_dict() for item in self.issues],
            "plan_digest": self.plan_digest,
            "plan_id": self.plan_id,
            "report_digest": self.report_digest,
            "schema_version": self.schema_version,
            "status": self.status,
        }
