"""Typed identifier validation and deterministic content identity."""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import fail
from .formats import OPID_PATTERN, RCID_PATTERN
from .jsonio import canonical_bytes, load_strict
from .profile import IdentityProfile

HASH_POLICY = "jcs-sha256-v1"
CONTENT_DOMAIN = "strling.regex-conformance.content-id"


@dataclass(frozen=True)
class ParsedIdentifier:
    scheme: str
    namespace: str
    mode: str
    payload: str


@dataclass(frozen=True)
class NamespaceRegistry:
    record: dict[str, Any]

    @classmethod
    def load(cls, path: Path | str) -> "NamespaceRegistry":
        return cls(load_strict(path))

    def permits(self, scheme: str, mode: str, namespace: str) -> bool:
        return namespace in self.record.get(scheme, {}).get(mode, [])

    def validate(self, identifier: str) -> ParsedIdentifier:
        parsed = parse_identifier(identifier)
        if not self.permits(parsed.scheme, parsed.mode, parsed.namespace):
            fail("unregistered-namespace", f"{parsed.scheme}/{parsed.mode}/{parsed.namespace} is not registered")
        if parsed.mode == "h":
            policy, _, _digest = parsed.payload.partition(":")
            if policy not in self.record["hash_policies"]:
                fail("unregistered-hash-policy", f"hash policy {policy!r} is not registered")
        return parsed


def parse_identifier(identifier: str) -> ParsedIdentifier:
    rcid = RCID_PATTERN.fullmatch(identifier)
    if rcid:
        mode = "u7" if rcid.group("u7") else "h"
        payload = rcid.group("uuid") if mode == "u7" else f"{rcid.group('policy')}:{rcid.group('digest')}"
        if mode == "u7":
            _validate_uuid7(payload)
        return ParsedIdentifier("rcid", rcid.group("namespace"), mode, payload)
    opid = OPID_PATTERN.fullmatch(identifier)
    if opid:
        _validate_uuid7(opid.group("uuid"))
        return ParsedIdentifier("opid", opid.group("namespace"), "u7", opid.group("uuid"))
    fail("invalid-identifier", "identifier does not match a supported typed-ID grammar")


def _validate_uuid7(value: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        fail("invalid-uuid", str(error))
    if str(parsed) != value or parsed.version != 7 or parsed.variant != uuid.RFC_4122:
        fail("invalid-uuid7", "assigned identifiers require canonical RFC-variant UUIDv7")


def uuid7(*, timestamp_ms: int | None = None) -> uuid.UUID:
    """Generate an RFC 9562 UUIDv7 without depending on a future stdlib API."""

    stamp = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    if not 0 <= stamp < 2**48:
        fail("invalid-uuid7-time", "UUIDv7 timestamp must fit in 48 bits")
    random_a = secrets.randbits(12)
    random_b = secrets.randbits(62)
    integer = (stamp << 80) | (0x7 << 76) | (random_a << 64) | (0b10 << 62) | random_b
    return uuid.UUID(int=integer)


def generate_assigned_id(registry: NamespaceRegistry, scheme: str, namespace: str) -> str:
    if scheme not in {"rcid", "opid"}:
        fail("invalid-id-scheme", "assigned identifier scheme must be rcid or opid")
    if not registry.permits(scheme, "u7", namespace):
        fail("unregistered-namespace", f"{scheme}/u7/{namespace} is not registered")
    return f"{scheme}:v1:{namespace}:u7:{uuid7()}"


def content_envelope(
    *,
    namespace: str,
    identity_schema_family_id: str,
    identity_schema_version: str,
    identity: Any,
) -> dict[str, Any]:
    return {
        "domain": CONTENT_DOMAIN,
        "hash_policy": HASH_POLICY,
        "namespace": namespace,
        "identity_schema_family_id": identity_schema_family_id,
        "identity_schema_version": identity_schema_version,
        "identity": identity,
    }


def build_content_identity(
    *,
    registry: NamespaceRegistry,
    profile: IdentityProfile,
    namespace: str,
    identity_schema_family_id: str,
    identity_schema_version: str,
    identity: Any,
) -> dict[str, Any]:
    if not registry.permits("rcid", "h", namespace):
        fail("unregistered-namespace", f"rcid/h/{namespace} is not registered")
    family = registry.validate(identity_schema_family_id)
    if (family.scheme, family.namespace, family.mode) != ("rcid", "schema-family", "u7"):
        fail("invalid-schema-family-id", "identity schema family must be an assigned schema-family rcid")
    if identity_schema_version != profile.profile_version:
        fail("profile-version-mismatch", "identity schema version does not match the loaded profile")
    projection = profile.project(identity)
    envelope = content_envelope(
        namespace=namespace,
        identity_schema_family_id=identity_schema_family_id,
        identity_schema_version=identity_schema_version,
        identity=projection,
    )
    encoded = canonical_bytes(envelope)
    digest = hashlib.sha256(encoded).hexdigest()
    content_id = f"rcid:v1:{namespace}:h:{HASH_POLICY}:{digest}"
    registry.validate(content_id)
    return {
        "projection": projection,
        "envelope": envelope,
        "canonical_utf8": encoded,
        "canonical_byte_length": len(encoded),
        "sha256": digest,
        "content_id": content_id,
    }


@dataclass
class CollisionGuard:
    """Quarantine the impossible-but-governed digest collision condition."""

    observations: dict[str, bytes] = field(default_factory=dict)
    quarantined: set[str] = field(default_factory=set)

    def observe(self, content_id: str, canonical: bytes) -> None:
        previous = self.observations.get(content_id)
        if previous is not None and previous != canonical:
            self.quarantined.add(content_id)
            fail("digest-collision", "same content ID observed with different canonical bytes")
        self.observations[content_id] = canonical
