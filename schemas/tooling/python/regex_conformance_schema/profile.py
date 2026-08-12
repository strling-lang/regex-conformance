"""Typed identity projection with explicit canonicalization semantics."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import re
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Any

from .errors import fail
from .formats import DIGEST_PATTERN, RCID_PATTERN, SEMVER_PATTERN, TOKEN_PATTERN
from .jsonio import canonical_bytes

SAFE_INTEGER_LIMIT = 9_007_199_254_740_991
EXACT_DECIMAL_PATTERN = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]*$")


@dataclass(frozen=True)
class IdentityProfile:
    profile_version: str
    root: dict[str, Any]

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "IdentityProfile":
        return cls(profile_version=record["profile_version"], root=record["root"])

    def project(self, value: Any) -> Any:
        return _project(self.root, value, "$")


def _project(node: dict[str, Any], value: Any, path: str) -> Any:
    kind = node["kind"]
    if kind == "object":
        return _project_object(node, value, path)
    if kind in {"sequence", "set"}:
        return _project_collection(node, value, path)
    if kind == "enum":
        if not isinstance(value, str) or value not in node["values"]:
            fail("invalid-enum", f"expected one of {node['values']!r}", path)
        return value
    if kind == "utc_instant":
        return _project_instant(value, node["precision"], path)
    if kind == "uuid":
        return _project_uuid(value, node.get("version"), path)
    return _project_scalar(kind, value, path)


def _project_object(node: dict[str, Any], value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("wrong-type", "expected object", path)
    properties = node["properties"]
    unknown = sorted(set(value) - set(properties))
    if unknown:
        fail("unknown-field", f"unknown fields: {', '.join(unknown)}", path)
    missing = sorted(set(node["required"]) - set(value))
    if missing:
        fail("missing-field", f"missing required fields: {', '.join(missing)}", path)
    return {
        key: _project(properties[key], value[key], f"{path}.{key}")
        for key in properties
        if key in value
    }


def _project_collection(node: dict[str, Any], value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        fail("wrong-type", "expected array", path)
    members = [_project(node["items"], member, f"{path}[{index}]") for index, member in enumerate(value)]
    if node["kind"] == "sequence":
        return members
    keyed = {canonical_bytes(member): member for member in members}
    return [keyed[key] for key in sorted(keyed)]


def _project_scalar(kind: str, value: Any, path: str) -> Any:
    if kind in {"raw_text", "canonical_text", "token", "exact_decimal", "date", "base64url", "semver", "rcid", "digest"}:
        if not isinstance(value, str):
            fail("wrong-type", "expected string", path)
    if kind == "raw_text":
        return value
    if kind == "canonical_text":
        return unicodedata.normalize("NFC", value)
    if kind == "token":
        if TOKEN_PATTERN.fullmatch(value) is None:
            fail("invalid-token", "expected lowercase canonical token", path)
        return value
    if kind == "safe_integer":
        if isinstance(value, bool) or not isinstance(value, int):
            fail("wrong-type", "expected integer", path)
        if not -SAFE_INTEGER_LIMIT <= value <= SAFE_INTEGER_LIMIT:
            fail("unsafe-integer", "integer exceeds the interoperable safe range", path)
        return value
    if kind == "exact_decimal":
        if EXACT_DECIMAL_PATTERN.fullmatch(value) is None or value in {"-0", "-0.0"}:
            fail("noncanonical-decimal", "expected a non-exponent decimal without redundant zeros", path)
        return value
    if kind == "date":
        if DATE_PATTERN.fullmatch(value) is None:
            fail("invalid-date", "expected YYYY-MM-DD", path)
        try:
            if dt.date.fromisoformat(value).isoformat() != value:
                raise ValueError
        except ValueError:
            fail("invalid-date", "calendar date is invalid", path)
        return value
    if kind == "base64url":
        if "=" in value or BASE64URL_PATTERN.fullmatch(value) is None:
            fail("noncanonical-base64url", "expected unpadded base64url", path)
        try:
            decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (binascii.Error, ValueError) as error:
            fail("noncanonical-base64url", str(error), path)
        if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
            fail("noncanonical-base64url", "encoding is not canonical", path)
        return value
    if kind == "boolean":
        if not isinstance(value, bool):
            fail("wrong-type", "expected boolean", path)
        return value
    if kind == "null":
        if value is not None:
            fail("wrong-type", "expected null", path)
        return value
    if kind == "semver":
        if SEMVER_PATTERN.fullmatch(value) is None:
            fail("invalid-semver", "expected canonical MAJOR.MINOR.PATCH", path)
        return value
    if kind == "rcid":
        if RCID_PATTERN.fullmatch(value) is None:
            fail("invalid-rcid", "expected a syntactically valid rcid:v1 identifier", path)
        return value
    if kind == "digest":
        if DIGEST_PATTERN.fullmatch(value) is None:
            fail("invalid-digest", "expected lowercase SHA-256 digest", path)
        return value
    fail("unknown-profile-kind", f"unsupported profile kind {kind!r}", path)


def _project_instant(value: Any, precision: int, path: str) -> str:
    if not isinstance(value, str):
        fail("wrong-type", "expected string", path)
    fraction = "" if precision == 0 else rf"\.[0-9]{{{precision}}}"
    pattern = re.compile(rf"^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}T[0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}{fraction}Z$")
    if pattern.fullmatch(value) is None:
        fail("noncanonical-instant", f"expected UTC Z timestamp with precision {precision}", path)
    try:
        dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        fail("invalid-instant", "timestamp is not a valid calendar instant", path)
    return value


def _project_uuid(value: Any, expected_version: int | None, path: str) -> str:
    if not isinstance(value, str) or value != value.lower():
        fail("noncanonical-uuid", "expected lowercase UUID text", path)
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        fail("invalid-uuid", str(error), path)
    if str(parsed) != value:
        fail("noncanonical-uuid", "expected canonical hyphenated UUID text", path)
    if parsed.variant != uuid.RFC_4122:
        fail("invalid-uuid", "expected RFC 4122 variant", path)
    if expected_version is not None and parsed.version != expected_version:
        fail("wrong-uuid-version", f"expected UUIDv{expected_version}", path)
    return value
