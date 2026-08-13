"""Exact request materialization and native-preserving response helpers."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import re
from typing import Any, Iterable

from .errors import AdapterError

TOKEN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
CORRELATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MANIFEST_ID = re.compile(r"^rcid:v1:adapter-release-manifest:h:jcs-sha256-v1:[0-9a-f]{64}$")
PROFILE_ID = re.compile(r"^rcid:v1:profile:u7:[0-9a-f-]{36}$")
RELEASE_ID = re.compile(r"^rcid:v1:release:u7:[0-9a-f-]{36}$")
OPERATIONS = frozenset(
    {
        "callback-replacement",
        "capture-extraction",
        "compile",
        "find-all",
        "full-match",
        "next-match",
        "replace-all",
        "replace-once",
        "search",
        "split",
        "test",
    }
)
OBSERVATIONS = frozenset(
    {
        "capture-history",
        "captures",
        "compile-diagnostics",
        "cursor",
        "match-state",
        "native-errors",
        "replacement-output",
        "runtime-identity",
        "spans",
        "split-output",
    }
)
ABSENCE_REASONS = frozenset(
    {
        "indeterminate",
        "not-applicable",
        "not-exposed",
        "not-requested",
        "prior-layer-failure",
        "redacted",
        "truncated",
        "unsupported",
    }
)


def exact_object(value: Any, fields: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterError("wrong-type", f"{label} must be an object")
    expected = frozenset(fields)
    actual = frozenset(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise AdapterError(
            "object-shape-invalid",
            f"{label} fields differ; missing={missing!r}, unknown={unknown!r}",
        )
    return value


def require_string(value: Any, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AdapterError("string-invalid", f"{label} must be a bounded non-empty string")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise AdapterError("invalid-unicode-scalar", f"{label} contains an isolated surrogate") from error
    return value


def require_token(value: Any, label: str) -> str:
    text = require_string(value, label, maximum=96)
    if TOKEN.fullmatch(text) is None:
        raise AdapterError("token-invalid", f"{label} must be a lowercase canonical token")
    return text


def require_integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AdapterError("integer-invalid", f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def sorted_unique_strings(value: Any, label: str, *, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AdapterError("list-invalid", f"{label} must be an array of strings")
    result = tuple(value)
    if result != tuple(sorted(result)) or len(result) != len(set(result)):
        raise AdapterError("list-order-invalid", f"{label} must use unique deterministic lexical order")
    if allowed is not None and any(item not in allowed for item in result):
        raise AdapterError("list-member-invalid", f"{label} contains an unsupported value")
    return result


@dataclass(frozen=True)
class Datum:
    domain: str
    value: bytes | str | tuple[int, ...]
    encoding: str | None
    endianness: str | None
    unit_width_bits: int | None

    @classmethod
    def from_record(cls, value: Any, label: str) -> "Datum":
        if not isinstance(value, dict) or not isinstance(value.get("domain"), str):
            raise AdapterError("datum-invalid", f"{label} must be a typed datum object")
        domain = value["domain"]
        if domain == "octets":
            exact_object(value, {"data", "domain", "encoding", "endianness", "unit_width_bits"}, label)
            if value["encoding"] is not None or value["endianness"] is not None or value["unit_width_bits"] != 8:
                raise AdapterError("datum-metadata-invalid", f"{label} octet metadata is inconsistent")
            encoded = value["data"]
            if not isinstance(encoded, str) or "=" in encoded or re.fullmatch(r"[A-Za-z0-9_-]*", encoded) is None:
                raise AdapterError("base64url-invalid", f"{label} octets require canonical unpadded base64url")
            try:
                decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            except (binascii.Error, ValueError) as error:
                raise AdapterError("base64url-invalid", f"{label} base64url is malformed") from error
            if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != encoded:
                raise AdapterError("base64url-invalid", f"{label} base64url is noncanonical")
            return cls(domain, decoded, None, None, 8)
        if domain == "unicode-scalars":
            exact_object(value, {"domain", "encoding", "endianness", "text", "unit_width_bits"}, label)
            text = value["text"]
            if not isinstance(text, str) or len(text) > 4_194_304:
                raise AdapterError("datum-text-invalid", f"{label} scalar text is invalid or too large")
            try:
                text.encode("utf-8", "strict")
            except UnicodeEncodeError as error:
                raise AdapterError("invalid-unicode-scalar", f"{label} contains an isolated surrogate") from error
            if (
                value["encoding"] != "unicode-scalar-values"
                or value["endianness"] is not None
                or value["unit_width_bits"] is not None
            ):
                raise AdapterError("datum-metadata-invalid", f"{label} scalar metadata is inconsistent")
            return cls(domain, text, "unicode-scalar-values", None, None)
        if domain == "code-units":
            exact_object(value, {"domain", "encoding", "endianness", "unit_width_bits", "units"}, label)
            width = value["unit_width_bits"]
            encoding = value["encoding"]
            endianness = value["endianness"]
            units = value["units"]
            if (width, encoding) not in {(16, "utf-16"), (32, "utf-32")} or endianness not in {"big", "little"}:
                raise AdapterError("datum-metadata-invalid", f"{label} code-unit metadata is inconsistent")
            if not isinstance(units, list) or len(units) > 4_194_304:
                raise AdapterError("datum-units-invalid", f"{label} code-unit array is invalid or too large")
            maximum = (1 << width) - 1
            result = tuple(require_integer(item, f"{label} unit", 0, maximum) for item in units)
            return cls(domain, result, encoding, endianness, width)
        raise AdapterError("datum-domain-unknown", f"{label} uses an unknown data domain")

    def to_record(self) -> dict[str, Any]:
        if self.domain == "octets":
            assert isinstance(self.value, bytes)
            return {
                "data": base64.urlsafe_b64encode(self.value).decode("ascii").rstrip("="),
                "domain": "octets",
                "encoding": None,
                "endianness": None,
                "unit_width_bits": 8,
            }
        if self.domain == "unicode-scalars":
            assert isinstance(self.value, str)
            return {
                "domain": "unicode-scalars",
                "encoding": "unicode-scalar-values",
                "endianness": None,
                "text": self.value,
                "unit_width_bits": None,
            }
        assert isinstance(self.value, tuple)
        return {
            "domain": "code-units",
            "encoding": self.encoding,
            "endianness": self.endianness,
            "unit_width_bits": self.unit_width_bits,
            "units": list(self.value),
        }


def _named_values(value: Any, label: str) -> tuple[tuple[str, Any], ...]:
    if not isinstance(value, list) or len(value) > 64:
        raise AdapterError("named-values-invalid", f"{label} must be a bounded array")
    result: list[tuple[str, Any]] = []
    for index, item in enumerate(value):
        record = exact_object(item, {"name", "value"}, f"{label}[{index}]")
        name = require_token(record["name"], f"{label}[{index}].name")
        member = record["value"]
        if isinstance(member, float) or not isinstance(member, (bool, int, str, type(None))):
            raise AdapterError("named-value-type-invalid", f"{label}[{index}].value has an unsupported type")
        if isinstance(member, int) and not isinstance(member, bool):
            require_integer(member, f"{label}[{index}].value", -9_007_199_254_740_991, 9_007_199_254_740_991)
        if isinstance(member, str) and len(member) > 4096:
            raise AdapterError("named-value-size-invalid", f"{label}[{index}].value is too large")
        result.append((name, member))
    if tuple(name for name, _ in result) != tuple(sorted(name for name, _ in result)):
        raise AdapterError("named-value-order-invalid", f"{label} must use deterministic name order")
    if len({name for name, _ in result}) != len(result):
        raise AdapterError("named-value-collision", f"{label} contains duplicate names")
    return tuple(result)


@dataclass(frozen=True)
class ExecuteRequest:
    correlation_id: str
    adapter_release_manifest_id: str
    profile_id: str
    target_release_id: str
    operation: str
    pattern: Datum
    subjects: tuple[Datum, ...]
    replacement: Datum | None
    callback_fixture: dict[str, Any] | None
    options: tuple[tuple[str, Any], ...]
    environment_inputs: tuple[tuple[str, Any], ...]
    start_offset: int
    occurrence: int
    requested_observations: tuple[str, ...]
    maximum_matches: int
    maximum_diagnostic_bytes: int
    maximum_output_bytes: int
    wall_time_ms: int
    trace_reference: str | None

    @classmethod
    def from_record(cls, value: Any) -> "ExecuteRequest":
        fields = {
            "adapter_release_manifest_id", "callback_fixture", "correlation_id", "environment_inputs",
            "initial_state", "limits", "message_type", "operation", "options", "pattern", "profile_id",
            "replacement", "requested_observations", "schema_version", "subjects", "target_release_id",
            "trace_reference",
        }
        record = exact_object(value, fields, "execute request")
        if record["schema_version"] != "adapter-request.v1" or record["message_type"] != "execute":
            raise AdapterError("request-version-invalid", "execute request schema/message version is unsupported")
        correlation = record["correlation_id"]
        if not isinstance(correlation, str) or CORRELATION.fullmatch(correlation) is None:
            raise AdapterError("correlation-invalid", "execute correlation ID is invalid")
        manifest_id = record["adapter_release_manifest_id"]
        if not isinstance(manifest_id, str) or MANIFEST_ID.fullmatch(manifest_id) is None:
            raise AdapterError("manifest-id-invalid", "execute request adapter manifest ID is invalid")
        profile = record["profile_id"]
        release = record["target_release_id"]
        if not isinstance(profile, str) or PROFILE_ID.fullmatch(profile) is None:
            raise AdapterError("profile-id-invalid", "execute request profile ID is invalid")
        if not isinstance(release, str) or RELEASE_ID.fullmatch(release) is None:
            raise AdapterError("release-id-invalid", "execute request release ID is invalid")
        operation = exact_object(record["operation"], {"name", "version"}, "operation")
        if operation["version"] != "1.0.0" or operation["name"] not in OPERATIONS:
            raise AdapterError("operation-invalid", "operation name/version is unsupported by protocol v1")
        subjects_value = record["subjects"]
        if not isinstance(subjects_value, list) or not 1 <= len(subjects_value) <= 16:
            raise AdapterError("subjects-invalid", "execute request requires one to sixteen subjects")
        replacement = None if record["replacement"] is None else Datum.from_record(record["replacement"], "replacement")
        callback = record["callback_fixture"]
        if callback is not None:
            callback = exact_object(callback, {"fixture_id", "parameters"}, "callback fixture")
            require_token(callback["fixture_id"], "callback fixture ID")
            _named_values(callback["parameters"], "callback parameters")
        replacement_operations = {"replace-all", "replace-once"}
        if operation["name"] in replacement_operations and replacement is None:
            raise AdapterError("replacement-missing", "replacement operation requires typed replacement data")
        if operation["name"] not in replacement_operations and replacement is not None:
            raise AdapterError("replacement-unexpected", "non-replacement operation cannot carry replacement data")
        if operation["name"] == "callback-replacement" and callback is None:
            raise AdapterError("callback-missing", "callback replacement requires a registered fixture")
        if operation["name"] != "callback-replacement" and callback is not None:
            raise AdapterError("callback-unexpected", "non-callback operation cannot carry a callback fixture")
        state = exact_object(record["initial_state"], {"occurrence", "start_offset"}, "initial state")
        limits = exact_object(
            record["limits"],
            {"maximum_diagnostic_bytes", "maximum_matches", "maximum_output_bytes", "wall_time_ms"},
            "execution limits",
        )
        trace = record["trace_reference"]
        if trace is not None and (not isinstance(trace, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", trace) is None):
            raise AdapterError("trace-reference-invalid", "trace reference is not an opaque bounded identifier")
        return cls(
            correlation_id=correlation,
            adapter_release_manifest_id=manifest_id,
            profile_id=profile,
            target_release_id=release,
            operation=operation["name"],
            pattern=Datum.from_record(record["pattern"], "pattern"),
            subjects=tuple(Datum.from_record(item, f"subject[{index}]") for index, item in enumerate(subjects_value)),
            replacement=replacement,
            callback_fixture=callback,
            options=_named_values(record["options"], "options"),
            environment_inputs=_named_values(record["environment_inputs"], "environment inputs"),
            start_offset=require_integer(state["start_offset"], "start offset", 0, 9_007_199_254_740_991),
            occurrence=require_integer(state["occurrence"], "occurrence", 1, 9_007_199_254_740_991),
            requested_observations=sorted_unique_strings(
                record["requested_observations"], "requested observations", allowed=OBSERVATIONS
            ),
            maximum_matches=require_integer(limits["maximum_matches"], "maximum matches", 1, 1_000_000),
            maximum_diagnostic_bytes=require_integer(
                limits["maximum_diagnostic_bytes"], "maximum diagnostic bytes", 1, 1_048_576
            ),
            maximum_output_bytes=require_integer(
                limits["maximum_output_bytes"], "maximum output bytes", 1, 16_777_216
            ),
            wall_time_ms=require_integer(limits["wall_time_ms"], "wall time", 1, 86_400_000),
            trace_reference=trace,
        )

    def option_map(self) -> dict[str, Any]:
        return dict(self.options)

    def environment_map(self) -> dict[str, Any]:
        return dict(self.environment_inputs)


def diagnostic_record(payload: bytes, maximum: int) -> dict[str, Any]:
    kept = payload[:maximum]
    return {
        "captured_bytes": len(kept),
        "content": kept.decode("utf-8", "replace"),
        "original_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "truncated": len(kept) != len(payload),
    }


def span_record(
    start: int,
    end: int,
    *,
    basis: str,
    provenance: str,
    origin_subject: int = 0,
    encoding: str | None = None,
    unit_width_bits: int | None = None,
    endianness: str | None = None,
) -> dict[str, Any]:
    if start < 0 or end < start:
        raise AdapterError("native-span-invalid", "native span bounds are invalid", "serialization", "serialization")
    return {
        "api_provenance": provenance,
        "base_origin": 0,
        "basis": basis,
        "encoding": encoding,
        "end": end,
        "endianness": endianness,
        "interval": "half-open",
        "origin_subject": origin_subject,
        "sentinel": "none",
        "start": start,
        "unit_width_bits": unit_width_bits,
    }


def absence(field: str, reason: str) -> dict[str, str]:
    if reason not in ABSENCE_REASONS:
        raise AdapterError("absence-reason-invalid", "adapter attempted to emit an unknown absence reason")
    return {"field": field, "reason": reason}
