"""Strict bounded JSON and uint32 big-endian frame handling."""

from __future__ import annotations

import json
import struct
from typing import Any, BinaryIO

from .errors import AdapterError

MAX_FRAME_BYTES = 1_048_576
MAX_LIST_ITEMS = 65_536
MAX_MESSAGE_COUNT = 1_000_000
MAX_NESTING_DEPTH = 32
SAFE_INTEGER = 9_007_199_254_740_991


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError("duplicate-json-key", f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AdapterError("nonfinite-json-number", f"non-finite JSON number {value!r} is forbidden")


def _walk(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise AdapterError("json-depth-exceeded", "JSON nesting exceeds the protocol limit")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -SAFE_INTEGER <= value <= SAFE_INTEGER:
            raise AdapterError("unsafe-json-integer", "JSON integers must fit the interoperable safe range")
        return
    if isinstance(value, float):
        raise AdapterError("json-float-forbidden", "adapter protocol numbers must be exact integers")
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise AdapterError("invalid-unicode-scalar", "JSON text contains an isolated surrogate") from error
        if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
            raise AdapterError("unsafe-json-text", "JSON text contains a forbidden control character")
        return
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise AdapterError("json-list-limit", "JSON list exceeds the protocol limit")
        for item in value:
            _walk(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_LIST_ITEMS:
            raise AdapterError("json-object-limit", "JSON object exceeds the protocol limit")
        for key, item in value.items():
            if not isinstance(key, str):
                raise AdapterError("json-key-type", "JSON object keys must be strings")
            _walk(key, depth=depth + 1)
            _walk(item, depth=depth + 1)
        return
    raise AdapterError("json-type-forbidden", f"unsupported JSON value type {type(value).__name__}")


def strict_loads(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise AdapterError("invalid-frame-utf8", "frame is not valid UTF-8") from error
    try:
        value = json.loads(text, object_pairs_hook=_strict_object, parse_constant=_reject_constant)
    except AdapterError:
        raise
    except (json.JSONDecodeError, ValueError) as error:
        raise AdapterError("invalid-json", "frame does not contain one valid JSON value") from error
    _walk(value)
    if not isinstance(value, dict):
        raise AdapterError("frame-not-object", "protocol frames must contain JSON objects")
    return value


def canonical_bytes(value: Any) -> bytes:
    _walk(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise AdapterError("canonicalization-failed", "value cannot be serialized canonically") from error


def encode_frame(value: Any) -> bytes:
    payload = canonical_bytes(value)
    if len(payload) > MAX_FRAME_BYTES:
        raise AdapterError("frame-size-exceeded", "serialized frame exceeds the protocol limit")
    return struct.pack(">I", len(payload)) + payload


def read_frame(stream: BinaryIO) -> dict[str, Any] | None:
    header = stream.read(4)
    if header == b"":
        return None
    if len(header) != 4:
        raise AdapterError("truncated-frame-header", "frame ended inside its length prefix")
    (length,) = struct.unpack(">I", header)
    if length == 0:
        raise AdapterError("empty-frame", "zero-length protocol frames are forbidden")
    if length > MAX_FRAME_BYTES:
        raise AdapterError("frame-size-exceeded", "declared frame length exceeds the protocol limit")
    payload = stream.read(length)
    if len(payload) != length:
        raise AdapterError("truncated-frame", "frame ended before its declared length")
    return strict_loads(payload)


def write_frame(stream: BinaryIO, value: Any) -> None:
    stream.write(encode_frame(value))
    stream.flush()
