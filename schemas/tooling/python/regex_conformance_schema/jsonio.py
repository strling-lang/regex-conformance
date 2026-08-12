"""Strict JSON loading and RFC 8785 serialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import rfc8785

from .errors import ConformanceDataError, fail


def _reject_constant(value: str) -> None:
    fail("invalid-json-number", f"non-finite JSON number {value!r} is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate-json-key", f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_lone_surrogates(value: Any, path: str = "$") -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            fail("invalid-unicode", "lone UTF-16 surrogate is forbidden", path)
    elif isinstance(value, list):
        for index, member in enumerate(value):
            _reject_lone_surrogates(member, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, member in value.items():
            _reject_lone_surrogates(key, path)
            _reject_lone_surrogates(member, f"{path}.{key}")


def loads_strict(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ConformanceDataError:
        raise
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ConformanceDataError("invalid-json", str(error)) from error
    _reject_lone_surrogates(value)
    return value


def load_strict(path: Path | str) -> Any:
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise ConformanceDataError("invalid-utf8", str(error)) from error
    return loads_strict(text)


def canonical_bytes(value: Any) -> bytes:
    _reject_lone_surrogates(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError, TypeError) as error:
        raise ConformanceDataError("canonicalization-failed", str(error)) from error


def canonical_text(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def dump_pretty(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
