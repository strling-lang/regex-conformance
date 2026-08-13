"""Credential rejection for durable scheduler checkpoint payloads."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit


FORBIDDEN_NAMES = frozenset(
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
FORBIDDEN_QUERY_NAMES = FORBIDDEN_NAMES | frozenset(
    {
        "awsaccesskeyid",
        "sig",
        "signature",
        "sharedaccesssignature",
        "xamzsignature",
        "xgoogsignature",
    }
)
AUTHORIZATION_VALUE = re.compile(r"(?i)\b(?:basic|bearer)\s+[A-Za-z0-9+/_.=-]{8,}")


class UnsafeCheckpointPayloadError(ValueError):
    """A checkpoint payload contains credential-bearing material."""


def _normalized(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _unsafe_string(value: str) -> bool:
    if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
        return True
    if AUTHORIZATION_VALUE.search(value) is not None:
        return True
    if "://" not in value:
        return False
    try:
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None:
            return True
        return any(
            _normalized(key) in FORBIDDEN_QUERY_NAMES for key, _item in parse_qsl(parsed.query)
        )
    except ValueError:
        return True


def validate_checkpoint_payload(value: Any, *, field_name: str | None = None) -> None:
    """Reject secrets recursively while leaving JSON shape validation to JCS."""

    if field_name is not None and _normalized(field_name) in FORBIDDEN_NAMES:
        raise UnsafeCheckpointPayloadError(
            "scheduler checkpoints cannot persist credential-bearing fields"
        )
    if isinstance(value, str):
        if _unsafe_string(value):
            raise UnsafeCheckpointPayloadError(
                "scheduler checkpoints cannot persist credential-bearing values"
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                validate_checkpoint_payload(item, field_name=key)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            validate_checkpoint_payload(item)
