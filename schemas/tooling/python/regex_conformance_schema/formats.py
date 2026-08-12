"""Shared lexical formats for canonical records and identifiers."""

from __future__ import annotations

import re

NAMESPACE_PATTERN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
SEMVER_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
DIGEST_PATTERN = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
RCID_PATTERN = re.compile(
    rf"^rcid:v1:(?P<namespace>{NAMESPACE_PATTERN}):(?:(?P<u7>u7):(?P<uuid>[0-9a-f-]{{36}})|(?P<h>h):(?P<policy>{NAMESPACE_PATTERN}):(?P<digest>[0-9a-f]{{64}}))$"
)
OPID_PATTERN = re.compile(
    rf"^opid:v1:(?P<namespace>{NAMESPACE_PATTERN}):u7:(?P<uuid>[0-9a-f-]{{36}})$"
)
