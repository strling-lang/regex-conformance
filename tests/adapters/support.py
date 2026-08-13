from __future__ import annotations

import base64
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "adapters" / "python", ROOT / "schemas" / "tooling" / "python"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_adapters.manifest import AdapterManifest
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.schema import validate_instance

PROTOCOL_REVISION = "rcid:v1:adapter-protocol-revision:h:jcs-sha256-v1:c9dd4b0a7e0c7fc6ae43586392e402b0036c03e9f2b1d5e0a43828d11945eda1"
BINDINGS = {
    "mysql-regex": {
        "manifest": "rcid:v1:adapter-release-manifest:h:jcs-sha256-v1:" + "a" * 64,
        "profile": "rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7",
        "release": "rcid:v1:release:u7:019ff984-a52e-7487-8f0d-5046164b1b61",
        "constraints": (("icu-version-source-bound", "77.1"), ("mysql-version", "8.4.10"), ("regexp-time-limit-ms", "1000")),
    },
    "pcre2-ordinary": {
        "manifest": "rcid:v1:adapter-release-manifest:h:jcs-sha256-v1:" + "b" * 64,
        "profile": "rcid:v1:profile:u7:019ff984-a52e-7cff-8789-6bbe35540702",
        "release": "rcid:v1:release:u7:019ff984-a52e-737a-8353-17af9584dc6f",
        "constraints": (("engine-version", "10.47"),),
    },
    "pcre2-dfa": {
        "manifest": "rcid:v1:adapter-release-manifest:h:jcs-sha256-v1:" + "e" * 64,
        "profile": "rcid:v1:profile:u7:019ffc57-9ad1-7be2-8067-73fce0a50770",
        "release": "rcid:v1:release:u7:019ff984-a52e-737a-8353-17af9584dc6f",
        "constraints": (("engine-version", "10.47"), ("matcher-api", "pcre2-dfa-match-8")),
    },
    "python-re": {
        "manifest": "rcid:v1:adapter-release-manifest:h:jcs-sha256-v1:" + "c" * 64,
        "profile": "rcid:v1:profile:u7:019ff984-a52e-746c-b7c9-7f82de44ebfd",
        "release": "rcid:v1:release:u7:019ff984-a52e-755c-a7b5-29741bc00c2c",
        "constraints": (("implementation", "cpython"), ("python-version", "3.14.6"), ("unicode-version", "16.0.0")),
    },
}


def manifest(selection: str, *, capabilities: tuple[str, ...] = ("operation-search",)) -> AdapterManifest:
    binding = BINDINGS[selection]
    return AdapterManifest(
        selection_key=selection,
        manifest_id=binding["manifest"],
        adapter_id="rcid:v1:adapter:u7:019ffb61-6ada-7e98-a046-3ee1f6cbbbd5",
        adapter_release_id="rcid:v1:adapter-release:u7:019ffb61-61fa-72db-b410-87742803ad0d",
        profile_id=binding["profile"],
        target_release_id=binding["release"],
        protocol_revision_id=PROTOCOL_REVISION,
        source_digest="d" * 64,
        capabilities=tuple(sorted(capabilities)),
        runtime_constraints=binding["constraints"],
        protocol_major=1,
        minimum_minor=0,
        maximum_minor=0,
        schema_versions=(
            "adapter-handshake-offer.v1",
            "adapter-handshake-result.v1",
            "adapter-request.v1",
            "adapter-response.v1",
        ),
    )


def scalar(value: str) -> dict[str, Any]:
    return {
        "domain": "unicode-scalars",
        "encoding": "unicode-scalar-values",
        "endianness": None,
        "text": value,
        "unit_width_bits": None,
    }


def octets(value: bytes) -> dict[str, Any]:
    return {
        "data": base64.urlsafe_b64encode(value).decode("ascii").rstrip("="),
        "domain": "octets",
        "encoding": None,
        "endianness": None,
        "unit_width_bits": 8,
    }


def offer(*, required: list[str] | None = None, major: int = 1) -> dict[str, Any]:
    return {
        "correlation_id": "handshake-1",
        "limits": {
            "maximum_frame_bytes": 1048576,
            "maximum_list_items": 65536,
            "maximum_message_count": 1000000,
            "maximum_nesting_depth": 32,
        },
        "message_type": "handshake-offer",
        "offered_schema_versions": [
            "adapter-handshake-offer.v1",
            "adapter-handshake-result.v1",
            "adapter-request.v1",
            "adapter-response.v1",
        ],
        "optional_capabilities": [],
        "protocol": {"major": major, "maximum_minor": 0, "minimum_minor": 0},
        "required_capabilities": sorted(required or ["operation-search"]),
        "schema_version": "adapter-handshake-offer.v1",
    }


def request(
    package: AdapterManifest,
    *,
    operation: str = "search",
    pattern: dict[str, Any] | None = None,
    subject: dict[str, Any] | None = None,
    replacement: dict[str, Any] | None = None,
    options: list[dict[str, Any]] | None = None,
    environment: list[dict[str, Any]] | None = None,
    observations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "adapter_release_manifest_id": package.manifest_id,
        "callback_fixture": None,
        "correlation_id": "execute-1",
        "environment_inputs": environment or [],
        "initial_state": {"occurrence": 1, "start_offset": 0},
        "limits": {
            "maximum_diagnostic_bytes": 4096,
            "maximum_matches": 100,
            "maximum_output_bytes": 65536,
            "wall_time_ms": 30000,
        },
        "message_type": "execute",
        "operation": {"name": operation, "version": "1.0.0"},
        "options": options or [],
        "pattern": pattern or scalar("a+"),
        "profile_id": package.profile_id,
        "replacement": replacement,
        "requested_observations": sorted(observations or ["captures", "match-state", "runtime-identity", "spans"]),
        "schema_version": "adapter-request.v1",
        "subjects": [subject or scalar("baaac")],
        "target_release_id": package.target_release_id,
        "trace_reference": None,
    }


def validate_schema(value: dict[str, Any], filename: str) -> None:
    validate_instance(value, load_strict(ROOT / "schemas" / "json" / filename))
