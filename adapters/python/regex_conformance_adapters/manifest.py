"""Pinned adapter package manifests and self-verification."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any

from .errors import AdapterError
from .jsonio import canonical_bytes, strict_loads
from .model import exact_object, require_string, require_token, sorted_unique_strings

CONTENT_DOMAIN = "strling.regex-conformance.content-id"
HASH_POLICY = "jcs-sha256-v1"
PACKAGE_SCHEMA_FAMILY = "rcid:v1:schema-family:u7:019ffb61-586b-7d24-aa51-33d64636d741"
PROTOCOL_SCHEMA_FAMILY = "rcid:v1:schema-family:u7:019ffb61-653a-7ca1-a185-5544b82ce17b"
MANIFEST_PATHS = {
    "mysql-regex": "adapters/manifests/mysql-regex.v1.json",
    "pcre2-ordinary": "adapters/manifests/pcre2-ordinary.v1.json",
    "python-re": "adapters/manifests/python-re.v1.json",
}
PROTOCOL_PATH = "protocol/adapter-protocol.v1.json"


def _load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AdapterError("manifest-path-invalid", f"manifest path is not a regular file: {path}")
    return strict_loads(path.read_bytes())


def _content_id(namespace: str, family: str, version: str, identity: dict[str, Any]) -> str:
    envelope = {
        "domain": CONTENT_DOMAIN,
        "hash_policy": HASH_POLICY,
        "identity": identity,
        "identity_schema_family_id": family,
        "identity_schema_version": version,
        "namespace": namespace,
    }
    return f"rcid:v1:{namespace}:h:{HASH_POLICY}:{hashlib.sha256(canonical_bytes(envelope)).hexdigest()}"


def verify_protocol_revision(repository_root: Path) -> str:
    record = _load(repository_root / PROTOCOL_PATH)
    exact_object(
        record,
        {
            "authority",
            "identity",
            "identity_schema_family_id",
            "identity_schema_version",
            "protocol_revision_id",
            "schema_version",
        },
        "protocol revision",
    )
    if (
        record["schema_version"] != "adapter-protocol-revision.v1"
        or record["identity_schema_family_id"] != PROTOCOL_SCHEMA_FAMILY
        or record["identity_schema_version"] != "1.0.0"
    ):
        raise AdapterError("protocol-revision-invalid", "protocol revision schema coordinates are invalid")
    expected = _content_id(
        "adapter-protocol-revision",
        PROTOCOL_SCHEMA_FAMILY,
        "1.0.0",
        record["identity"],
    )
    if record["protocol_revision_id"] != expected:
        raise AdapterError("protocol-revision-id-mismatch", "protocol revision content ID does not match its identity")
    digests = {
        "handshake_schema_sha256": repository_root / "schemas/json/adapter-handshake.schema.json",
        "request_schema_sha256": repository_root / "schemas/json/adapter-request.schema.json",
        "response_schema_sha256": repository_root / "schemas/json/adapter-response.schema.json",
    }
    for field, path in digests.items():
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record["identity"][field]:
            raise AdapterError("protocol-schema-digest-mismatch", f"protocol schema digest does not match {path.name}")
    return expected


@dataclass(frozen=True)
class AdapterManifest:
    selection_key: str
    manifest_id: str
    adapter_id: str
    adapter_release_id: str
    profile_id: str
    target_release_id: str
    protocol_revision_id: str
    source_digest: str
    capabilities: tuple[str, ...]
    runtime_constraints: tuple[tuple[str, str], ...]
    protocol_major: int
    minimum_minor: int
    maximum_minor: int
    schema_versions: tuple[str, ...]


def load_manifest(repository_root: Path, selection_key: str) -> AdapterManifest:
    try:
        relative = MANIFEST_PATHS[selection_key]
    except KeyError as error:
        raise AdapterError("adapter-selection-unknown", f"no governed adapter exists for {selection_key!r}") from error
    root = repository_root.resolve(strict=True)
    record = _load(root / relative)
    exact_object(
        record,
        {
            "adapter_release_manifest_id",
            "build",
            "certification",
            "identity",
            "identity_schema_family_id",
            "identity_schema_version",
            "license",
            "protocol",
            "runtime_constraints",
            "schema_version",
            "source_files",
            "supersedes",
        },
        "adapter release manifest",
    )
    if (
        record["schema_version"] != "adapter-release-manifest.v1"
        or record["identity_schema_family_id"] != PACKAGE_SCHEMA_FAMILY
        or record["identity_schema_version"] != "1.0.0"
        or record["license"] != "MPL-2.0"
    ):
        raise AdapterError("adapter-manifest-invalid", "adapter manifest schema/license coordinates are invalid")
    identity = exact_object(
        record["identity"],
        {
            "adapter",
            "adapter_release",
            "capabilities",
            "entrypoint",
            "profile",
            "protocol_revision",
            "selection_key",
            "source_digest",
            "target_release",
        },
        "adapter manifest identity",
    )
    if identity["selection_key"] != selection_key or identity["entrypoint"] != "adapters/python/run.py":
        raise AdapterError("adapter-binding-mismatch", "adapter manifest selection or entrypoint is invalid")
    capabilities = sorted_unique_strings(identity["capabilities"], "adapter capabilities")
    protocol_revision = verify_protocol_revision(root)
    if identity["protocol_revision"] != protocol_revision:
        raise AdapterError("adapter-protocol-mismatch", "adapter manifest names a different protocol revision")
    source_files = record["source_files"]
    if not isinstance(source_files, list) or not source_files:
        raise AdapterError("adapter-source-set-invalid", "adapter manifest source file set is empty")
    source_projection: list[dict[str, str]] = []
    previous = ""
    for index, item in enumerate(source_files):
        member = exact_object(item, {"path", "sha256"}, f"source file {index}")
        path_text = require_string(member["path"], f"source file {index} path", maximum=256)
        digest = require_string(member["sha256"], f"source file {index} digest", maximum=64)
        if path_text <= previous or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise AdapterError("adapter-source-set-invalid", "adapter source files must be unique, sorted, and SHA-256 bound")
        previous = path_text
        unresolved_source = root / path_text
        if unresolved_source.is_symlink() or not unresolved_source.is_file():
            raise AdapterError("adapter-source-path-unsafe", "adapter source must be a regular non-link file")
        source = unresolved_source.resolve(strict=True)
        try:
            source.relative_to(root)
        except ValueError as error:
            raise AdapterError("adapter-source-path-unsafe", "adapter source path escaped the repository") from error
        if source.suffix != ".py":
            raise AdapterError("adapter-source-path-unsafe", "adapter source must be a Python file")
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise AdapterError("adapter-source-digest-mismatch", f"adapter source digest differs for {path_text}")
        source_projection.append({"path": path_text, "sha256": digest})
    aggregate = hashlib.sha256(canonical_bytes(source_projection)).hexdigest()
    if identity["source_digest"] != aggregate:
        raise AdapterError("adapter-source-digest-mismatch", "adapter aggregate source digest differs")
    expected_manifest = _content_id("adapter-release-manifest", PACKAGE_SCHEMA_FAMILY, "1.0.0", identity)
    if record["adapter_release_manifest_id"] != expected_manifest:
        raise AdapterError("adapter-manifest-id-mismatch", "adapter manifest content ID does not match its identity")
    protocol = exact_object(
        record["protocol"], {"major", "maximum_minor", "minimum_minor", "schema_versions"}, "protocol support"
    )
    if protocol["major"] != 1 or protocol["minimum_minor"] != 0 or protocol["maximum_minor"] != 0:
        raise AdapterError("adapter-protocol-range-invalid", "minimal adapters must pin protocol 1.0")
    schemas = sorted_unique_strings(protocol["schema_versions"], "adapter schema versions")
    required_schemas = {"adapter-handshake-offer.v1", "adapter-handshake-result.v1", "adapter-request.v1", "adapter-response.v1"}
    if set(schemas) != required_schemas:
        raise AdapterError("adapter-schema-set-invalid", "adapter manifest schema set is incomplete or ambiguous")
    constraints = record["runtime_constraints"]
    if not isinstance(constraints, list) or not constraints:
        raise AdapterError("runtime-constraints-invalid", "adapter runtime constraints are required")
    pairs: list[tuple[str, str]] = []
    for index, item in enumerate(constraints):
        member = exact_object(item, {"name", "value"}, f"runtime constraint {index}")
        pairs.append((require_token(member["name"], "runtime constraint name"), require_string(member["value"], "runtime constraint value", maximum=1024)))
    if tuple(name for name, _ in pairs) != tuple(sorted(name for name, _ in pairs)) or len({name for name, _ in pairs}) != len(pairs):
        raise AdapterError("runtime-constraints-invalid", "runtime constraints must be unique and sorted")
    return AdapterManifest(
        selection_key=selection_key,
        manifest_id=expected_manifest,
        adapter_id=identity["adapter"],
        adapter_release_id=identity["adapter_release"],
        profile_id=identity["profile"],
        target_release_id=identity["target_release"],
        protocol_revision_id=protocol_revision,
        source_digest=aggregate,
        capabilities=capabilities,
        runtime_constraints=tuple(pairs),
        protocol_major=1,
        minimum_minor=0,
        maximum_minor=0,
        schema_versions=schemas,
    )
