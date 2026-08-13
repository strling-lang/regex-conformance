"""Self-verifying adapter manifests added after the frozen P17 vertical slice."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .errors import AdapterError
from .jsonio import canonical_bytes
from .manifest import (
    PACKAGE_SCHEMA_FAMILY,
    AdapterManifest,
    _content_id,
    _load,
    verify_protocol_revision,
)
from .model import exact_object, require_string, require_token, sorted_unique_strings

QUALIFICATION_MANIFEST_PATHS = {
    "pcre2-dfa": "adapters/qualification-manifests/pcre2-dfa.v1.json",
}


def load_qualification_manifest(repository_root: Path, selection_key: str) -> AdapterManifest:
    try:
        relative = QUALIFICATION_MANIFEST_PATHS[selection_key]
    except KeyError as error:
        raise AdapterError(
            "adapter-selection-unknown", f"no qualification adapter exists for {selection_key!r}"
        ) from error
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
        "qualification adapter manifest",
    )
    if (
        record["schema_version"] != "adapter-release-manifest.v1"
        or record["identity_schema_family_id"] != PACKAGE_SCHEMA_FAMILY
        or record["identity_schema_version"] != "1.0.0"
        or record["license"] != "MPL-2.0"
    ):
        raise AdapterError(
            "adapter-manifest-invalid", "qualification manifest coordinates are invalid"
        )
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
        "qualification adapter identity",
    )
    if (
        identity["selection_key"] != selection_key
        or identity["entrypoint"] != "adapters/python/run_qualification.py"
    ):
        raise AdapterError(
            "adapter-binding-mismatch",
            "qualification adapter entrypoint or selection is invalid",
        )
    protocol_revision = verify_protocol_revision(root)
    if identity["protocol_revision"] != protocol_revision:
        raise AdapterError(
            "adapter-protocol-mismatch", "qualification adapter binds another protocol"
        )
    capabilities = sorted_unique_strings(identity["capabilities"], "adapter capabilities")
    source_files = record["source_files"]
    if not isinstance(source_files, list) or not source_files:
        raise AdapterError(
            "adapter-source-set-invalid", "qualification adapter source set is empty"
        )
    source_projection: list[dict[str, str]] = []
    previous = ""
    for index, item in enumerate(source_files):
        member = exact_object(item, {"path", "sha256"}, f"source file {index}")
        path_text = require_string(
            member["path"], f"source file {index} path", maximum=256
        )
        digest = require_string(
            member["sha256"], f"source file {index} digest", maximum=64
        )
        if (
            path_text <= previous
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise AdapterError(
                "adapter-source-set-invalid",
                "qualification sources must be unique, sorted, and SHA-256 bound",
            )
        previous = path_text
        unresolved = root / path_text
        if unresolved.is_symlink() or not unresolved.is_file():
            raise AdapterError(
                "adapter-source-path-unsafe",
                "qualification source must be a regular non-link file",
            )
        path = unresolved.resolve(strict=True)
        try:
            path.relative_to(root)
        except ValueError as error:
            raise AdapterError(
                "adapter-source-path-unsafe",
                "qualification source escaped the repository",
            ) from error
        if path.suffix != ".py":
            raise AdapterError(
                "adapter-source-path-unsafe", "qualification source must be a Python file"
            )
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise AdapterError(
                "adapter-source-digest-mismatch",
                f"source digest differs for {path_text}",
            )
        source_projection.append({"path": path_text, "sha256": digest})
    aggregate = hashlib.sha256(canonical_bytes(source_projection)).hexdigest()
    if aggregate != identity["source_digest"]:
        raise AdapterError(
            "adapter-source-digest-mismatch",
            "qualification adapter aggregate digest differs",
        )
    expected_manifest = _content_id(
        "adapter-release-manifest",
        record["identity_schema_family_id"],
        record["identity_schema_version"],
        identity,
    )
    if record["adapter_release_manifest_id"] != expected_manifest:
        raise AdapterError(
            "adapter-manifest-id-mismatch", "qualification adapter manifest ID differs"
        )
    protocol = exact_object(
        record["protocol"],
        {"major", "maximum_minor", "minimum_minor", "schema_versions"},
        "qualification protocol support",
    )
    if (
        protocol["major"] != 1
        or protocol["minimum_minor"] != 0
        or protocol["maximum_minor"] != 0
    ):
        raise AdapterError(
            "adapter-protocol-range-invalid",
            "qualification adapter must pin protocol 1.0",
        )
    schemas = sorted_unique_strings(
        protocol["schema_versions"], "adapter schema versions"
    )
    required_schemas = {
        "adapter-handshake-offer.v1",
        "adapter-handshake-result.v1",
        "adapter-request.v1",
        "adapter-response.v1",
    }
    if set(schemas) != required_schemas:
        raise AdapterError(
            "adapter-schema-set-invalid", "qualification schema set is incomplete"
        )
    raw_constraints = record["runtime_constraints"]
    if not isinstance(raw_constraints, list) or not raw_constraints:
        raise AdapterError(
            "runtime-constraints-invalid",
            "qualification runtime constraints are required",
        )
    pairs: list[tuple[str, str]] = []
    for index, item in enumerate(raw_constraints):
        member = exact_object(
            item, {"name", "value"}, f"runtime constraint {index}"
        )
        pairs.append(
            (
                require_token(member["name"], "runtime constraint name"),
                require_string(
                    member["value"], "runtime constraint value", maximum=1024
                ),
            )
        )
    names = tuple(name for name, _ in pairs)
    if names != tuple(sorted(names)) or len(names) != len(set(names)):
        raise AdapterError(
            "runtime-constraints-invalid",
            "runtime constraints must be unique and sorted",
        )
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
