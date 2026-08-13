"""Cross-record validation for governed thin-adapter packages and protocol."""

from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .errors import fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .profile import IdentityProfile

PROTOCOL_FAMILY = "rcid:v1:schema-family:u7:019ffb61-653a-7ca1-a185-5544b82ce17b"
MANIFEST_FAMILY = "rcid:v1:schema-family:u7:019ffb61-586b-7d24-aa51-33d64636d741"
PROTOCOL_PATH = "protocol/adapter-protocol.v1.json"
MANIFEST_DIRECTORY = "adapters/manifests"
REQUIRED_SCHEMA_VERSIONS = [
    "adapter-handshake-offer.v1",
    "adapter-handshake-result.v1",
    "adapter-request.v1",
    "adapter-response.v1",
]


def _sha256(path: Path, *, code: str, source: str) -> str:
    if path.is_symlink() or not path.is_file():
        fail(code, "bound path must be a regular non-link file", source)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _content_id(
    record: dict[str, Any],
    *,
    namespace: str,
    id_field: str,
    profile: IdentityProfile,
    registry: NamespaceRegistry,
    source: str,
) -> str:
    result = build_content_identity(
        registry=registry,
        profile=profile,
        namespace=namespace,
        identity_schema_family_id=record["identity_schema_family_id"],
        identity_schema_version=record["identity_schema_version"],
        identity=record["identity"],
    )
    expected = result["content_id"]
    if record[id_field] != expected:
        fail(f"{namespace}-id-mismatch", "content ID does not match the canonical identity projection", source)
    return expected


def validate_adapter_protocol_revision(
    record: dict[str, Any],
    *,
    root: Path,
    registry: NamespaceRegistry,
    profile: IdentityProfile,
    source: str,
) -> str:
    if record["identity_schema_family_id"] != PROTOCOL_FAMILY:
        fail("adapter-protocol-family-mismatch", "protocol record uses the wrong identity family", source)
    protocol_id = _content_id(
        record,
        namespace="adapter-protocol-revision",
        id_field="protocol_revision_id",
        profile=profile,
        registry=registry,
        source=source,
    )
    schema_bindings = {
        "handshake_schema_sha256": "adapter-handshake.schema.json",
        "request_schema_sha256": "adapter-request.schema.json",
        "response_schema_sha256": "adapter-response.schema.json",
    }
    for field, filename in schema_bindings.items():
        schema_path = root / "schemas" / "json" / filename
        if _sha256(schema_path, code="adapter-protocol-schema-path-unsafe", source=source) != record["identity"][field]:
            fail("adapter-protocol-schema-digest-mismatch", f"protocol digest differs for {filename}", source)
    return protocol_id


def _validate_source_path(root: Path, path_text: str, *, source: str) -> Path:
    relative = PurePosixPath(path_text)
    if relative.is_absolute() or ".." in relative.parts or "\\" in path_text or relative.suffix != ".py":
        fail("adapter-source-path-unsafe", f"unsafe adapter source path {path_text!r}", source)
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            fail("adapter-source-path-unsafe", f"adapter source traverses a symbolic link: {path_text}", source)
    if not candidate.is_file():
        fail("adapter-source-path-unsafe", f"adapter source is not a regular file: {path_text}", source)
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        fail("adapter-source-path-unsafe", f"adapter source escapes the repository: {path_text}", source)
    return candidate


def validate_adapter_release_manifest(
    record: dict[str, Any],
    *,
    root: Path,
    coordinates: dict[str, Any],
    protocol_id: str,
    registry: NamespaceRegistry,
    profile: IdentityProfile,
    source: str,
) -> tuple[str, str, str, str]:
    if record["identity_schema_family_id"] != MANIFEST_FAMILY:
        fail("adapter-manifest-family-mismatch", "adapter manifest uses the wrong identity family", source)
    identity = record["identity"]
    selection_key = identity["selection_key"]
    profile_binding = next(
        (item for item in coordinates["profiles"] if item["selection_key"] == selection_key), None
    )
    if profile_binding is None:
        fail("adapter-coordinate-selection-unknown", f"manifest selection is not executable: {selection_key}", source)
    root_node = next(item for item in profile_binding["nodes"] if item["node_key"] == profile_binding["root_node"])
    if (identity["profile"], identity["target_release"]) != (
        profile_binding["profile_id"],
        root_node["release_id"],
    ):
        fail("adapter-coordinate-mismatch", "manifest profile/release does not match exact execution coordinates", source)
    if identity["protocol_revision"] != protocol_id:
        fail("adapter-protocol-mismatch", "manifest does not bind the governed protocol revision", source)

    for value, namespace in (
        (identity["adapter"], "adapter"),
        (identity["adapter_release"], "adapter-release"),
        (identity["profile"], "profile"),
        (identity["target_release"], "release"),
    ):
        parsed = registry.validate(value)
        if (parsed.scheme, parsed.namespace, parsed.mode) != ("rcid", namespace, "u7"):
            fail("adapter-namespace-mismatch", f"identifier is not an assigned {namespace} ID", source)

    for label, values in (
        ("capabilities", identity["capabilities"]),
        ("protocol schema versions", record["protocol"]["schema_versions"]),
        ("build dependencies", record["build"]["dependencies"]),
    ):
        if values != sorted(values) or len(values) != len(set(values)):
            fail("adapter-order-nondeterministic", f"{label} must be unique and code-point sorted", source)
    if record["protocol"]["schema_versions"] != REQUIRED_SCHEMA_VERSIONS:
        fail("adapter-schema-set-incomplete", "manifest does not bind the exact adapter protocol schemas", source)
    constraint_names = [item["name"] for item in record["runtime_constraints"]]
    if constraint_names != sorted(constraint_names) or len(constraint_names) != len(set(constraint_names)):
        fail("adapter-order-nondeterministic", "runtime constraints must be unique and sorted", source)

    source_paths = [item["path"] for item in record["source_files"]]
    if source_paths != sorted(source_paths) or len(source_paths) != len(set(source_paths)):
        fail("adapter-order-nondeterministic", "source files must be unique and sorted", source)
    source_projection: list[dict[str, str]] = []
    for member in record["source_files"]:
        path = _validate_source_path(root, member["path"], source=source)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != member["sha256"]:
            fail("adapter-source-digest-mismatch", f"source digest differs for {member['path']}", source)
        source_projection.append({"path": member["path"], "sha256": member["sha256"]})
    aggregate = hashlib.sha256(canonical_bytes(source_projection)).hexdigest()
    if aggregate != identity["source_digest"]:
        fail("adapter-source-digest-mismatch", "aggregate source digest differs", source)

    manifest_id = _content_id(
        record,
        namespace="adapter-release-manifest",
        id_field="adapter_release_manifest_id",
        profile=profile,
        registry=registry,
        source=source,
    )
    return selection_key, identity["adapter"], identity["adapter_release"], manifest_id


def validate_minimal_adapter_certification(
    record: dict[str, Any],
    *,
    protocol_id: str,
    manifests_by_key: dict[str, dict[str, Any]],
    recipes_by_key: dict[str, dict[str, Any]],
    environment_results_by_key: dict[str, dict[str, Any]],
    expected_keys: list[str],
    source: str,
) -> None:
    digest = record["evidence_sha256"]
    if record["evidence_filename"] != f"minimal-adapter-certification-sha256-{digest}.json":
        fail(
            "adapter-certification-evidence-reference-mismatch",
            "adapter evidence filename does not encode its declared digest",
            source,
        )
    if record["protocol_revision_id"] != protocol_id:
        fail(
            "adapter-certification-protocol-mismatch",
            "adapter certificate does not bind the governed protocol revision",
            source,
        )
    result_keys = [item["selection_key"] for item in record["results"]]
    if result_keys != expected_keys:
        fail(
            "adapter-certification-accounting-mismatch",
            "adapter certificate results do not use the exact coordinate order",
            source,
        )
    manifest_ids = [item["adapter_release_manifest_id"] for item in record["results"]]
    if len(manifest_ids) != len(set(manifest_ids)):
        fail(
            "adapter-certification-manifest-collision",
            "adapter certificate manifest identities must be unique",
            source,
        )
    for result in record["results"]:
        key = result["selection_key"]
        manifest = manifests_by_key.get(key)
        recipe = recipes_by_key.get(key)
        environment = environment_results_by_key.get(key)
        if manifest is None or recipe is None or environment is None:
            fail(
                "adapter-certification-accounting-mismatch",
                f"adapter certificate result has no complete governed binding for {key}",
                source,
            )
        identity = manifest["identity"]
        expected = (
            manifest["adapter_release_manifest_id"],
            identity["source_digest"],
            recipe["recipe_revision_id"],
            identity["profile"],
            identity["target_release"],
            environment["environment_fingerprint_id"],
            environment["verification_digest"],
            environment["provider_implementation_digest"],
        )
        actual = (
            result["adapter_release_manifest_id"],
            result["adapter_source_digest"],
            result["recipe_revision_id"],
            result["target_profile_id"],
            result["target_release_id"],
            result["environment_fingerprint_id"],
            result["environment_verification_digest"],
            result["provider_implementation_digest"],
        )
        if actual != expected:
            fail(
                "adapter-certification-binding-mismatch",
                f"adapter certificate differs from its manifest, recipe, or environment evidence for {key}",
                source,
            )


def load_and_validate_adapter_records(root: Path, *, validate_instance: Callable[..., None]) -> dict[str, int]:
    schemas = root / "schemas" / "json"
    registry = NamespaceRegistry.load(root / "registries" / "identity" / "namespaces.v1.json")
    protocol_path = root / PROTOCOL_PATH
    protocol_record = load_strict(protocol_path)
    validate_instance(
        protocol_record,
        load_strict(schemas / "adapter-protocol-revision.schema.json"),
        source=PROTOCOL_PATH,
    )
    protocol_id = validate_adapter_protocol_revision(
        protocol_record,
        root=root,
        registry=registry,
        profile=IdentityProfile.from_record(
            load_strict(root / "schemas" / "identity-profiles" / "adapter-protocol-revision.v1.json")
        ),
        source=PROTOCOL_PATH,
    )

    coordinates = load_strict(root / "registries" / "profiles" / "vertical-slice-coordinates.v1.json")
    manifest_schema = load_strict(schemas / "adapter-release-manifest.schema.json")
    manifest_profile = IdentityProfile.from_record(
        load_strict(root / "schemas" / "identity-profiles" / "adapter-release-manifest.v1.json")
    )
    paths = sorted((root / MANIFEST_DIRECTORY).glob("*.json"))
    expected_keys = [item["selection_key"] for item in coordinates["profiles"]]
    observed_keys: list[str] = []
    identifiers: dict[str, set[str]] = {"adapter": set(), "adapter-release": set(), "manifest": set()}
    manifests_by_key: dict[str, dict[str, Any]] = {}
    for path in paths:
        source = path.relative_to(root).as_posix()
        record = load_strict(path)
        validate_instance(record, manifest_schema, source=source)
        key, adapter_id, release_id, manifest_id = validate_adapter_release_manifest(
            record,
            root=root,
            coordinates=coordinates,
            protocol_id=protocol_id,
            registry=registry,
            profile=manifest_profile,
            source=source,
        )
        if path.name != f"{key}.v1.json":
            fail("adapter-manifest-path-mismatch", "manifest filename does not match its selection", source)
        observed_keys.append(key)
        manifests_by_key[key] = record
        for label, value in (("adapter", adapter_id), ("adapter-release", release_id), ("manifest", manifest_id)):
            if value in identifiers[label]:
                fail("adapter-identity-collision", f"duplicate {label} identity: {value}", source)
            identifiers[label].add(value)
    if len(observed_keys) != len(set(observed_keys)) or set(observed_keys) != set(expected_keys):
        fail("adapter-accounting-mismatch", "adapter manifests do not exactly cover executable coordinates", MANIFEST_DIRECTORY)

    recipes_by_key = {
        record["selection_key"]: record
        for record in (
            load_strict(path)
            for path in sorted((root / "environments" / "recipes").glob("*.json"))
        )
    }
    environment_certification = load_strict(
        root / "reports" / "vertical-slice" / "minimal-environment-certification.json"
    )
    environment_results_by_key = {
        item["selection_key"]: item for item in environment_certification["results"]
    }
    certification_path = root / "reports" / "vertical-slice" / "minimal-adapter-certification.json"
    certification = load_strict(certification_path)
    validate_instance(
        certification,
        load_strict(schemas / "minimal-adapter-certification.schema.json"),
        source=str(certification_path),
    )
    validate_minimal_adapter_certification(
        certification,
        protocol_id=protocol_id,
        manifests_by_key=manifests_by_key,
        recipes_by_key=recipes_by_key,
        environment_results_by_key=environment_results_by_key,
        expected_keys=expected_keys,
        source=str(certification_path),
    )
    return {
        "adapter_protocol_revisions": 1,
        "adapter_release_manifests": len(paths),
        "minimal_adapter_certifications": 1,
    }
