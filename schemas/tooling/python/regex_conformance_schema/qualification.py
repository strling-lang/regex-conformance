"""Cross-record validation for the P18 profile/vector qualification expansion."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable

from .adapters import validate_adapter_protocol_revision, validate_adapter_release_manifest
from .environments import validate_certified_environment_recipe
from .errors import fail
from .identity import NamespaceRegistry
from .jsonio import load_strict
from .profile import IdentityProfile


def _require_unique(values: list[str], label: str, source: str) -> None:
    if len(values) != len(set(values)):
        fail("qualification-identity-collision", f"{label} contains a duplicate", source)


def _require_assigned(
    registry: NamespaceRegistry, value: str, namespace: str, source: str
) -> None:
    parsed = registry.validate(value)
    if (parsed.scheme, parsed.namespace, parsed.mode) != ("rcid", namespace, "u7"):
        fail(
            "qualification-namespace-mismatch",
            f"identifier is not an assigned {namespace} ID",
            source,
        )


def load_and_validate_qualification_records(
    root: Path,
    *,
    validate_instance: Callable[..., None],
) -> dict[str, int]:
    schemas = root / "schemas" / "json"
    registry = NamespaceRegistry.load(root / "registries" / "identity" / "namespaces.v1.json")
    base_path = root / "registries" / "profiles" / "vertical-slice-coordinates.v1.json"
    overlay_path = root / "registries" / "profiles" / "small-scale-qualification.v1.json"
    base = load_strict(base_path)
    overlay = load_strict(overlay_path)
    validate_instance(
        overlay,
        load_strict(schemas / "qualification-profile-overlay.schema.json"),
        source=str(overlay_path),
    )
    if overlay["base_coordinates"] != {
        "path": "registries/profiles/vertical-slice-coordinates.v1.json",
        "sha256": hashlib.sha256(base_path.read_bytes()).hexdigest(),
    }:
        fail(
            "qualification-base-coordinate-drift",
            "qualification overlay does not bind the exact P17 coordinate bytes",
            str(overlay_path),
        )
    base_keys = {item["selection_key"] for item in base["profiles"]}
    added_keys = [item["selection_key"] for item in overlay["profiles"]]
    family_keys = [item["selection_key"] for item in overlay["profile_families"]]
    binding_keys = [item["selection_key"] for item in overlay["environment_bindings"]]
    if added_keys != sorted(added_keys) or added_keys != family_keys or added_keys != binding_keys:
        fail(
            "qualification-coordinate-accounting",
            "added families, profiles, and bindings must use one deterministic key set",
            str(overlay_path),
        )
    if base_keys.intersection(added_keys):
        fail(
            "qualification-coordinate-collision",
            "qualification profile collides with a frozen P17 selection",
            str(overlay_path),
        )
    releases = {item["release_id"]: item for item in base["releases"]}
    components = {item["component_id"]: item for item in base["components"]}
    families = {item["selection_key"]: item for item in overlay["profile_families"]}
    bindings = {item["selection_key"]: item for item in overlay["environment_bindings"]}
    ids: list[str] = []
    for family in overlay["profile_families"]:
        _require_assigned(registry, family["profile_family_id"], "profile-family", str(overlay_path))
        ids.append(family["profile_family_id"])
    for profile in overlay["profiles"]:
        _require_assigned(registry, profile["profile_id"], "profile", str(overlay_path))
        ids.append(profile["profile_id"])
        key = profile["selection_key"]
        if profile["profile_family_id"] != families[key]["profile_family_id"]:
            fail(
                "qualification-profile-family-mismatch",
                f"profile family differs for {key}",
                str(overlay_path),
            )
        node_keys = [item["node_key"] for item in profile["nodes"]]
        _require_unique(node_keys, "profile node keys", str(overlay_path))
        if profile["root_node"] not in node_keys:
            fail("qualification-root-missing", f"root node is absent for {key}", str(overlay_path))
        for node in profile["nodes"]:
            release = releases.get(node["release_id"])
            if (
                release is None
                or release["component_id"] != node["component_id"]
                or node["component_id"] not in components
            ):
                fail(
                    "qualification-node-release-mismatch",
                    f"profile node does not bind an exact base release for {key}",
                    str(overlay_path),
                )
            facets = [item["name"] for item in node["facets"]]
            if facets != sorted(facets) or len(facets) != len(set(facets)):
                fail(
                    "qualification-facet-order",
                    f"profile facets are not unique and ordered for {key}",
                    str(overlay_path),
                )
        root_node = next(item for item in profile["nodes"] if item["node_key"] == profile["root_node"])
        binding = bindings[key]
        if (
            binding["profile_id"] != profile["profile_id"]
            or binding["target_release_id"] != root_node["release_id"]
        ):
            fail(
                "qualification-environment-binding-mismatch",
                f"environment binding differs from profile {key}",
                str(overlay_path),
            )
        _require_assigned(
            registry, binding["environment_recipe_id"], "environment-recipe", str(overlay_path)
        )
        ids.append(binding["environment_recipe_id"])
    _require_unique(ids, "added assigned IDs", str(overlay_path))

    merged: dict[str, Any] = {
        **base,
        "profile_families": [*base["profile_families"], *overlay["profile_families"]],
        "profiles": [*base["profiles"], *overlay["profiles"]],
        "environment_bindings": [*base["environment_bindings"], *overlay["environment_bindings"]],
    }
    recipe_schema = load_strict(schemas / "certified-environment-recipe.schema.json")
    recipe_paths = [root / item["recipe_path"] for item in overlay["environment_bindings"]]
    for path in recipe_paths:
        recipe = load_strict(path)
        validate_instance(recipe, recipe_schema, source=str(path))
        validate_certified_environment_recipe(
            recipe,
            coordinates=merged,
            registry=registry,
            source=str(path),
        )

    protocol_path = root / "protocol" / "adapter-protocol.v1.json"
    protocol = load_strict(protocol_path)
    protocol_id = validate_adapter_protocol_revision(
        protocol,
        root=root,
        registry=registry,
        profile=IdentityProfile.from_record(
            load_strict(root / "schemas" / "identity-profiles" / "adapter-protocol-revision.v1.json")
        ),
        source=str(protocol_path),
    )
    manifest_schema = load_strict(schemas / "adapter-release-manifest.schema.json")
    manifest_profile = IdentityProfile.from_record(
        load_strict(root / "schemas" / "identity-profiles" / "adapter-release-manifest.v1.json")
    )
    manifest_paths = sorted((root / "adapters" / "qualification-manifests").glob("*.json"))
    observed: list[str] = []
    for path in manifest_paths:
        manifest = load_strict(path)
        validate_instance(manifest, manifest_schema, source=str(path))
        key, _, _, _ = validate_adapter_release_manifest(
            manifest,
            root=root,
            coordinates=merged,
            protocol_id=protocol_id,
            registry=registry,
            profile=manifest_profile,
            source=str(path),
        )
        if manifest["identity"]["entrypoint"] != "adapters/python/run_qualification.py":
            fail(
                "qualification-adapter-entrypoint",
                "qualification adapter does not use the isolated entrypoint",
                str(path),
            )
        if path.name != f"{key}.v1.json":
            fail(
                "qualification-adapter-path",
                "qualification adapter filename differs from its selection",
                str(path),
            )
        observed.append(key)
    if observed != added_keys:
        fail(
            "qualification-adapter-accounting",
            "qualification manifests do not exactly cover added profiles",
            "adapters/qualification-manifests",
        )
    return {
        "qualification_profile_overlays": 1,
        "qualification_profile_coordinates": len(added_keys),
        "qualification_environment_recipes": len(recipe_paths),
        "qualification_adapter_manifests": len(manifest_paths),
    }
