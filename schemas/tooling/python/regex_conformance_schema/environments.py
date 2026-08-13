"""Cross-record validation for executable vertical-slice coordinates and recipes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .errors import fail
from .identity import CONTENT_DOMAIN, HASH_POLICY, NamespaceRegistry
from .jsonio import canonical_bytes, load_strict

COORDINATE_SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:019ff984-a52e-7a92-b209-bf5f2d1de5e3"
RECIPE_SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:019ff984-a52e-74e2-bc5c-82fcc3e2134a"
RECIPE_IDENTITY_VERSION = "1.0.0"
ISOLATION_DOMAIN = "strling.regex-conformance.environment-isolation-policy"


def isolation_policy_digest(policy: dict[str, Any]) -> str:
    identity = {key: value for key, value in policy.items() if key != "digest"}
    return hashlib.sha256(canonical_bytes({"domain": ISOLATION_DOMAIN, "policy": identity})).hexdigest()


def environment_recipe_revision(record: dict[str, Any]) -> str:
    identity = {key: value for key, value in record.items() if key != "recipe_revision_id"}
    envelope = {
        "domain": CONTENT_DOMAIN,
        "hash_policy": HASH_POLICY,
        "namespace": "environment-recipe-revision",
        "identity_schema_family_id": record["recipe_schema_family_id"],
        "identity_schema_version": RECIPE_IDENTITY_VERSION,
        "identity": identity,
    }
    digest = hashlib.sha256(canonical_bytes(envelope)).hexdigest()
    return f"rcid:v1:environment-recipe-revision:h:{HASH_POLICY}:{digest}"


def validate_vertical_slice_coordinates(
    record: dict[str, Any], *, selection: dict[str, Any], registry: NamespaceRegistry, source: str
) -> None:
    if record["coordinate_schema_family_id"] != COORDINATE_SCHEMA_FAMILY_ID:
        fail("coordinate-schema-family-mismatch", "coordinate record uses the wrong schema family", source)
    selected_keys = [item["selection_key"] for item in selection["selected_archetypes"]]
    if record["selection_source"]["selected_keys"] != selected_keys:
        fail("coordinate-selection-mismatch", "coordinate selections do not match the governed archetype order", source)

    _require_order("systems", [item["system_key"] for item in record["systems"]], source)
    _require_order("components", [item["component_key"] for item in record["components"]], source)
    _require_order("profile families", [item["selection_key"] for item in record["profile_families"]], source)
    _require_order("profiles", [item["selection_key"] for item in record["profiles"]], source, expected=selected_keys)
    _require_order("environment bindings", [item["selection_key"] for item in record["environment_bindings"]], source, expected=selected_keys)

    collections = {
        "system": (record["systems"], "system_id", "system_key"),
        "component": (record["components"], "component_id", "component_key"),
        "release": (record["releases"], "release_id", "release_id"),
        "profile-family": (record["profile_families"], "profile_family_id", "selection_key"),
        "profile": (record["profiles"], "profile_id", "selection_key"),
        "environment-recipe": (record["environment_bindings"], "environment_recipe_id", "selection_key"),
    }
    for namespace, (items, id_field, key_field) in collections.items():
        ids = [item[id_field] for item in items]
        keys = [item[key_field] for item in items]
        _require_unique(f"{namespace} IDs", ids, source)
        _require_unique(f"{namespace} keys", keys, source)
        for identifier in ids:
            parsed = registry.validate(identifier)
            if (parsed.scheme, parsed.namespace, parsed.mode) != ("rcid", namespace, "u7"):
                fail("coordinate-namespace-mismatch", f"{identifier} is not an assigned {namespace} ID", source)

    system_ids = {item["system_id"] for item in record["systems"]}
    component_by_id = {item["component_id"]: item for item in record["components"]}
    release_by_id = {item["release_id"]: item for item in record["releases"]}
    family_ids = {item["profile_family_id"] for item in record["profile_families"]}
    for component in record["components"]:
        if component["system_id"] not in system_ids:
            fail("coordinate-reference-unknown", "component references an unknown system", source)
    for release in record["releases"]:
        if release["component_id"] not in component_by_id:
            fail("coordinate-reference-unknown", "release references an unknown component", source)
    release_sort_keys = {
        item["release_id"]: (component_by_id[item["component_id"]]["component_key"], item["version"], item["release_id"])
        for item in record["releases"]
    }
    _require_order(
        "releases",
        [item["release_id"] for item in record["releases"]],
        source,
        expected=sorted(release_sort_keys, key=release_sort_keys.__getitem__),
    )

    profiles_by_key = {item["selection_key"]: item for item in record["profiles"]}
    families_by_key = {item["selection_key"]: item for item in record["profile_families"]}
    bindings_by_key = {item["selection_key"]: item for item in record["environment_bindings"]}
    if set(profiles_by_key) != set(selected_keys) or set(families_by_key) != set(selected_keys) or set(bindings_by_key) != set(selected_keys):
        fail("coordinate-accounting-mismatch", "every selected archetype requires one family, profile, and recipe binding", source)

    required_roles = {item["selection_key"]: set(item["required_node_roles"]) for item in selection["selected_archetypes"]}
    required_strategy = {item["selection_key"]: item["required_environment_strategy"] for item in selection["selected_archetypes"]}
    for key in selected_keys:
        profile = profiles_by_key[key]
        family = families_by_key[key]
        binding = bindings_by_key[key]
        if profile["profile_family_id"] != family["profile_family_id"] or family["profile_family_id"] not in family_ids:
            fail("coordinate-profile-family-mismatch", f"profile family mismatch for {key}", source)
        node_keys = [node["node_key"] for node in profile["nodes"]]
        _require_unique("profile node keys", node_keys, source)
        if profile["root_node"] not in node_keys:
            fail("coordinate-root-node-missing", f"root node is absent for {key}", source)
        expected_node_keys = [profile["root_node"], *sorted(item for item in node_keys if item != profile["root_node"])]
        _require_order(
            f"profile nodes for {key}",
            node_keys,
            source,
            expected=expected_node_keys,
        )
        edge_order = [(item["from"], item["relation"], item["to"]) for item in profile["edges"]]
        _require_order(f"profile edges for {key}", edge_order, source)

        roles: set[str] = set()
        for node in profile["nodes"]:
            roles.update(node["roles"])
            release = release_by_id.get(node["release_id"])
            if release is None or release["component_id"] != node["component_id"] or node["component_id"] not in component_by_id:
                fail("coordinate-node-release-mismatch", f"node release/component mismatch for {key}", source)
            _require_unique("profile node roles", node["roles"], source)
            _require_unique("profile facet names", [item["name"] for item in node["facets"]], source)
        if not required_roles[key].issubset(roles):
            missing = sorted(required_roles[key] - roles)
            fail("coordinate-role-coverage-missing", f"{key} lacks required roles: {', '.join(missing)}", source)
        for edge in profile["edges"]:
            if edge["from"] not in node_keys or edge["to"] not in node_keys:
                fail("coordinate-edge-node-unknown", f"profile edge references an unknown node for {key}", source)
        if binding["profile_id"] != profile["profile_id"] or binding["strategy"] != required_strategy[key]:
            fail("coordinate-environment-binding-mismatch", f"environment binding mismatch for {key}", source)
        root = next(item for item in profile["nodes"] if item["node_key"] == profile["root_node"])
        if binding["target_release_id"] != root["release_id"]:
            fail("coordinate-root-release-mismatch", f"environment target is not the root release for {key}", source)


def validate_certified_environment_recipe(
    record: dict[str, Any], *, coordinates: dict[str, Any], registry: NamespaceRegistry, source: str
) -> None:
    if record["recipe_schema_family_id"] != RECIPE_SCHEMA_FAMILY_ID:
        fail("recipe-schema-family-mismatch", "recipe uses the wrong schema family", source)
    for field, namespace, mode in (
        ("environment_recipe_id", "environment-recipe", "u7"),
        ("recipe_revision_id", "environment-recipe-revision", "h"),
        ("target_profile_id", "profile", "u7"),
        ("target_release_id", "release", "u7"),
    ):
        parsed = registry.validate(record[field])
        if (parsed.scheme, parsed.namespace, parsed.mode) != ("rcid", namespace, mode):
            fail("recipe-namespace-mismatch", f"{field} uses the wrong identity namespace", source)
    if record["recipe_revision_id"] != environment_recipe_revision(record):
        fail("recipe-revision-mismatch", "recipe revision does not match its canonical identity projection", source)
    if record["isolation_policy"]["digest"] != isolation_policy_digest(record["isolation_policy"]):
        fail("isolation-policy-digest-mismatch", "isolation policy digest does not match canonical policy bytes", source)

    binding = next((item for item in coordinates["environment_bindings"] if item["selection_key"] == record["selection_key"]), None)
    if binding is None:
        fail("recipe-selection-unknown", "recipe does not bind a selected archetype", source)
    expected = (binding["environment_recipe_id"], binding["profile_id"], binding["target_release_id"], binding["strategy"])
    actual = (record["environment_recipe_id"], record["target_profile_id"], record["target_release_id"], record["strategy"])
    if actual != expected:
        fail("recipe-coordinate-mismatch", "recipe execution coordinates do not match the profile binding", source)

    _require_sorted_unique("artifact names", record["artifacts"], "name", source)
    _require_sorted_unique("runtime fact names", record["expected_runtime_facts"], "name", source)
    _require_sorted_unique("configuration names", record["expected_configuration"], "name", source)
    _require_sorted_unique("construction parameter names", record["construction"]["parameters"], "name", source)
    for label in ("required_capabilities", "smoke_probe_ids"):
        if record[label] != sorted(record[label]) or len(record[label]) != len(set(record[label])):
            fail("recipe-order-nondeterministic", f"{label} must be unique and code-point sorted", source)
    for artifact in record["artifacts"]:
        for locator in artifact["locators"]:
            lowered = locator.lower()
            if any(alias in lowered for alias in (":latest", "/latest", "/current")):
                fail("recipe-mutable-locator", "mutable artifact aliases are forbidden", source)
    if record["construction"]["hermeticity"] == "bounded-host-toolchain" and not any(
        item["name"] == "toolchain-bound" for item in record["construction"]["parameters"]
    ):
        fail("recipe-nonhermetic-bound-missing", "bounded host builds must state the admitted toolchain boundary", source)
    if record["isolation_policy"]["runtime_network"] != "none":
        fail("recipe-runtime-network-unsafe", "certified runtime network must be disabled", source)


def validate_minimal_environment_certification(
    record: dict[str, Any],
    *,
    coordinates: dict[str, Any],
    recipes_by_key: dict[str, dict[str, Any]],
    source: str,
) -> None:
    digest = record["evidence_sha256"]
    expected_filename = f"minimal-environment-certification-sha256-{digest}.json"
    if record["evidence_filename"] != expected_filename:
        fail("certification-evidence-reference-mismatch", "evidence filename does not encode its declared digest", source)

    expected_keys = [item["selection_key"] for item in coordinates["environment_bindings"]]
    result_keys = [item["selection_key"] for item in record["results"]]
    if result_keys != expected_keys:
        fail("certification-accounting-mismatch", "certificate results do not use the exact coordinate order", source)
    fingerprints = [item["environment_fingerprint_id"] for item in record["results"]]
    if len(fingerprints) != len(set(fingerprints)):
        fail("certification-fingerprint-collision", "realized environment fingerprints must be unique", source)

    bindings_by_key = {item["selection_key"]: item for item in coordinates["environment_bindings"]}
    for result in record["results"]:
        key = result["selection_key"]
        recipe = recipes_by_key.get(key)
        binding = bindings_by_key.get(key)
        if recipe is None or binding is None:
            fail("certification-accounting-mismatch", f"certificate result has no recipe binding for {key}", source)
        expected = (
            recipe["recipe_revision_id"],
            binding["profile_id"],
            binding["target_release_id"],
        )
        actual = (result["recipe_revision_id"], result["target_profile_id"], result["target_release_id"])
        if actual != expected:
            fail("certification-coordinate-mismatch", f"certificate result does not match exact coordinates for {key}", source)


def load_and_validate_environment_records(root: Path, *, validate_instance: Any) -> dict[str, int]:
    schemas = root / "schemas" / "json"
    registry = NamespaceRegistry.load(root / "registries" / "identity" / "namespaces.v1.json")
    selection = load_strict(root / "registries" / "profiles" / "vertical-slice-archetypes.v1.json")
    coordinate_path = root / "registries" / "profiles" / "vertical-slice-coordinates.v1.json"
    coordinate_source = "registries/profiles/vertical-slice-coordinates.v1.json"
    if selection["authority"].get("coordinate_registry_path") != coordinate_source:
        fail("selection-coordinate-source-mismatch", "selection authority does not bind the canonical coordinate registry", str(coordinate_path))
    policy = selection["selection_policy"]
    if (
        policy.get("canonical_execution_coordinates_allocated") is not True
        or policy.get("execution_eligible") is not True
        or policy.get("exact_coordinates_source") != coordinate_source
    ):
        fail("selection-not-execution-eligible", "vertical-slice selection is not activated against its coordinate registry", str(coordinate_path))
    coordinates = load_strict(coordinate_path)
    validate_instance(coordinates, load_strict(schemas / "vertical-slice-coordinates.schema.json"), source=str(coordinate_path))
    validate_vertical_slice_coordinates(coordinates, selection=selection, registry=registry, source=str(coordinate_path))
    recipe_paths = sorted((root / "environments" / "recipes").glob("*.json"))
    seen_ids: set[str] = set()
    seen_revisions: set[str] = set()
    seen_keys: set[str] = set()
    recipes_by_key: dict[str, dict[str, Any]] = {}
    recipe_schema = load_strict(schemas / "certified-environment-recipe.schema.json")
    for path in recipe_paths:
        record = load_strict(path)
        validate_instance(record, recipe_schema, source=str(path))
        validate_certified_environment_recipe(record, coordinates=coordinates, registry=registry, source=str(path))
        for value, ledger, label in (
            (record["environment_recipe_id"], seen_ids, "recipe ID"),
            (record["recipe_revision_id"], seen_revisions, "recipe revision"),
            (record["selection_key"], seen_keys, "recipe selection"),
        ):
            if value in ledger:
                fail("recipe-identity-collision", f"duplicate {label}: {value}", str(path))
            ledger.add(value)
        recipes_by_key[record["selection_key"]] = record
    expected_keys = {item["selection_key"] for item in coordinates["environment_bindings"]}
    if seen_keys != expected_keys:
        fail("recipe-accounting-mismatch", "recipe set does not exactly cover vertical-slice bindings", str(root / "environments" / "recipes"))

    certification_path = root / "reports" / "vertical-slice" / "minimal-environment-certification.json"
    certification = load_strict(certification_path)
    validate_instance(certification, load_strict(schemas / "minimal-environment-certification.schema.json"), source=str(certification_path))
    validate_minimal_environment_certification(
        certification,
        coordinates=coordinates,
        recipes_by_key=recipes_by_key,
        source=str(certification_path),
    )
    return {"vertical_slice_coordinates": 1, "certified_environment_recipes": len(recipe_paths), "minimal_environment_certifications": 1}


def _require_unique(label: str, values: list[str], source: str) -> None:
    if len(values) != len(set(values)):
        fail("coordinate-identity-collision", f"{label} must be unique", source)


def _require_order(label: str, values: list[Any], source: str, *, expected: list[Any] | None = None) -> None:
    if expected is None:
        expected = sorted(values)
    if values != expected:
        fail("coordinate-order-nondeterministic", f"{label} do not use their canonical order", source)


def _require_sorted_unique(label: str, values: list[dict[str, Any]], key: str, source: str) -> None:
    names = [item[key] for item in values]
    if names != sorted(names) or len(names) != len(set(names)):
        fail("recipe-order-nondeterministic", f"{label} must be unique and code-point sorted", source)
