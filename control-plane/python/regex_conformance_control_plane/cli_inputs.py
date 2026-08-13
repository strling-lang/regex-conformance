"""Strict bounded request decoding for the Control Plane CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

from .cache_models import CacheEntry
from .environment_models import ArtifactRequirement, EnvironmentRecipe, NamedValue
from .resource_models import ResourceEstimate, TransferForecast
from .state_models import canonical_json


MAXIMUM_REQUEST_BYTES = 1024 * 1024


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def load_request(path: str) -> Any:
    selected = Path(path)
    try:
        before = selected.lstat()
    except OSError as error:
        raise ValueError("request file cannot be inspected") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError("request input must be a regular non-symlink file")
    if before.st_size > MAXIMUM_REQUEST_BYTES:
        raise ValueError("request input exceeds the 1 MiB limit")
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(selected, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("request input must be a regular non-symlink file")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("request input was substituted before it was read")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            encoded = source.read(MAXIMUM_REQUEST_BYTES + 1)
            after = os.fstat(source.fileno())
        final = selected.lstat()
        if len(encoded) > MAXIMUM_REQUEST_BYTES:
            raise ValueError("request input exceeds the 1 MiB limit")
        value = json.loads(encoded.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("request input is not strict UTF-8 JSON") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if identity != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
        raise ValueError("request input changed while it was read")
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("request input changed while it was read")
    if identity != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) or stat.S_ISLNK(final.st_mode):
        raise ValueError("request input changed while it was read")
    canonical_json(value)
    return value


def _object(value: Any, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    unexpected = set(value) - keys
    missing = keys - set(value)
    if unexpected or missing:
        raise ValueError(f"{label} fields are incomplete or unexpected")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be an array of strings")
    return tuple(value)


def load_environment_recipe(path: str) -> EnvironmentRecipe:
    value = _object(
        load_request(path),
        "environment recipe",
        {
            "artifacts",
            "expected_configuration",
            "expected_runtime_facts",
            "isolation_policy_digest",
            "network_policy",
            "recipe_revision_id",
            "required_capabilities",
            "smoke_probe_ids",
            "strategy",
            "target_profile_id",
            "target_release_id",
        },
    )
    if not isinstance(value["artifacts"], list):
        raise ValueError("environment recipe artifacts must be an array")
    artifacts = tuple(
        ArtifactRequirement(
            **{
                **_object(item, "artifact requirement", {"locators", "media_type", "name", "sha256", "size_bytes"}),
                "locators": _strings(item["locators"], "artifact locators"),
            }
        )
        for item in value["artifacts"]
    )

    def facts(name: str) -> tuple[NamedValue, ...]:
        selected = value[name]
        if not isinstance(selected, list):
            raise ValueError(f"{name} must be an array")
        return tuple(NamedValue(**_object(item, name, {"name", "value"})) for item in selected)

    return EnvironmentRecipe(
        recipe_revision_id=value["recipe_revision_id"],
        target_profile_id=value["target_profile_id"],
        target_release_id=value["target_release_id"],
        strategy=value["strategy"],
        artifacts=artifacts,
        expected_runtime_facts=facts("expected_runtime_facts"),
        expected_configuration=facts("expected_configuration"),
        required_capabilities=_strings(value["required_capabilities"], "required capabilities"),
        smoke_probe_ids=_strings(value["smoke_probe_ids"], "smoke probe IDs"),
        isolation_policy_digest=value["isolation_policy_digest"],
        network_policy=value["network_policy"],
    )


def load_resource_request(path: str) -> dict[str, Any]:
    value = _object(
        load_request(path),
        "resource request",
        {
            "eligible_trust_classes",
            "estimates",
            "operation_id",
            "provider_name",
            "provider_strategy",
            "requested_concurrency",
            "required_capabilities",
            "transfers",
        },
    )
    if not isinstance(value["estimates"], list) or not isinstance(value["transfers"], list):
        raise ValueError("resource estimates and transfers must be arrays")
    estimate_keys = {"confidence", "diagnostic", "expected", "name", "pool_kind", "source", "unit", "upper_bound"}
    transfer_keys = {
        "confidence",
        "diagnostic",
        "direction",
        "expected_bytes",
        "name",
        "source",
        "upper_bound_bytes",
    }
    return {
        "operation_id": value["operation_id"],
        "estimates": tuple(ResourceEstimate(**_object(item, "resource estimate", estimate_keys)) for item in value["estimates"]),
        "transfers": tuple(TransferForecast(**_object(item, "transfer forecast", transfer_keys)) for item in value["transfers"]),
        "provider_name": value["provider_name"],
        "provider_strategy": value["provider_strategy"],
        "required_capabilities": _strings(value["required_capabilities"], "required capabilities"),
        "eligible_trust_classes": _strings(value["eligible_trust_classes"], "eligible trust classes"),
        "requested_concurrency": value["requested_concurrency"],
    }


def load_cache_entries(path: str) -> tuple[CacheEntry, ...]:
    value = _object(load_request(path), "cache inventory request", {"entries"})
    if not isinstance(value["entries"], list):
        raise ValueError("cache entries must be an array")
    keys = {
        "accounting_basis", "active_leases", "cache_key", "content_id", "dependencies", "future_dependencies",
        "kind", "last_used_at", "observed_at", "pinned", "provider_name", "reacquisition_cost_microunits",
        "reacquisition_time_seconds", "reclaimable_bytes", "reconstruction_difficulty", "registry_authority",
        "relative_path", "retention_class", "sha256", "size_bytes", "source", "staleness_seconds",
        "upstream_fragility", "verification_status", "verified_at",
    }
    result = []
    for item in value["entries"]:
        selected = _object(item, "cache entry", keys)
        result.append(
            CacheEntry(
                **{
                    **selected,
                    "active_leases": _strings(selected["active_leases"], "active leases"),
                    "future_dependencies": _strings(selected["future_dependencies"], "future dependencies"),
                    "dependencies": _strings(selected["dependencies"], "cache dependencies"),
                }
            )
        )
    return tuple(result)
