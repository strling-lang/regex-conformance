"""Compile the first vertical slice into proof-bearing immutable coordinates."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from regex_conformance_matrix import compile_candidates
from regex_conformance_scheduler import shard_by_selection_locality
from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.profile import IdentityProfile
from regex_conformance_schema.schema import validate_instance


SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:019ffbeb-56fb-7745-8720-61ac3f7877d6"


class CampaignCompileError(ValueError):
    """Campaign inputs cannot produce one deterministic, complete denominator."""


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _content_id(root: Path, namespace: str, kind: str, identity: Any) -> str:
    registry = NamespaceRegistry.load(root / "registries" / "identity" / "namespaces.v1.json")
    profile = IdentityProfile.from_record(
        load_strict(root / "schemas" / "identity-profiles" / "campaign-content.v1.json")
    )
    result = build_content_identity(
        registry=registry,
        profile=profile,
        namespace=namespace,
        identity_schema_family_id=SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity={"artifact_kind": kind, "content_sha256": _digest(identity)},
    )
    return str(result["content_id"])


def _by_key(records: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        value = record[key]
        if value in result:
            raise CampaignCompileError(f"duplicate {label} {value!r}")
        result[value] = record
    return result


def _request_semantics(
    definition: dict[str, Any],
    vector: dict[str, Any],
    inputs: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    identity = manifest["identity"]
    return {
        "adapter_release_manifest_id": manifest["adapter_release_manifest_id"],
        "callback_fixture": None,
        "environment_inputs": inputs["dimensions"],
        "initial_state": {"occurrence": 1, "start_offset": 0},
        "limits": definition["limits"],
        "message_type": "execute",
        "operation": {"name": definition["operation"], "version": "1.0.0"},
        "options": inputs["options"],
        "pattern": vector["pattern"],
        "profile_id": identity["profile"],
        "replacement": None,
        "requested_observations": definition["requested_observations"],
        "schema_version": "adapter-request.v1",
        "subjects": [vector["subject"]],
        "target_release_id": identity["target_release"],
    }


def compile_vertical_slice(root: Path, *, _verify: bool = True) -> dict[str, Any]:
    root = root.resolve()
    definition_path = root / "campaigns" / "definitions" / "first-vertical-slice.v1.json"
    definition = load_strict(definition_path)
    validate_instance(
        definition,
        load_strict(root / "schemas" / "json" / "vertical-slice-campaign-definition.schema.json"),
        source=str(definition_path),
    )
    coordinates_path = root / "registries" / "profiles" / "vertical-slice-coordinates.v1.json"
    coordinates = load_strict(coordinates_path)
    vector_path = root / definition["vector_source"]
    vector_set = load_strict(vector_path)
    validate_instance(
        vector_set,
        load_strict(root / "schemas" / "json" / "probe-vector-set.schema.json"),
        source=str(vector_path),
    )
    applicability_path = root / definition["applicability_source"]
    applicability = load_strict(applicability_path)
    validate_instance(
        applicability,
        load_strict(root / "schemas" / "json" / "applicability-policy.schema.json"),
        source=str(applicability_path),
    )
    if vector_set["classification"]["probe_only"] != definition["classification"]["probe_only"]:
        raise CampaignCompileError("campaign and vector classifications disagree")
    profiles = _by_key(coordinates["profiles"], "selection_key", "profile")
    bindings = _by_key(coordinates["environment_bindings"], "selection_key", "environment binding")
    inputs = _by_key(definition["profile_inputs"], "selection_key", "profile input")
    selected = sorted(profiles)
    if selected != sorted(bindings) or selected != sorted(inputs):
        raise CampaignCompileError("profile, environment, and input selections do not form the same closed set")

    manifest_paths = {key: root / "adapters" / "manifests" / f"{key}.v1.json" for key in selected}
    recipe_paths = {
        "mysql-regex": root / "environments" / "recipes" / "mysql-8.4.10-linux-amd64.v1.json",
        "pcre2-ordinary": root / "environments" / "recipes" / "pcre2-10.47-linux-x86-64.v1.json",
        "python-re": root / "environments" / "recipes" / "cpython-3.14.6-linux-24.04-x64.v1.json",
    }
    manifests = {key: load_strict(path) for key, path in manifest_paths.items()}
    recipes = {key: load_strict(path) for key, path in recipe_paths.items()}
    for key in selected:
        if manifests[key]["identity"]["profile"] != profiles[key]["profile_id"]:
            raise CampaignCompileError(f"adapter profile mismatch for {key}")
        if recipes[key]["recipe_revision_id"] is None or bindings[key]["profile_id"] != profiles[key]["profile_id"]:
            raise CampaignCompileError(f"environment binding mismatch for {key}")

    implementation_paths = (
        root / "campaigns" / "python" / "regex_conformance_campaign" / "compiler.py",
        root / "control-plane" / "python" / "regex_conformance_control_plane" / "campaign_manager.py",
        root / "matrix" / "python" / "regex_conformance_matrix" / "applicability.py",
        root / "scheduler" / "python" / "regex_conformance_scheduler" / "sharding.py",
        root / "tools" / "campaigns" / "run_vertical_slice.py",
        root / "verifier" / "python" / "regex_conformance_verifier" / "evidence.py",
        root / "warehouse" / "python" / "regex_conformance_warehouse" / "builder.py",
    )
    contract_paths = (
        root / "registries" / "identity" / "namespaces.v1.json",
        root / "schemas" / "identity-profiles" / "campaign-content.v1.json",
        root / "schemas" / "json" / "adapter-request.schema.json",
        root / "schemas" / "json" / "adapter-response.schema.json",
        root / "schemas" / "json" / "compiled-campaign.schema.json",
    )
    source_paths = [
        definition_path, coordinates_path, vector_path, applicability_path,
        *manifest_paths.values(), *recipe_paths.values(), *implementation_paths, *contract_paths,
    ]
    source_digests = {
        path.relative_to(root).as_posix(): _file_digest(path) for path in sorted(source_paths)
    }
    definition_revision_id = _content_id(root, "campaign-definition-revision", "campaign-definition", definition)
    applicability_policy_id = _content_id(root, "applicability-policy", "applicability-policy", applicability)

    vectors: list[tuple[dict[str, Any], str]] = []
    for vector in sorted(vector_set["vectors"], key=lambda item: item["key"]):
        revision_identity = {key: vector[key] for key in ("vector_id", "key", "domain", "pattern", "subject")}
        vectors.append((vector, _content_id(root, "vector-revision", "vector-revision", revision_identity)))

    candidates = compile_candidates(profiles, vectors, applicability, applicability_policy_id)
    candidates_by_key = {item["candidate_key"]: item for item in candidates}
    logical_executions: list[dict[str, Any]] = []
    for selection_key in selected:
        profile = profiles[selection_key]
        manifest = manifests[selection_key]
        recipe = recipes[selection_key]
        for vector, vector_revision_id in vectors:
            candidate_key = f"{selection_key}:{vector['key']}"
            if candidates_by_key[candidate_key]["applicability"] != "included":
                continue
            semantics = _request_semantics(definition, vector, inputs[selection_key], manifest)
            identity = {
                "adapter_release_manifest_id": manifest["adapter_release_manifest_id"],
                "applicability_policy_id": applicability_policy_id,
                "candidate_key": candidate_key,
                "environment_recipe_revision_id": recipe["recipe_revision_id"],
                "profile_id": profile["profile_id"],
                "protocol_revision_id": manifest["identity"]["protocol_revision"],
                "request_semantics_sha256": _digest(semantics),
                "target_release_id": manifest["identity"]["target_release"],
                "vector_revision_id": vector_revision_id,
            }
            logical_id = _content_id(root, "logical-execution", "logical-execution-v2", identity)
            request = dict(semantics)
            request["correlation_id"] = logical_id
            request["trace_reference"] = f"campaign:{definition['campaign_id']}:{logical_id}"
            logical_executions.append(
                {
                    "logical_execution_id": logical_id,
                    "selection_key": selection_key,
                    "profile_id": profile["profile_id"],
                    "target_release_id": manifest["identity"]["target_release"],
                    "vector_revision_id": vector_revision_id,
                    "request": request,
                }
            )

    logical_executions.sort(key=lambda item: item["logical_execution_id"])
    exclusions = [item for item in candidates if item["applicability"] == "excluded"]
    exclusion_ledger_id = _content_id(root, "exclusion-ledger", "exclusion-ledger", exclusions)
    matrix_identity = {
        "applicability_policy_id": applicability_policy_id,
        "candidates": candidates,
        "definition_revision_id": definition_revision_id,
        "exclusion_ledger_id": exclusion_ledger_id,
        "logical_execution_ids": [item["logical_execution_id"] for item in logical_executions],
    }
    matrix_id = _content_id(root, "matrix", "matrix", matrix_identity)

    shards = shard_by_selection_locality(
        logical_executions,
        definition["shard_size"],
        lambda value: _content_id(root, "shard", "bounded-locality-shard", value),
    )
    denominator = {
        "candidate_count": len(candidates),
        "excluded_count": len(exclusions),
        "included_count": len(logical_executions),
        "invalid_count": 0,
        "unresolved_count": 0,
    }
    if denominator["candidate_count"] != denominator["included_count"] + denominator["excluded_count"]:
        raise CampaignCompileError("candidate denominator does not reconcile")
    manifest_body = {
        "applicability_policy_id": applicability_policy_id,
        "campaign_definition_revision_id": definition_revision_id,
        "campaign_id": definition["campaign_id"],
        "classification": definition["classification"],
        "denominator": denominator,
        "exclusion_ledger_id": exclusion_ledger_id,
        "logical_execution_ids": [item["logical_execution_id"] for item in logical_executions],
        "matrix_id": matrix_id,
        "policy": {
            "attempts_are_append_only": True,
            "infrastructure_failure_is_observation": False,
            "maximum_attempts_per_logical_execution": 1,
            "sharding": "bounded-selection-locality-then-logical-id-v1",
        },
        "shard_ids": [item["shard_id"] for item in shards],
        "source_digests": source_digests,
    }
    campaign_manifest_id = _content_id(root, "campaign-manifest", "campaign-manifest-v1", manifest_body)
    compiled = {
        "schema_version": "compiled-campaign.v1",
        "campaign_definition_id": definition["campaign_definition_id"],
        "campaign_definition_revision_id": definition_revision_id,
        "campaign_id": definition["campaign_id"],
        "campaign_manifest_id": campaign_manifest_id,
        "classification": definition["classification"],
        "source_digests": source_digests,
        "applicability_policy_id": applicability_policy_id,
        "matrix_id": matrix_id,
        "exclusion_ledger_id": exclusion_ledger_id,
        "candidates": candidates,
        "logical_executions": logical_executions,
        "shards": shards,
        "denominator": denominator,
        "campaign_manifest": {"campaign_manifest_id": campaign_manifest_id, **manifest_body},
    }
    if _verify:
        verify_compiled_campaign(root, compiled)
    return compiled


def verify_compiled_campaign(root: Path, compiled: dict[str, Any]) -> None:
    validate_instance(
        compiled,
        load_strict(root / "schemas" / "json" / "compiled-campaign.schema.json"),
        source="compiled campaign",
    )
    logical_ids = [item["logical_execution_id"] for item in compiled["logical_executions"]]
    if logical_ids != sorted(logical_ids) or len(logical_ids) != len(set(logical_ids)):
        raise CampaignCompileError("logical execution IDs must be unique and ordered")
    shard_members = [member for shard in compiled["shards"] for member in shard["logical_execution_ids"]]
    if sorted(shard_members) != logical_ids:
        raise CampaignCompileError("shards do not partition the logical execution set exactly")
    if len(shard_members) != len(set(shard_members)):
        raise CampaignCompileError("logical execution appears in more than one shard")
    denominator = compiled["denominator"]
    states = [item["applicability"] for item in compiled["candidates"]]
    if denominator != {
        "candidate_count": len(states),
        "excluded_count": states.count("excluded"),
        "included_count": len(logical_ids),
        "invalid_count": 0,
        "unresolved_count": 0,
    }:
        raise CampaignCompileError("compiled denominator is inconsistent")
    manifest = dict(compiled["campaign_manifest"])
    claimed = manifest.pop("campaign_manifest_id")
    if claimed != compiled["campaign_manifest_id"] or claimed != _content_id(
        root, "campaign-manifest", "campaign-manifest-v1", manifest
    ):
        raise CampaignCompileError("campaign manifest identity does not match its content")
    if manifest["logical_execution_ids"] != logical_ids:
        raise CampaignCompileError("campaign manifest logical order differs from compiled matrix")
    for relative, digest in compiled["source_digests"].items():
        path = (root / relative).resolve(strict=True)
        path.relative_to(root.resolve())
        if _file_digest(path) != digest:
            raise CampaignCompileError(f"source digest changed for {relative}")
    expected = compile_vertical_slice(root, _verify=False)
    if canonical_bytes(compiled) != canonical_bytes(expected):
        raise CampaignCompileError("compiled campaign differs from deterministic source compilation")
