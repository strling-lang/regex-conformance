"""Compile the broader P18 probe/profile slice without mutating frozen P17 inputs."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from regex_conformance_campaign.compiler import _content_id, _digest
from regex_conformance_matrix import compile_candidates
from regex_conformance_scheduler import shard_by_selection_locality
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance


REQUIRED_CATEGORIES = (
    "capture",
    "error",
    "iteration",
    "profile-differential",
    "rejection",
    "replacement",
    "success",
    "timeout",
    "unicode",
)


class QualificationCompileError(ValueError):
    """The qualification inputs do not form a closed deterministic plan."""


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_assigned(
    registry: NamespaceRegistry, value: str, namespace: str, label: str
) -> None:
    parsed = registry.validate(value)
    if (parsed.scheme, parsed.namespace, parsed.mode) != ("rcid", namespace, "u7"):
        raise QualificationCompileError(
            f"{label} must be an assigned {namespace} identifier"
        )


def _by_key(records: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        value = record[key]
        if value in result:
            raise QualificationCompileError(f"duplicate {label} {value!r}")
        result[value] = record
    return result


def _sorted_named(values: list[dict[str, Any]], label: str) -> list[dict[str, Any]]:
    names = [item["name"] for item in values]
    if names != sorted(names) or len(names) != len(set(names)):
        raise QualificationCompileError(f"{label} must have unique code-point-sorted names")
    return values


def _merge_profiles(root: Path, definition: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    base_path = root / definition["base_coordinates_source"]
    overlay_path = root / definition["profile_overlay_source"]
    base = load_strict(base_path)
    overlay = load_strict(overlay_path)
    validate_instance(
        overlay,
        load_strict(root / "schemas" / "json" / "qualification-profile-overlay.schema.json"),
        source=str(overlay_path),
    )
    if overlay["base_coordinates"] != {
        "path": definition["base_coordinates_source"],
        "sha256": _file_digest(base_path),
    }:
        raise QualificationCompileError("profile overlay does not bind the exact frozen base coordinates")
    profiles = _by_key([*base["profiles"], *overlay["profiles"]], "selection_key", "profile")
    bindings = _by_key(
        [*base["environment_bindings"], *overlay["environment_bindings"]],
        "selection_key",
        "environment binding",
    )
    families = _by_key(
        [*base["profile_families"], *overlay["profile_families"]],
        "selection_key",
        "profile family",
    )
    if set(profiles) != set(bindings) or set(profiles) != set(families):
        raise QualificationCompileError("merged profiles, families, and environment bindings are not closed")
    return profiles, bindings, overlay


def _request_semantics(
    vector: dict[str, Any], profile_input: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    options = [*profile_input["options"], *vector["options"]]
    _sorted_named(options, "merged request options")
    return {
        "adapter_release_manifest_id": manifest["adapter_release_manifest_id"],
        "callback_fixture": vector["callback_fixture"],
        "environment_inputs": profile_input["dimensions"],
        "initial_state": vector["initial_state"],
        "limits": vector["limits"],
        "message_type": "execute",
        "operation": vector["operation"],
        "options": options,
        "pattern": vector["pattern"],
        "profile_id": manifest["identity"]["profile"],
        "replacement": vector["replacement"],
        "requested_observations": vector["requested_observations"],
        "schema_version": "adapter-request.v1",
        "subjects": vector["subjects"],
        "target_release_id": manifest["identity"]["target_release"],
    }


def compile_qualification(root: Path, *, _verify: bool = True) -> dict[str, Any]:
    root = root.resolve()
    definition_path = root / "campaigns" / "definitions" / "small-scale-qualification.v1.json"
    definition = load_strict(definition_path)
    validate_instance(
        definition,
        load_strict(root / "schemas" / "json" / "small-scale-campaign-definition.schema.json"),
        source=str(definition_path),
    )
    registry = NamespaceRegistry.load(
        root / "registries" / "identity" / "namespaces.v1.json"
    )
    _require_assigned(
        registry,
        definition["campaign_definition_id"],
        "campaign-definition",
        "campaign definition ID",
    )
    _require_assigned(
        registry, definition["campaign_id"], "campaign", "campaign ID"
    )
    profiles, bindings, overlay = _merge_profiles(root, definition)
    inputs = _by_key(definition["profile_inputs"], "selection_key", "profile input")
    if list(inputs) != sorted(inputs) or set(inputs) != set(profiles):
        raise QualificationCompileError(
            "profile inputs must deterministically and exactly cover merged profiles"
        )
    for key, value in inputs.items():
        _sorted_named(value["dimensions"], f"{key} environment inputs")
        _sorted_named(value["options"], f"{key} default options")

    vector_path = root / definition["vector_source"]
    vector_set = load_strict(vector_path)
    validate_instance(
        vector_set,
        load_strict(root / "schemas" / "json" / "qualification-probe-vector-set.schema.json"),
        source=str(vector_path),
    )
    _require_assigned(
        registry,
        vector_set["vector_family_id"],
        "vector-family",
        "vector family ID",
    )
    vectors_by_key = _by_key(vector_set["vectors"], "key", "vector")
    if list(vectors_by_key) != sorted(vectors_by_key):
        raise QualificationCompileError("qualification vectors must use deterministic key order")
    vector_ids = [item["vector_id"] for item in vector_set["vectors"]]
    if len(vector_ids) != len(set(vector_ids)):
        raise QualificationCompileError("qualification vector IDs contain a collision")
    for vector in vector_set["vectors"]:
        _require_assigned(registry, vector["vector_id"], "vector", "vector ID")
        if vector["qualification_categories"] != sorted(vector["qualification_categories"]):
            raise QualificationCompileError(f"qualification categories are not ordered for {vector['key']}")
        _sorted_named(vector["options"], f"{vector['key']} options")
        observations = vector["requested_observations"]
        if observations != sorted(observations):
            raise QualificationCompileError(
                f"requested observations are not ordered for {vector['key']}"
            )
        if any(item["domain"] != vector["domain"] for item in [vector["pattern"], *vector["subjects"]]):
            raise QualificationCompileError(f"datum domain mismatch for {vector['key']}")
        if vector["replacement"] is not None and vector["replacement"]["domain"] != vector["domain"]:
            raise QualificationCompileError(f"replacement domain mismatch for {vector['key']}")

    applicability_path = root / definition["applicability_source"]
    applicability = load_strict(applicability_path)
    validate_instance(
        applicability,
        load_strict(root / "schemas" / "json" / "applicability-policy.schema.json"),
        source=str(applicability_path),
    )
    rule_order = [(item["selection_key"], item["vector_key"], item["rule_key"]) for item in applicability["rules"]]
    if rule_order != sorted(rule_order):
        raise QualificationCompileError("qualification applicability rules are not deterministically ordered")

    manifest_paths = {
        "mysql-regex": root / "adapters" / "manifests" / "mysql-regex.v1.json",
        "pcre2-dfa": root / "adapters" / "qualification-manifests" / "pcre2-dfa.v1.json",
        "pcre2-ordinary": root / "adapters" / "manifests" / "pcre2-ordinary.v1.json",
        "python-re": root / "adapters" / "manifests" / "python-re.v1.json",
    }
    recipe_paths = {
        "mysql-regex": root / "environments" / "recipes" / "mysql-8.4.10-linux-amd64.v1.json",
        "pcre2-dfa": root / overlay["environment_bindings"][0]["recipe_path"],
        "pcre2-ordinary": root / "environments" / "recipes" / "pcre2-10.47-linux-x86-64.v1.json",
        "python-re": root / "environments" / "recipes" / "cpython-3.14.6-linux-24.04-x64.v1.json",
    }
    manifests = {key: load_strict(path) for key, path in manifest_paths.items()}
    recipes = {key: load_strict(path) for key, path in recipe_paths.items()}
    for key in sorted(profiles):
        if manifests[key]["identity"]["profile"] != profiles[key]["profile_id"]:
            raise QualificationCompileError(f"adapter profile mismatch for {key}")
        binding = bindings[key]
        if (
            recipes[key]["environment_recipe_id"] != binding["environment_recipe_id"]
            or recipes[key]["target_profile_id"] != binding["profile_id"]
            or recipes[key]["target_release_id"] != binding["target_release_id"]
        ):
            raise QualificationCompileError(f"environment recipe mismatch for {key}")

    vector_revisions = [
        (vector, _content_id(root, "vector-revision", "qualification-vector-revision", vector))
        for vector in vector_set["vectors"]
    ]
    applicability_policy_id = _content_id(
        root, "applicability-policy", "qualification-applicability-policy", applicability
    )
    candidates = compile_candidates(profiles, vector_revisions, applicability, applicability_policy_id)
    candidates_by_key = {item["candidate_key"]: item for item in candidates}
    logical_executions: list[dict[str, Any]] = []
    for selection_key in sorted(profiles):
        for vector, vector_revision_id in vector_revisions:
            candidate_key = f"{selection_key}:{vector['key']}"
            if candidates_by_key[candidate_key]["applicability"] != "included":
                continue
            manifest = manifests[selection_key]
            semantics = _request_semantics(vector, inputs[selection_key], manifest)
            identity = {
                "adapter_release_manifest_id": manifest["adapter_release_manifest_id"],
                "applicability_policy_id": applicability_policy_id,
                "candidate_key": candidate_key,
                "environment_recipe_revision_id": recipes[selection_key]["recipe_revision_id"],
                "profile_id": profiles[selection_key]["profile_id"],
                "protocol_revision_id": manifest["identity"]["protocol_revision"],
                "request_semantics_sha256": _digest(semantics),
                "target_release_id": manifest["identity"]["target_release"],
                "vector_revision_id": vector_revision_id,
            }
            logical_id = _content_id(root, "logical-execution", "qualification-logical-execution", identity)
            request = dict(semantics)
            request["correlation_id"] = logical_id
            request["trace_reference"] = f"campaign:{definition['campaign_id']}:{logical_id}"
            validate_instance(
                request,
                load_strict(root / "schemas" / "json" / "adapter-request.schema.json"),
                source=candidate_key,
            )
            logical_executions.append(
                {
                    "logical_execution_id": logical_id,
                    "selection_key": selection_key,
                    "profile_id": profiles[selection_key]["profile_id"],
                    "target_release_id": manifest["identity"]["target_release"],
                    "vector_revision_id": vector_revision_id,
                    "request": request,
                }
            )
    logical_executions.sort(key=lambda item: item["logical_execution_id"])
    exclusions = [item for item in candidates if item["applicability"] == "excluded"]
    exclusion_ledger_id = _content_id(root, "exclusion-ledger", "qualification-exclusion-ledger", exclusions)
    definition_revision_id = _content_id(
        root, "campaign-definition-revision", "small-scale-campaign-definition", definition
    )
    matrix_identity = {
        "applicability_policy_id": applicability_policy_id,
        "candidates": candidates,
        "definition_revision_id": definition_revision_id,
        "exclusion_ledger_id": exclusion_ledger_id,
        "logical_execution_ids": [item["logical_execution_id"] for item in logical_executions],
    }
    matrix_id = _content_id(root, "matrix", "qualification-matrix", matrix_identity)
    shards = shard_by_selection_locality(
        logical_executions,
        definition["shard_size"],
        lambda value: _content_id(root, "shard", "qualification-locality-shard", value),
    )
    implementation_paths = (
        root / "campaigns" / "python" / "regex_conformance_campaign" / "compiler.py",
        root / "campaigns" / "python" / "regex_conformance_qualification" / "compiler.py",
        root / "matrix" / "python" / "regex_conformance_matrix" / "applicability.py",
        root / "scheduler" / "python" / "regex_conformance_scheduler" / "sharding.py",
        root / "verifier" / "python" / "regex_conformance_verifier" / "evidence.py",
        root / "verifier" / "python" / "regex_conformance_verifier" / "result_verifier.py",
        root / "warehouse" / "python" / "regex_conformance_warehouse" / "builder.py",
    )
    source_paths = [
        definition_path,
        root / definition["base_coordinates_source"],
        root / definition["profile_overlay_source"],
        vector_path,
        applicability_path,
        *manifest_paths.values(),
        *recipe_paths.values(),
        *implementation_paths,
        root / "schemas" / "json" / "adapter-request.schema.json",
        root / "schemas" / "json" / "adapter-response.schema.json",
        root / "schemas" / "json" / "compiled-campaign.schema.json",
        root / "schemas" / "json" / "evidence-manifest.schema.json",
        root / "schemas" / "json" / "observation-content.schema.json",
        root / "schemas" / "json" / "physical-attempt-evidence.schema.json",
        root / "schemas" / "json" / "result-shard.schema.json",
    ]
    source_digests = {
        path.relative_to(root).as_posix(): _file_digest(path) for path in sorted(source_paths)
    }
    denominator = {
        "candidate_count": len(candidates),
        "excluded_count": len(exclusions),
        "included_count": len(logical_executions),
        "invalid_count": 0,
        "unresolved_count": 0,
    }
    if denominator["candidate_count"] != denominator["included_count"] + denominator["excluded_count"]:
        raise QualificationCompileError("qualification denominator does not reconcile")
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
    campaign_manifest_id = _content_id(
        root, "campaign-manifest", "small-scale-campaign-manifest", manifest_body
    )
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
        verify_compiled_qualification(root, compiled)
    return compiled


def verify_compiled_qualification(root: Path, compiled: dict[str, Any]) -> None:
    validate_instance(
        compiled,
        load_strict(root / "schemas" / "json" / "compiled-campaign.schema.json"),
        source="compiled qualification campaign",
    )
    logical_ids = [item["logical_execution_id"] for item in compiled["logical_executions"]]
    if logical_ids != sorted(logical_ids) or len(logical_ids) != len(set(logical_ids)):
        raise QualificationCompileError("qualification logical IDs are not unique and ordered")
    members = [member for shard in compiled["shards"] for member in shard["logical_execution_ids"]]
    if sorted(members) != logical_ids or len(members) != len(set(members)):
        raise QualificationCompileError("qualification shards do not partition logical executions")
    if compiled["denominator"]["candidate_count"] != (
        compiled["denominator"]["included_count"] + compiled["denominator"]["excluded_count"]
    ):
        raise QualificationCompileError("qualification denominator is inconsistent")
    for relative, digest in compiled["source_digests"].items():
        try:
            path = (root / relative).resolve(strict=True)
            path.relative_to(root.resolve())
        except (OSError, ValueError) as error:
            raise QualificationCompileError(
                f"qualification source path is unsafe or absent: {relative}"
            ) from error
        if _file_digest(path) != digest:
            raise QualificationCompileError(f"qualification source digest changed for {relative}")
    expected = compile_qualification(root, _verify=False)
    if canonical_bytes(compiled) != canonical_bytes(expected):
        raise QualificationCompileError("qualification campaign differs from deterministic compilation")


def build_coverage_report(root: Path, compiled: dict[str, Any]) -> dict[str, Any]:
    vector_set = load_strict(root / "vectors" / "definitions" / "small-scale-qualification.v1.json")
    overlay = load_strict(root / "registries" / "profiles" / "small-scale-qualification.v1.json")
    revisions = {
        _content_id(root, "vector-revision", "qualification-vector-revision", item): item
        for item in vector_set["vectors"]
    }
    coverage: dict[str, dict[str, set[str] | int]] = {
        category: {"vector_keys": set(), "selection_keys": set(), "count": 0}
        for category in REQUIRED_CATEGORIES
    }
    for logical in compiled["logical_executions"]:
        vector = revisions[logical["vector_revision_id"]]
        for category in vector["qualification_categories"]:
            item = coverage[category]
            item["vector_keys"].add(vector["key"])
            item["selection_keys"].add(logical["selection_key"])
            item["count"] += 1
    missing = [category for category, item in coverage.items() if item["count"] == 0]
    if missing:
        raise QualificationCompileError(f"qualification categories lack included coordinates: {missing!r}")
    selections = sorted({item["selection_key"] for item in compiled["logical_executions"]})
    report = {
        "schema_version": "qualification-coverage-report.v1",
        "campaign_manifest_id": compiled["campaign_manifest_id"],
        "classification": {
            "normative_authority": False,
            "operational_qualification_only": True,
            "semantic_authority": False,
        },
        "profile_coordinate_count": len(selections),
        "selection_keys": selections,
        "added_profile_keys": sorted(item["selection_key"] for item in overlay["profiles"]),
        "vector_count": len(vector_set["vectors"]),
        **compiled["denominator"],
        "categories": [
            {
                "category": category,
                "logical_execution_count": coverage[category]["count"],
                "selection_keys": sorted(coverage[category]["selection_keys"]),
                "vector_keys": sorted(coverage[category]["vector_keys"]),
            }
            for category in REQUIRED_CATEGORIES
        ],
    }
    validate_instance(
        report,
        load_strict(root / "schemas" / "json" / "qualification-coverage-report.schema.json"),
        source="qualification coverage report",
    )
    return report


def verify_coverage_report(
    root: Path, compiled: dict[str, Any], report: dict[str, Any]
) -> None:
    validate_instance(
        report,
        load_strict(root / "schemas" / "json" / "qualification-coverage-report.schema.json"),
        source="qualification coverage report",
    )
    expected = build_coverage_report(root, compiled)
    if canonical_bytes(report) != canonical_bytes(expected):
        raise QualificationCompileError(
            "qualification coverage report differs from compiled logical executions"
        )
