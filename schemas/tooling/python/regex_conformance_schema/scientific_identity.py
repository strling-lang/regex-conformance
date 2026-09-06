"""Permanent scientific-identity bindings, fingerprints, and lineage checks."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any
import unicodedata

from .errors import fail
from .identity import NamespaceRegistry, build_content_identity, generate_assigned_id
from .jsonio import canonical_bytes, dump_pretty, load_strict
from .profile import IdentityProfile


CATALOG_PATH = Path("registries/identity/scientific-identities.v1.json")
NAMESPACE_PATH = Path("registries/identity/namespaces.v2.json")
LINEAGE_PROFILE_PATH = Path("schemas/identity-profiles/scientific-lineage.v1.json")
LINEAGE_SCHEMA_FAMILY_ID = (
    "rcid:v1:schema-family:u7:01a0779c-531b-71f6-a7eb-f93664268dd2"
)
ENTITY_NAMESPACES = {
    "feature": "feature",
    "manifestation": "manifestation",
    "modifier": "modifier",
    "obligation": "obligation",
    "operation": "operation",
    "semantic-requirement": "semantic-requirement",
    "semantic-variant": "semantic-variant",
    "typed-interaction": "semantic-interaction",
}
ACTIVE = "active"
SAFE_INTEGER_LIMIT = 9_007_199_254_740_991
SUPERSESSION_KINDS = {
    "merged-from",
    "split-from",
    "superseded-by",
    "supersedes",
}


@dataclass(frozen=True)
class ScientificDescriptor:
    entity_class: str
    key: str
    source_role: str
    record: dict[str, Any]
    parent_key: str | None = None


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _artifact_digest(value: dict[str, Any]) -> str:
    body = {key: member for key, member in value.items() if key != "catalog_digest_sha256"}
    return _digest(body)


def catalog_digest(value: dict[str, Any]) -> str:
    """Return the catalog commitment while excluding its digest field."""

    return _artifact_digest(value)


def _nfc(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_nfc(member) for member in value]
    if isinstance(value, dict):
        projected: dict[str, Any] = {}
        for key, member in value.items():
            canonical_key = unicodedata.normalize("NFC", key)
            if canonical_key in projected:
                fail("canonical-key-collision", "object keys collide after NFC normalization")
            projected[canonical_key] = _nfc(member)
        return projected
    return value


def canonical_nested_value(value: Any, path: str = "$") -> Any:
    """Canonicalize nested scientific JSON without changing array order."""

    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -SAFE_INTEGER_LIMIT <= value <= SAFE_INTEGER_LIMIT:
            fail("unsafe-integer", "integer exceeds the interoperable safe range", path)
        return value
    if isinstance(value, float):
        fail(
            "inexact-number",
            "canonical scientific JSON forbids binary floating-point values",
            path,
        )
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            fail("invalid-unicode", "lone UTF-16 surrogate is forbidden", path)
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [
            canonical_nested_value(member, f"{path}[{index}]")
            for index, member in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, member in value.items():
            if not isinstance(key, str):
                fail("wrong-type", "canonical JSON object keys must be strings", path)
            canonical_key = canonical_nested_value(key, path)
            if canonical_key in result:
                fail(
                    "canonical-key-collision",
                    "object keys collide after NFC normalization",
                    path,
                )
            result[canonical_key] = canonical_nested_value(
                member, f"{path}.{canonical_key}"
            )
        return result
    fail("wrong-type", "expected closed JSON data", path)


def nested_content_digest(value: Any, *, unordered: bool = False) -> str:
    """Hash one typed nested value after the permanent inner canonicalization."""

    projected = canonical_nested_value(value)
    if unordered:
        if not isinstance(projected, list):
            fail("wrong-type", "unordered nested content must be an array")
        keyed = {canonical_bytes(member): member for member in projected}
        projected = [keyed[key] for key in sorted(keyed)]
    return _digest(
        {
            "domain": "strling.regex-conformance.nested-scientific-content.v1",
            "value": projected,
        }
    )


def production_vector_projection(value: dict[str, Any]) -> dict[str, Any]:
    """Project exact production-vector content; presentation metadata is absent."""

    required = {
        "applicability_preconditions",
        "callback_fixture",
        "deterministic_limits",
        "domain",
        "initial_state",
        "interaction_ids",
        "obligation_ids",
        "operation_id",
        "options",
        "pattern",
        "replacement",
        "requested_observations",
        "semantic_requirement_ids",
        "subjects",
    }
    if set(value) != required:
        fail(
            "vector-identity-fields",
            f"production vector identity fields differ: {sorted(set(value) ^ required)}",
        )
    return {
        "applicability_preconditions_sha256": nested_content_digest(
            normalize_predicate(value["applicability_preconditions"])
        ),
        "callback_fixture_sha256": nested_content_digest(value["callback_fixture"]),
        "deterministic_limits_sha256": nested_content_digest(
            value["deterministic_limits"]
        ),
        "domain": value["domain"],
        "initial_state_sha256": nested_content_digest(value["initial_state"]),
        "interaction_ids": value["interaction_ids"],
        "obligation_ids": value["obligation_ids"],
        "operation_id": value["operation_id"],
        "options_sha256": nested_content_digest(value["options"], unordered=True),
        "pattern_sha256": nested_content_digest(value["pattern"]),
        "replacement_sha256": nested_content_digest(value["replacement"]),
        "requested_observations": value["requested_observations"],
        "semantic_requirement_ids": value["semantic_requirement_ids"],
        "subjects_sha256": nested_content_digest(value["subjects"]),
    }


def applicability_coordinate_projection(value: dict[str, Any]) -> dict[str, Any]:
    """Project the exact semantic applicability coordinate fields."""

    required = {
        "applicability_inputs",
        "applicability_rule_set_id",
        "obligation_ids",
        "operation_id",
        "profile_revision_id",
        "semantic_requirement_ids",
        "target_release_revision_id",
        "vector_revision_id",
    }
    if set(value) != required:
        fail(
            "coordinate-identity-fields",
            f"applicability coordinate identity fields differ: {sorted(set(value) ^ required)}",
        )
    return {
        "applicability_inputs_sha256": nested_content_digest(
            normalize_predicate(value["applicability_inputs"])
        ),
        "applicability_rule_set_id": value["applicability_rule_set_id"],
        "obligation_ids": value["obligation_ids"],
        "operation_id": value["operation_id"],
        "profile_revision_id": value["profile_revision_id"],
        "semantic_requirement_ids": value["semantic_requirement_ids"],
        "target_release_revision_id": value["target_release_revision_id"],
        "vector_revision_id": value["vector_revision_id"],
    }


def normalize_predicate(value: Any) -> Any:
    """Canonicalize commutative predicate members without changing meaning."""

    projected = _nfc(value)
    if isinstance(projected, list):
        return [normalize_predicate(member) for member in projected]
    if not isinstance(projected, dict):
        return projected
    normalized = {
        key: normalize_predicate(member) for key, member in projected.items()
    }
    if normalized.get("operator") in {"all", "any"} and isinstance(
        normalized.get("clauses"), list
    ):
        keyed = {
            canonical_bytes(member): member for member in normalized["clauses"]
        }
        normalized["clauses"] = [keyed[key] for key in sorted(keyed)]
    if normalized.get("operator") == "in" and isinstance(
        normalized.get("values"), list
    ):
        keyed = {canonical_bytes(member): member for member in normalized["values"]}
        normalized["values"] = [keyed[key] for key in sorted(keyed)]
    return normalized


def collect_descriptors(root: Path) -> tuple[list[ScientificDescriptor], list[dict[str, Any]]]:
    corpus = load_strict(
        root
        / "semantic-corpus"
        / "snapshots"
        / "regex-semantic-features-2026-08-22.v1.json"
    )
    projection = load_strict(
        root
        / "ontology"
        / "projections"
        / "regex-semantic-projection-2026-08-22.v1.json"
    )
    requirements = load_strict(
        root
        / "vectors"
        / "requirements"
        / "regex-semantic-vector-requirements-2026-08-22.v1.json"
    )
    descriptors: list[ScientificDescriptor] = []
    for feature in corpus["features"]:
        descriptors.append(
            ScientificDescriptor("feature", feature["feature_id"], "semantic-snapshot", feature)
        )
        for variant in feature["semantic_variants"]:
            descriptors.append(
                ScientificDescriptor(
                    "semantic-variant",
                    variant["variant_id"],
                    "semantic-snapshot",
                    variant,
                    feature["feature_id"],
                )
            )
    descriptors.extend(
        ScientificDescriptor("modifier", item["modifier_id"], "semantic-snapshot", item)
        for item in corpus["modifiers"]
    )
    descriptors.extend(
        ScientificDescriptor("operation", item["operation_id"], "semantic-snapshot", item)
        for item in corpus["operations"]
    )
    descriptors.extend(
        ScientificDescriptor(
            "manifestation", item["manifestation_id"], "semantic-snapshot", item
        )
        for item in corpus["manifestations"]
    )
    descriptors.extend(
        ScientificDescriptor(
            "typed-interaction", item["interaction_id"], "semantic-snapshot", item
        )
        for item in corpus["interactions"]
    )
    descriptors.extend(
        ScientificDescriptor(
            "obligation", item["obligation_id"], "semantic-projection", item
        )
        for item in projection["semantic_obligation_templates"]
    )
    descriptors.extend(
        ScientificDescriptor(
            "semantic-requirement",
            item["requirement_id"],
            "vector-requirement-ledger",
            item,
        )
        for item in requirements["requirements"]
    )
    descriptors.sort(key=lambda item: (item.entity_class, item.key))
    keys = [item.key for item in descriptors]
    if len(keys) != len(set(keys)):
        fail("duplicate-scientific-key", "current semantic artifacts reuse an entity key")
    sources = [
        {
            "role": "semantic-snapshot",
            "artifact_id": corpus["snapshot_id"],
            "digest_sha256": corpus["corpus_digest_sha256"],
        },
        {
            "role": "semantic-projection",
            "artifact_id": projection["projection_id"],
            "digest_sha256": projection["projection_digest_sha256"],
        },
        {
            "role": "vector-requirement-ledger",
            "artifact_id": None,
            "digest_sha256": requirements["requirements_digest_sha256"],
        },
    ]
    return descriptors, sorted(sources, key=lambda item: item["role"])


def _reference(value: str, identities: dict[str, str], prefix: str | None = None) -> str:
    candidates = [value]
    if prefix and not value.startswith(f"{prefix}."):
        candidates.append(f"{prefix}.{value}")
    for candidate in candidates:
        if candidate in identities:
            return identities[candidate]
    return value


def _predicate_references(value: Any, identities: dict[str, str]) -> Any:
    normalized = normalize_predicate(value)
    if isinstance(normalized, list):
        return [_predicate_references(member, identities) for member in normalized]
    if isinstance(normalized, dict):
        result = {
            key: _predicate_references(member, identities)
            for key, member in normalized.items()
        }
        if isinstance(result.get("value"), str):
            result["value"] = _reference(result["value"], identities, "operation")
        if isinstance(result.get("values"), list):
            result["values"] = [
                _reference(member, identities, "operation")
                if isinstance(member, str)
                else member
                for member in result["values"]
            ]
        return normalize_predicate(result)
    return normalized


def scientific_basis(
    descriptor: ScientificDescriptor, identities: dict[str, str]
) -> dict[str, Any]:
    item = descriptor.record
    entity_class = descriptor.entity_class
    if entity_class == "feature":
        return {
            "feature_class": item["feature_class"],
            "semantic_definition": item["semantic_definition"],
            "prerequisite_ids": sorted(
                _reference(value, identities, "feature")
                for value in item["prerequisite_feature_ids"]
            ),
            "modifier_ids": sorted(
                _reference(value, identities, "modifier") for value in item["modifier_ids"]
            ),
            "variant_ids": sorted(
                _reference(value["variant_id"], identities)
                for value in item["semantic_variants"]
            ),
            "typed_relations": sorted(
                (
                    {
                        "relation_type": value["relation_type"],
                        "target_id": _reference(value["target_id"], identities),
                    }
                    for value in item["typed_relations"]
                ),
                key=canonical_bytes,
            ),
            "abstract_grammar_form": item["abstract_grammar_form"],
            "supported_operation_ids": sorted(
                _reference(value, identities, "operation")
                for value in item["supported_operation_ids"]
            ),
            "capture_result_semantics": item["capture_result_semantics"],
            "replacement_implications": item["replacement_implications"],
            "unicode_encoding_implications": item["unicode_encoding_implications"],
            "option_state_dependencies": sorted(item["option_state_dependencies"]),
            "diagnostic_error_semantics": item["diagnostic_error_semantics"],
            "resource_termination_implications": item["resource_termination_implications"],
        }
    if entity_class == "semantic-variant":
        return {
            "parent_feature_id": _reference(descriptor.parent_key or "", identities),
            "distinguishing_rule": item["distinguishing_rule"],
        }
    if entity_class == "modifier":
        return {"semantic_effect": item["semantic_effect"]}
    if entity_class == "operation":
        return {"semantic_contract": item["semantic_contract"]}
    if entity_class == "manifestation":
        return {
            "kind": item["kind"],
            "source_id": item["source_id"],
            "syntax_or_api_form": item["syntax_or_api_form"],
            "semantic_feature_id": _reference(item["semantic_feature_id"], identities),
        }
    if entity_class == "typed-interaction":
        return {
            "source_id": _reference(item["source_id"], identities),
            "target_id": _reference(item["target_id"], identities),
            "interaction_type": item["interaction_type"],
        }
    if entity_class == "obligation":
        return {
            "feature_id": _reference(item["feature_id"], identities),
            "facet": item["facet"],
            "case": item["case"],
            "classification": item["classification"],
            "operation_ids": sorted(
                _reference(value, identities, "operation")
                for value in item["operation_ids"]
            ),
            "applicability_predicate": _predicate_references(
                item["applicability_predicate"], identities
            ),
            "expected_observation_contract": item["expected_observation_contract"],
            "single_credit_rule": item["single_credit_rule"],
        }
    if entity_class == "semantic-requirement":
        return {
            "feature_id": _reference(item["feature_id"], identities),
            "obligation_id": _reference(item["obligation_id"], identities),
            "facet": item["facet"],
            "vector_role": item["vector_role"],
            "required_operation_ids": sorted(
                _reference(value, identities, "operation")
                for value in item["required_operation_ids"]
            ),
            "required_attribution": item["required_attribution"],
        }
    fail("unknown-scientific-class", f"unsupported entity class {entity_class!r}")


def semantic_fingerprint(
    descriptor: ScientificDescriptor, identities: dict[str, str]
) -> str:
    return _digest(
        {
            "domain": "strling.regex-conformance.scientific-basis.v1",
            "entity_class": descriptor.entity_class,
            "basis": _nfc(scientific_basis(descriptor, identities)),
        }
    )


def _owner_index(bindings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    owners: dict[str, dict[str, Any]] = {}
    for binding in bindings:
        for key in [binding["canonical_key"], *binding["former_keys"]]:
            if key in owners:
                fail("multiple-canonical-owners", f"key {key!r} has multiple owners")
            owners[key] = binding
    return owners


def resolve_scientific_id(catalog: dict[str, Any], key: str) -> str:
    """Resolve either a current or former readable key to its permanent ID."""

    binding = _owner_index(catalog["bindings"]).get(key)
    if binding is None:
        fail("unknown-scientific-key", f"no scientific identity owns {key!r}")
    return str(binding["scientific_id"])


def lineage_record_id(root: Path, record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "lineage_record_id"}
    result = build_content_identity(
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / LINEAGE_PROFILE_PATH)),
        namespace="identity-migration",
        identity_schema_family_id=LINEAGE_SCHEMA_FAMILY_ID,
        identity_schema_version="1.0.0",
        identity=body,
    )
    return str(result["content_id"])


def validate_lineage_records(
    root: Path, records: list[dict[str, Any]], scientific_ids: set[str]
) -> None:
    record_ids: set[str] = set()
    edges: dict[str, set[str]] = {identifier: set() for identifier in scientific_ids}
    for record in records:
        identifier = record["lineage_record_id"]
        if identifier in record_ids:
            fail("duplicate-lineage-record", f"duplicate lineage record {identifier}")
        record_ids.add(identifier)
        if identifier != lineage_record_id(root, record):
            fail("lineage-id-mismatch", f"lineage record {identifier} is not content-derived")
        sources = set(record["source_ids"])
        targets = set(record["target_ids"])
        missing = sorted((sources | targets) - scientific_ids)
        if missing:
            fail("missing-lineage-identity", f"lineage references missing identities: {missing[:3]}")
        kind = record["change_kind"]
        effect = record["identity_effect"]
        if kind in {"renamed-from", "corrected-without-semantic-change"}:
            if len(sources) != 1 or sources != targets or effect != "retained":
                fail("invalid-retained-lineage", f"{kind} must retain one identity")
        elif kind == "alias-of":
            if sources or len(targets) != 1 or effect != "no-identity":
                fail("invalid-alias-lineage", "alias-of names one target and creates no identity")
        elif kind == "deprecated":
            if len(sources) != 1 or targets or effect != "retained":
                fail("invalid-deprecation-lineage", "deprecation retains one historical identity")
        elif kind == "split-from":
            if len(sources) != 1 or len(targets) < 2 or effect != "new-identity":
                fail("invalid-split-lineage", "split requires one predecessor and multiple successors")
        elif kind == "merged-from":
            if len(sources) < 2 or len(targets) != 1 or effect != "new-identity":
                fail("invalid-merge-lineage", "merge requires multiple predecessors and one successor")
        elif kind in {"supersedes", "superseded-by"}:
            if not sources or not targets or sources & targets or effect != "new-identity":
                fail("invalid-supersession-lineage", "supersession requires distinct old and new identities")
        if kind in SUPERSESSION_KINDS:
            for source in sources:
                edges[source].update(targets)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            fail("lineage-cycle", f"lineage contains a cycle at {identifier}")
        if identifier in visited:
            return
        visiting.add(identifier)
        for target in edges[identifier]:
            visit(target)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in sorted(scientific_ids):
        visit(identifier)


def verify_catalog(root: Path, catalog: dict[str, Any] | None = None) -> dict[str, int]:
    record = catalog or load_strict(root / CATALOG_PATH)
    if record["catalog_digest_sha256"] != _artifact_digest(record):
        fail("catalog-digest-mismatch", "scientific identity catalog digest differs")
    registry = NamespaceRegistry.load(root / NAMESPACE_PATH)
    bindings = record["bindings"]
    identifiers = [binding["scientific_id"] for binding in bindings]
    if len(identifiers) != len(set(identifiers)):
        fail("reused-scientific-id", "one immutable scientific ID has multiple bindings")
    for binding in bindings:
        parsed = registry.validate(binding["scientific_id"])
        expected = ENTITY_NAMESPACES[binding["entity_class"]]
        if (parsed.scheme, parsed.mode, parsed.namespace) != ("rcid", "u7", expected):
            fail(
                "wrong-scientific-namespace",
                f"{binding['entity_class']} must use rcid/u7/{expected}",
            )
        history = binding["semantic_fingerprint_history"]
        if history[0]["lineage_record_id"] is not None:
            fail("invalid-identity-adoption", "the first fingerprint cannot cite later lineage")
        dates = [item["effective_date"] for item in history]
        if dates != sorted(dates):
            fail("unordered-fingerprint-history", "fingerprint history must be chronological")
    owners = _owner_index(bindings)
    validate_lineage_records(root, record["lineage_records"], set(identifiers))
    lineage_by_id = {
        item["lineage_record_id"]: item for item in record["lineage_records"]
    }
    for binding in bindings:
        for history in binding["semantic_fingerprint_history"][1:]:
            lineage = lineage_by_id.get(history["lineage_record_id"])
            if (
                lineage is None
                or lineage["identity_effect"] != "retained"
                or binding["scientific_id"] not in lineage["source_ids"]
                or binding["scientific_id"] not in lineage["target_ids"]
            ):
                fail("unexplained-fingerprint-change", "fingerprint change lacks retained-identity lineage")

    descriptors, sources = collect_descriptors(root)
    if record["source_artifacts"] != sources:
        fail("identity-source-mismatch", "catalog source artifact bindings differ")
    identities = {
        key: binding["scientific_id"] for key, binding in owners.items()
    }
    matched: set[str] = set()
    for descriptor in descriptors:
        binding = owners.get(descriptor.key)
        if binding is None:
            fail("missing-scientific-identity", f"no immutable ID for {descriptor.key}")
        if binding["scientific_id"] in matched:
            fail("duplicate-current-owner", "multiple current entities resolve to one ID")
        matched.add(binding["scientific_id"])
        if binding["status"] != ACTIVE or binding["entity_class"] != descriptor.entity_class:
            fail("retired-identity-reuse", f"current entity {descriptor.key} reuses historical identity")
        if binding["source_role"] != descriptor.source_role:
            fail("identity-source-role-mismatch", f"source role differs for {descriptor.key}")
        actual = semantic_fingerprint(descriptor, identities)
        if actual != binding["semantic_fingerprint_history"][-1]["fingerprint_sha256"]:
            fail("scientific-content-mutation", f"semantic basis changed for {descriptor.key}")
    active_ids = {
        binding["scientific_id"] for binding in bindings if binding["status"] == ACTIVE
    }
    if matched != active_ids:
        fail("orphaned-active-identity", "active identity has no current canonical entity")

    by_class = dict(sorted(Counter(item["entity_class"] for item in bindings).items()))
    expected_counts = {
        "active": len(active_ids),
        "historical": len(bindings) - len(active_ids),
        "by_class": by_class,
        "lineage_records": len(record["lineage_records"]),
        "total": len(bindings),
    }
    if record["counts"] != expected_counts:
        fail("identity-count-mismatch", "scientific identity catalog counts differ")
    return {
        "scientific_identities": len(bindings),
        "scientific_lineage_records": len(record["lineage_records"]),
    }


def initialize_catalog(root: Path, *, effective_date: str) -> dict[str, Any]:
    path = root / CATALOG_PATH
    registry = NamespaceRegistry.load(root / NAMESPACE_PATH)
    descriptors, sources = collect_descriptors(root)
    if path.exists():
        record = load_strict(path)
        bindings = list(record["bindings"])
        lineage_records = list(record["lineage_records"])
        adoption = record["adoption"]
    else:
        bindings = []
        lineage_records = []
        adoption = {
            "effective_date": effective_date,
            "legacy_keys_remain_resolvable": True,
            "allocation_rule": (
                "Allocate one registered UUIDv7 payload inside the existing typed rcid envelope "
                "only for mutable-key semantic entities; persist the binding forever and never derive "
                "a replacement ID from a renamed label."
            ),
        }
    owners = _owner_index(bindings)
    for descriptor in descriptors:
        if descriptor.key in owners:
            continue
        namespace = ENTITY_NAMESPACES[descriptor.entity_class]
        binding = {
            "scientific_id": generate_assigned_id(registry, "rcid", namespace),
            "entity_class": descriptor.entity_class,
            "canonical_key": descriptor.key,
            "former_keys": [],
            "status": ACTIVE,
            "source_role": descriptor.source_role,
            "semantic_fingerprint_history": [],
        }
        bindings.append(binding)
        owners[descriptor.key] = binding
    identities = {
        key: binding["scientific_id"] for key, binding in owners.items()
    }
    by_key = {descriptor.key: descriptor for descriptor in descriptors}
    for binding in bindings:
        descriptor = next(
            (by_key[key] for key in [binding["canonical_key"], *binding["former_keys"]] if key in by_key),
            None,
        )
        if descriptor is None or binding["status"] != ACTIVE:
            continue
        fingerprint = semantic_fingerprint(descriptor, identities)
        if not binding["semantic_fingerprint_history"]:
            binding["semantic_fingerprint_history"].append(
                {
                    "effective_date": effective_date,
                    "fingerprint_sha256": fingerprint,
                    "lineage_record_id": None,
                }
            )
        elif binding["semantic_fingerprint_history"][-1]["fingerprint_sha256"] != fingerprint:
            fail(
                "scientific-content-mutation",
                f"refusing to rewrite the locked semantic basis for {binding['canonical_key']}",
            )
    bindings.sort(key=lambda item: (item["entity_class"], item["canonical_key"]))
    active = sum(item["status"] == ACTIVE for item in bindings)
    record = {
        "schema_version": "scientific-identity-catalog.v1",
        "namespace_registry": NAMESPACE_PATH.as_posix(),
        "adoption": adoption,
        "source_artifacts": sources,
        "bindings": bindings,
        "lineage_records": sorted(
            lineage_records, key=lambda item: item["lineage_record_id"]
        ),
        "counts": {
            "active": active,
            "historical": len(bindings) - active,
            "by_class": dict(
                sorted(Counter(item["entity_class"] for item in bindings).items())
            ),
            "lineage_records": len(lineage_records),
            "total": len(bindings),
        },
    }
    record["catalog_digest_sha256"] = _artifact_digest(record)
    path.write_text(dump_pretty(record), encoding="utf-8", newline="\n")
    return record
