"""Resolve reviewed interaction identities alongside the frozen base catalog."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from .errors import fail
from .identity import NamespaceRegistry
from .jsonio import canonical_bytes, load_strict
from .schema import validate_instance
from .scientific_identity import ScientificDescriptor, catalog_digest, semantic_fingerprint


ALLOCATIONS_PATH = Path("registries/identity/production-interaction-allocations.v1.json")
SCHEMA_PATH = Path("schemas/json/production-interaction-allocations.schema.json")


def verify_interaction_allocations(
    root: Path, record: dict, *, catalog: dict, obligation_ref: dict,
    obligations: dict, registry: NamespaceRegistry,
) -> dict[str, str]:
    """Return additive identities for the exact, already materialized relations."""
    validate_instance(record, load_strict(root / SCHEMA_PATH), source=ALLOCATIONS_PATH.as_posix())
    base_digest = catalog["catalog_digest_sha256"]
    if catalog_digest(catalog) != base_digest or record["base_catalog_digest_sha256"] != base_digest:
        fail("interaction-base-catalog", "supplement and base catalog commitments differ")
    if record["obligation_snapshot_digest_sha256"] != obligation_ref["digest_sha256"]:
        fail("interaction-obligation-snapshot", "supplement binds a different obligation snapshot")
    body = {key: value for key, value in record.items() if key != "allocation_digest_sha256"}
    if sha256(canonical_bytes(body)).hexdigest() != record["allocation_digest_sha256"]:
        fail("interaction-allocation-digest", "supplement digest differs")

    by_key = {
        key: item for item in catalog["bindings"]
        for key in [item["canonical_key"], *item["former_keys"]]
    }
    ids = {item["scientific_id"] for item in catalog["bindings"]}
    active = {key: item["scientific_id"] for key, item in by_key.items() if item["status"] == "active"}
    added = {}
    keys = [item["canonical_key"] for item in record["bindings"]]
    if keys != sorted(set(keys)):
        fail("interaction-allocation-order", "bindings must be unique and sorted by canonical key")
    for item in record["bindings"]:
        key, identifier = item["canonical_key"], item["scientific_id"]
        if key in by_key or identifier in ids:
            fail("interaction-allocation-reuse", "supplement reuses a scientific identity or key", key)
        parsed = registry.validate(identifier)
        if (parsed.scheme, parsed.mode, parsed.namespace) != ("rcid", "u7", "semantic-interaction"):
            fail("interaction-allocation-namespace", "expected the assigned semantic-interaction namespace", key)

        obligation = obligations.get(item["obligation_id"])
        if obligation is None or (basis := obligation["interaction_basis"]) is None:
            fail("interaction-allocation-obligation", "binding must name an existing interaction obligation", key)
        source, target = obligation["feature_id"], basis["target_id"]
        kind = basis["relation_type"]
        if (
            key != f"interaction.{source}.{kind}.{target}"
            or active.get(source) != obligation["feature_scientific_id"]
            or active.get(target) != basis["target_scientific_id"]
        ):
            fail("interaction-allocation-relation", "binding does not describe the exact frozen relation", key)
        descriptor = ScientificDescriptor("typed-interaction", key, "semantic-obligation-snapshot", {
            "source_id": source, "target_id": target, "interaction_type": kind,
        })
        if semantic_fingerprint(descriptor, active) != item["semantic_fingerprint_sha256"]:
            fail("interaction-allocation-fingerprint", "scientific relation fingerprint differs", key)
        ids.add(identifier)
        added[key] = identifier
    return added
