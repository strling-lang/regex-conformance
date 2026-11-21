"""Freeze explicit oracle records at an exact production vector coordinate."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from pathlib import Path

from .errors import fail
from .jsonio import canonical_bytes, load_strict
from .oracle import (
    AUTHORITY_PATH,
    CONTRACT_PATH,
    _content_id,
    _finalize,
    _traverse_dependencies,
    validate_oracle_collection,
    validate_vector_binding,
)


def digest(value: object) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def load_pinned_contract(root: Path, contract_path: Path = CONTRACT_PATH, authority_path: Path = AUTHORITY_PATH) -> dict:
    authority = load_strict(root / authority_path)
    path = root / contract_path
    contract = load_strict(path)
    body = {key: value for key, value in contract.items() if key not in {"contract_id", "contract_digest_sha256"}}
    reference = authority["current_contract"]
    index = {key: value for key, value in authority.items() if key not in {"index_id", "index_digest_sha256"}}
    if (
        authority["index_digest_sha256"] != digest(index)
        or reference["path"] != contract_path.as_posix()
        or reference["file_sha256"] != sha256(path.read_bytes()).hexdigest()
        or reference["artifact_id"] != contract["contract_id"]
        or reference["digest_sha256"] != digest(body)
        or contract["contract_digest_sha256"] != reference["digest_sha256"]
    ):
        fail("production-policy-binding", "contract is detached from its governed identity", contract_path.as_posix())
    return contract


def resolve_coordinate(
    root: Path,
    contract: dict,
    coordinate: dict,
    records: list[dict],
    *,
    frozen_at: str,
) -> dict:
    """Resolve already source-verified records, preserving conflicting authorities."""
    requirement_id = coordinate["semantic_requirement_id"]
    profile_id = coordinate["profile_id"]
    operation_id = coordinate["operation_id"]
    ordered = sorted(records, key=lambda item: item["oracle_id"])
    for record in ordered:
        scope = record["scope"]
        if (
            record["requirement_scientific_id"] != requirement_id
            or scope["profile_ids"] != [profile_id]
            or scope["operation_scientific_ids"] != [operation_id]
            or record["independence"]["evaluated_profile_ids"] != [profile_id]
            or coordinate["stimulus_generator_authority"] not in record["independence"]["stimulus_generator_authority_domain_ids"]
        ):
            fail("production-oracle-scope", "oracle scope or evaluated profile differs from the exact coordinate")
        nodes, _, reachable = _traverse_dependencies(record)
        stimulus_nodes = [node for node in nodes.values() if node["semantic_role"] == "stimulus-only"]
        if not any(
            node["dependency_id"] == coordinate["vector_revision_id"]
            and node["content_digest_sha256"] == coordinate["stimulus_sha256"]
            and node["kind"] == "generator"
            and node["authority_domain_id"] == coordinate["stimulus_generator_authority"]
            and not node["upstream_dependency_ids"]
            and node["dependency_id"] not in reachable
            for node in stimulus_nodes
        ):
            fail("production-oracle-stimulus", "oracle has no isolated exact stimulus dependency")

    established = [record for record in ordered if record["resolution_state"] == "oracle-established"]
    conventional = [
        record for record in established
        if record["expected_result"] is not None and record["expected_result"]["result_type"] == "conventional"
    ]
    distinct = {canonical_bytes(record["expected_result"]["value"]) for record in conventional}
    conflicts = []
    if len(distinct) > 1:
        body = {
            "requirement_scientific_id": requirement_id,
            "oracle_ids": sorted(record["oracle_id"] for record in conventional),
            "resolution_state": "conflicting-authoritative-expectations",
            "selected_oracle_id": None,
            "scope_overlap_basis": canonical_bytes(coordinate).decode("utf-8"),
        }
        conflicts.append({**body, "conflict_id": _content_id(root, "expectation-projection", "production-oracle-conflict-v1", body)})
    # Each collection is for one stimulus. Different stimuli may legitimately have
    # different expected values even when their semantic requirement is the same.
    validate_oracle_collection(root, contract, ordered, conflicts)

    states = Counter(record["resolution_state"] for record in ordered)
    priority = (
        "conflicting-authoritative-expectations", "expectation-ambiguous", "expectation-under-specified",
        "oracle-inputs-unavailable", "oracle-established", "characterization-only", "oracle-inapplicable",
    )
    resolution = priority[0] if conflicts else next((state for state in priority if states[state]), "oracle-inputs-unavailable")
    refs = [{key: record[key] for key in ("oracle_id", "oracle_digest_sha256")} for record in ordered]
    binding = None
    if refs:
        binding = _finalize(
            root,
            {
                "schema_version": "oracle-vector-binding.v1",
                "vector_revision_id": coordinate["vector_revision_id"],
                "semantic_requirement_id": requirement_id,
                "contract_ref": {key: contract[key] for key in ("contract_id", "contract_digest_sha256")},
                "oracle_refs": refs,
                "resolution_state": resolution,
                "frozen_at": frozen_at,
                "campaign_definition_revision_id": coordinate["campaign_definition_revision_id"],
                "mutable_latest_alias_used": False,
            },
            namespace="expectation-projection",
            artifact_kind="oracle-vector-binding-v1",
            id_field="binding_id",
            digest_field="binding_digest_sha256",
        )
        validate_vector_binding(root, contract, binding, ordered)
    return {
        "coordinate": coordinate,
        "resolution_state": resolution,
        "oracle_states": dict(states),
        "oracle_records": ordered,
        "binding": binding,
        "conflicts": conflicts,
        "execution_eligible": False,
    }
