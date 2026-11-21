"""Expand attributable stimuli against the frozen semantic denominator."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
from itertools import product
from math import prod
from pathlib import Path
from typing import Any

from .errors import fail
from .identity import NamespaceRegistry, build_content_identity
from .jsonio import canonical_bytes, load_strict
from .obligation_snapshots import AUTHORITY_PATH, OBLIGATION_PATH, REQUIREMENT_PATH, SNAPSHOT_PATH
from .profile import IdentityProfile
from .schema import validate_instance
from .scientific_identity import CATALOG_PATH, NAMESPACE_PATH, normalize_predicate, production_vector_projection


FAMILY_SCHEMA_PATH = Path("schemas/json/production-vector-family.schema.json")
VECTOR_PROFILE_PATH = Path("schemas/identity-profiles/production-vector-revision.v1.json")
VECTOR_SCHEMA_FAMILY_ID = "rcid:v1:schema-family:u7:01a0779c-5485-7240-b0ee-4846554fd816"
MAX_FAMILY_MEMBERS = 4096
MAX_VECTOR_BYTES = 256 * 1024
MAX_MANIFEST_VECTOR_BYTES = 16 * 1024 * 1024


def _digest(value: Any) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _load_snapshot(root: Path, path: Path, reference: dict) -> dict:
    snapshot = load_strict(root / path)
    body = {key: value for key, value in snapshot.items() if key not in {"snapshot_id", "snapshot_digest_sha256"}}
    if reference != {
        "path": path.as_posix(),
        "artifact_id": snapshot["snapshot_id"],
        "digest_sha256": _digest(body),
    } or snapshot["snapshot_digest_sha256"] != reference["digest_sha256"]:
        fail("vector-denominator-drift", "snapshot differs from its frozen reference", path.as_posix())
    return snapshot


def _attribution(family: dict, inputs: VectorCompilerInputs) -> dict:
    requirement = inputs.requirements.get(family["requirement_id"])
    if requirement is None or family["operation_id"] not in requirement["required_operation_scientific_ids"]:
        fail("vector-attribution", "requirement or operation is outside the frozen scope", family["key"])
    members = [inputs.obligations[identifier] for identifier in requirement["obligation_scientific_ids"]]
    variant_ids = sorted({
        member["semantic_variant_basis"]["variant_scientific_id"]
        for member in members if member["semantic_variant_basis"] is not None
    })
    interaction_ids = set()
    for member in members:
        interaction = member["interaction_basis"]
        if interaction is not None:
            key = f"interaction.{member['feature_id']}.{interaction['relation_type']}.{interaction['target_id']}"
            identifier = inputs.identities.get(key)
            if identifier is None:
                fail("vector-attribution", "obligation interaction has no scientific identity", key)
            interaction_ids.add(identifier)

    manifestation_id = family["manifestation_id"]
    manifestation_scopes = [
        clause["values"] for clause in requirement["profile_condition"]["clauses"]
        if clause["field"] == "profile.manifestation_scientific_ids"
    ]
    if manifestation_id is not None:
        manifestation = inputs.manifestations.get(manifestation_id)
        if manifestation is None or manifestation["semantic_feature_id"] != requirement["feature_id"]:
            fail("vector-attribution", "manifestation belongs to a different feature or is unknown", family["key"])
    if any(manifestation_id not in scope for scope in manifestation_scopes):
        fail("vector-attribution", "family must select an in-scope manifestation", family["key"])

    return {
        "feature_id": requirement["feature_scientific_id"],
        "facet_ids": sorted({member["facet_scientific_id"] for member in members}),
        "variant_ids": variant_ids,
        "manifestation_id": manifestation_id,
        "interaction_ids": sorted(interaction_ids),
        "operation_id": family["operation_id"],
        "requirement_id": family["requirement_id"],
        "obligation_ids": sorted(requirement["obligation_scientific_ids"]),
        "evidence_role": requirement["evidence_role"],
        "execution_requirement": requirement["execution_requirement"],
    }


def _finite_count(family: dict) -> int:
    finite = family["finite_subjects"]
    if finite is None:
        return 1
    if "subjects" in family["axes"] or family["inputs"]["subjects"]:
        fail("vector-subject-source-conflict", "finite subjects require an empty exemplar and no subject axis", family["key"])
    if finite["min_length"] > finite["max_length"]:
        fail("vector-finite-length", "minimum length exceeds maximum length", family["key"])
    alphabet = sorted(finite["alphabet_hex"])
    if any(right.startswith(left) for left, right in zip(alphabet, alphabet[1:])):
        fail("vector-finite-alphabet", "finite alphabet must be prefix-free", family["key"])
    return sum(len(alphabet) ** length for length in range(finite["min_length"], finite["max_length"] + 1))


def _axes(family: dict) -> dict:
    axes = dict(family["axes"])
    finite = family["finite_subjects"]
    if prod(map(len, axes.values())) * _finite_count(family) > MAX_FAMILY_MEMBERS:
        fail("vector-family-size", "declared expansion exceeds the family limit", family["key"])
    if finite is not None:
        axes["subjects"] = [
            [{"encoding": finite["encoding"], "hex": "".join(word)}]
            for length in range(finite["min_length"], finite["max_length"] + 1)
            for word in product(finite["alphabet_hex"], repeat=length)
        ]
    return axes


def _check_datum(datum: dict, domain: str, key: str) -> None:
    encoding = datum["encoding"]
    if (domain == "octets") != (encoding == "octets"):
        fail("vector-input-domain", "stimulus encoding does not match the declared domain", key)
    if domain == "unicode-scalars":
        if encoding != "utf-8":
            fail("vector-input-domain", "Unicode scalars require canonical UTF-8 bytes", key)
        try:
            bytes.fromhex(datum["hex"]).decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail("vector-input-domain", "malformed Unicode belongs in the encoded code unit domain", key)


def _stimuli(family: dict, attribution: dict, requirement: dict):
    axes = _axes(family)
    names = sorted(axes)
    clauses = list(requirement["profile_condition"]["clauses"])
    clauses.append({
        "field": "profile.operation_scientific_ids",
        "operator": "contains",
        "value": family["operation_id"],
    })
    if attribution["manifestation_id"] is not None:
        clauses.append({
            "field": "profile.manifestation_scientific_ids",
            "operator": "contains",
            "value": attribution["manifestation_id"],
        })
    preconditions = normalize_predicate({"operator": "all", "clauses": clauses})
    for choices in product(*(axes[name] for name in names)):
        inputs = {**family["inputs"], **dict(zip(names, choices, strict=True))}
        data = [inputs["pattern"], *inputs["subjects"], inputs["replacement"], inputs["callback_fixture"]]
        for datum in data:
            if datum is not None:
                _check_datum(datum, family["domain"], family["key"])
        options = sorted(inputs["options"], key=lambda option: option["name"])
        if len({option["name"] for option in options}) != len(options):
            fail("vector-option-conflict", "an option cannot have multiple values", family["key"])
        yield {
            **inputs,
            "options": options,
            "domain": family["domain"],
            "operation_id": family["operation_id"],
            "requested_observations": sorted(family["requested_observations"]),
            "obligation_ids": attribution["obligation_ids"],
            "semantic_requirement_ids": [family["requirement_id"]],
            "interaction_ids": attribution["interaction_ids"],
            "applicability_preconditions": preconditions,
            "deterministic_limits": family["deterministic_limits"],
        }


@dataclass(frozen=True)
class VectorCompilerInputs:
    schema: dict
    requirement_snapshot: dict
    obligation_snapshot: dict
    requirements: dict
    obligations: dict
    manifestations: dict
    identities: dict
    registry: NamespaceRegistry
    profile: IdentityProfile


def load_vector_compiler_inputs(root: Path) -> VectorCompilerInputs:
    """Read and verify the exact frozen inputs for one compiler invocation."""
    schema = load_strict(root / FAMILY_SCHEMA_PATH)
    authority = load_strict(root / AUTHORITY_PATH)
    authority_body = {key: value for key, value in authority.items() if key not in {"index_id", "index_digest_sha256"}}
    if _digest(authority_body) != authority["index_digest_sha256"]:
        fail("vector-denominator-drift", "current denominator authority digest differs")
    current = authority["current"]
    requirements = _load_snapshot(root, REQUIREMENT_PATH, current["requirement_snapshot"])
    obligations = _load_snapshot(root, OBLIGATION_PATH, current["obligation_snapshot"])
    if requirements["obligation_snapshot"] != current["obligation_snapshot"]:
        fail("vector-denominator-drift", "requirements do not bind the current obligations")
    semantics = _load_snapshot(root, SNAPSHOT_PATH, obligations["semantic_authority"])
    return VectorCompilerInputs(
        schema=schema,
        requirement_snapshot=current["requirement_snapshot"],
        obligation_snapshot=current["obligation_snapshot"],
        requirements={item["scientific_id"]: item for item in requirements["requirements"]},
        obligations={item["scientific_id"]: item for item in obligations["obligations"]},
        manifestations={item["scientific_id"]: item for item in semantics["manifestations"]},
        identities={item["canonical_key"]: item["scientific_id"] for item in load_strict(root / CATALOG_PATH)["bindings"]},
        registry=NamespaceRegistry.load(root / NAMESPACE_PATH),
        profile=IdentityProfile.from_record(load_strict(root / VECTOR_PROFILE_PATH)),
    )


def compile_vector_manifest(inputs: VectorCompilerInputs, families: list[dict]) -> dict:
    """Compile bounded stimuli and account for every requirement without granting C4 credit."""
    family_records = {}
    vectors = {}
    by_requirement_vectors = defaultdict(set)
    total_bytes = 0
    for family in families:
        validate_instance(family, inputs.schema, source="production vector family")
        key = family["key"]
        if key in family_records:
            fail("duplicate-vector-family", "family key occurs more than once", key)
        attribution = _attribution(family, inputs)
        revisions = set()
        for vector in _stimuli(family, attribution, inputs.requirements[family["requirement_id"]]):
            encoded = canonical_bytes(vector)
            total_bytes += len(encoded)
            if len(encoded) > MAX_VECTOR_BYTES or total_bytes > MAX_MANIFEST_VECTOR_BYTES:
                fail("vector-byte-budget", "expanded stimulus exceeds the byte limit", key)
            identity = build_content_identity(
                registry=inputs.registry, profile=inputs.profile, namespace="vector-revision",
                identity_schema_family_id=VECTOR_SCHEMA_FAMILY_ID, identity_schema_version="1.0.0",
                identity=production_vector_projection(vector),
            )["content_id"]
            if identity in revisions:
                fail("duplicate-vector-expansion", "distinct family members produce the same scientific vector", key)
            revisions.add(identity)
            previous = vectors.setdefault(identity, vector)
            if previous != vector:
                fail("vector-identity-conflict", "different stimuli have the same revision identity", key)
        by_requirement_vectors[family["requirement_id"]].update(revisions)
        family_records[key] = {
            "key": key, "definition_sha256": _digest(family), "attribution": attribution,
            "vector_revision_ids": sorted(revisions),
        }

    coverage = []
    for identifier in sorted(inputs.requirements):
        revisions = sorted(by_requirement_vectors[identifier])
        coverage.append({
            "requirement_id": identifier,
            "status": "candidate-stimuli-only" if revisions else "missing",
            "vector_revision_ids": revisions,
        })
    body = {
        "schema_version": "production-vector-expansion-manifest.v1",
        "scope": "stimulus-expansion-only",
        "requirement_snapshot": inputs.requirement_snapshot,
        "obligation_snapshot": inputs.obligation_snapshot,
        "counts": {
            "requirements": len(coverage),
            "requirements_with_candidate_stimuli": sum(bool(row["vector_revision_ids"]) for row in coverage),
            "vector_revisions": len(vectors),
        },
        "families": [family_records[key] for key in sorted(family_records)],
        "vectors": [{"vector_revision_id": key, "stimulus": vectors[key]} for key in sorted(vectors)],
        "requirement_coverage": coverage,
    }
    return {**body, "manifest_digest_sha256": _digest(body)}
