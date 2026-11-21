"""Verify candidate vector identities and coverage without running expansion."""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from math import prod

from .errors import fail
from .identity import build_content_identity
from .jsonio import canonical_bytes
from .production_vectors import (
    MAX_FAMILY_MEMBERS,
    MAX_MANIFEST_VECTOR_BYTES,
    MAX_VECTOR_BYTES,
    VECTOR_SCHEMA_FAMILY_ID,
    VectorCompilerInputs,
    _attribution,
    _finite_count,
)
from .schema import validate_instance
from .scientific_identity import normalize_predicate, production_vector_projection


def _index(rows: list[dict], key: str) -> dict:
    keys = [row[key] for row in rows]
    if keys != sorted(set(keys)):
        fail("vector-manifest-order", f"{key} population is duplicated or out of order")
    return dict(zip(keys, rows, strict=True))


def _finite_subject_member(subjects: list[dict], finite: dict) -> bool:
    if len(subjects) != 1 or subjects[0]["encoding"] != finite["encoding"]:
        return False
    word = subjects[0]["hex"]
    length = 0
    while word:
        symbol = next((item for item in finite["alphabet_hex"] if word.startswith(item)), None)
        if symbol is None:
            return False
        word = word[len(symbol):]
        length += 1
    return finite["min_length"] <= length <= finite["max_length"]


def _axis_members(family: dict) -> dict[str, set[bytes]]:
    members = {}
    for field, exemplar in family["inputs"].items():
        if field == "subjects" and family["finite_subjects"] is not None:
            continue
        choices = family["axes"].get(field, [exemplar])
        if field == "options":
            choices = [sorted(options, key=lambda option: option["name"]) for options in choices]
        members[field] = {canonical_bytes(value) for value in choices}
        if len(members[field]) != len(choices):
            fail("vector-manifest-axis", "distinct axis entries normalize to one value", family["key"])
    return members


def verify_vector_manifest(
    inputs: VectorCompilerInputs, manifest: dict, families: list[dict], *, expected_digest: str,
) -> dict:
    """Reconcile every vector, family, and denominator row to the pinned manifest."""
    manifest_body = dict(manifest)
    claimed_digest = manifest_body.pop("manifest_digest_sha256", None)
    if claimed_digest != expected_digest or sha256(canonical_bytes(manifest_body)).hexdigest() != expected_digest:
        fail("vector-manifest-digest", "manifest differs from its pinned digest")
    if (manifest.get("schema_version"), manifest.get("scope")) != (
        "production-vector-expansion-manifest.v1", "stimulus-expansion-only",
    ):
        fail("vector-manifest-scope", "expected the candidate-stimulus contract")
    if set(manifest_body) != {
        "schema_version", "scope", "requirement_snapshot", "obligation_snapshot",
        "counts", "requirement_coverage", "families", "vectors",
    }:
        fail("vector-manifest-scope", "manifest has missing or unexpected members")
    if (manifest["requirement_snapshot"], manifest["obligation_snapshot"]) != (
        inputs.requirement_snapshot, inputs.obligation_snapshot,
    ):
        fail("vector-manifest-denominator", "manifest does not bind the verified denominator")

    coverage = _index(manifest["requirement_coverage"], "requirement_id")
    vectors = _index(manifest["vectors"], "vector_revision_id")
    emitted_families = _index(manifest["families"], "key")
    definitions = _index(sorted(families, key=lambda item: item["key"]), "key")
    if coverage.keys() != inputs.requirements.keys():
        fail("vector-manifest-requirement-set", "requirement coverage has missing or extra identities")
    if definitions.keys() != emitted_families.keys():
        fail("vector-manifest-family-set", "family set differs from the supplied exact definitions")

    vector_sizes = {}
    for identifier, record in vectors.items():
        if set(record) != {"vector_revision_id", "stimulus"}:
            fail("vector-manifest-scope", "vector record has unexpected members", identifier)
        identity = build_content_identity(
            registry=inputs.registry, profile=inputs.profile, namespace="vector-revision",
            identity_schema_family_id=VECTOR_SCHEMA_FAMILY_ID, identity_schema_version="1.0.0",
            identity=production_vector_projection(record["stimulus"]),
        )["content_id"]
        if identifier != identity:
            fail("vector-manifest-revision", "stimulus differs from its content-derived identity", identifier)
        vector_sizes[identifier] = len(canonical_bytes(record["stimulus"]))
        if vector_sizes[identifier] > MAX_VECTOR_BYTES:
            fail("vector-manifest-byte-budget", "stimulus exceeds its byte limit", identifier)

    reached = set()
    by_requirement = defaultdict(set)
    expanded_bytes = 0
    for key, family in definitions.items():
        validate_instance(family, inputs.schema, source="production vector family")
        row = emitted_families[key]
        if set(row) != {"key", "definition_sha256", "attribution", "vector_revision_ids"}:
            fail("vector-manifest-scope", "family record has unexpected members", key)
        if row["definition_sha256"] != sha256(canonical_bytes(family)).hexdigest():
            fail("vector-manifest-family-digest", "exact family definition differs", key)
        attribution = _attribution(family, inputs)
        if row["attribution"] != attribution:
            fail("vector-manifest-attribution", "family attribution differs from the denominator", key)

        requirement = inputs.requirements[family["requirement_id"]]
        clauses = [*requirement["profile_condition"]["clauses"], {
            "field": "profile.operation_scientific_ids", "operator": "contains", "value": family["operation_id"],
        }]
        if family["manifestation_id"] is not None:
            clauses.append({
                "field": "profile.manifestation_scientific_ids", "operator": "contains", "value": family["manifestation_id"],
            })
        predicate = normalize_predicate({"operator": "all", "clauses": clauses})
        revisions = row["vector_revision_ids"]
        if not revisions or revisions != sorted(set(revisions)) or not set(revisions) <= vectors.keys():
            fail("vector-manifest-family-members", "family has absent, repeated, or unknown vectors", key)
        members = _axis_members(family)
        finite = family["finite_subjects"]
        if len(revisions) != _finite_count(family) * prod(map(len, members.values())):
            fail("vector-manifest-family-cardinality", "family omits or adds expanded stimuli", key)
        if len(revisions) > MAX_FAMILY_MEMBERS:
            fail("vector-manifest-family-cardinality", "family exceeds its expansion limit", key)
        expanded_bytes += sum(vector_sizes[identifier] for identifier in revisions)
        if expanded_bytes > MAX_MANIFEST_VECTOR_BYTES:
            fail("vector-manifest-byte-budget", "expanded stimuli exceed their aggregate byte limit", key)
        for identifier in revisions:
            stimulus = vectors[identifier]["stimulus"]
            expected = {
                "semantic_requirement_ids": [family["requirement_id"]],
                "obligation_ids": attribution["obligation_ids"],
                "interaction_ids": attribution["interaction_ids"],
                "operation_id": family["operation_id"],
                "domain": family["domain"],
                "applicability_preconditions": predicate,
                "deterministic_limits": family["deterministic_limits"],
                "requested_observations": sorted(family["requested_observations"]),
            }
            if any(stimulus[field] != value for field, value in expected.items()):
                fail("vector-manifest-stimulus-scope", "vector does not belong to its declared family", key)
            if any(canonical_bytes(stimulus[field]) not in values for field, values in members.items()):
                fail("vector-manifest-axis", "stimulus includes an undeclared axis value", key)
            if finite is not None and not _finite_subject_member(stimulus["subjects"], finite):
                fail("vector-manifest-axis", "subject is outside the finite language", key)
        by_requirement[family["requirement_id"]].update(revisions)
        reached.update(revisions)
    if reached != vectors.keys():
        fail("vector-manifest-orphan", "unattributed vector revisions are present")

    for identifier, row in coverage.items():
        revisions = sorted(by_requirement[identifier])
        missing = inputs.unresolved_interactions.get(identifier)
        status = "candidate-stimuli-only" if revisions else "missing"
        expected = {"requirement_id": identifier, "status": status, "vector_revision_ids": revisions}
        if missing:
            expected.update(status="interaction-identity-unresolved", blocking_interaction_keys=missing)
        if row != expected:
            fail("vector-manifest-coverage", "requirement row disagrees with verified family incidence", identifier)
    counts = {
        "requirements": len(coverage),
        "requirements_with_candidate_stimuli": sum(bool(revisions) for revisions in by_requirement.values()),
        "requirements_with_unresolved_interaction_identities": len(inputs.unresolved_interactions),
        "vector_revisions": len(vectors),
    }
    if counts != manifest["counts"]:
        fail("vector-manifest-counts", "manifest counts disagree with verified populations")
    return counts
