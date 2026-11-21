"""Bind reviewed candidate premises to vectors and a provisional profile design."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from .errors import fail
from .interaction_allocations import ALLOCATIONS_PATH
from .jsonio import canonical_bytes, load_strict
from .production_vectors import VectorCompilerInputs
from .schema import validate_instance
from .vector_manifest_verification import verify_vector_manifest


BASIS_PATH = Path("vectors/expectations/production-candidate-basis.v1.json")
BASIS_SCHEMA = Path("schemas/json/production-candidate-basis.schema.json")
PROFILE_PATH = Path("registries/profiles/vertical-slice-coordinates.v1.json")
ADAPTER_PATH = Path("adapters/manifests/pcre2-ordinary.v1.json")
RECIPE_PATH = Path("environments/recipes/pcre2-10.47-linux-x86-64.v1.json")
PROFILE_SCOPE = "pcre2-10.47-ordinary-8"
COMPLEMENT = {"match": "no-match", "no-match": "match", "compile-accept": "compile-reject", "compile-reject": "compile-accept"}
PCRE2_OPERATIONS = {
    "rcid:v1:operation:u7:01a077a2-095f-7d7f-8566-1b1ae078bb47": "compile",
    "rcid:v1:operation:u7:01a077a2-095f-70a3-b65f-ebfd7c23c9ea": "full-match",
    "rcid:v1:operation:u7:01a077a2-095f-79a2-bed1-eed10d753928": "search",
}


def bind_candidate_bases(root: Path, inputs: VectorCompilerInputs, manifest: dict, basis: dict) -> list[dict]:
    """Require a source rationale for each family and close relational control pairs."""
    validate_instance(basis, load_strict(root / BASIS_SCHEMA), source=BASIS_PATH.as_posix())
    families = {item["key"]: item for item in manifest["families"]}
    records = {row["family_key"]: row for row in basis["families"]}
    if len(records) != len(basis["families"]) or records.keys() != families.keys():
        fail("candidate-basis-coverage", "basis population must cover every family exactly once")

    bindings = []
    outcomes = {item["vector_revision_id"]: item["stimulus"] for item in manifest["vectors"]}
    for key, family in sorted(families.items()):
        entry = records[key]
        if entry["definition_sha256"] != family["definition_sha256"]:
            fail("candidate-basis-digest", "basis references a different family definition", key)
        attribution = family["attribution"]
        requirement = inputs.requirements[attribution["requirement_id"]]
        expected = entry["expected_outcome"]
        if requirement["evidence_role"] == "characterization" and expected is not None:
            fail("candidate-basis-characterization", "characterization cannot carry a verdict", key)
        observation = "compile-diagnostics" if expected in {"compile-accept", "compile-reject"} else "match-state"
        if expected is not None and any(observation not in outcomes[value]["requested_observations"] for value in family["vector_revision_ids"]):
            fail("candidate-basis-observation", "stimuli do not request the stated observation", key)
        peer_key = entry["comparison_family"]
        if requirement["expected_oracle_capability"] == "relational-comparison" or peer_key is not None:
            peer = records.get(peer_key)
            if peer is None or peer_key == key:
                fail("candidate-basis-comparison", "comparison requires a distinct control family", key)
            other = families[peer_key]["attribution"]
            if (
                peer["comparison_family"] != key or peer["profile_scope"] != entry["profile_scope"]
                or expected is None or peer["expected_outcome"] != COMPLEMENT[expected]
                or attribution["operation_id"] != other["operation_id"]
                or attribution["obligation_ids"] != other["obligation_ids"]
                or {attribution["evidence_role"], other["evidence_role"]} != {"positive", "negative"}
            ):
                fail("candidate-basis-comparison", "comparison control differs in scope, obligation, role, operation, or outcome", key)
        bindings.append({**entry, "requirement_id": attribution["requirement_id"], "vector_revision_ids": family["vector_revision_ids"]})
    return bindings


def build_production_campaign_design(
    root: Path, inputs: VectorCompilerInputs, manifest: dict, families: list[dict], *, expected_manifest_digest: str,
) -> dict:
    verify_vector_manifest(inputs, manifest, families, expected_digest=expected_manifest_digest)
    basis = load_strict(root / BASIS_PATH)
    bindings = bind_candidate_bases(root, inputs, manifest, basis)
    profile_bytes = (root / PROFILE_PATH).read_bytes()
    registry = load_strict(root / PROFILE_PATH)
    profile = next(item for item in registry["profiles"] if item["selection_key"] == "pcre2-ordinary")
    environment = next(item for item in registry["environment_bindings"] if item["profile_id"] == profile["profile_id"])
    release = next(item for item in registry["releases"] if item["release_id"] == environment["target_release_id"])
    if release["version"] != "10.47":
        fail("candidate-profile-release", "the pinned candidate premises require PCRE2 10.47")
    adapter = load_strict(root / ADAPTER_PATH)
    adapter_identity = adapter["identity"]
    recipe = load_strict(root / RECIPE_PATH)
    coordinate = (profile["profile_id"], release["release_id"])
    if (
        (adapter_identity["profile"], adapter_identity["target_release"]) != coordinate
        or (recipe["target_profile_id"], recipe["target_release_id"]) != coordinate
        or recipe["environment_recipe_id"] != environment["environment_recipe_id"]
    ):
        fail("candidate-profile-inputs", "adapter and recipe must bind the same profile and release")
    capabilities = set(adapter_identity["capabilities"])
    stimuli = {item["vector_revision_id"]: item["stimulus"] for item in manifest["vectors"]}
    selection = []
    for row in bindings:
        if row["profile_scope"] != PROFILE_SCOPE:
            continue
        selected = [stimuli[identifier] for identifier in row["vector_revision_ids"]]
        operation = PCRE2_OPERATIONS.get(selected[0]["operation_id"])
        required_capabilities = {f"operation-{operation}", "datum-octets", "native-index-octet"}
        for stimulus in selected:
            required_capabilities.update(
                request if request == "native-errors" else f"observation-{request}"
                for request in stimulus["requested_observations"]
            )
            data = [stimulus["pattern"], *stimulus["subjects"]]
            if any(item["encoding"] not in {"octets", "utf-8"} for item in data):
                fail("candidate-profile-datum", "the PCRE2 8-bit proposal accepts exact octets or UTF-8 bytes", row["family_key"])
        if operation is None or not required_capabilities <= capabilities:
            fail("candidate-profile-capability", "adapter lacks the mapped operation or observation", row["family_key"])
        selection.append({**row, "adapter_operation": operation})
    body = {
        "schema_version": "first-production-campaign-design.v1",
        "execution_ready": False,
        "production_execution_denominator": None,
        "candidate_manifest_sha256": expected_manifest_digest,
        "candidate_basis_sha256": sha256(canonical_bytes(basis)).hexdigest(),
        "profile_registry_sha256": sha256(profile_bytes).hexdigest(),
        "interaction_allocation_digest_sha256": load_strict(root / ALLOCATIONS_PATH)["allocation_digest_sha256"],
        "proposed_profile_id": profile["profile_id"],
        "proposed_release_id": release["release_id"],
        "proposed_environment_recipe_id": environment["environment_recipe_id"],
        "proposed_environment_recipe_revision_id": recipe["recipe_revision_id"],
        "environment_recipe_sha256": sha256((root / RECIPE_PATH).read_bytes()).hexdigest(),
        "proposed_adapter_manifest_id": adapter["adapter_release_manifest_id"],
        "adapter_manifest_sha256": sha256((root / ADAPTER_PATH).read_bytes()).hexdigest(),
        "adapter_source_sha256": adapter_identity["source_digest"],
        "adapter_transport_datum": "octets",
        "native_span_unit": "octet",
        "candidate_selection_count": len({identifier for row in selection for identifier in row["vector_revision_ids"]}),
        "candidate_bindings": selection,
        "outstanding_inputs": [
            "reviewed oracle records and exact expectation bindings",
            "frozen production profile capabilities and evaluated applicability coordinates",
            "qualified production runtime and native operation mapping",
            "explicit authorization of the frozen executable campaign",
        ],
    }
    return {**body, "design_digest_sha256": sha256(canonical_bytes(body)).hexdigest()}
