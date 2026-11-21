"""Reconstruct realized PCRE2 capabilities and evaluate the reviewed campaign predicates."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from . import applicability
from .errors import fail
from .jsonio import canonical_bytes, load_strict, loads_strict
from .pcre2_campaign_handoff import build_handoff
from .pcre2_qualification import build_plan, verify_responses
from .production_campaign_design import ADAPTER_PATH, PCRE2_OPERATIONS, PROFILE_PATH, RECIPE_PATH
from .production_oracle import digest, load_pinned_contract
from .schema import validate_instance


def reconstruct_qualification(root: Path, raw: bytes, *, expected_sha256: str, protected_head: str) -> tuple[dict, list[dict]]:
    if len(raw) > 2_097_152 or sha256(raw).hexdigest() != expected_sha256:
        fail("pcre2-qualification-evidence-digest", "qualification bytes do not match the independent receipt")
    evidence = loads_strict(raw.decode("utf-8"))
    if raw != canonical_bytes(evidence) + b"\n":
        fail("pcre2-qualification-evidence-canonical", "qualification evidence must be canonical")
    plan = build_plan(root)
    expected = {
        "schema_version": "pcre2-bounded-capability-qualification.v1", "classification": "qualification-only",
        "source_head": protected_head, "trust_class": "trusted_executioner", "release_state": "released",
        "plan_digest_sha256": plan["plan_digest_sha256"], "profile_id": plan["profile_id"],
        "release_id": plan["target_release_id"], "adapter_manifest_id": plan["adapter_manifest_id"],
        "production_logical_executions": 0, "certified_requirement_count": 0,
    }
    if any(evidence.get(field) != value for field, value in expected.items()):
        fail("pcre2-qualification-evidence-scope", "qualification scope differs from the protected assignment")
    environment = evidence["environment"]
    validate_instance(environment, load_strict(root / "schemas/json/environment-lifecycle.schema.json"))
    runtime = environment["runtime_identity"]
    recipe = load_strict(root / RECIPE_PATH)
    actual_facts = {row["name"]: row["value"] for row in runtime["facts"]}
    actual_configuration = {row["name"]: row["value"] for row in runtime["relevant_configuration"]}
    if (
        environment["state"] != "ready" or not environment["admission"]["admitted"]
        or environment["recipe"]["recipe_revision_id"] != plan["recipe_revision_id"]
        or environment["recipe"]["target_profile_id"] != plan["profile_id"]
        or environment["recipe"]["target_release_id"] != plan["target_release_id"]
        or runtime["isolation_policy_digest"] != recipe["isolation_policy"]["digest"]
        or runtime["provider_implementation_digest"] != environment["provider"]["implementation_digest"]
        or environment["verified_artifacts"] != [{k: v for k, v in item.items() if k != "locators"} for item in plan["source_artifacts"]]
        or any(actual_facts.get(row["name"]) != row["value"] for row in recipe["expected_runtime_facts"])
        or any(actual_configuration.get(row["name"]) != row["value"] for row in recipe["expected_configuration"])
        or sorted(item["probe_id"] for item in environment["smoke_observations"] if item["passed"]) != plan["environment_smoke_probe_ids"]
    ):
        fail("pcre2-qualification-realization", "verified environment identity or resource admission does not reconcile")
    signature = evidence["source_signature_status"].split()
    if signature[:2] != ["[GNUPG:]", "VALIDSIG"] or signature[-1] != plan["publisher_fingerprint"]:
        fail("pcre2-qualification-signer", "qualification has no verification from the pinned publisher")
    handshake = evidence["capability_handshake"]
    validate_instance(handshake, load_strict(root / "schemas/json/adapter-handshake.schema.json"))
    adapter = load_strict(root / ADAPTER_PATH)
    native = handshake["runtime_identity"]
    facts = {row["name"]: row["value"] for row in native["facts"]}
    if (
        handshake["outcome"] != "accepted" or handshake["adapter_release_manifest_id"] != plan["adapter_manifest_id"]
        or handshake["capabilities"] != sorted(adapter["identity"]["capabilities"])
        or native["profile_id"] != plan["profile_id"] or native["target_release_id"] != plan["target_release_id"]
        or native != evidence["smoke"]["handshake"]["runtime_identity"]
        or any(actual_facts.get(name) != value for name, value in facts.items())
    ):
        fail("pcre2-qualification-handshake-binding", "adapter handshake does not match the realized runtime")
    assertions = verify_responses(root, plan, evidence["capability_responses"], native["facts"])
    if assertions != evidence["capability_assertions"]:
        fail("pcre2-qualification-assertion-drift", "assertions differ from independently replayed responses")
    return evidence, assertions


def compile_qualified_applicability(
    root: Path, manifest: dict, oracle_review: dict, qualification: bytes, *, expected_manifest_digest: str,
    expected_review_digest: str, expected_qualification_sha256: str, protected_head: str,
) -> dict:
    handoff = build_handoff(root, oracle_review, expected_review_digest=expected_review_digest)
    manifest_body = {key: value for key, value in manifest.items() if key != "manifest_digest_sha256"}
    if digest(manifest_body) != expected_manifest_digest or manifest["manifest_digest_sha256"] != expected_manifest_digest:
        fail("pcre2-applicability-stimulus-manifest", "candidate manifest differs from its pinned digest")
    evidence, assertions = reconstruct_qualification(
        root, qualification, expected_sha256=expected_qualification_sha256, protected_head=protected_head,
    )
    environment = evidence["environment"]
    graph = next(row for row in load_strict(root / PROFILE_PATH)["profiles"] if row["profile_id"] == evidence["profile_id"])
    scope = {
        "profile_graph": graph, "recipe_revision_id": environment["recipe"]["recipe_revision_id"],
        "release_id": evidence["release_id"], "adapter_manifest_id": evidence["adapter_manifest_id"],
        "environment_fingerprint_id": environment["environment_fingerprint_id"],
        "environment_verification_sha256": environment["verification_digest"],
        "runtime_identity": environment["runtime_identity"], "qualification_sha256": expected_qualification_sha256,
    }
    revision = applicability._content_id(root, "profile-revision", "qualified-pcre2-profile-scope-v1", scope)
    contract = load_pinned_contract(root, applicability.CONTRACT_PATH, applicability.AUTHORITY_PATH)
    registry = {row["field"]: row for row in contract["field_registry"]}
    source_id = applicability._content_id(root, "trust-assessment", "pcre2-capability-qualification-v1", {
        "qualification_sha256": expected_qualification_sha256, "source_head": protected_head,
    })
    facts = []
    entries = [
        (row["field"], row["scientific_id"], f"/capability_assertions/{index}")
        for index, row in enumerate(assertions) if row["state"] == "verified-in-qualification"
    ]
    entries.extend(
        ("profile.operation_scientific_ids", identifier, f"/capability_handshake/capabilities/{name}")
        for identifier, name in sorted(PCRE2_OPERATIONS.items())
        if f"operation-{name}" in evidence["capability_handshake"]["capabilities"]
    )
    for field, value, locator in entries:
        spec = registry[field]
        facts.append(applicability._finalize_fact(root, {
            "fact_revision_id": applicability._content_id(root, "applicability-rule-set", "qualified-pcre2-capability-v1", {
                "field": field, "value": value, "source": source_id,
            }),
            "field": field, "field_id": spec["field_id"], "assertion": "member-present",
            "value_type": spec["member_type"], "value": value,
            "authority_class": "certified-adapter-capability", "authority_state": "admissible",
            "source": {"artifact_id": source_id, "revision_id": source_id, "digest_sha256": expected_qualification_sha256, "locator": locator},
            "dependencies": [{"dependency_id": evidence["adapter_manifest_id"], "kind": "certified-adapter"},
                             {"dependency_id": scope["environment_fingerprint_id"], "kind": "certified-environment"}],
        }))
    snapshot = applicability._finalize(root, {
        "schema_version": "profile-capability-fact-snapshot.v1", "classification": "frozen-profile-capability-authority",
        "profile_id": evidence["profile_id"], "profile_revision_id": revision, "world_assumption": "open",
        "field_closure_rules": [], "facts": facts,
    }, namespace="ontology-projection", kind="profile-capability-fact-snapshot-v1", id_field="snapshot_id", digest_field="snapshot_digest_sha256")
    vectors = {row["vector_revision_id"]: row["stimulus"] for row in manifest["vectors"]}
    requirements = {row["scientific_id"]: row for row in load_strict(root / applicability.REQUIREMENT_PATH)["requirements"]}
    rows = []
    for comparison in handoff["comparisons"]:
        coordinate = comparison["coordinate"]
        stimulus = vectors.get(coordinate["vector_revision_id"])
        if stimulus is None or digest(stimulus) != coordinate["stimulus_sha256"]:
            fail("pcre2-applicability-stimulus", "oracle and applicability need the same immutable stimulus")
        requirement = requirements[coordinate["semantic_requirement_id"]]
        predicate = stimulus["applicability_preconditions"]
        predicate_id = applicability._predicate_id(root, predicate)
        result = applicability.evaluate(root, contract, requirement, {
            "requirement_scientific_id": requirement["scientific_id"], "feature_scientific_id": requirement["feature_scientific_id"],
            "operation_scientific_ids": requirement["required_operation_scientific_ids"], "predicate_id": predicate_id,
        }, {"predicate_id": predicate_id, "predicate": predicate}, snapshot)
        rows.append({"coordinate": coordinate, "applicability": result, "oracle_binding_id": comparison["oracle_binding_id"],
                     "execution_eligible": False})
    report = {
        "schema_version": "pcre2-qualified-applicability-review.v1", "classification": "scoped-qualification-derived-applicability",
        "profile_revision_id": revision, "profile_scope": scope, "capability_snapshot": snapshot,
        "handoff_digest_sha256": handoff["handoff_digest_sha256"], "manifest_digest_sha256": expected_manifest_digest,
        "adjudication_campaign_authorized": False, "production_credit": 0, "rows": rows,
    }
    return {**report, "report_digest_sha256": digest(report)}
