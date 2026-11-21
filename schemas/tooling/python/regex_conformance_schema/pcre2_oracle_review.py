"""Project documented PCRE2 10.47 propositions onto the reviewed stimuli."""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import tarfile

from . import evidence_admissibility
from .errors import fail
from .jsonio import load_strict
from .oracle import ORACLE_CLASSES, _content_id, _contract_derivation, finalize_oracle_record
from .production_admission import build_admission_review
from .production_campaign_design import RECIPE_PATH, build_production_campaign_design
from .production_oracle import digest, load_pinned_contract, resolve_coordinate
from .production_preflight import build_production_preflight


SOURCE_SHA256 = "46ce364a99ffe363930c64bef9668074da4ac801debd39f0d927523e7dbebff0"
SOURCE_GIT_BLOB = "0ad38db3fbd548b9751c9023fb199d74f3f06f2d"
SOURCE_GIT_COMMIT = "f454e231fe5006dd7ff8f4693fd2b8eb94333429"
SOURCE_URL = f"https://github.com/PCRE2Project/pcre2/blob/{SOURCE_GIT_COMMIT}/doc/pcre2pattern.3"
SOURCE_AUTHORITY = "urn:strling:authority:pcre2-project-documentation"
STIMULUS_AUTHORITY = "urn:strling:authority:production-vector-family-expander"
CUTOFF = "2026-09-08T00:14:25Z"

KELVIN = "\N{KELVIN SIGN}".encode("utf-8")
ELEVEN_CAPTURES = b"()" * 10 + rb"(a)\11"


# Each entry specifies the full bounded domain of one reviewed proposition.
# These source-derived domains are checked against the expanded stimuli.
DOMAINS = {
    "backreference-equality": {
        "source_lines": [(2483, 2496)],
        "operation": "full-match",
        "pattern": rb"([ab])\1",
        "subjects": {b"aa", b"ab", b"ba", b"bb"},
        "scope": "Caseful octet matching and a participating single-octet capture.",
        "proposition": "A numbered backreference consumes the octet actually captured.",
    },
    "out-of-range-reference": {
        "source_lines": [(2431, 2434)],
        "operation": "compile",
        "patterns": {rb"\1", rb"(a)\2"},
        "scope": "Caseful compile with a single-digit reference below eight.",
        "proposition": "Compilation fails when a reference number below eight exceeds the total capture count.",
    },
    "group-local-restriction": {
        "source_lines": [(1461, 1466), (1847, 1847), (1859, 1863)],
        "operation": "search",
        "pattern": b"(*UTF)(?i)(?r:k)k",
        "subjects": {b"K" + KELVIN, b"k" + KELVIN, KELVIN + b"k"},
        "scope": "UTF mode, inline caseless matching, group-local restriction, and Turkish casing disabled.",
        "proposition": "A Kelvin sign can occupy the unrestricted position. Moving it to the restricted position changes match state.",
    },
    "capture-threshold": {
        "source_lines": [(535, 539), (545, 548), (2483, 2496)],
        "operation": "full-match",
        "pattern": ELEVEN_CAPTURES,
        "subjects": {b"aa", b"a\t"},
        "scope": "Ordinary caseful octet matching and the default Perl numeric escape grammar.",
        "proposition": "Eleven preceding groups make the escape a reference to captured a. The tab substitution changes match state.",
    },
    "capture-reference-control": {
        "source_lines": [(535, 539), (2431, 2434)],
        "operation": "compile",
        "patterns": {rb"(a)\1", rb"(a)\2"},
        "scope": "Ordinary compile with one capture and the default Perl numeric escape grammar.",
        "proposition": "Changing the reference from an existing capture to an absent one changes compile acceptance.",
    },
    "restricted-fold-domain": {
        "source_lines": [(286, 293), (1461, 1466)],
        "operation": "full-match",
        "pattern": b"(*UTF)(?ir)k",
        "subjects": {b"K", b"k", KELVIN},
        "scope": "UTF mode, caseless restriction, and Turkish casing disabled.",
        "proposition": "Restriction retains the ASCII folding equivalence. The Kelvin sign substitution changes match state.",
    },
}
FAMILY_RULE = {
    "numbered-reference-mismatch": "backreference-equality",
    "numbered-reference-repeat": "backreference-equality",
    "invalid-numbered-reference": "out-of-range-reference",
    "inline-caseless-restrict-local": "group-local-restriction",
    "inline-caseless-restrict-reject": "group-local-restriction",
    "numeric-escape-capture-threshold-match": "capture-threshold",
    "numeric-escape-capture-threshold-reject": "capture-threshold",
    "numeric-escape-invalid-reference-rejected": "capture-reference-control",
    "numeric-escape-valid-reference-control": "capture-reference-control",
    "simple-fold-restricted-cross-boundary": "restricted-fold-domain",
    "simple-fold-restricted-within-ascii": "restricted-fold-domain",
}
CONVENTIONAL_RULES = {"backreference-equality", "out-of-range-reference"}


def _source(raw: bytes) -> dict:
    if sha256(raw).hexdigest() != SOURCE_SHA256:
        fail("production-oracle-source-digest", "PCRE2 document bytes differ from the pinned 10.47 manual")
    return {
        "identity": "pcre2-pattern",
        "release": "10.47",
        "git_commit": SOURCE_GIT_COMMIT,
        "git_blob": SOURCE_GIT_BLOB,
        "sha256": SOURCE_SHA256,
        "url": SOURCE_URL,
    }


def _release_artifacts(root: Path, archive: bytes, signature: bytes, manual: bytes) -> dict:
    recipe = load_strict(root / RECIPE_PATH)
    artifact = {entry["name"]: entry for entry in recipe["artifacts"]}
    verified = {}
    for name, raw in (("pcre2-source", archive), ("pcre2-signature", signature)):
        entry = artifact[name]
        if sha256(raw).hexdigest() != entry["sha256"] or len(raw) != entry["size_bytes"]:
            fail("production-oracle-release-artifact", "archive or signature differs from recipe commitment", name)
        verified[name] = {"sha256": entry["sha256"], "size_bytes": entry["size_bytes"]}
    with tarfile.open(fileobj=BytesIO(archive), mode="r:gz") as release:
        member = release.getmember("pcre2-10.47/doc/pcre2pattern.3")
        if not member.isfile() or member.size != len(manual):
            fail("production-oracle-release-manual", "release archive does not contain the exact manual")
        with release.extractfile(member) as stream:
            if stream.read() != manual:
                fail("production-oracle-release-manual", "archive and Git manual bytes differ")
    return {"recipe_revision_id": recipe["recipe_revision_id"], "verified_bytes": verified, "signature_verified_here": False}


def _epistemic_scope(contract: dict, record: dict) -> dict:
    if record["oracle_class"] == "O4":
        return {
            "state": "relational-premise-frozen",
            "pending": "admissible terminal observations for the vector and its exact controls",
        }
    role = "implementation-documentation-evidence"
    use = "establish-implementation-documentation-expectation"
    conclusion = "implementation-documented-expectation"
    quality = evidence_admissibility._role_spec(contract, role)
    purpose = evidence_admissibility._use_spec(contract, use)
    strength = evidence_admissibility._strength_spec(contract, "conditional")
    if (
        quality["oracle_class"] != record["oracle_class"]
        or use not in quality["potentially_admitted_uses"]
        or role not in purpose["admissible_evidence_roles"]
        or any(conclusion not in scope["permitted_conclusions"] for scope in (quality, purpose, strength))
    ):
        fail("production-oracle-evidence-use", "documentation conclusion exceeds governed admissibility")
    return {
        "state": "documentation-premise-frozen", "evidence_role": role, "epistemic_use": use,
        "permitted_conclusion": conclusion, "source_language_strength": "conditional",
        "external_normative_authority": False,
    }


def _source_proposition(root: Path, key: str, lines: list[bytes], source: dict) -> dict:
    rule = DOMAINS[key]
    body = {
        "key": key,
        "source": source,
        "locators": [
            {"first_line": start, "last_line": end, "sha256": sha256(b"".join(lines[start - 1:end])).hexdigest()}
            for start, end in rule["source_lines"]
        ],
        "proposition": rule["proposition"],
        "scope_statement": rule["scope"],
    }
    return {**body, "claim_revision_id": _content_id(root, "finding-revision", "pcre2-documentation-proposition-v1", body)}


def _documented_partition(key: str, pattern: bytes, subjects: tuple[bytes, ...]) -> str:
    if key in {"out-of-range-reference", "capture-reference-control"}:
        return "compile-accept" if pattern == rb"(a)\1" else "compile-reject"
    subject = subjects[0]
    if key == "backreference-equality":
        matches = subject[0] == subject[1]
    elif key == "group-local-restriction":
        matches = subject.endswith(KELVIN)
    elif key == "capture-threshold":
        matches = subject == b"aa"
    elif key == "restricted-fold-domain":
        matches = subject in {b"K", b"k"}
    else:
        fail("production-oracle-rule", "no documented comparison partition exists", key)
    return "match" if matches else "no-match"


def _members(design: dict, manifest: dict) -> dict:
    stimuli = {row["vector_revision_id"]: row["stimulus"] for row in manifest["vectors"]}
    by_rule = defaultdict(list)
    if {row["family_key"] for row in design["candidate_bindings"]} != FAMILY_RULE.keys():
        fail("production-oracle-population", "selected family population differs from the reviewed rules")
    for binding in design["candidate_bindings"]:
        key = FAMILY_RULE[binding["family_key"]]
        for identifier in binding["vector_revision_ids"]:
            stimulus = stimuli[identifier]
            semantic_inputs = (bytes.fromhex(stimulus["pattern"]["hex"]), tuple(bytes.fromhex(item["hex"]) for item in stimulus["subjects"]))
            if (
                binding["adapter_operation"] != DOMAINS[key]["operation"]
                or stimulus["options"] or stimulus["initial_state"]
                or stimulus["replacement"] is not None or stimulus["callback_fixture"] is not None
                or stimulus["domain"] not in {"octets", "unicode-scalars"}
            ):
                fail("production-oracle-stimulus", "operation, encoding, options, or state exceeds the reviewed domain", identifier)
            by_rule[key].append((identifier, stimulus, binding["requirement_id"], semantic_inputs))
    for key, rule in DOMAINS.items():
        if "patterns" in rule:
            expected = {(pattern, ()) for pattern in rule["patterns"]}
        else:
            expected = {(rule["pattern"], (subject,)) for subject in rule["subjects"]}
        reached = [row[-1] for row in by_rule[key]]
        if len(reached) != len(expected) or set(reached) != expected:
            fail("production-oracle-population", "expanded stimuli differ from the exact documented case set", key)
    partitions = {identifier: _documented_partition(key, *case) for key, rows in by_rule.items() for identifier, _, _, case in rows}
    for binding in design["candidate_bindings"]:
        if any(partitions[identifier] != binding["expected_outcome"] for identifier in binding["vector_revision_ids"]):
            fail("production-oracle-control-partition", "candidate pairing falls outside the documented comparison partition", binding["family_key"])
    return by_rule


def _dependency(identifier: str, kind: str, role: str, version: str, sha: str, *, authority: str, upstream: list[str] | None = None) -> dict:
    return {
        "dependency_id": identifier, "kind": kind, "semantic_role": role,
        "authority_domain_id": authority, "version": version, "content_digest_sha256": sha,
        "upstream_dependency_ids": upstream or [], "subject_profile_ids": [], "semantic_evaluator": False,
    }


def _oracle_record(root, contract, inputs, coordinate, key, proposition, members, member):
    oracle_class = "O6" if key in CONVENTIONAL_RULES else "O4"
    spec = ORACLE_CLASSES[oracle_class]
    claim = proposition["claim_revision_id"]
    anchor = f"{SOURCE_URL}#L{proposition['locators'][0]['first_line']}"
    source = _dependency(
        claim, "implementation-documentation", "expected-basis", SOURCE_GIT_COMMIT, digest(proposition),
        authority=SOURCE_AUTHORITY,
    )
    generator = _dependency(
        coordinate["vector_revision_id"], "generator", "stimulus-only", "production-vector-family.v1",
        coordinate["stimulus_sha256"], authority=STIMULUS_AUTHORITY,
    )
    nodes = [source, generator]
    if oracle_class == "O6":
        result = (
            {"compile_status": "rejected"} if key == "out-of-range-reference"
            else {"match_state": _documented_partition(key, *member[-1])}
        )
        expected = {"result_type": "conventional", "value": result, "scope_statement": proposition["scope_statement"]}
        provenance = {
            "claim_revision_id": claim, "documentation_identity": "pcre2-pattern",
            "documentation_version": SOURCE_GIT_COMMIT, "implementation_scope_id": coordinate["profile_id"],
            "locator": anchor, "scope_statement": proposition["scope_statement"],
        }
        roots = [claim]
    else:
        comparison_ids = sorted(row[0] for row in members if row[2] != member[2])
        if not comparison_ids:
            fail("production-oracle-relation-controls", "relational case has no complementary requirement control", key)
        relation = {
            "relation": "distinct-observation-field",
            "field": "compile_status" if key == "capture-reference-control" else "match_state",
            "terminal_values": ["accepted", "rejected"] if key == "capture-reference-control" else ["match", "no-match"],
            "control_vector_revision_ids": comparison_ids,
        }
        result_id = _content_id(root, "expectation-projection", "pcre2-documented-relation-v1", {"claim": claim, **relation})
        nodes.append(_dependency(result_id, "relation-definition", "expected-basis", "1.0.0", digest(relation), authority=SOURCE_AUTHORITY, upstream=[claim]))
        expected = {"result_type": "relation", "value": relation, "scope_statement": proposition["scope_statement"]}
        provenance = {
            "relation_identity": result_id, "relation_version": "1.0.0",
            "source_construction_ids": [claim], "follow_up_construction_ids": comparison_ids,
            "applicability_gates": [proposition["scope_statement"], "Exact same realized profile and terminal native outcomes."],
            "permitted_conclusion": "relation-violated",
        }
        roots = [result_id]
    requirement = inputs.requirements[coordinate["semantic_requirement_id"]]
    assertions = sorted({
        assertion for obligation_id in requirement["obligation_scientific_ids"]
        for assertion in inputs.obligations[obligation_id]["source_semantic_assertion_ids"]
    })
    return finalize_oracle_record(root, {
        "schema_version": "oracle-record.v1", "oracle_record_version": "1.0.0",
        "contract_ref": {name: contract[name] for name in ("contract_id", "contract_digest_sha256")},
        "requirement_scientific_id": coordinate["semantic_requirement_id"],
        "oracle_class": oracle_class, "resolution_state": "oracle-established",
        "scope": {
            "kind": spec["scope_kind"], "profile_ids": [coordinate["profile_id"]], "profile_family_id": None,
            "operation_scientific_ids": [coordinate["operation_id"]], "semantic_assertion_revision_ids": assertions,
        },
        "applicability_conditions": {"operator": "all", "clauses": [
            {"field": "profile.id", "operator": "equals", "value": coordinate["profile_id"]},
            {"field": "release.id", "operator": "equals", "value": coordinate["target_release_id"]},
            {"field": "vector.revision-id", "operator": "equals", "value": coordinate["vector_revision_id"]},
        ]},
        "provenance": provenance,
        "dependency_graph": {"nodes": nodes, "root_dependency_ids": roots},
        "independence": {
            "evaluated_profile_ids": [coordinate["profile_id"]],
            "stimulus_generator_authority_domain_ids": [STIMULUS_AUTHORITY], "requires_independent_basis": oracle_class == "O6",
        },
        "permitted_judgments": spec["permitted_judgments"],
        "expected_result": expected, "promotion_event": None, "derivation": _contract_derivation(root),
    })


def build_pcre2_oracle_report(
    root: Path, inputs, manifest: dict, families: list[dict], source_bytes: bytes | None, *,
    expected_manifest_digest: str, expected_preflight_digest: str, frozen_at: str,
    release_artifacts: tuple[bytes, bytes] | None = None,
) -> dict:
    design = build_production_campaign_design(root, inputs, manifest, families, expected_manifest_digest=expected_manifest_digest)
    preflight = build_production_preflight(root, inputs, manifest, families, expected_manifest_digest=expected_manifest_digest)
    if preflight["preflight_digest_sha256"] != expected_preflight_digest:
        fail("production-oracle-preflight", "recomputed preflight differs from the separately pinned digest")
    contract = load_pinned_contract(root)
    evidence_contract = load_pinned_contract(root, evidence_admissibility.CONTRACT_PATH, evidence_admissibility.AUTHORITY_PATH)
    by_rule = _members(design, manifest)
    source = _source(source_bytes) if source_bytes is not None else None
    if release_artifacts is not None and source is None:
        fail("production-oracle-release-manual", "archived release proof requires the reviewed manual")
    archived_release = _release_artifacts(root, *release_artifacts, source_bytes) if release_artifacts is not None else None
    lines = source_bytes.splitlines(keepends=True) if source is not None else []
    propositions = {key: _source_proposition(root, key, lines, source) for key in sorted(by_rule)} if source is not None else {}
    scope = {
        "cutoff": CUTOFF, "frozen_at": frozen_at, "preflight_digest_sha256": expected_preflight_digest,
        "profile_id": design["proposed_profile_id"], "target_release_id": design["proposed_release_id"],
        "environment_recipe_revision_id": design["proposed_environment_recipe_revision_id"],
        "adapter_manifest_id": design["proposed_adapter_manifest_id"],
        "documentation_sha256": SOURCE_SHA256,
        "propositions_sha256": digest(propositions) if source is not None else None,
        "evidence_admissibility_contract_sha256": evidence_contract["contract_digest_sha256"],
        "archived_release_sha256": digest(archived_release) if archived_release is not None else None,
    }
    campaign_revision = _content_id(root, "campaign-definition-revision", "pcre2-first-candidate-campaign-scope-v1", scope)
    rows = []
    for key, members in by_rule.items():
        for member in members:
            identifier, stimulus, requirement, _ = member
            coordinate = {
                "vector_revision_id": identifier, "stimulus_sha256": digest(stimulus),
                "semantic_requirement_id": requirement, "operation_id": stimulus["operation_id"],
                "profile_id": scope["profile_id"], "target_release_id": scope["target_release_id"],
                "campaign_definition_revision_id": campaign_revision, "stimulus_generator_authority": STIMULUS_AUTHORITY,
            }
            records = [] if source is None else [_oracle_record(root, contract, inputs, coordinate, key, propositions[key], members, member)]
            row = resolve_coordinate(root, contract, coordinate, records, frozen_at=frozen_at)
            row["epistemic_scope"] = _epistemic_scope(evidence_contract, records[0]) if records else None
            rows.append(row)
    body = {
        "schema_version": "pcre2-production-oracle-review.v1", "scope": scope,
        "candidate_campaign_revision_id": campaign_revision, "source": source, "archived_release": archived_release,
        "propositions": list(propositions.values()),
        "resolution_rows": sorted(rows, key=lambda row: row["coordinate"]["vector_revision_id"]),
        "execution_ready": False, "production_execution_denominator": None,
        "blockers": ["Realized profile capability authority", "Exact bounded production authorization"],
    }
    body["admission_review"] = build_admission_review(root, inputs, manifest, design, body)
    return {**body, "report_digest_sha256": digest(body)}
