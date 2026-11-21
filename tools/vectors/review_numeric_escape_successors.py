#!/usr/bin/env python3
"""Replay the proposed numeric-escape interaction changes without allocating IDs."""

from __future__ import annotations

import argparse
from hashlib import sha256
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "schemas/tooling/python"))

from regex_conformance_schema.errors import fail  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402
from regex_conformance_schema.obligation_derivation import CONTRACT_PATH, SNAPSHOT_PATH, derive_feature  # noqa: E402
from regex_conformance_schema.production_vectors import load_vector_compiler_inputs  # noqa: E402


FEATURE = "feature.numeric-escape-disambiguation"
OLD_LITERAL = "feature.escaped-literal"
NEW_LITERAL = "feature.literal-unit"
OLD_OCTAL = "feature.numeric-unicode-code-point-escape"
ANNEX_B = "https://tc39.es/ecma262/2026/multipage/additional-ecmascript-features-for-web-browsers.html#sec-regular-expressions-patterns"
PCRE2_OCTAL = "https://raw.githubusercontent.com/PCRE2Project/pcre2/pcre2-10.47/doc/pcre2pattern.3#L501"
ECMA_EARLY_ERRORS = "https://tc39.es/ecma262/2026/multipage/text-processing.html#sec-patterns-static-semantics-early-errors"


def digest(data: object) -> str:
    return sha256(canonical_bytes(data)).hexdigest()


def build_review(root: Path) -> dict:
    inputs = load_vector_compiler_inputs(root)
    snapshot = load_strict(root / SNAPSHOT_PATH)
    contract = load_strict(root / CONTRACT_PATH)
    feature = next(row for row in snapshot["features"] if row["feature_id"] == FEATURE)

    def by_target(record: dict) -> dict:
        return {
            candidate["interaction_basis"]["target_id"]: candidate["prospective_identity_basis"]
            for decision in derive_feature(snapshot, contract, record)
            for candidate in decision["provisional_obligations"]
            if candidate["interaction_basis"] and candidate["interaction_basis"]["relation_type"] == "prerequisite"
        }

    before = by_target(feature)
    proposed = {
        **feature,
        "prerequisite_feature_ids": [
            NEW_LITERAL if key == OLD_LITERAL else key for key in feature["prerequisite_feature_ids"]
        ],
    }
    after = by_target(proposed)
    if before.keys() - after.keys() != {OLD_LITERAL} or after.keys() - before.keys() != {NEW_LITERAL}:
        fail("numeric-escape-successor-target-set", "literal-only replay must replace exactly one prerequisite")
    if any(before[key] != after[key] for key in before.keys() & after.keys()):
        fail("numeric-escape-successor-drift", "literal-only replay changed the identity basis of another edge")

    obligations = {
        row["interaction_basis"]["target_id"]: row
        for row in inputs.obligations.values()
        if row["feature_id"] == FEATURE and row["interaction_basis"]
        and row["interaction_basis"]["relation_type"] == "prerequisite"
    }
    if before != {key: row["identity_basis"] for key, row in obligations.items()}:
        fail("numeric-escape-successor-baseline", "derived prerequisite bases differ from the accepted snapshot")
    dispositions = []
    for target in (OLD_LITERAL, OLD_OCTAL):
        obligation = obligations[target]
        identifier = obligation["scientific_id"]
        affected = [
            row for row in inputs.requirements.values()
            if identifier in row["obligation_scientific_ids"]
        ]
        replacements = {row["evidence_role"]: row["scientific_id"] for row in affected}
        if (
            len(affected) != 2 or sorted(replacements) != ["negative", "positive"]
            or not set(replacements.values()) <= inputs.unresolved_interactions.keys()
        ):
            fail("numeric-escape-successor-lineage", "each retained question requires its own unresolved positive and negative predecessor")
        literal = target == OLD_LITERAL
        dispositions.append({
            "predecessor_obligation_id": identifier,
            "predecessor_identity_basis_sha256": digest(before[target]),
            "predecessor_requirements_by_retained_role": replacements,
            "proposed_target_key": NEW_LITERAL if literal else None,
            "proposed_target_semantics": "Annex B legacy source-character identity escape for an unbound digit" if literal else "Octal character value under the profile's numeric-escape grammar",
            "primary_source": ANNEX_B if literal else PCRE2_OCTAL,
            "proposed_literal_target_only_basis_sha256": digest(after[NEW_LITERAL]) if literal else None,
            "additional_applicability_constraint": "Annex B, Unicode mode absent, no corresponding capture" if literal else "Target's octal branch and its exact capture-count or digit-width rule",
            "successor_obligation_id": None,
            "successor_requirement_ids": None,
        })
    body = {
        "schema_version": "numeric-escape-interaction-successor-review.v1",
        "classification": "unadopted-scientific-review",
        "obligation_snapshot": inputs.obligation_snapshot,
        "requirement_snapshot": inputs.requirement_snapshot,
        "derivation_contract_sha256": contract["contract_digest_sha256"],
        "literal_only_replay_preserves_prerequisite_count": len(before) == len(after),
        "retained_by_identity_if_only_two_edges_change": {
            "obligations": len(inputs.obligations) - len(dispositions),
            "requirements": len(inputs.requirements) - sum(len(row["predecessor_requirements_by_retained_role"]) for row in dispositions),
        },
        "successor_full_denominator": None,
        "dispositions": dispositions,
    }
    return {**body, "review_digest_sha256": digest(body)}


def build_joint_review(root: Path) -> dict:
    """Reconcile both Annex B questions with the accepted predecessor population."""
    original = build_review(root)
    inputs = load_vector_compiler_inputs(root)
    questions = (
        {
            "name": "literal-digit-fallback", "production": "SourceCharacterIdentityEscape",
            "existing_prerequisite_scientific_id": next(
                row["scientific_id"] for row in load_strict(root / SNAPSHOT_PATH)["features"]
                if row["feature_id"] == NEW_LITERAL
            ),
            "positive_stimulus": {"pattern": r"\8", "subject": "8", "interpretation": "literal U+0038"},
            "negative_stimulus": {"pattern": r"()()()()()()()(q)\8", "subject": "q8", "interpretation": "reference to group 8"},
            "forward_reference_control": {"pattern": r"\8()()()()()()()(q)", "subject": "q", "interpretation": "reference to group 8"},
        },
        {
            "name": "legacy-octal-fallback", "production": "LegacyOctalEscapeSequence",
            "existing_prerequisite_scientific_id": None,
            "positive_stimulus": {"pattern": r"\11", "subject": "\t", "interpretation": "octal 011 gives U+0009"},
            "negative_stimulus": {"pattern": r"()()()()()()()()()()(q)\11", "subject": "q\t", "interpretation": "reference to group 11"},
            "forward_reference_control": {"pattern": r"\11()()()()()()()()()()(q)", "subject": "q", "interpretation": "reference to group 11"},
        },
    )
    obligation_ids = set()
    requirement_ids = set()
    mappings = []
    for question, row in zip(questions, original["dispositions"], strict=True):
        predecessor = row["predecessor_obligation_id"]
        roles = row["predecessor_requirements_by_retained_role"]
        if predecessor in obligation_ids or requirement_ids.intersection(roles.values()):
            fail("numeric-escape-joint-duplicate", "the two questions must have distinct predecessors")
        obligation_ids.add(predecessor)
        requirement_ids.update(roles.values())
        mappings.append({**question, "predecessor_obligation_scientific_id": predecessor, "roles": [
            {"role": role, "predecessor_requirement_scientific_id": identifier, "successor_requirement_scientific_id": None}
            for role, identifier in sorted(roles.items())
        ], "successor_obligation_scientific_id": None})
    dependent = {
        identifier for identifier, row in inputs.requirements.items()
        if obligation_ids.intersection(row["obligation_scientific_ids"])
    }
    if dependent != requirement_ids or set(inputs.unresolved_interactions) != requirement_ids:
        fail("numeric-escape-joint-lineage", "the proposed lineage does not cover the complete unresolved predecessor set")
    retained_obligations = sorted(inputs.obligations.keys() - obligation_ids)
    retained_requirements = sorted(inputs.requirements.keys() - requirement_ids)
    body = {
        "schema_version": "numeric-escape-joint-successor-verification.v1",
        "classification": "prospective-migration",
        "predecessor_review_digest_sha256": original["review_digest_sha256"],
        "sources": [ANNEX_B, ECMA_EARLY_ERRORS, PCRE2_OCTAL,
                    "https://www.unicode.org/reports/tr18/tr18-25.html#Hex_notation"],
        "profile_scope": "ECMAScript host with the Annex B RegExp grammar",
        "stimulus_scope": "Outside character classes. For fallback probes omit u and v and count captures across the entire pattern.",
        "unicode_mode_control": "Without a corresponding capture, both digit sequences are early errors in u and v modes.",
        "comparison_boundary": "The separate PCRE2 Perl-compatible octal rule uses preceding captures.",
        "mappings": mappings,
        "identity_retention": {
            "obligation_count": len(retained_obligations), "obligation_id_set_sha256": digest(retained_obligations),
            "requirement_count": len(retained_requirements), "requirement_id_set_sha256": digest(retained_requirements),
        },
        "one_for_one_replacement_totals": {
            "obligations": len(retained_obligations) + len(mappings),
            "requirements": len(retained_requirements) + sum(len(row["roles"]) for row in mappings),
        },
        "unadopted_dependencies": ["allocate exact Annex B grammar capability and octal prerequisite identities",
                                   "compile and independently reconcile complete successor snapshots and predicate revisions"],
    }
    return {**body, "verification_digest_sha256": digest(body)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--joint-review", action="store_true")
    args = parser.parse_args()
    builder = build_joint_review if args.joint_review else build_review
    encoded = canonical_bytes(builder(ROOT)) + b"\n"
    if args.output:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    else:
        print(encoded.decode("utf-8"), end="")


if __name__ == "__main__":
    main()
