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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = canonical_bytes(build_review(ROOT)) + b"\n"
    if args.output:
        with args.output.open("xb") as stream:
            stream.write(encoded)
    else:
        print(encoded.decode("utf-8"), end="")


if __name__ == "__main__":
    main()
