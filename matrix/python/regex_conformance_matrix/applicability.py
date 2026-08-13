"""Evaluate the closed applicability rule set without runtime-observation feedback."""

from __future__ import annotations

from typing import Any


class MatrixCompileError(ValueError):
    pass


def compile_candidates(
    profiles: dict[str, dict[str, Any]],
    vectors: list[tuple[dict[str, Any], str]],
    policy: dict[str, Any],
    policy_id: str,
) -> list[dict[str, Any]]:
    rules: dict[tuple[str, str], str] = {}
    for rule in policy["rules"]:
        coordinate = (rule["selection_key"], rule["vector_key"])
        if coordinate in rules:
            raise MatrixCompileError(f"duplicate applicability coordinate {coordinate!r}")
        rules[coordinate] = rule["rule_key"]
    known = {(selection, vector["key"]) for selection in profiles for vector, _ in vectors}
    unknown = sorted(set(rules) - known)
    if unknown:
        raise MatrixCompileError(f"applicability rules reference unknown candidates: {unknown!r}")
    candidates: list[dict[str, Any]] = []
    for selection_key in sorted(profiles):
        for vector, vector_revision_id in vectors:
            coordinate = (selection_key, vector["key"])
            applicable = coordinate in rules
            candidates.append(
                {
                    "applicability": "included" if applicable else policy["default_outcome"],
                    "candidate_key": f"{selection_key}:{vector['key']}",
                    "proof": {
                        "outcome_source": "matched-rule" if applicable else "default-outcome",
                        "policy_id": policy_id,
                        "predicate": policy["predicate"],
                        "rule_key": rules.get(coordinate),
                        "selection_key": selection_key,
                        "vector_key": vector["key"],
                    },
                    "profile_id": profiles[selection_key]["profile_id"],
                    "selection_key": selection_key,
                    "vector_revision_id": vector_revision_id,
                }
            )
    return sorted(candidates, key=lambda item: item["candidate_key"])
