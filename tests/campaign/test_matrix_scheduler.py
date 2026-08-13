from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "matrix" / "python", ROOT / "scheduler" / "python"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_matrix import MatrixCompileError, compile_candidates
from regex_conformance_scheduler import shard_by_selection_locality


class MatrixAndSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profiles = {"engine": {"profile_id": "rcid:v1:profile:u7:019ffbeb-56fb-75df-8c1c-abb6b9c7eb56"}}
        self.vectors = [
            (
                {"key": "probe"},
                "rcid:v1:vector-revision:h:jcs-sha256-v1:" + "1" * 64,
            )
        ]
        self.policy = {
            "default_outcome": "excluded",
            "predicate": "exact-selection-and-vector-key-membership",
            "rules": [{"rule_key": "include", "selection_key": "engine", "vector_key": "probe"}],
        }

    def test_applicability_is_total_and_proof_bearing(self) -> None:
        included = compile_candidates(self.profiles, self.vectors, self.policy, "policy-id")
        excluded_policy = {**self.policy, "rules": []}
        excluded = compile_candidates(self.profiles, self.vectors, excluded_policy, "policy-id")
        self.assertEqual(included[0]["applicability"], "included")
        self.assertEqual(included[0]["proof"]["rule_key"], "include")
        self.assertEqual(excluded[0]["applicability"], "excluded")
        self.assertEqual(excluded[0]["proof"]["outcome_source"], "default-outcome")

    def test_duplicate_and_unknown_rules_fail_closed(self) -> None:
        duplicate = {**self.policy, "rules": self.policy["rules"] * 2}
        with self.assertRaises(MatrixCompileError):
            compile_candidates(self.profiles, self.vectors, duplicate, "policy-id")
        unknown = {
            **self.policy,
            "rules": [{"rule_key": "bad", "selection_key": "missing", "vector_key": "probe"}],
        }
        with self.assertRaises(MatrixCompileError):
            compile_candidates(self.profiles, self.vectors, unknown, "policy-id")

    def test_sharding_is_bounded_deterministic_and_exact(self) -> None:
        logicals = [
            {"logical_execution_id": value, "selection_key": selection}
            for value, selection in (("b", "one"), ("a", "one"), ("c", "two"))
        ]
        identity = lambda body: "shard:" + body["selection_key"] + ":" + "-".join(body["logical_execution_ids"])
        first = shard_by_selection_locality(logicals, 1, identity)
        second = shard_by_selection_locality(list(reversed(logicals)), 1, identity)
        self.assertEqual(first, second)
        self.assertEqual(sorted(member for shard in first for member in shard["logical_execution_ids"]), ["a", "b", "c"])
        with self.assertRaises(ValueError):
            shard_by_selection_locality(logicals, 0, identity)


if __name__ == "__main__":
    unittest.main()
