from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
import unittest

from support import ROOT
from regex_conformance_schema.derivation import (
    CATALOG_PATH as DERIVATION_CATALOG_PATH,
    require_assertion_gate,
)
from regex_conformance_schema.foundation import verify_foundation_history
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.scientific_identity import verify_catalog as verify_identity_catalog


SCRIPT = ROOT / "tools/semantics/freeze_semantic_universe.py"
SPEC = importlib.util.spec_from_file_location("freeze_semantic_universe", SCRIPT)
assert SPEC and SPEC.loader
compiler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compiler)


class SemanticUniverseFreezeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.allocation = load_strict(ROOT / compiler.ALLOCATION_PATH)
        cls.artifacts = compiler.build_all(cls.allocation)
        cls.snapshot = cls.artifacts[compiler.SNAPSHOT_PATH]
        cls.ledger = cls.artifacts[compiler.LEDGER_PATH]
        cls.coverage = cls.artifacts[compiler.SOURCE_COVERAGE_PATH]
        cls.audit = cls.artifacts[compiler.AUDIT_REPORT_PATH]
        cls.freeze = cls.artifacts[compiler.FREEZE_PATH]
        cls.derivations = load_strict(ROOT / DERIVATION_CATALOG_PATH)

    def test_every_prior_and_new_candidate_is_terminally_dispositioned(self) -> None:
        self.assertEqual(self.ledger["counts"]["total"], 91)
        self.assertEqual(self.ledger["counts"]["prior_revalidated"], 73)
        self.assertEqual(self.ledger["counts"]["newly_discovered"], 18)
        self.assertEqual(self.ledger["counts"]["blocking_unresolved"], 0)
        self.assertEqual(
            self.ledger["counts"]["new_candidate_yield_by_strategy"],
            {"ontology-first": 3, "operation-first": 3, "source-first": 7, "terminology-first": 1, "test-corpus-first": 4},
        )
        self.assertEqual(len({item["candidate_id"] for item in self.ledger["candidates"]}), 91)

    def test_only_material_residual_semantics_are_promoted(self) -> None:
        features = {item["feature_id"]: item for item in self.snapshot["features"]}
        modifiers = {item["modifier_id"]: item for item in self.snapshot["modifiers"]}
        candidates = {item["candidate_key"]: item for item in self.ledger["candidates"]}
        self.assertIn("feature.numeric-escape-disambiguation", features)
        self.assertIn("modifier.caseless-restrict", modifiers)
        self.assertEqual(
            candidates["candidate.residual.feature.earliest-detected-match"]["disposition"],
            "profile-specific-not-canonical",
        )
        self.assertNotIn("feature.earliest-detected-match", features)
        self.assertEqual(len(features["feature.numeric-escape-disambiguation"]["semantic_assertions"]), 10)

    def test_source_coverage_has_no_orphan_or_secondary_only_feature(self) -> None:
        self.assertEqual(self.coverage["summary"]["feature_count"], 269)
        self.assertEqual(self.coverage["summary"]["source_orphan_count"], 0)
        self.assertEqual(self.coverage["summary"]["secondary_only_count"], 0)
        self.assertTrue(all(item["source_ids"] for item in self.coverage["features"]))

    def test_freeze_report_quantifies_the_complete_semantic_population(self) -> None:
        self.assertEqual(
            self.audit["semantic_population"],
            {
                "canonical_features": 269,
                "operations": 33,
                "semantic_facets": 15,
                "source_identities": 60,
                "semantic_variants": 93,
                "syntax_manifestations": 326,
                "modifiers": 33,
                "typed_interactions": 108,
            },
        )
        self.assertEqual(self.audit["identity_change_summary"]["total_scientific_identity_additions"], 4)

    def test_adversarial_corruptions_fail_closed(self) -> None:
        orphaned = deepcopy(self.artifacts)
        orphaned[compiler.SOURCE_COVERAGE_PATH]["summary"]["source_orphan_count"] = 1
        with self.assertRaisesRegex(ValueError, "source-orphaned"):
            compiler.verify(self.allocation, orphaned)

        duplicate = deepcopy(self.artifacts)
        duplicate[compiler.SNAPSHOT_PATH]["features"][-1]["canonical_name"] = duplicate[compiler.SNAPSHOT_PATH]["features"][0]["canonical_name"]
        with self.assertRaisesRegex(ValueError, "duplicate canonical"):
            compiler.verify(self.allocation, duplicate)

        blocked = deepcopy(self.artifacts)
        blocked[compiler.LEDGER_PATH]["counts"]["blocking_unresolved"] = 1
        with self.assertRaisesRegex(ValueError, "candidate ledger"):
            compiler.verify(self.allocation, blocked)

        dangling_source = deepcopy(self.artifacts)
        dangling_source[compiler.LEDGER_PATH]["candidates"][0]["evidence_source_ids"] = ["source.missing"]
        with self.assertRaisesRegex(ValueError, "candidate disposition references an unknown source"):
            compiler.verify(self.allocation, dangling_source)

    def test_freeze_manifest_and_authority_pointer_close(self) -> None:
        self.assertEqual(self.freeze["closure"]["result"], "PASS")
        self.assertEqual(self.freeze["closure"]["blocking_candidates"], 0)
        authority = self.artifacts[compiler.AUTHORITY_PATH]
        self.assertEqual(authority["current_snapshot"]["id"], self.snapshot["snapshot_id"])
        self.assertEqual(authority["freeze_manifest"]["id"], self.freeze["manifest_id"])
        self.assertEqual(authority["denominator_authority"]["state"], "pre-rederivation-predecessor-bound")

    def test_scientific_identities_are_additive_and_locked(self) -> None:
        predecessor = load_strict(ROOT / compiler.PREDECESSOR_PATH)
        before = {item["feature_id"]: item["scientific_id"] for item in predecessor["features"]}
        after = {item["feature_id"]: item["scientific_id"] for item in self.snapshot["features"]}
        self.assertEqual(before, {key: after[key] for key in before})
        identities = verify_identity_catalog(ROOT)
        self.assertGreaterEqual(identities["scientific_identities"], 22431)
        self.assertGreaterEqual(identities["scientific_lineage_records"], 0)

    def test_predecessors_and_denominator_are_byte_stable(self) -> None:
        expected = {
            "semantic-corpus/snapshots/regex-semantic-features-2026-08-22.v1.json": "a1a684abea7cc5a5224b4f94004ee21f05efd2cf5306ce4711dcbe437ff84645",
            "semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v2.json": "25642d3e5bc7788e4135c0e846e164fb4a69afdee3c86787594cc0f65aeca748",
            "semantic-corpus/snapshots/regex-semantic-features-2026-09-07.v3.json": "0365f7c6d6c0899c46670260c9e4a38454d625ef183f7b165b5082fb7acfae95",
            **{path.as_posix(): digest for key, path in compiler.DENOMINATOR_PATHS.items() for digest in [compiler.DENOMINATOR_SHA256[key]]},
        }
        for path, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest)
        self.assertTrue(self.audit["denominator_boundary"]["artifacts_unchanged"])
        self.assertEqual(self.audit["denominator_boundary"]["obligation_templates"], 12048)
        self.assertEqual(self.audit["denominator_boundary"]["vector_requirements"], 9506)

    def test_derivation_is_admissible_and_foundation_history_remains_valid(self) -> None:
        require_assertion_gate(
            self.derivations,
            compiler.SNAPSHOT_PATH.as_posix(),
            "/features/0/semantic_assertions/definition/statement",
            "semantic-completeness",
        )
        require_assertion_gate(
            self.derivations,
            compiler.LEDGER_PATH.as_posix(),
            "/candidates/0/rationale",
            "independent-evidence",
        )
        self.assertEqual(verify_foundation_history(ROOT)["foundation_acceptance"], "PASS")

    def test_regeneration_is_byte_deterministic(self) -> None:
        second = compiler.build_all(self.allocation)
        self.assertEqual(self.artifacts, second)
        for path, artifact in self.artifacts.items():
            self.assertEqual((ROOT / path).read_bytes(), canonical_bytes(artifact) + b"\n")


if __name__ == "__main__":
    unittest.main()
