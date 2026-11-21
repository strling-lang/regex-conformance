from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.oracle import finalize_oracle_record, validate_vector_binding
from regex_conformance_schema.pcre2_oracle_review import (
    SOURCE_AUTHORITY,
    STIMULUS_AUTHORITY,
    _dependency,
    _members,
    _oracle_record,
    _source,
)
from regex_conformance_schema.production_admission import build_admission_review
from regex_conformance_schema.production_campaign_design import build_production_campaign_design
from regex_conformance_schema.production_oracle import digest, load_pinned_contract, resolve_coordinate
from regex_conformance_schema.production_vectors import compile_vector_manifest, load_vector_compiler_inputs


class ProductionOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = load_pinned_contract(ROOT)
        cls.inputs = load_vector_compiler_inputs(ROOT)
        families = [load_strict(path) for path in sorted((ROOT / "vectors/families").glob("*.json"))]
        cls.manifest = compile_vector_manifest(cls.inputs, families)
        cls.design = build_production_campaign_design(
            ROOT, cls.inputs, cls.manifest, families, expected_manifest_digest=cls.manifest["manifest_digest_sha256"],
        )
        cls.members = _members(cls.design, cls.manifest)
        member = cls.members["backreference-equality"][0]
        cls.coordinate = cls.make_coordinate(member)
        cls.record = cls.make_record("backreference-equality", member)

    @classmethod
    def make_coordinate(cls, member):
        return {
            "vector_revision_id": member[0], "stimulus_sha256": digest(member[1]), "semantic_requirement_id": member[2],
            "operation_id": member[1]["operation_id"], "profile_id": cls.design["proposed_profile_id"],
            "target_release_id": cls.design["proposed_release_id"], "stimulus_generator_authority": STIMULUS_AUTHORITY,
            "campaign_definition_revision_id": "rcid:v1:campaign-definition-revision:h:jcs-sha256-v1:" + "d" * 64,
        }

    @classmethod
    def make_record(cls, kind, member):
        # Structural oracle tests use a synthetic source proposition. The actual
        # production CLI requires the separately pinned complete vendor manual.
        proposition = {
            "claim_revision_id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "c" * 64,
            "scope_statement": "Synthetic evidence for resolver tests only.",
            "locators": [{"first_line": 1}],
        }
        return _oracle_record(ROOT, cls.contract, cls.inputs, cls.make_coordinate(member), kind, proposition, cls.members[kind], member)

    def resolve(self, records, coordinate=None):
        return resolve_coordinate(ROOT, self.contract, coordinate or self.coordinate, records, frozen_at="2026-11-21T14:40:00Z")

    def test_binds_exact_revisions_and_leaves_execution_unadmitted(self):
        result = self.resolve([self.record])
        self.assertEqual(result["resolution_state"], "oracle-established")
        self.assertFalse(result["execution_eligible"])
        binding = result["binding"]
        self.assertEqual(binding["vector_revision_id"], self.coordinate["vector_revision_id"])
        self.assertEqual(binding["semantic_requirement_id"], self.coordinate["semantic_requirement_id"])
        self.assertEqual(binding["campaign_definition_revision_id"], self.coordinate["campaign_definition_revision_id"])
        self.assertFalse(binding["mutable_latest_alias_used"])
        with self.assertRaisesRegex(ConformanceDataError, "frozen-oracle-drift"):
            validate_vector_binding(ROOT, self.contract, binding, [])

    def test_absent_and_unestablished_authorities_remain_explicit(self):
        self.assertEqual(self.resolve([])["resolution_state"], "oracle-inputs-unavailable")
        self.assertIsNone(self.resolve([])["binding"])
        for state in ("oracle-inapplicable", "expectation-ambiguous", "expectation-under-specified"):
            with self.subTest(state=state):
                record = finalize_oracle_record(ROOT, {**self.record, "resolution_state": state, "expected_result": None})
                self.assertEqual(self.resolve([record])["resolution_state"], state)

    def test_rejects_cross_scope_and_changed_semantic_stimulus(self):
        for key in ("profile_id", "semantic_requirement_id", "operation_id"):
            with self.subTest(key=key), self.assertRaisesRegex(ConformanceDataError, "production-oracle-scope"):
                self.resolve([self.record], {**self.coordinate, key: "unrelated"})
        for key in ("vector_revision_id", "stimulus_sha256"):
            with self.subTest(key=key), self.assertRaisesRegex(ConformanceDataError, "production-oracle-stimulus"):
                self.resolve([self.record], {**self.coordinate, key: "changed"})

    def test_rejects_unpinned_manual_and_changed_record(self):
        with self.assertRaisesRegex(ConformanceDataError, "production-oracle-source-digest"):
            _source(b"Unpinned source")
        record = {**self.record, "oracle_digest_sha256": "0" * 64}
        with self.assertRaisesRegex(ConformanceDataError, "oracle-record-identity"):
            self.resolve([record])

    def test_preserves_simultaneous_conflicting_claims(self):
        record = deepcopy(self.record)
        expected = record["expected_result"]["value"]
        expected["match_state"] = "no-match" if expected["match_state"] == "match" else "match"
        record = finalize_oracle_record(ROOT, record)
        result = self.resolve([self.record, record])
        self.assertEqual(result, self.resolve([record, self.record]))
        self.assertEqual(result["resolution_state"], "conflicting-authoritative-expectations")
        self.assertIsNone(result["conflicts"][0]["selected_oracle_id"])
        self.assertCountEqual(result["conflicts"][0]["oracle_ids"], [self.record["oracle_id"], record["oracle_id"]])

    def test_rejects_transitive_target_consensus_and_stimulus_influence(self):
        for kind, code in (
            ("target-implementation-output", "target-self-oracle"),
            ("empirical-consensus", "consensus-oracle-forbidden"),
            ("empirical-observation", "observation-as-expectation"),
        ):
            record = deepcopy(self.record)
            graph = record["dependency_graph"]
            graph["nodes"][0]["upstream_dependency_ids"] = ["transitive"]
            graph["nodes"].append(_dependency("transitive", kind, "context-only", "1", "d" * 64, authority=SOURCE_AUTHORITY))
            with self.subTest(kind=kind), self.assertRaisesRegex(ConformanceDataError, code):
                self.resolve([finalize_oracle_record(ROOT, record)])
        record = deepcopy(self.record)
        record["dependency_graph"]["nodes"][0]["upstream_dependency_ids"] = [self.coordinate["vector_revision_id"]]
        with self.assertRaisesRegex(ConformanceDataError, "production-oracle-stimulus"):
            self.resolve([finalize_oracle_record(ROOT, record)])

    def test_rejects_cyclic_or_mutable_provenance_and_escalation(self):
        cases = (
            ("oracle-dependency-cycle", lambda record: record["dependency_graph"]["nodes"][0].update({
                "upstream_dependency_ids": record["dependency_graph"]["root_dependency_ids"],
            })),
            ("mutable-oracle-version", lambda record: record["provenance"].update({"documentation_version": "latest"})),
            ("oracle-judgment-escalation", lambda record: record.update({"permitted_judgments": ["normative-conformant"]})),
        )
        for code, mutate in cases:
            record = deepcopy(self.record)
            mutate(record)
            with self.subTest(code=code), self.assertRaisesRegex(ConformanceDataError, code):
                self.resolve([finalize_oracle_record(ROOT, record)])

    def test_relational_class_never_contains_a_standalone_expectation(self):
        member = self.members["capture-threshold"][0]
        record = self.make_record("capture-threshold", member)
        coordinate = self.make_coordinate(member)
        result = self.resolve([record], coordinate)
        expected = result["oracle_records"][0]["expected_result"]
        self.assertEqual(expected["result_type"], "relation")
        self.assertEqual(len(expected["value"]["control_vector_revision_ids"]), 1)
        record["expected_result"] = {
            "result_type": "conventional", "value": {"match_state": "match"}, "scope_statement": "wrong oracle class",
        }
        with self.assertRaisesRegex(ConformanceDataError, "missing-relational-condition"):
            self.resolve([finalize_oracle_record(ROOT, record)], coordinate)

    def test_independent_population_check_rejects_omitted_case(self):
        design = deepcopy(self.design)
        next(row for row in design["candidate_bindings"] if row["family_key"] == "numbered-reference-repeat")["vector_revision_ids"].pop()
        with self.assertRaisesRegex(ConformanceDataError, "production-oracle-population"):
            _members(design, self.manifest)

    def test_exact_population_still_rejects_swapped_control_partition(self):
        design = deepcopy(self.design)
        families = {row["family_key"]: row for row in design["candidate_bindings"]}
        left = families["numeric-escape-capture-threshold-match"]
        right = families["numeric-escape-capture-threshold-reject"]
        left["vector_revision_ids"], right["vector_revision_ids"] = right["vector_revision_ids"], left["vector_revision_ids"]
        with self.assertRaisesRegex(ConformanceDataError, "production-oracle-control-partition"):
            _members(design, self.manifest)

    def test_historical_operation_facts_do_not_close_current_applicability(self):
        report = {
            "resolution_rows": [
                self.resolve([], self.make_coordinate(member))
                for members in self.members.values() for member in members
            ]
        }
        admission = build_admission_review(ROOT, self.inputs, self.manifest, self.design, report)
        self.assertIsNone(admission["current_production_profile_revision_id"])
        self.assertEqual(admission["runnable_revision_ids"], [])
        self.assertEqual(len(admission["historical_capability_snapshot"]["facts"]), 3)
        self.assertEqual(len(admission["blocked_coordinates"]), 16)
        self.assertTrue(all(row["applicability"]["result"] == "unresolved" for row in admission["blocked_coordinates"]))
        self.assertTrue(all("oracle-inputs-unavailable" in row["blockers"] for row in admission["blocked_coordinates"]))


if __name__ == "__main__":
    unittest.main()
