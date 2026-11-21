from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.execution_provenance import (
    POLICY_PATH,
    _attempt,
    _lineage,
    _u,
    build_reference_fixture,
    lineage_set_sha256,
)
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.pcre2_production_adjudication import _compare, compare_production_lineage
from regex_conformance_schema.pcre2_qualified_applicability import reconstruct_qualification
from regex_conformance_schema.production_oracle import digest


class Pcre2ProductionAdjudicationTests(unittest.TestCase):
    """Exercise comparisons against synthetic lineage, with no campaign authority."""

    @classmethod
    def setUpClass(cls):
        cls.policy = load_strict(ROOT / POLICY_PATH)
        cls.reference = build_reference_fixture(ROOT, cls.policy)

    def fixture(self, *, second_outcome="no-match", same_realization=True):
        attempts = [
            _attempt(self.policy["policy_revision_sha256"], n, n, 1, outcome=outcome, terminal=True,
                     semantic_result={"match_state": outcome, "native_spans": []})
            for n, outcome in enumerate(("match", second_outcome), start=1)
        ]
        if not same_realization:
            attempts[1]["execution_context"]["environment_realization_id"] = _u("environment-realization", 2)
        entries = [_lineage(ROOT, [item]) for item in attempts]
        lineage = deepcopy(self.reference)
        lineage["lineages"] = sorted(entries, key=lambda row: row["logical_execution_id"])
        lineage["counts"] = dict.fromkeys(lineage["counts"], 0)
        for key in ("logical_execution_count", "physical_attempt_count", "terminal_attempt_count", "terminal_observation_count"):
            lineage["counts"][key] = 2
        lineage["lineage_set_sha256"] = lineage_set_sha256(lineage)

        contexts = [attempt["execution_context"] for attempt in attempts]
        vectors = [context["vector_revision_id"] for context in contexts]
        plan = {
            "classification": "comparison-plan-only",
            "profile_revision_id": contexts[0]["profile_revision_id"],
            "environment_fingerprint_id": contexts[0]["environment_fingerprint_id"],
            "adapter_manifest_id": contexts[0]["adapter_release_manifest_id"],
            "comparisons": [
                {"coordinate": {"vector_revision_id": vector}, "applicability_state": "applicable",
                 "request_preview_sha256": f"{n:064x}", "observation_field": "match_state",
                 "oracle_binding_id": f"synthetic-{n}", "oracle_class": "O4",
                 "comparison": {"kind": "distinct-from-controls", "controls": [vectors[1 - n]]}}
                for n, vector in enumerate(vectors)
            ],
        }
        plan["plan_digest_sha256"] = digest(plan)
        admission = {
            "classification": "authorized-production-evidence-admission",
            "comparison_plan_digest_sha256": plan["plan_digest_sha256"],
            "campaign_manifest_id": lineage["campaign_manifest_id"], "lineage_set_sha256": lineage["lineage_set_sha256"],
            "logical_assignments": [
                {"logical_execution_id": entry["logical_execution_id"], "request_preview_sha256": f"{index:064x}",
                 "vector_revision_id": scope["vector_revision_id"], "applicability_coordinate_id": scope["applicability_coordinate_id"],
                 "target_release_revision_id": scope["target_release_revision_id"]}
                for index, (entry, scope) in enumerate(zip(entries, contexts, strict=True))
            ],
            "admitted_observation_content_ids": [entry["observations"][0]["observation_content_id"] for entry in entries],
        }
        return plan, lineage, admission

    def compare(self, plan, lineage, admission):
        admission["admission_digest_sha256"] = digest({k: v for k, v in admission.items() if k != "admission_digest_sha256"})
        return compare_production_lineage(ROOT, plan, lineage, admission, expected_plan_digest=plan["plan_digest_sha256"],
                                          expected_admission_digest=admission["admission_digest_sha256"])

    def test_profile_projection_uses_existing_exact_and_relational_comparators(self):
        self.assertEqual(_compare("compile_status", "rejected", "rejected"), "agreement")
        self.assertEqual(_compare("match_state", "match", "no-match"), "disagreement")
        self.assertEqual(_compare("match_state", "match", "no-match", distinct=True), "agreement")

    def test_relationship_requires_real_controls_and_preserves_epistemic_scope(self):
        result = self.compare(*self.fixture())
        self.assertEqual({r["state"] for r in result["rows"]}, {"agreement"})
        self.assertEqual({r["oracle_class"] for r in result["rows"]}, {"O4"})
        self.assertEqual((result["issued_claims"], result["production_credit"]), (0, 0))
        self.assertEqual({r["state"] for r in self.compare(*self.fixture(second_outcome="match"))["rows"]}, {"disagreement"})
        plan, lineage, admission = self.fixture()
        admission["admitted_observation_content_ids"].pop()
        self.assertEqual({r["state"] for r in self.compare(plan, lineage, admission)["rows"]}, {"unobserved"})

    def test_controls_from_other_realizations_are_not_comparable(self):
        result = self.compare(*self.fixture(same_realization=False))
        self.assertEqual({r["state"] for r in result["rows"]}, {"not-comparable"})

    def test_qualification_and_rehashed_wrong_assignment_are_rejected(self):
        for mutation in ("classification", "request", "scope"):
            plan, lineage, admission = self.fixture()
            if mutation == "classification":
                admission["classification"] = "qualification-only"
                expected = "pcre2-comparison-unapproved-lineage"
            elif mutation == "request":
                admission["logical_assignments"][0]["request_preview_sha256"] = "f" * 64
                expected = "pcre2-comparison-admission-scope"
            else:
                admission["logical_assignments"][0]["applicability_coordinate_id"] = "different-coordinate"
                expected = "pcre2-comparison-observation-scope"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ConformanceDataError, expected):
                self.compare(plan, lineage, admission)

    def test_qualification_rejects_substitution_before_interpretation(self):
        with self.assertRaisesRegex(ConformanceDataError, "pcre2-qualification-evidence-digest"):
            reconstruct_qualification(ROOT, b"{}\n", expected_sha256="0" * 64, protected_head="e" * 40)
