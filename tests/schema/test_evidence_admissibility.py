from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "schemas" / "tooling" / "python"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from regex_conformance_schema.evidence_admissibility import (  # noqa: E402
    AUTHORITY_PATH,
    CONTRACT_PATH,
    FIXTURE_PATH,
    REPORT_PATH,
    ROLE_SPECS,
    evaluate_admissibility,
    finalize_evidence_record,
    validate_contract,
    validate_evidence_record,
    validate_expectation_basis,
    validate_fixtures,
    verify_current,
)
from regex_conformance_schema.errors import ConformanceDataError  # noqa: E402
from regex_conformance_schema.jsonio import canonical_bytes, load_strict  # noqa: E402


class EvidenceAdmissibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_strict(ROOT / CONTRACT_PATH)
        cls.fixture = load_strict(ROOT / FIXTURE_PATH)
        cls.records = {item["evidence_role"]: item for item in cls.fixture["valid_evidence"]}

    def _request(self, role: str, use: str, conclusion: str) -> dict:
        record = self.records[role]
        scope = record["semantic_scope"]
        return {
            "schema_version": "evidence-admissibility-request.v1",
            "evidence_refs": [{"evidence_id": record["evidence_id"], "evidence_digest_sha256": record["evidence_digest_sha256"]}],
            "epistemic_use": use,
            "requested_conclusion": conclusion,
            "scope": {key: scope[key] for key in ("requirement_scientific_ids", "profile_ids", "profile_family_ids", "operation_scientific_ids")},
            "oracle_class": record["oracle_compatibility"][0],
            "require_independent_authorities": False,
            "minimum_authority_domains": 1,
        }

    def _refresh(self, record: dict) -> dict:
        return finalize_evidence_record(ROOT, record)

    def test_committed_contract_fixtures_and_report_close(self) -> None:
        validate_contract(ROOT, self.contract)
        counts = validate_fixtures(ROOT, self.contract, self.fixture)
        self.assertEqual(counts, {"valid_role_fixtures": 8, "valid_cases": 8, "same_material": 2, "rejected": 12})
        result = verify_current(ROOT, broad_foundations=False)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["requirements"], 3378)
        self.assertTrue((ROOT / REPORT_PATH).is_file())
        self.assertTrue((ROOT / AUTHORITY_PATH).is_file())

    def test_o1_through_o8_map_one_to_one_to_evidence_roles(self) -> None:
        self.assertEqual([spec["oracle_class"] for spec in ROLE_SPECS.values()], [f"O{index}" for index in range(1, 9)])
        for record in self.records.values():
            validate_evidence_record(ROOT, self.contract, record)

    def test_all_representative_o1_through_o8_uses_are_admitted(self) -> None:
        for case in self.fixture["valid_cases"]:
            self.assertEqual(evaluate_admissibility(ROOT, self.contract, self.fixture["valid_evidence"], case["request"])["decision"], "admissible")

    def test_implementation_documentation_is_scoped_to_self_documentation(self) -> None:
        accepted = self._request("implementation-documentation-evidence", "establish-implementation-documentation-expectation", "implementation-documented-expectation")
        self.assertEqual(evaluate_admissibility(ROOT, self.contract, self.fixture["valid_evidence"], accepted)["decision"], "admissible")
        rejected = self._request("implementation-documentation-evidence", "establish-normative-expectation", "normative-required-expectation")
        with self.assertRaisesRegex(ConformanceDataError, "evidence-role-inadmissible"):
            evaluate_admissibility(ROOT, self.contract, self.fixture["valid_evidence"], rejected)

    def test_repeated_characterization_does_not_change_role(self) -> None:
        changed = deepcopy(self.records["characterization-only-evidence"])
        changed["quality"]["reproducibility_status"] = "reproduced"
        changed = self._refresh(changed)
        records = [changed if item["evidence_role"] == changed["evidence_role"] else item for item in self.fixture["valid_evidence"]]
        request = self._request("characterization-only-evidence", "establish-normative-expectation", "normative-required-expectation")
        request["evidence_refs"] = [{"evidence_id": changed["evidence_id"], "evidence_digest_sha256": changed["evidence_digest_sha256"]}]
        with self.assertRaisesRegex(ConformanceDataError, "evidence-role-inadmissible"):
            evaluate_admissibility(ROOT, self.contract, records, request)

    def test_quality_is_orthogonal_but_correctness_requires_integrity(self) -> None:
        changed = deepcopy(self.records["normative-source-evidence"])
        changed["quality"]["integrity_status"] = "unverified"
        changed = self._refresh(changed)
        validate_evidence_record(ROOT, self.contract, changed)
        records = [changed if item["evidence_role"] == changed["evidence_role"] else item for item in self.fixture["valid_evidence"]]
        request = self._request("normative-source-evidence", "establish-normative-expectation", "normative-required-expectation")
        request["evidence_refs"] = [{"evidence_id": changed["evidence_id"], "evidence_digest_sha256": changed["evidence_digest_sha256"]}]
        with self.assertRaisesRegex(ConformanceDataError, "expectation-evidence-quality-incomplete"):
            evaluate_admissibility(ROOT, self.contract, records, request)

    def test_incomplete_characterization_can_motivate_research_but_not_establish_fact(self) -> None:
        changed = deepcopy(self.records["characterization-only-evidence"])
        changed["quality"]["preservation_status"] = "incomplete"
        changed = self._refresh(changed)
        records = [changed if item["evidence_role"] == changed["evidence_role"] else item for item in self.fixture["valid_evidence"]]
        research = self._request("characterization-only-evidence", "support-research-revision", "research-revision-input")
        research["evidence_refs"] = [{"evidence_id": changed["evidence_id"], "evidence_digest_sha256": changed["evidence_digest_sha256"]}]
        self.assertEqual(evaluate_admissibility(ROOT, self.contract, records, research)["decision"], "admissible")
        establish = self._request("characterization-only-evidence", "establish-characterization", "characterization-recorded")
        establish["evidence_refs"] = research["evidence_refs"]
        with self.assertRaisesRegex(ConformanceDataError, "evidence-quality-incomplete"):
            evaluate_admissibility(ROOT, self.contract, records, establish)

    def test_informative_ambiguous_and_silent_source_language_cannot_be_mandatory(self) -> None:
        expected = {
            "informative-non-normative": "informative-prose-as-mandatory",
            "ambiguous": "ambiguous-evidence-as-established",
            "silent-not-established": "silence-means-unsupported",
        }
        for strength, code in expected.items():
            with self.subTest(strength=strength):
                changed = deepcopy(self.records["normative-source-evidence"])
                changed["normative_strength"] = strength
                changed = self._refresh(changed)
                records = [changed if item["evidence_role"] == changed["evidence_role"] else item for item in self.fixture["valid_evidence"]]
                request = self._request("normative-source-evidence", "establish-normative-expectation", "normative-required-expectation")
                request["evidence_refs"] = [{"evidence_id": changed["evidence_id"], "evidence_digest_sha256": changed["evidence_digest_sha256"]}]
                with self.assertRaisesRegex(ConformanceDataError, code):
                    evaluate_admissibility(ROOT, self.contract, records, request)

    def test_permission_optionality_prohibition_and_condition_remain_distinct(self) -> None:
        conclusions = {
            "prohibited": "normative-prohibited-expectation",
            "permitted": "normative-permission",
            "optional": "normative-optionality",
            "conditional": "normative-conditional-expectation",
        }
        for strength, conclusion in conclusions.items():
            with self.subTest(strength=strength):
                changed = deepcopy(self.records["normative-source-evidence"])
                changed["normative_strength"] = strength
                changed = self._refresh(changed)
                records = [changed if item["evidence_role"] == changed["evidence_role"] else item for item in self.fixture["valid_evidence"]]
                request = self._request("normative-source-evidence", "establish-normative-expectation", conclusion)
                request["evidence_refs"] = [{"evidence_id": changed["evidence_id"], "evidence_digest_sha256": changed["evidence_digest_sha256"]}]
                self.assertEqual(evaluate_admissibility(ROOT, self.contract, records, request)["decision"], "admissible")
                request["requested_conclusion"] = "normative-required-expectation"
                with self.assertRaisesRegex(ConformanceDataError, "normative-strength-conclusion-mismatch"):
                    evaluate_admissibility(ROOT, self.contract, records, request)

    def test_data_derived_expectation_needs_data_and_semantic_rule(self) -> None:
        changed = deepcopy(self.records["authoritative-data-derived-evidence"])
        removed = {node["dependency_id"] for node in changed["dependency_graph"]["nodes"] if node["kind"] == "research-claim"}
        changed["dependency_graph"]["nodes"] = [node for node in changed["dependency_graph"]["nodes"] if node["dependency_id"] not in removed]
        changed["dependency_graph"]["root_dependency_ids"] = [identifier for identifier in changed["dependency_graph"]["root_dependency_ids"] if identifier not in removed]
        changed["dependency_graph"]["nodes"][0]["upstream_dependency_ids"] = []
        changed = self._refresh(changed)
        with self.assertRaisesRegex(ConformanceDataError, "data-without-semantic-rule"):
            validate_evidence_record(ROOT, self.contract, changed)

    def test_dependency_cycles_are_rejected_transitively(self) -> None:
        changed = deepcopy(self.records["formal-derivation-evidence"])
        node = changed["dependency_graph"]["nodes"][0]
        node["upstream_dependency_ids"] = [node["dependency_id"]]
        changed = self._refresh(changed)
        with self.assertRaisesRegex(ConformanceDataError, "oracle-dependency-cycle"):
            validate_evidence_record(ROOT, self.contract, changed)

    def test_two_wrappers_with_one_upstream_authority_are_not_independent(self) -> None:
        common = {
            "dependency_id": "urn:strling:test:common-formal-authority", "kind": "formal-construction", "semantic_role": "expected-basis",
            "authority_domain_id": "urn:strling:authority:common-formal-engine", "version": "1.0.0", "content_digest_sha256": "d" * 64,
            "upstream_dependency_ids": [], "subject_profile_ids": [], "semantic_evaluator": False,
        }
        records = []
        for suffix in ("one", "two"):
            changed = deepcopy(self.records["formal-derivation-evidence"])
            root_node = changed["dependency_graph"]["nodes"][0]
            root_node["authority_domain_id"] = f"urn:strling:authority:wrapper-{suffix}"
            root_node["upstream_dependency_ids"] = [common["dependency_id"]]
            changed["dependency_graph"]["nodes"].append(deepcopy(common))
            changed["source_authority"]["authority_domain_id"] = root_node["authority_domain_id"]
            changed["source_authority"]["source_identity"] = f"urn:strling:formal-wrapper:{suffix}"
            changed["source_authority"]["locator"] = f"urn:strling:formal-wrapper:{suffix}#proof"
            records.append(self._refresh(changed))
        request = self._request("formal-derivation-evidence", "establish-formal-model-expectation", "formal-model-expectation")
        request["evidence_refs"] = [{"evidence_id": item["evidence_id"], "evidence_digest_sha256": item["evidence_digest_sha256"]} for item in records]
        request["require_independent_authorities"] = True
        request["minimum_authority_domains"] = 2
        with self.assertRaisesRegex(ConformanceDataError, "shared-authority-false-independence"):
            evaluate_admissibility(ROOT, self.contract, records, request)

    def test_scope_cannot_expand_beyond_evidence(self) -> None:
        request = self._request("normative-source-evidence", "establish-normative-expectation", "normative-required-expectation")
        request["scope"]["profile_ids"] = ["rcid:v1:profile:u7:019ff984-a52e-711e-82d2-03b77a6192e7"]
        with self.assertRaisesRegex(ConformanceDataError, "evidence-scope-mismatch"):
            evaluate_admissibility(ROOT, self.contract, self.fixture["valid_evidence"], request)

    def test_frozen_expectation_basis_is_exact_and_immutable(self) -> None:
        validate_expectation_basis(ROOT, self.contract, self.fixture["valid_evidence"], self.fixture["valid_expectation_basis"])
        changed = deepcopy(self.fixture["valid_expectation_basis"])
        changed["mutable_latest_alias_used"] = True
        with self.assertRaises(ConformanceDataError):
            validate_expectation_basis(ROOT, self.contract, self.fixture["valid_evidence"], changed)

    def test_generated_artifacts_are_canonical_bytes(self) -> None:
        for path in (CONTRACT_PATH, FIXTURE_PATH, REPORT_PATH, AUTHORITY_PATH):
            value = load_strict(ROOT / path)
            self.assertEqual((ROOT / path).read_bytes(), canonical_bytes(value) + b"\n")


if __name__ == "__main__":
    unittest.main()
