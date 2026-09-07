from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.foundation import (
    ACCEPTANCE_PATH,
    MANIFEST_PATH,
    REQUIRED_GATE_CHECKS,
    _finalize,
    build_acceptance_report,
    build_manifest,
    scan_certification_bypasses,
    validate_acceptance_report,
    validate_manifest,
    verify_current_foundation,
    verify_foundation_history,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


class ScientificFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_strict(ROOT / MANIFEST_PATH)
        cls.report = load_strict(ROOT / ACCEPTANCE_PATH)

    def test_foundation_manifest_binds_exact_four_authorities(self) -> None:
        validate_manifest(ROOT, self.manifest, verify_current_files=True)
        self.assertEqual(
            [item["foundation_key"] for item in self.manifest["foundations"]],
            [
                "certification-predicates",
                "execution-provenance",
                "generated-assertion-derivation",
                "scientific-identity",
            ],
        )
        matrix = self.manifest["authority_matrix"]
        self.assertEqual(len({item["decision_domain"] for item in matrix}), 4)
        self.assertEqual(len({item["canonical_owner"] for item in matrix}), 4)

    def test_acceptance_is_distinct_from_scientific_certification(self) -> None:
        validate_acceptance_report(ROOT, self.manifest, self.report)
        self.assertEqual(self.report["foundation_acceptance"], "PASS")
        self.assertEqual(self.report["current_scientific_certification"]["final_state"], "FAIL")
        self.assertFalse(self.report["current_scientific_certification"]["certification_eligible"])
        self.assertEqual(
            {item["criterion_id"]: item["status"] for item in self.report["current_scientific_certification"]["criteria"]},
            {"C1": "BLOCKED", "C2": "BLOCKED", "C3": "BLOCKED", "C4": "FAIL", "C5": "BLOCKED", "C6": "BLOCKED", "C7": "BLOCKED"},
        )

    def test_gate_executes_exact_required_checks(self) -> None:
        self.assertEqual(
            tuple(sorted(item["check_id"] for item in self.report["checks"])),
            REQUIRED_GATE_CHECKS,
        )
        self.assertEqual({item["status"] for item in self.report["checks"]}, {"PASS"})

    def test_c5_and_c6_cross_contract_scenarios_pass(self) -> None:
        scenarios = {item["scenario"]: item for item in self.report["integration_scenarios"]}
        self.assertEqual(
            {
                "one-terminal-attempt",
                "retry-after-inconclusive",
                "retry-exhaustion",
                "repeat-measurement",
                "target-crash",
                "adapter-crash",
            },
            {name for name in scenarios if name in {
                "one-terminal-attempt", "retry-after-inconclusive", "retry-exhaustion",
                "repeat-measurement", "target-crash", "adapter-crash",
            }},
        )
        self.assertEqual({item["status"] for item in scenarios.values()}, {"PASS"})
        integrity = {
            "identity-mismatch",
            "dangling-derivation",
            "broken-attempt-predecessor",
            "observation-wrong-attempt",
            "evidence-object-digest-mismatch",
            "certification-input-digest-drift",
        }
        self.assertTrue(integrity.issubset(scenarios))
        for name in integrity:
            facts = {item["name"]: item["value"] for item in scenarios[name]["facts"]}
            self.assertEqual(facts["c6-status"], "FAIL")
            self.assertTrue(facts["other-criteria-reportable"])

    def test_migration_readiness_covers_semantic_evolution(self) -> None:
        scenarios = {item["scenario"] for item in self.report["migration_readiness"]}
        self.assertEqual(
            scenarios,
            {
                "feature-rename",
                "feature-category-move",
                "feature-semantic-correction",
                "feature-split",
                "feature-merge",
                "obligation-removal",
                "new-obligation",
                "generator-reorder",
                "derivation-method-revision",
                "semantic-snapshot-successor",
                "certification-contract-successor",
            },
        )
        self.assertEqual({item["status"] for item in self.report["migration_readiness"]}, {"PASS"})

    def test_no_authoritative_certification_bypass_is_present(self) -> None:
        self.assertEqual(scan_certification_bypasses(ROOT), [])

    def test_authority_conflict_and_manifest_drift_fail_closed(self) -> None:
        duplicate = deepcopy(self.manifest)
        duplicate["authority_matrix"][1]["decision_domain"] = duplicate["authority_matrix"][0]["decision_domain"]
        duplicate = _finalize(
            ROOT,
            {
                key: value
                for key, value in duplicate.items()
                if key not in {"foundation_manifest_id", "foundation_manifest_digest_sha256", "identity_schema_family_id", "identity_schema_version"}
            },
            namespace="artifact-set-manifest",
            artifact_kind="scientific-foundation-manifest-v1",
            id_field="foundation_manifest_id",
            digest_field="foundation_manifest_digest_sha256",
        )
        with self.assertRaisesRegex(ConformanceDataError, "foundation-authority-conflict"):
            validate_manifest(ROOT, duplicate, verify_current_files=False)

        drift = deepcopy(self.manifest)
        drift["foundations"][0]["artifacts"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ConformanceDataError, "foundation-manifest-digest-mismatch"):
            validate_manifest(ROOT, drift, verify_current_files=True)

    def test_historical_acceptance_is_self_verifying(self) -> None:
        self.assertEqual(verify_foundation_history(ROOT)["foundation_acceptance"], "PASS")
        self.assertFalse(self.manifest["historical_compatibility"]["historical_records_rewritten"])
        self.assertEqual(len(self.manifest["historical_compatibility"]["schema_contracts"]), 4)

    def test_rebuild_is_deterministic_and_current(self) -> None:
        first_manifest = build_manifest(ROOT)
        second_manifest = build_manifest(ROOT)
        self.assertEqual(canonical_bytes(first_manifest), canonical_bytes(second_manifest))
        first_report = build_acceptance_report(ROOT, first_manifest)
        second_report = build_acceptance_report(ROOT, second_manifest)
        self.assertEqual(canonical_bytes(first_report), canonical_bytes(second_report))
        self.assertEqual(canonical_bytes(first_manifest), canonical_bytes(self.manifest))
        self.assertEqual(canonical_bytes(first_report), canonical_bytes(self.report))
        self.assertEqual(
            verify_current_foundation(ROOT),
            {
                "foundation_acceptance": "PASS",
                "foundation_checks": 12,
                "foundation_integration_scenarios": 12,
                "foundation_migration_scenarios": 11,
            },
        )


if __name__ == "__main__":
    unittest.main()
