from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.semantic_foundation import (
    ACCEPTANCE_PATH,
    ARCHITECTURE_LEDGER_PATH,
    AUTHORITY_PATH,
    CANDIDATE_LEDGER_PATH,
    FACET_INPUTS,
    FREEZE_PATH,
    MANIFEST_PATH,
    SNAPSHOT_PATH,
    SOURCE_COVERAGE_PATH,
    _denominator_readiness,
    _validate_authority_pointer,
    _validate_candidates,
    _validate_features,
    _validate_identity_evolution,
    _validate_operations_and_facets,
    _validate_source_coverage,
    build_acceptance_report,
    build_manifest,
    validate_acceptance_report,
    validate_manifest,
)
from regex_conformance_schema.foundation import scan_certification_bypasses


class SemanticKnowledgeFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = load_strict(ROOT / SNAPSHOT_PATH)
        cls.prior = load_strict(ROOT / ARCHITECTURE_LEDGER_PATH)
        cls.ledger = load_strict(ROOT / CANDIDATE_LEDGER_PATH)
        cls.coverage = load_strict(ROOT / SOURCE_COVERAGE_PATH)
        cls.authority = load_strict(ROOT / AUTHORITY_PATH)
        cls.freeze = load_strict(ROOT / FREEZE_PATH)

    def test_current_gate_passes_with_exact_population(self) -> None:
        report = load_strict(ROOT / ACCEPTANCE_PATH)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(len(report["checks"]), 16)
        self.assertEqual(
            (report["semantic_population"]["features"], report["semantic_population"]["operations"], report["semantic_population"]["facets"]),
            (269, 33, 15),
        )
        self.assertEqual(report["denominator_baseline"]["vector_requirements"], 9506)
        wrong_identity = deepcopy(report)
        replacement = "0" if report["report_id"][-1] != "0" else "1"
        wrong_identity["report_id"] = f"{report['report_id'][:-1]}{replacement}"
        with self.assertRaisesRegex(ConformanceDataError, "semantic-foundation-report-id"):
            validate_acceptance_report(ROOT, load_strict(ROOT / MANIFEST_PATH), wrong_identity)
        changed_denominator = deepcopy(load_strict(ROOT / MANIFEST_PATH))
        changed_denominator["denominator_baseline"]["artifact_sha256"]["vector_requirements"] = "0" * 64
        with self.assertRaises(ConformanceDataError):
            validate_manifest(ROOT, changed_denominator, verify_current_files=False)

    def test_scoped_acceptance_report_does_not_bypass_certification_authority(self) -> None:
        self.assertEqual(scan_certification_bypasses(ROOT), [])

    def test_source_orphan_and_template_regression_fail_closed(self) -> None:
        orphan = deepcopy(self.coverage)
        orphan["summary"]["source_orphan_count"] = 1
        with self.assertRaisesRegex(ConformanceDataError, "semantic-source-orphan"):
            _validate_source_coverage(self.snapshot, orphan)

        templated = deepcopy(self.snapshot)
        templated["features"][0]["semantic_assertions"]["definition"]["statement"] = "Behavior may vary by implementation."
        with self.assertRaisesRegex(ConformanceDataError, "template-semantic-regression"):
            _validate_features(ROOT, templated)

    def test_blocker_and_missing_accepted_candidate_fail_closed(self) -> None:
        blocked = deepcopy(self.ledger)
        blocked["candidates"][0]["blocking"] = True
        blocked["counts"]["blocking_unresolved"] = 1
        with self.assertRaisesRegex(ConformanceDataError, "semantic-candidate-blocking"):
            _validate_candidates(self.snapshot, self.prior, blocked)

        missing = deepcopy(self.snapshot)
        missing["features"] = [item for item in missing["features"] if item["feature_id"] != "feature.numeric-escape-disambiguation"]
        with self.assertRaisesRegex(ConformanceDataError, "accepted-candidate-missing"):
            _validate_candidates(missing, self.prior, self.ledger)

    def test_duplicate_identity_invalid_facet_and_missing_operation_fail_closed(self) -> None:
        duplicate = deepcopy(self.snapshot)
        duplicate["features"][1]["scientific_id"] = duplicate["features"][0]["scientific_id"]
        with self.assertRaisesRegex(ConformanceDataError, "duplicate-canonical-ownership"):
            _validate_features(ROOT, duplicate)

        facet = deepcopy(self.snapshot)
        next(item for item in facet["semantic_facets"] if item["facet_id"] == "facet.phase")["domain"] = ["compile"]
        with self.assertRaisesRegex(ConformanceDataError, "semantic-facet-vocabulary"):
            _validate_operations_and_facets(ROOT, facet)

        operation = deepcopy(self.snapshot)
        operation["operations"] = [item for item in operation["operations"] if item["operation_id"] != "operation.escape-pattern"]
        with self.assertRaisesRegex(ConformanceDataError, "semantic-operation-population"):
            _validate_operations_and_facets(ROOT, operation)

    def test_stale_authority_and_identity_churn_fail_closed(self) -> None:
        authority = deepcopy(self.authority)
        authority["current_snapshot"]["id"] = "stale"
        with self.assertRaisesRegex(ConformanceDataError, "stale-semantic-authority"):
            _validate_authority_pointer(self.snapshot, authority, self.freeze)

        changed = deepcopy(self.snapshot)
        changed["features"][0]["scientific_id"] = changed["features"][1]["scientific_id"]
        with self.assertRaisesRegex(ConformanceDataError, "semantic-identity-churn"):
            _validate_identity_evolution(ROOT, changed)

    def test_denominator_readiness_preserves_semantic_distinctions(self) -> None:
        readiness = _denominator_readiness(self.snapshot)
        self.assertEqual(readiness["features_inspectable"], 269)
        self.assertEqual(readiness["facet_mappings"], len(FACET_INPUTS))
        self.assertEqual(readiness["operations_inspectable"], 33)
        self.assertFalse(readiness["template_fallback_permitted"])
        self.assertEqual(len(readiness["fixtures"]), 6)
        self.assertTrue(all(item["status"] == "PASS" for item in readiness["fixtures"]))

    def test_manifest_and_report_regenerate_deterministically(self) -> None:
        manifest = build_manifest(ROOT)
        report = build_acceptance_report(ROOT, manifest)
        self.assertEqual((ROOT / MANIFEST_PATH).read_bytes(), canonical_bytes(manifest) + b"\n")
        self.assertEqual((ROOT / ACCEPTANCE_PATH).read_bytes(), canonical_bytes(report) + b"\n")
        self.assertEqual(build_manifest(ROOT), manifest)
        self.assertEqual(build_acceptance_report(ROOT, manifest), report)


if __name__ == "__main__":
    unittest.main()
