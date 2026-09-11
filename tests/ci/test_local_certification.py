from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOLING = ROOT / "tools" / "ci"
if str(TOOLING) not in sys.path:
    sys.path.insert(0, str(TOOLING))

from local_certification import LocalCertificationError, _verify_adjudication_scientific_boundary, merkleless_root, sha256_bytes, verify_manifest
from regex_conformance_schema.jsonio import canonical_bytes, dump_pretty


class LocalCertificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "certification/local").mkdir(parents=True)
        (self.root / "registries/identity").mkdir(parents=True)
        (self.root / "registries/provenance").mkdir(parents=True)
        (self.root / "reports/semantics").mkdir(parents=True)
        (self.root / "ontology/denominator").mkdir(parents=True)
        (self.root / "registries/identity/scientific-identities.v1.json").write_text("{}", encoding="utf-8")
        revision = "rcid:v1:assertion-derivation-revision:h:jcs-sha256-v1:" + "d" * 64
        (self.root / "registries/provenance/generated-assertion-derivations.v1.json").write_text(revision, encoding="utf-8")
        (self.root / "reports/semantics/semantic-denominator-materialization-2026-09-08.v1.json").write_text(dump_pretty({"derivations": {"materialization_derivation_revision_id": revision}}), encoding="utf-8")
        (self.root / "reports/semantics/regex-semantic-denominator-audit-2026-09-10.v1.json").write_text(dump_pretty({"result": "PASS", "derivation_revision_id": revision}), encoding="utf-8")
        foundation_id = "rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:" + "9" * 64
        gate_id = "rcid:v1:trust-assessment:h:jcs-sha256-v1:" + "a" * 64
        (self.root / "ontology/denominator/true-obligation-denominator-foundation-2026-09-10.v1.json").write_text(dump_pretty({"manifest_id": foundation_id}), encoding="utf-8")
        (self.root / "reports/semantics/true-obligation-denominator-acceptance-2026-09-10.v1.json").write_text(dump_pretty({"report_id": gate_id, "result": "PASS", "checks": [{"status": "PASS"}] * 20, "foundation_manifest": {"artifact_id": foundation_id}}), encoding="utf-8")
        self.entry = {"role": "fixture", "path": "fixture.json", "sha256": "a" * 64, "byte_length": 1}
        self.test = {"test_id": "local-01", "argv": ["python", "check.py"], "result": "PASS", "exit_code": 0, "output_sha256": "b" * 64, "duration_milliseconds": 1}
        self.aggregates = {"value": 1}
        self.manifest = {
            "schema_version": "local-authoritative-certification.v1",
            "architecture": "Local Authoritative Certification / Hosted Integrity Verification",
            "hash_policy": "jcs-sha256-v1",
            "certified_source": {"git_sha": "c" * 40, "tree_sha": "e" * 40, "worktree_clean": True},
            "promotion_envelope": {"manifest_path": "certification/local/current-local-certification.v1.json", "source_must_be_single_parent": True, "manifest_only_commit_required": True},
            "bindings": {
                "current_certification": {"result": "FAIL"},
                "semantic_snapshot": {"id": "rcid:v1:ontology-snapshot:h:jcs-sha256-v1:" + "1" * 64},
                "obligation_snapshot": {"id": "rcid:v1:ontology-snapshot:h:jcs-sha256-v1:" + "2" * 64},
                "requirement_snapshot": {"id": "rcid:v1:ontology-snapshot:h:jcs-sha256-v1:" + "3" * 64},
                "migration_ledger": {"id": "rcid:v1:reconciliation-set:h:jcs-sha256-v1:" + "4" * 64},
                "denominator_accounting_contract": {"id": "rcid:v1:applicability-rule-set:h:jcs-sha256-v1:" + "5" * 64},
                "denominator_audit": {"id": "rcid:v1:finding-revision:h:jcs-sha256-v1:" + "6" * 64, "path": "reports/semantics/regex-semantic-denominator-audit-2026-09-10.v1.json"},
                "profile_expansion_handoff": {"id": "rcid:v1:ontology-projection:h:jcs-sha256-v1:" + "7" * 64},
                "denominator_audit_authority": {"id": "rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:" + "8" * 64},
                "true_denominator_foundation": {"id": foundation_id, "path": "ontology/denominator/true-obligation-denominator-foundation-2026-09-10.v1.json"},
                "true_denominator_gate": {"id": gate_id, "path": "reports/semantics/true-obligation-denominator-acceptance-2026-09-10.v1.json"},
            },
            "generated_artifacts": {"entries": [self.entry], "root_sha256": merkleless_root([self.entry])},
            "test_results": {"entries": [self.test], "root_sha256": merkleless_root([self.test])},
            "cheap_aggregates": self.aggregates,
            "final_local_certification": {"result": "PASS", "scientific_certification_result": "FAIL", "all_authoritative_checks_passed": True},
        }
        self._seal()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _seal(self) -> None:
        payload = {key: value for key, value in self.manifest.items() if key not in {"local_certification_root", "manifest_id"}}
        digest = sha256_bytes(canonical_bytes(payload))
        self.manifest["local_certification_root"] = digest
        self.manifest["manifest_id"] = "rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:" + digest
        (self.root / "certification/local/current-local-certification.v1.json").write_text(dump_pretty(self.manifest), encoding="utf-8")

    def _verify(self) -> dict:
        with mock.patch("local_certification.file_binding", return_value=self.entry), mock.patch("local_certification._cheap_aggregates", return_value=self.aggregates):
            return verify_manifest(self.root, Path("certification/local/current-local-certification.v1.json"), require_envelope=False)

    def test_valid_complete_manifest_passes_bounded_verification(self) -> None:
        self.assertEqual(self._verify()["result"], "PASS")

    def test_digest_tampering_fails(self) -> None:
        self.manifest["local_certification_root"] = "0" * 64
        (self.root / "certification/local/current-local-certification.v1.json").write_text(dump_pretty(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(LocalCertificationError, "root mismatch"):
            self._verify()

    def test_failed_local_check_cannot_claim_pass(self) -> None:
        self.manifest["test_results"]["entries"][0]["result"] = "FAIL"
        self._seal()
        with self.assertRaisesRegex(LocalCertificationError, "not all PASS"):
            self._verify()

    def test_artifact_mismatch_vetoes_certificate(self) -> None:
        wrong = copy.deepcopy(self.entry)
        wrong["sha256"] = "f" * 64
        with mock.patch("local_certification.file_binding", return_value=wrong), mock.patch("local_certification._cheap_aggregates", return_value=self.aggregates):
            with self.assertRaisesRegex(LocalCertificationError, "artifact binding mismatch"):
                verify_manifest(self.root, Path("certification/local/current-local-certification.v1.json"), require_envelope=False)

    def test_cheap_aggregate_mismatch_vetoes_certificate(self) -> None:
        with mock.patch("local_certification.file_binding", return_value=self.entry), mock.patch("local_certification._cheap_aggregates", return_value={"value": 2}):
            with self.assertRaisesRegex(LocalCertificationError, "aggregate"):
                verify_manifest(self.root, Path("certification/local/current-local-certification.v1.json"), require_envelope=False)

    def test_adjudication_boundary_uses_canonical_generated_coordinate_count(self) -> None:
        report = {
            "result": "PASS",
            "coverage": {"adversarial_case_count": 17},
            "certification_state": {"C4": "FAIL", "C4_completed": 0, "C4_denominator": 3378},
            "denominator_boundary": {"obligations": 2390, "requirements": 3378, "real_profile_coordinates_generated": 0},
        }
        _verify_adjudication_scientific_boundary(report)
        report["denominator_boundary"] = {"obligations": 2390, "requirements": 3378, "real_profile_coordinates": 0}
        with self.assertRaisesRegex(LocalCertificationError, "profile-coordinate boundary"):
            _verify_adjudication_scientific_boundary(report)


if __name__ == "__main__":
    unittest.main()
