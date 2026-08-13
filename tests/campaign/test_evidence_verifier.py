from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "control-plane" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
    ROOT / "verifier" / "python",
    ROOT / "warehouse" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from evidence_support import completed_response
from regex_conformance_campaign import compile_vertical_slice
from regex_conformance_campaign.compiler import _content_id
from regex_conformance_control_plane.campaign_manager import CampaignCoordinator
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance
from regex_conformance_verifier import ImmutableEvidenceStore
from regex_conformance_verifier.qualification import corruption_cases
from regex_conformance_warehouse import WarehouseIntegrityError, build_warehouse


class SuccessfulWorker:
    def execute_shard(self, selection_key, logical_executions):
        return [
            {
                "logical_execution_id": item["logical_execution_id"],
                "provenance": {"selection_key": selection_key},
                "response": completed_response(item),
            }
            for item in logical_executions
        ]


def _artifact(root: Path, reference: dict) -> Path:
    return root / reference["relative_path"]


def _rewrite_artifact(root: Path, reference: dict, payload: dict) -> None:
    encoded = canonical_bytes(payload) + b"\n"
    path = _artifact(root, reference)
    path.write_bytes(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    destination = path.with_name(f"{digest}.json")
    path.rename(destination)
    reference["sha256"] = digest
    reference["size_bytes"] = len(encoded)
    reference["relative_path"] = destination.relative_to(root).as_posix()


def _raw_reference(root: Path, reference: dict, encoded: bytes) -> None:
    digest = hashlib.sha256(encoded).hexdigest()
    path = _artifact(root, reference).with_name(f"{digest}.json")
    path.write_bytes(encoded)
    reference["sha256"] = digest
    reference["size_bytes"] = len(encoded)
    reference["relative_path"] = path.relative_to(root).as_posix()


def _seal_manifest(root: Path, manifest: dict) -> None:
    body = {
        key: value
        for key, value in manifest.items()
        if key not in {"evidence_manifest_id", "manifest_reference", "schema_version"}
    }
    manifest["evidence_manifest_id"] = _content_id(
        ROOT, "evidence-manifest", "evidence-manifest-v2", body
    )
    payload = {key: value for key, value in manifest.items() if key != "manifest_reference"}
    encoded = canonical_bytes(payload) + b"\n"
    digest = hashlib.sha256(encoded).hexdigest()
    path = root / "manifests" / "sha256" / f"{digest}.json"
    path.write_bytes(encoded)
    manifest["manifest_reference"] = {
        "category": "manifests",
        "relative_path": path.relative_to(root).as_posix(),
        "sha256": digest,
        "size_bytes": len(encoded),
    }


def _rewrite_response_pair(root: Path, manifest: dict, observation_reference: dict, payload: dict) -> None:
    physical_id = payload["physical_run_id"]
    attempt_reference = next(
        item for item in manifest["attempts"] if item["physical_run_id"] == physical_id
    )
    attempt = load_strict(_artifact(root, attempt_reference))
    attempt["response"] = payload["response"]
    _rewrite_artifact(root, attempt_reference, attempt)
    _rewrite_artifact(root, observation_reference, payload)


class EvidenceVerifierQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compiled = compile_vertical_slice(ROOT)
        self.coordinator = CampaignCoordinator(
            NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")
        )

    def _baseline(self, base: Path):
        evidence = base / "evidence"
        store = ImmutableEvidenceStore(ROOT, evidence)
        manifest = self.coordinator.execute(self.compiled, SuccessfulWorker(), store)
        return evidence, store, manifest

    def _case(self, case_key: str, base: Path):
        source_root, _source_store, source_manifest = self._baseline(base / "source")
        source_digest = hashlib.sha256(
            b"".join(
                path.relative_to(source_root).as_posix().encode() + b"\0" + path.read_bytes()
                for path in sorted(source_root.rglob("*.json"))
            )
        ).hexdigest()
        fixture_root = base / "fixture"
        shutil.copytree(source_root, fixture_root)
        manifest = deepcopy(source_manifest)
        reference = manifest["observations"][0]
        artifact = _artifact(fixture_root, reference)
        payload = load_strict(artifact)

        if case_key == "artifact-digest-substitution":
            encoded = artifact.read_bytes()
            artifact.write_bytes(bytes([encoded[0] ^ 1]) + encoded[1:])
        elif case_key == "artifact-reference-category":
            reference["relative_path"] = f"observations/sha256/{'0' * 64}.json"
        elif case_key == "artifact-size-truncation":
            artifact.write_bytes(artifact.read_bytes()[:-1])
        elif case_key == "artifact-symlink-indirection":
            target = _artifact(fixture_root, manifest["observations"][1])
            artifact.unlink()
            artifact.symlink_to(target)
        elif case_key == "attempt-timestamp-naive":
            attempt_reference = manifest["attempts"][0]
            attempt = load_strict(_artifact(fixture_root, attempt_reference))
            attempt["observed_at"] = "2026-08-13T12:00:00"
            _rewrite_artifact(fixture_root, attempt_reference, attempt)
        elif case_key == "duplicate-json-member":
            _raw_reference(
                fixture_root,
                reference,
                b'{"schema_version":"observation-content.v1","schema_version":"observation-content.v1"}\n',
            )
        elif case_key == "invalid-json-truncation":
            _raw_reference(fixture_root, reference, artifact.read_bytes()[:-2])
        elif case_key == "manifest-root-substitution":
            manifest["root_digest"] = "0" * 64
        elif case_key == "match-state-empty":
            payload["response"]["observation"]["matches"] = []
            _rewrite_response_pair(fixture_root, manifest, reference, payload)
        elif case_key == "noncanonical-json":
            _raw_reference(
                fixture_root,
                reference,
                json.dumps(payload, ensure_ascii=False, indent=2).encode() + b"\n",
            )
        elif case_key == "nonmatch-with-matches":
            payload["response"]["observation"]["match_state"] = "no-match"
            _rewrite_response_pair(fixture_root, manifest, reference, payload)
        elif case_key == "observation-attempt-substitution":
            payload["provenance"] = {"selection_key": "substituted"}
            _rewrite_artifact(fixture_root, reference, payload)
        elif case_key == "response-correlation-substitution":
            payload["response"]["correlation_id"] = self.compiled["logical_executions"][1]["logical_execution_id"]
            _rewrite_response_pair(fixture_root, manifest, reference, payload)
        elif case_key == "response-plan-substitution":
            payload["response"]["target_release_id"] = self.compiled["logical_executions"][1]["target_release_id"]
            _rewrite_response_pair(fixture_root, manifest, reference, payload)
        elif case_key == "response-schema-violation":
            payload["response"].pop("message_type")
            _rewrite_response_pair(fixture_root, manifest, reference, payload)
        elif case_key == "shard-membership-substitution":
            shard_reference = manifest["result_shards"][0]
            shard = load_strict(_artifact(fixture_root, shard_reference))
            shard["planned_logical_execution_ids"] = self.compiled["shards"][1]["logical_execution_ids"]
            shard_body = {
                key: value for key, value in shard.items()
                if key not in {"schema_version", "result_shard_id"}
            }
            shard_id = _content_id(ROOT, "result-shard", "result-shard-v1", shard_body)
            shard["result_shard_id"] = shard_id
            _rewrite_artifact(fixture_root, shard_reference, shard)
            shard_reference["result_shard_id"] = shard_id
        elif case_key == "span-order-impossible":
            payload["response"]["observation"]["matches"][0]["span"]["start"] = 1
            _rewrite_response_pair(fixture_root, manifest, reference, payload)
        elif case_key == "unknown-artifact-field":
            payload["untrusted_extra"] = True
            _rewrite_artifact(fixture_root, reference, payload)
        else:
            self.fail(f"unimplemented seeded case {case_key}")

        if case_key not in {
            "artifact-digest-substitution",
            "artifact-size-truncation",
            "artifact-symlink-indirection",
        }:
            _seal_manifest(fixture_root, manifest)

        fixture_store = ImmutableEvidenceStore(ROOT, fixture_root)
        assessment = fixture_store.qualify_manifest(self.compiled, manifest)
        with self.assertRaises(WarehouseIntegrityError):
            build_warehouse(
                ROOT,
                base / "warehouse",
                self.compiled,
                manifest,
                fixture_store,
            )
        source_digest_after = hashlib.sha256(
            b"".join(
                path.relative_to(source_root).as_posix().encode() + b"\0" + path.read_bytes()
                for path in sorted(source_root.rglob("*.json"))
            )
        ).hexdigest()
        self.assertEqual(source_digest_after, source_digest)
        return assessment

    def test_seeded_corruptions_are_quarantined_and_excluded(self) -> None:
        for case_key, _corruption_class, expected_code in corruption_cases():
            with self.subTest(case_key=case_key), tempfile.TemporaryDirectory() as temporary:
                assessment = self._case(case_key, Path(temporary))
                self.assertEqual(assessment["disposition"], "quarantined")
                self.assertFalse(assessment["analytical_admissible"])
                self.assertFalse(assessment["certification_admissible"])
                self.assertEqual(assessment["findings"][0]["code"], expected_code)
                self.assertEqual(assessment["trust_qualification"], "not-assessed")
                stored = load_strict(
                    Path(temporary)
                    / "fixture"
                    / assessment["assessment_reference"]["relative_path"]
                )
                self.assertEqual(canonical_bytes(stored), canonical_bytes({
                    key: value for key, value in assessment.items() if key != "assessment_reference"
                }))

    def test_clean_complete_evidence_is_admitted_but_not_declared_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            _root, store, manifest = self._baseline(base)
            assessment = store.qualify_manifest(self.compiled, manifest)
            self.assertEqual(assessment["disposition"], "admitted")
            self.assertTrue(assessment["analytical_admissible"])
            self.assertFalse(assessment["certification_admissible"])
            self.assertEqual(assessment["integrity_qualification"], "passed")
            self.assertEqual(assessment["trust_qualification"], "not-assessed")
            self.assertFalse(assessment["classification"]["semantic_authority"])

    def test_reference_report_is_schema_valid_and_matches_executed_cases(self) -> None:
        report = load_strict(
            ROOT / "reports" / "small-scale" / "evidence-verification-qualification.json"
        )
        validate_instance(
            report,
            load_strict(
                ROOT / "schemas" / "json" / "evidence-verification-qualification.schema.json"
            ),
        )
        expected = [(item["case_key"], item["corruption_class"], item["expected_code"]) for item in report["cases"]]
        self.assertEqual(expected, list(corruption_cases()))

    def test_publication_refuses_indirect_category_directories_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            evidence_root = base / "evidence"
            store = ImmutableEvidenceStore(ROOT, evidence_root)
            external = base / "external"
            external.mkdir()
            (evidence_root / "attempts").symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(Exception, "artifact-directory-invalid"):
                self.coordinator.execute(self.compiled, SuccessfulWorker(), store)
            self.assertEqual(list(external.iterdir()), [])

            (evidence_root / "attempts").unlink()
            manifest = self.coordinator.execute(self.compiled, SuccessfulWorker(), store)
            assessment_external = base / "assessment-external"
            assessment_external.mkdir()
            (evidence_root / "trust-assessments").symlink_to(
                assessment_external, target_is_directory=True
            )
            with self.assertRaisesRegex(Exception, "artifact-directory-invalid"):
                store.qualify_manifest(self.compiled, manifest)
            self.assertEqual(list(assessment_external.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
