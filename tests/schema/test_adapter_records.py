from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from support import ROOT
from regex_conformance_schema.adapters import (
    validate_adapter_protocol_revision,
    validate_adapter_release_manifest,
    validate_minimal_adapter_certification,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.profile import IdentityProfile
from regex_conformance_schema.schema import validate_instance, validate_repository


class AdapterRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")
        cls.coordinates = load_strict(ROOT / "registries" / "profiles" / "vertical-slice-coordinates.v1.json")
        cls.protocol = load_strict(ROOT / "protocol" / "adapter-protocol.v1.json")
        cls.protocol_profile = IdentityProfile.from_record(
            load_strict(ROOT / "schemas" / "identity-profiles" / "adapter-protocol-revision.v1.json")
        )
        cls.manifest_profile = IdentityProfile.from_record(
            load_strict(ROOT / "schemas" / "identity-profiles" / "adapter-release-manifest.v1.json")
        )
        cls.protocol_id = validate_adapter_protocol_revision(
            cls.protocol,
            root=ROOT,
            registry=cls.registry,
            profile=cls.protocol_profile,
            source="protocol",
        )
        cls.manifest_schema = load_strict(ROOT / "schemas" / "json" / "adapter-release-manifest.schema.json")
        cls.manifests = [load_strict(path) for path in sorted((ROOT / "adapters" / "manifests").glob("*.json"))]
        cls.manifests_by_key = {item["identity"]["selection_key"]: item for item in cls.manifests}
        cls.recipes_by_key = {
            item["selection_key"]: item
            for item in (
                load_strict(path)
                for path in sorted((ROOT / "environments" / "recipes").glob("*.json"))
            )
        }
        environment = load_strict(ROOT / "reports" / "vertical-slice" / "minimal-environment-certification.json")
        cls.environment_results_by_key = {item["selection_key"]: item for item in environment["results"]}
        cls.certification = load_strict(ROOT / "reports" / "vertical-slice" / "minimal-adapter-certification.json")
        cls.certification_schema = load_strict(
            ROOT / "schemas" / "json" / "minimal-adapter-certification.schema.json"
        )
        cls.expected_keys = [item["selection_key"] for item in cls.coordinates["profiles"]]

    def _validate_manifest(self, record: dict, *, root: Path = ROOT) -> tuple[str, str, str, str]:
        return validate_adapter_release_manifest(
            record,
            root=root,
            coordinates=self.coordinates,
            protocol_id=self.protocol_id,
            registry=self.registry,
            profile=self.manifest_profile,
            source="manifest",
        )

    def test_repository_accounts_for_exact_adapter_package_set(self) -> None:
        counts = validate_repository(ROOT)
        self.assertEqual(counts["adapter_protocol_revisions"], 1)
        self.assertEqual(counts["adapter_release_manifests"], 3)
        identities = [record["identity"] for record in self.manifests]
        self.assertEqual(counts["minimal_adapter_certifications"], 1)
        self.assertEqual({item["selection_key"] for item in identities}, {"mysql-regex", "pcre2-ordinary", "python-re"})
        self.assertEqual(len({item["adapter"] for item in identities}), 3)
        self.assertEqual(len({item["adapter_release"] for item in identities}), 3)

    def test_schema_rejects_malformed_manifest(self) -> None:
        malformed = deepcopy(self.manifests[0])
        malformed["unexpected"] = True
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            validate_instance(malformed, self.manifest_schema, source="malformed")

    def test_source_substitution_and_coordinate_drift_fail_closed(self) -> None:
        substituted = deepcopy(self.manifests[0])
        substituted["source_files"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ConformanceDataError, "adapter-source-digest-mismatch"):
            self._validate_manifest(substituted)

        drift = deepcopy(self.manifests[0])
        drift["identity"]["profile"] = self.manifests[1]["identity"]["profile"]
        with self.assertRaisesRegex(ConformanceDataError, "adapter-coordinate-mismatch"):
            self._validate_manifest(drift)

    def test_protocol_identity_and_schema_substitution_fail_closed(self) -> None:
        wrong_id = deepcopy(self.protocol)
        wrong_id["protocol_revision_id"] = wrong_id["protocol_revision_id"][:-1] + "0"
        with self.assertRaisesRegex(ConformanceDataError, "adapter-protocol-revision-id-mismatch"):
            validate_adapter_protocol_revision(
                wrong_id,
                root=ROOT,
                registry=self.registry,
                profile=self.protocol_profile,
                source="wrong-id",
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema_directory = root / "schemas" / "json"
            schema_directory.mkdir(parents=True)
            for name in ("adapter-handshake.schema.json", "adapter-request.schema.json", "adapter-response.schema.json"):
                source = ROOT / "schemas" / "json" / name
                (schema_directory / name).write_bytes(source.read_bytes())
            (schema_directory / "adapter-response.schema.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "adapter-protocol-schema-digest-mismatch"):
                validate_adapter_protocol_revision(
                    self.protocol,
                    root=root,
                    registry=self.registry,
                    profile=self.protocol_profile,
                    source="substituted-schema",
                )

    def test_set_order_and_source_symlink_fail_closed(self) -> None:
        unordered = deepcopy(self.manifests[0])
        unordered["identity"]["capabilities"].reverse()
        with self.assertRaisesRegex(ConformanceDataError, "adapter-order-nondeterministic"):
            self._validate_manifest(unordered)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_directory = root / "adapters" / "python"
            source_directory.mkdir(parents=True)
            outside = root / "outside.py"
            outside.write_text("pass\n", encoding="utf-8")
            (source_directory / "linked.py").symlink_to(outside)
            linked = deepcopy(self.manifests[0])
            linked["source_files"] = [{"path": "adapters/python/linked.py", "sha256": "f" * 64}]
            with self.assertRaisesRegex(ConformanceDataError, "adapter-source-path-unsafe"):
                self._validate_manifest(linked, root=root)

    def test_adapter_certificate_references_and_governed_bindings_fail_closed(self) -> None:
        validate_minimal_adapter_certification(
            self.certification,
            protocol_id=self.protocol_id,
            manifests_by_key=self.manifests_by_key,
            recipes_by_key=self.recipes_by_key,
            environment_results_by_key=self.environment_results_by_key,
            expected_keys=self.expected_keys,
            source="certificate",
        )

        filename = deepcopy(self.certification)
        filename["evidence_filename"] = "minimal-adapter-certification-sha256-" + "f" * 64 + ".json"
        with self.assertRaisesRegex(ConformanceDataError, "adapter-certification-evidence-reference-mismatch"):
            validate_minimal_adapter_certification(
                filename,
                protocol_id=self.protocol_id,
                manifests_by_key=self.manifests_by_key,
                recipes_by_key=self.recipes_by_key,
                environment_results_by_key=self.environment_results_by_key,
                expected_keys=self.expected_keys,
                source="filename",
            )

        reordered = deepcopy(self.certification)
        reordered["results"].reverse()
        with self.assertRaisesRegex(ConformanceDataError, "adapter-certification-accounting-mismatch"):
            validate_minimal_adapter_certification(
                reordered,
                protocol_id=self.protocol_id,
                manifests_by_key=self.manifests_by_key,
                recipes_by_key=self.recipes_by_key,
                environment_results_by_key=self.environment_results_by_key,
                expected_keys=self.expected_keys,
                source="reordered",
            )

        collision = deepcopy(self.certification)
        collision["results"][1]["adapter_release_manifest_id"] = collision["results"][0]["adapter_release_manifest_id"]
        with self.assertRaisesRegex(ConformanceDataError, "adapter-certification-manifest-collision"):
            validate_minimal_adapter_certification(
                collision,
                protocol_id=self.protocol_id,
                manifests_by_key=self.manifests_by_key,
                recipes_by_key=self.recipes_by_key,
                environment_results_by_key=self.environment_results_by_key,
                expected_keys=self.expected_keys,
                source="collision",
            )

        drift = deepcopy(self.certification)
        drift["results"][0]["environment_verification_digest"] = "f" * 64
        with self.assertRaisesRegex(ConformanceDataError, "adapter-certification-binding-mismatch"):
            validate_minimal_adapter_certification(
                drift,
                protocol_id=self.protocol_id,
                manifests_by_key=self.manifests_by_key,
                recipes_by_key=self.recipes_by_key,
                environment_results_by_key=self.environment_results_by_key,
                expected_keys=self.expected_keys,
                source="drift",
            )

        protocol = deepcopy(self.certification)
        protocol["protocol_revision_id"] = protocol["protocol_revision_id"][:-1] + (
            "0" if protocol["protocol_revision_id"][-1] != "0" else "1"
        )
        with self.assertRaisesRegex(ConformanceDataError, "adapter-certification-protocol-mismatch"):
            validate_minimal_adapter_certification(
                protocol,
                protocol_id=self.protocol_id,
                manifests_by_key=self.manifests_by_key,
                recipes_by_key=self.recipes_by_key,
                environment_results_by_key=self.environment_results_by_key,
                expected_keys=self.expected_keys,
                source="protocol",
            )

        malformed = deepcopy(self.certification)
        malformed["unexpected"] = True
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            validate_instance(malformed, self.certification_schema, source="malformed")

if __name__ == "__main__":
    unittest.main()
