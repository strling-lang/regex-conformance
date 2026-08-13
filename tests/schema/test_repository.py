from __future__ import annotations

import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.fixtures import verify_manifest
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.schema import validate_instance, validate_repository


class RepositoryValidationTests(unittest.TestCase):
    def test_all_repository_schemas_profiles_and_manifests_validate(self) -> None:
        counts = validate_repository(ROOT)
        self.assertGreaterEqual(counts["schemas"], 4)
        self.assertGreaterEqual(counts["profiles"], 7)
        self.assertEqual(counts["manifests"], 1)
        self.assertEqual(counts["adapter_protocol_revisions"], 1)
        self.assertEqual(counts["adapter_release_manifests"], 3)

    def test_identity_profile_unknown_field_is_rejected(self) -> None:
        schema = load_strict(ROOT / "schemas" / "json" / "identity-profile.schema.json")
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            validate_instance(
                {"profile_version": "1.0.0", "root": {"kind": "raw_text"}, "unknown": True},
                schema,
            )

    def test_cross_language_fixture_corpus_verifies(self) -> None:
        counts = verify_manifest(ROOT, ROOT / "tests" / "fixtures" / "identity" / "manifest.json")
        self.assertEqual(counts, {"jcs": 3, "content-id": 23, "projection-error": 9, "assertions": 11})
