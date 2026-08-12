from __future__ import annotations

import unittest

from support import profile, registry
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import CollisionGuard, build_content_identity, generate_assigned_id

FAMILY = "rcid:v1:schema-family:u7:01890f3e-b240-7cc3-98c4-dc0c0c07398f"


def content(**overrides):
    values = {
        "registry": registry(),
        "profile": profile("ordered-values.v1.json"),
        "namespace": "vector-revision",
        "identity_schema_family_id": FAMILY,
        "identity_schema_version": "1.0.0",
        "identity": {"label": "alpha", "pattern": "a", "sequence": [], "tags": []},
    }
    values.update(overrides)
    return build_content_identity(**values)


class IdentityTests(unittest.TestCase):
    def test_object_permutation_is_identity_stable(self) -> None:
        first = content()
        second = content(identity={"tags": [], "sequence": [], "pattern": "a", "label": "alpha"})
        self.assertEqual(first["content_id"], second["content_id"])
        self.assertEqual(first["canonical_utf8"], second["canonical_utf8"])

    def test_domain_and_profile_coordinates_affect_identity(self) -> None:
        first = content()
        different_namespace = content(namespace="component-revision")
        different_family = content(
            identity_schema_family_id="rcid:v1:schema-family:u7:01890f3e-b246-7cc3-98c4-dc0c0c07398f"
        )
        self.assertNotEqual(first["content_id"], different_namespace["content_id"])
        self.assertNotEqual(first["content_id"], different_family["content_id"])

    def test_profile_version_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "profile-version-mismatch"):
            content(identity_schema_version="2.0.0")

    def test_unregistered_namespace_is_rejected(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "unregistered-namespace"):
            content(namespace="not-registered")

    def test_assigned_identifier_generation_is_registered_uuid7(self) -> None:
        identifier = generate_assigned_id(registry(), "rcid", "profile")
        parsed = registry().validate(identifier)
        self.assertEqual((parsed.scheme, parsed.mode, parsed.namespace), ("rcid", "u7", "profile"))

    def test_collision_guard_preserves_and_quarantines_conflict(self) -> None:
        guard = CollisionGuard()
        guard.observe("id", b"first")
        guard.observe("id", b"first")
        with self.assertRaisesRegex(ConformanceDataError, "digest-collision"):
            guard.observe("id", b"second")
        self.assertIn("id", guard.quarantined)
