from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import build_content_identity
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.profile import IdentityProfile
from regex_conformance_schema.scientific_identity import (
    CATALOG_PATH,
    NAMESPACE_PATH,
    ScientificDescriptor,
    applicability_coordinate_projection,
    catalog_digest,
    collect_descriptors,
    lineage_record_id,
    normalize_predicate,
    resolve_scientific_id,
    semantic_fingerprint,
    production_vector_projection,
    validate_lineage_records,
    verify_catalog,
)
from regex_conformance_schema.identity import NamespaceRegistry


VECTOR_FAMILY = "rcid:v1:schema-family:u7:01a0779c-5485-7240-b0ee-4846554fd816"
COORDINATE_FAMILY = "rcid:v1:schema-family:u7:01a0779c-55e6-7dff-ac38-09757c679707"


class ScientificIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_strict(ROOT / CATALOG_PATH)
        cls.registry = NamespaceRegistry.load(ROOT / NAMESPACE_PATH)
        cls.descriptors, _ = collect_descriptors(ROOT)
        cls.identities = {
            key: binding["scientific_id"]
            for binding in cls.catalog["bindings"]
            for key in [binding["canonical_key"], *binding["former_keys"]]
        }

    def test_current_catalog_is_complete_and_locked(self) -> None:
        self.assertEqual(
            verify_catalog(ROOT),
            {"scientific_identities": 28016, "scientific_lineage_records": 3162},
        )
        self.assertEqual(
            self.catalog["counts"]["by_class"],
            {
                "feature": 269,
                "manifestation": 326,
                "modifier": 33,
                "obligation": 14287,
                "operation": 33,
                "semantic-facet": 15,
                "semantic-requirement": 12852,
                "semantic-variant": 93,
                "typed-interaction": 108,
            },
        )

    def test_presentation_and_relocation_fields_do_not_change_feature_basis(self) -> None:
        original = next(item for item in self.descriptors if item.entity_class == "feature")
        changed = deepcopy(original.record)
        changed["canonical_name"] = "Clearer display name"
        changed["category"] = "relocated-category"
        changed["aliases"] = [*changed["aliases"], "display alias"]
        changed["provenance"] = {"source_ids": ["documentation-moved"]}
        relocated = ScientificDescriptor(
            original.entity_class,
            original.key,
            "semantic-snapshot",
            changed,
        )
        self.assertEqual(
            semantic_fingerprint(original, self.identities),
            semantic_fingerprint(relocated, self.identities),
        )

    def test_semantic_change_changes_locked_fingerprint(self) -> None:
        original = next(item for item in self.descriptors if item.entity_class == "feature")
        changed = deepcopy(original.record)
        changed["semantic_definition"] += " Materially different observable behavior."
        successor_basis = ScientificDescriptor(
            original.entity_class, original.key, original.source_role, changed
        )
        self.assertNotEqual(
            semantic_fingerprint(original, self.identities),
            semantic_fingerprint(successor_basis, self.identities),
        )

    def test_predicate_commutative_order_is_canonical(self) -> None:
        value = {
            "operator": "all",
            "clauses": [
                {"field": "b", "operator": "in", "values": ["z", "a"]},
                {"field": "a", "operator": "exists"},
            ],
        }
        reordered = {
            "clauses": [
                {"operator": "exists", "field": "a"},
                {"values": ["a", "z"], "operator": "in", "field": "b"},
            ],
            "operator": "all",
        }
        self.assertEqual(normalize_predicate(value), normalize_predicate(reordered))

    def test_former_key_resolves_to_same_identity_after_rename(self) -> None:
        catalog = {"bindings": [deepcopy(self.catalog["bindings"][0])]}
        binding = catalog["bindings"][0]
        old_key = binding["canonical_key"]
        binding["canonical_key"] = "renamed-readable-key"
        binding["former_keys"].append(old_key)
        self.assertEqual(
            resolve_scientific_id(catalog, old_key),
            resolve_scientific_id(catalog, "renamed-readable-key"),
        )

    def _content(self, profile: str, family: str, namespace: str, identity: dict):
        return build_content_identity(
            registry=self.registry,
            profile=IdentityProfile.from_record(
                load_strict(ROOT / "schemas" / "identity-profiles" / profile)
            ),
            namespace=namespace,
            identity_schema_family_id=family,
            identity_schema_version="1.0.0",
            identity=identity,
        )

    def _vector_identity(self) -> dict:
        operation = resolve_scientific_id(self.catalog, "operation.search")
        requirement = next(
            item["scientific_id"]
            for item in self.catalog["bindings"]
            if item["entity_class"] == "semantic-requirement"
        )
        obligation = next(
            item["scientific_id"]
            for item in self.catalog["bindings"]
            if item["entity_class"] == "obligation"
        )
        interaction = next(
            item["scientific_id"]
            for item in self.catalog["bindings"]
            if item["entity_class"] == "typed-interaction"
        )
        return {
            "applicability_preconditions": {"required": True, "tags": ["a", "b"]},
            "callback_fixture": None,
            "deterministic_limits": {"maximum_matches": 10, "wall_time_ms": 1000},
            "domain": "unicode-scalars",
            "initial_state": {"occurrence": 1, "start_offset": 0},
            "interaction_ids": [interaction],
            "obligation_ids": [obligation],
            "operation_id": operation,
            "options": [{"name": "unicode", "value": True}, {"name": "multiline", "value": False}],
            "pattern": {"text": "é"},
            "replacement": None,
            "requested_observations": ["spans", "captures"],
            "semantic_requirement_ids": [requirement],
            "subjects": [{"text": "é"}],
        }

    def test_vector_identity_ignores_set_and_serialization_order(self) -> None:
        first = self._vector_identity()
        second = deepcopy(first)
        second["options"].reverse()
        second["requested_observations"].reverse()
        second["pattern"] = {"text": "e\u0301"}
        left = self._content(
            "production-vector-revision.v1.json",
            VECTOR_FAMILY,
            "vector-revision",
            production_vector_projection(first),
        )
        right = self._content(
            "production-vector-revision.v1.json",
            VECTOR_FAMILY,
            "vector-revision",
            production_vector_projection(second),
        )
        self.assertEqual(left["content_id"], right["content_id"])

    def test_vector_semantic_change_changes_content_identity(self) -> None:
        first = self._vector_identity()
        second = deepcopy(first)
        second["subjects"] = [{"text": "different"}]
        self.assertNotEqual(
            self._content(
                "production-vector-revision.v1.json",
                VECTOR_FAMILY,
                "vector-revision",
                production_vector_projection(first),
            )["content_id"],
            self._content(
                "production-vector-revision.v1.json",
                VECTOR_FAMILY,
                "vector-revision",
                production_vector_projection(second),
            )["content_id"],
        )

    def test_coordinate_operation_and_applicability_are_identity_fields(self) -> None:
        vector = self._content(
            "production-vector-revision.v1.json",
            VECTOR_FAMILY,
            "vector-revision",
            production_vector_projection(self._vector_identity()),
        )["content_id"]
        base = {
            "applicability_inputs": {"feature_state": "supported"},
            "applicability_rule_set_id": "rcid:v1:applicability-rule-set:h:jcs-sha256-v1:" + "1" * 64,
            "obligation_ids": [next(item["scientific_id"] for item in self.catalog["bindings"] if item["entity_class"] == "obligation")],
            "operation_id": resolve_scientific_id(self.catalog, "operation.search"),
            "profile_revision_id": "rcid:v1:profile-revision:h:jcs-sha256-v1:" + "2" * 64,
            "semantic_requirement_ids": [next(item["scientific_id"] for item in self.catalog["bindings"] if item["entity_class"] == "semantic-requirement")],
            "target_release_revision_id": "rcid:v1:release-revision:h:jcs-sha256-v1:" + "3" * 64,
            "vector_revision_id": vector,
        }
        operation_changed = deepcopy(base)
        operation_changed["operation_id"] = resolve_scientific_id(
            self.catalog, "operation.compile"
        )
        applicability_changed = deepcopy(base)
        applicability_changed["applicability_inputs"]["feature_state"] = "unknown"
        content_ids = {
            self._content(
                "applicability-coordinate.v1.json",
                COORDINATE_FAMILY,
                "applicability-coordinate",
                applicability_coordinate_projection(value),
            )["content_id"]
            for value in (base, operation_changed, applicability_changed)
        }
        self.assertEqual(len(content_ids), 3)

    def _lineage(self, **overrides) -> dict:
        record = {
            "change_kind": "renamed-from",
            "current_fingerprints": [],
            "current_keys": ["new-key"],
            "effective_date": "2026-09-06",
            "identity_effect": "retained",
            "prior_fingerprints": [],
            "prior_keys": ["old-key"],
            "rationale": "The scientific entity is unchanged.",
            "source_ids": [],
            "target_ids": [],
        }
        record.update(overrides)
        record["lineage_record_id"] = lineage_record_id(ROOT, record)
        return record

    def test_valid_rename_successor_split_merge_deprecation_and_alias(self) -> None:
        ids = [item["scientific_id"] for item in self.catalog["bindings"][:7]]
        records = [
            self._lineage(source_ids=[ids[0]], target_ids=[ids[0]]),
            self._lineage(change_kind="supersedes", identity_effect="new-identity", source_ids=[ids[0]], target_ids=[ids[1]]),
            self._lineage(change_kind="split-from", identity_effect="new-identity", source_ids=[ids[1]], target_ids=[ids[2], ids[3]]),
            self._lineage(change_kind="merged-from", identity_effect="new-identity", source_ids=[ids[2], ids[3]], target_ids=[ids[4]]),
            self._lineage(change_kind="deprecated", source_ids=[ids[5]], target_ids=[], current_keys=[]),
            self._lineage(change_kind="alias-of", identity_effect="no-identity", source_ids=[], target_ids=[ids[6]], prior_keys=["alias-key"]),
        ]
        validate_lineage_records(ROOT, records, set(ids))

    def test_invalid_cycle_and_missing_predecessor_fail(self) -> None:
        ids = [item["scientific_id"] for item in self.catalog["bindings"][:2]]
        cycle = [
            self._lineage(change_kind="supersedes", identity_effect="new-identity", source_ids=[ids[0]], target_ids=[ids[1]]),
            self._lineage(change_kind="supersedes", identity_effect="new-identity", source_ids=[ids[1]], target_ids=[ids[0]]),
        ]
        with self.assertRaisesRegex(ConformanceDataError, "lineage-cycle"):
            validate_lineage_records(ROOT, cycle, set(ids))
        missing = self._lineage(
            change_kind="supersedes",
            identity_effect="new-identity",
            source_ids=[ids[0]],
            target_ids=["rcid:v1:feature:u7:01890f3e-b240-7cc3-98c4-dc0c0c07398f"],
        )
        with self.assertRaisesRegex(ConformanceDataError, "missing-lineage-identity"):
            validate_lineage_records(ROOT, [missing], set(ids))

    def test_reused_identity_fails_closed(self) -> None:
        catalog = deepcopy(self.catalog)
        duplicate = deepcopy(catalog["bindings"][0])
        duplicate["canonical_key"] = "different-owner"
        catalog["bindings"].append(duplicate)
        catalog["catalog_digest_sha256"] = catalog_digest(catalog)
        with self.assertRaisesRegex(ConformanceDataError, "reused-scientific-id"):
            verify_catalog(ROOT, catalog)

    def test_retired_identity_cannot_be_reused_by_current_entity(self) -> None:
        catalog = deepcopy(self.catalog)
        catalog["bindings"][0]["status"] = "deprecated"
        catalog["counts"]["active"] -= 1
        catalog["counts"]["historical"] += 1
        catalog["catalog_digest_sha256"] = catalog_digest(catalog)
        with self.assertRaisesRegex(ConformanceDataError, "retired-identity-reuse"):
            verify_catalog(ROOT, catalog)

    def test_regeneration_inputs_preserve_existing_internal_ids(self) -> None:
        before = {
            item.key: semantic_fingerprint(item, self.identities)
            for item in self.descriptors
        }
        unrelated = dict(self.identities)
        unrelated["feature.unrelated-new-entity"] = self.catalog["bindings"][0]["scientific_id"]
        after = {
            item.key: semantic_fingerprint(item, unrelated)
            for item in reversed(self.descriptors)
        }
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
