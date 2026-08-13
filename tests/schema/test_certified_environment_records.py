from __future__ import annotations

from copy import deepcopy
import unittest

from support import ROOT
from regex_conformance_schema.environments import (
    environment_recipe_revision,
    isolation_policy_digest,
    validate_certified_environment_recipe,
    validate_minimal_environment_certification,
    validate_vertical_slice_coordinates,
)
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.identity import NamespaceRegistry
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.schema import validate_instance, validate_repository


class CertifiedEnvironmentRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.coordinates_path = ROOT / "registries" / "profiles" / "vertical-slice-coordinates.v1.json"
        cls.coordinates = load_strict(cls.coordinates_path)
        cls.selection = load_strict(ROOT / "registries" / "profiles" / "vertical-slice-archetypes.v1.json")
        cls.registry = NamespaceRegistry.load(ROOT / "registries" / "identity" / "namespaces.v1.json")
        cls.coordinate_schema = load_strict(ROOT / "schemas" / "json" / "vertical-slice-coordinates.schema.json")
        cls.recipe_schema = load_strict(ROOT / "schemas" / "json" / "certified-environment-recipe.schema.json")
        cls.recipe_paths = sorted((ROOT / "environments" / "recipes").glob("*.json"))
        cls.recipes = [load_strict(path) for path in cls.recipe_paths]
        cls.certification = load_strict(ROOT / "reports" / "vertical-slice" / "minimal-environment-certification.json")

    def test_repository_validation_accounts_for_coordinates_and_all_recipes(self) -> None:
        counts = validate_repository(ROOT)
        self.assertEqual(counts["vertical_slice_coordinates"], 1)
        self.assertEqual(counts["certified_environment_recipes"], 3)
        self.assertEqual(counts["minimal_environment_certifications"], 1)
        self.assertEqual({item["selection_key"] for item in self.recipes}, {"pcre2-ordinary", "python-re", "mysql-regex"})

    def test_profile_graphs_bind_every_node_to_an_exact_release(self) -> None:
        releases = {item["release_id"]: item for item in self.coordinates["releases"]}
        for profile in self.coordinates["profiles"]:
            for node in profile["nodes"]:
                self.assertIn(node["release_id"], releases)
                self.assertEqual(releases[node["release_id"]]["component_id"], node["component_id"])
        mysql = next(item for item in self.coordinates["profiles"] if item["selection_key"] == "mysql-regex")
        self.assertEqual(len(mysql["nodes"]), 2)
        self.assertEqual(mysql["edges"], [{"from": "mysql-regex", "to": "icu-regex", "relation": "embeds-backend"}])

    def test_recipe_revisions_and_isolation_digests_are_content_derived(self) -> None:
        for recipe in self.recipes:
            self.assertEqual(recipe["recipe_revision_id"], environment_recipe_revision(recipe))
            self.assertEqual(recipe["isolation_policy"]["digest"], isolation_policy_digest(recipe["isolation_policy"]))
            reordered = dict(reversed(list(recipe.items())))
            self.assertEqual(environment_recipe_revision(reordered), recipe["recipe_revision_id"])
            self.assertEqual(canonical_bytes(recipe), canonical_bytes(reordered))

    def test_coordinate_identity_collision_and_unknown_release_fail_closed(self) -> None:
        collision = deepcopy(self.coordinates)
        collision["systems"][1]["system_id"] = collision["systems"][0]["system_id"]
        with self.assertRaisesRegex(ConformanceDataError, "coordinate-identity-collision"):
            validate_vertical_slice_coordinates(collision, selection=self.selection, registry=self.registry, source="collision")
        unknown = deepcopy(self.coordinates)
        unknown["profiles"][0]["nodes"][0]["release_id"] = "rcid:v1:release:u7:019ff999-0000-7000-8000-000000000000"
        with self.assertRaisesRegex(ConformanceDataError, "coordinate-node-release-mismatch"):
            validate_vertical_slice_coordinates(unknown, selection=self.selection, registry=self.registry, source="unknown")
        unknown_component = deepcopy(self.coordinates)
        unknown_component["releases"][0]["component_id"] = "rcid:v1:component:u7:019ff999-0000-7000-8000-000000000000"
        with self.assertRaisesRegex(ConformanceDataError, "coordinate-reference-unknown"):
            validate_vertical_slice_coordinates(unknown_component, selection=self.selection, registry=self.registry, source="unknown-component")

    def test_missing_backend_role_and_edge_to_unknown_node_fail_closed(self) -> None:
        missing = deepcopy(self.coordinates)
        mysql = next(item for item in missing["profiles"] if item["selection_key"] == "mysql-regex")
        icu = next(item for item in mysql["nodes"] if item["node_key"] == "icu-regex")
        icu["roles"].remove("engine-backend")
        with self.assertRaisesRegex(ConformanceDataError, "coordinate-role-coverage-missing"):
            validate_vertical_slice_coordinates(missing, selection=self.selection, registry=self.registry, source="missing")
        edge = deepcopy(self.coordinates)
        mysql = next(item for item in edge["profiles"] if item["selection_key"] == "mysql-regex")
        mysql["edges"][0]["to"] = "unknown-backend"
        with self.assertRaisesRegex(ConformanceDataError, "coordinate-edge-node-unknown"):
            validate_vertical_slice_coordinates(edge, selection=self.selection, registry=self.registry, source="edge")

    def test_mutable_locator_revision_substitution_and_binding_drift_fail_closed(self) -> None:
        recipe = deepcopy(self.recipes[0])
        recipe["artifacts"][0]["locators"] = ["https://github.com/example/releases/latest/runtime.tar.gz"]
        recipe["recipe_revision_id"] = environment_recipe_revision(recipe)
        with self.assertRaisesRegex(ConformanceDataError, "recipe-mutable-locator"):
            validate_certified_environment_recipe(recipe, coordinates=self.coordinates, registry=self.registry, source="mutable")

        substituted = deepcopy(self.recipes[0])
        substituted["artifacts"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(ConformanceDataError, "recipe-revision-mismatch"):
            validate_certified_environment_recipe(substituted, coordinates=self.coordinates, registry=self.registry, source="substituted")

        drift = deepcopy(self.recipes[0])
        drift["target_profile_id"] = self.recipes[1]["target_profile_id"]
        drift["recipe_revision_id"] = environment_recipe_revision(drift)
        with self.assertRaisesRegex(ConformanceDataError, "recipe-coordinate-mismatch"):
            validate_certified_environment_recipe(drift, coordinates=self.coordinates, registry=self.registry, source="drift")

    def test_nondeterministic_member_order_and_policy_mutation_fail_closed(self) -> None:
        unordered = deepcopy(self.recipes[0])
        unordered["expected_runtime_facts"].reverse()
        unordered["recipe_revision_id"] = environment_recipe_revision(unordered)
        with self.assertRaisesRegex(ConformanceDataError, "recipe-order-nondeterministic"):
            validate_certified_environment_recipe(unordered, coordinates=self.coordinates, registry=self.registry, source="unordered")

        policy = deepcopy(self.recipes[0])
        policy["isolation_policy"]["build_network"] = "none"
        policy["recipe_revision_id"] = environment_recipe_revision(policy)
        with self.assertRaisesRegex(ConformanceDataError, "isolation-policy-digest-mismatch"):
            validate_certified_environment_recipe(policy, coordinates=self.coordinates, registry=self.registry, source="policy")

    def test_nondeterministic_coordinate_orders_fail_closed(self) -> None:
        mutations = []
        for collection in ("systems", "components", "releases", "profile_families", "profiles", "environment_bindings"):
            reordered = deepcopy(self.coordinates)
            reordered[collection].reverse()
            mutations.append(reordered)
        nodes = deepcopy(self.coordinates)
        mysql = next(item for item in nodes["profiles"] if item["selection_key"] == "mysql-regex")
        mysql["nodes"].reverse()
        mutations.append(nodes)
        edges = deepcopy(self.coordinates)
        mysql = next(item for item in edges["profiles"] if item["selection_key"] == "mysql-regex")
        mysql["edges"].append({"from": "icu-regex", "to": "mysql-regex", "relation": "reports-to"})
        mutations.append(edges)
        for mutation in mutations:
            with self.assertRaisesRegex(ConformanceDataError, "coordinate-order-nondeterministic"):
                validate_vertical_slice_coordinates(mutation, selection=self.selection, registry=self.registry, source="unordered")

    def test_certificate_reference_accounting_and_coordinate_drift_fail_closed(self) -> None:
        recipes = {item["selection_key"]: item for item in self.recipes}
        filename = deepcopy(self.certification)
        filename["evidence_filename"] = "minimal-environment-certification-sha256-" + "f" * 64 + ".json"
        with self.assertRaisesRegex(ConformanceDataError, "certification-evidence-reference-mismatch"):
            validate_minimal_environment_certification(
                filename, coordinates=self.coordinates, recipes_by_key=recipes, source="filename"
            )

        duplicate = deepcopy(self.certification)
        duplicate["results"][1] = deepcopy(duplicate["results"][0])
        with self.assertRaisesRegex(ConformanceDataError, "certification-accounting-mismatch"):
            validate_minimal_environment_certification(
                duplicate, coordinates=self.coordinates, recipes_by_key=recipes, source="duplicate"
            )

        drift = deepcopy(self.certification)
        drift["results"][0]["target_release_id"] = drift["results"][1]["target_release_id"]
        with self.assertRaisesRegex(ConformanceDataError, "certification-coordinate-mismatch"):
            validate_minimal_environment_certification(
                drift, coordinates=self.coordinates, recipes_by_key=recipes, source="drift"
            )

        collision = deepcopy(self.certification)
        collision["results"][1]["environment_fingerprint_id"] = collision["results"][0]["environment_fingerprint_id"]
        with self.assertRaisesRegex(ConformanceDataError, "certification-fingerprint-collision"):
            validate_minimal_environment_certification(
                collision, coordinates=self.coordinates, recipes_by_key=recipes, source="collision"
            )

    def test_schema_rejects_malformed_records_and_unpinned_artifacts(self) -> None:
        malformed = deepcopy(self.recipes[0])
        malformed["artifacts"][0]["sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            validate_instance(malformed, self.recipe_schema, source="malformed")
        malformed_coordinates = deepcopy(self.coordinates)
        del malformed_coordinates["profiles"][0]["root_node"]
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            validate_instance(malformed_coordinates, self.coordinate_schema, source="coordinates")


if __name__ == "__main__":
    unittest.main()
