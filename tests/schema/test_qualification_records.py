from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_text, load_strict
from regex_conformance_schema.qualification import load_and_validate_qualification_records
from regex_conformance_schema.schema import validate_instance, validate_repository


class QualificationRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.overlay_path = ROOT / "registries" / "profiles" / "small-scale-qualification.v1.json"
        cls.overlay = load_strict(cls.overlay_path)
        cls.recipe_path = ROOT / cls.overlay["environment_bindings"][0]["recipe_path"]
        cls.manifest_path = ROOT / "adapters" / "qualification-manifests" / "pcre2-dfa.v1.json"

    def _fixture_root(self, directory: str) -> Path:
        root = Path(directory)
        for relative in (
            "adapters/python",
            "adapters/qualification-manifests",
            "environments/qualification-recipes",
            "protocol",
            "registries/identity",
            "registries/profiles",
            "schemas/identity-profiles",
            "schemas/json",
        ):
            source = ROOT / relative
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, destination)
        return root

    def _validate(self, root: Path) -> dict[str, int]:
        return load_and_validate_qualification_records(root, validate_instance=validate_instance)

    def test_repository_accounts_for_the_isolated_qualification_layer(self) -> None:
        counts = validate_repository(ROOT)
        self.assertEqual(counts["qualification_profile_overlays"], 1)
        self.assertEqual(counts["qualification_profile_coordinates"], 1)
        self.assertEqual(counts["qualification_environment_recipes"], 1)
        self.assertEqual(counts["qualification_adapter_manifests"], 1)
        self.assertEqual(self.overlay["profiles"][0]["selection_key"], "pcre2-dfa")

    def test_overlay_base_digest_and_selection_collision_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._fixture_root(directory)
            path = root / self.overlay_path.relative_to(ROOT)
            record = load_strict(path)
            record["base_coordinates"]["sha256"] = "f" * 64
            path.write_text(canonical_text(record), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "qualification-base-coordinate-drift"):
                self._validate(root)

        with tempfile.TemporaryDirectory() as directory:
            root = self._fixture_root(directory)
            path = root / self.overlay_path.relative_to(ROOT)
            record = load_strict(path)
            for collection in ("profile_families", "profiles", "environment_bindings"):
                record[collection][0]["selection_key"] = "pcre2-ordinary"
            path.write_text(canonical_text(record), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "qualification-coordinate-collision"):
                self._validate(root)

    def test_recipe_and_adapter_source_substitution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._fixture_root(directory)
            path = root / self.recipe_path.relative_to(ROOT)
            record = load_strict(path)
            record["artifacts"][0]["sha256"] = "f" * 64
            path.write_text(canonical_text(record), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "recipe-revision-mismatch"):
                self._validate(root)

        with tempfile.TemporaryDirectory() as directory:
            root = self._fixture_root(directory)
            path = root / self.manifest_path.relative_to(ROOT)
            record = load_strict(path)
            record["source_files"][0]["sha256"] = "f" * 64
            path.write_text(canonical_text(record), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "adapter-source-digest-mismatch"):
                self._validate(root)

    def test_profile_facet_order_and_recipe_binding_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._fixture_root(directory)
            path = root / self.overlay_path.relative_to(ROOT)
            record = load_strict(path)
            record["profiles"][0]["nodes"][0]["facets"].reverse()
            path.write_text(canonical_text(record), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "qualification-facet-order"):
                self._validate(root)

        with tempfile.TemporaryDirectory() as directory:
            root = self._fixture_root(directory)
            path = root / self.overlay_path.relative_to(ROOT)
            record = load_strict(path)
            record["environment_bindings"][0]["target_release_id"] = (
                "rcid:v1:release:u7:019ff984-a52e-755c-a7b5-29741bc00c2c"
            )
            path.write_text(canonical_text(record), encoding="utf-8")
            with self.assertRaisesRegex(
                ConformanceDataError, "qualification-environment-binding-mismatch"
            ):
                self._validate(root)


        with tempfile.TemporaryDirectory() as directory:
            root = self._fixture_root(directory)
            path = root / self.overlay_path.relative_to(ROOT)
            record = load_strict(path)
            wrong_namespace = record["environment_bindings"][0][
                "environment_recipe_id"
            ]
            record["profiles"][0]["profile_id"] = wrong_namespace
            record["environment_bindings"][0]["profile_id"] = wrong_namespace
            path.write_text(canonical_text(record), encoding="utf-8")
            with self.assertRaisesRegex(
                ConformanceDataError, "qualification-namespace-mismatch"
            ):
                self._validate(root)


if __name__ == "__main__":
    unittest.main()
