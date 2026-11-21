from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.production_vectors import (
    _load_snapshot,
    compile_vector_manifest,
    load_vector_compiler_inputs,
)


class ProductionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.families = [load_strict(path) for path in sorted((ROOT / "vectors/families").glob("*.json"))]
        cls.inputs = load_vector_compiler_inputs(ROOT)
        cls.manifest = compile_vector_manifest(cls.inputs, cls.families)

    def test_candidate_manifest_accounts_for_the_whole_denominator(self):
        self.assertEqual(self.manifest, compile_vector_manifest(self.inputs, list(reversed(self.families))))
        self.assertEqual(self.manifest["counts"], {
            "requirements": 3378, "requirements_with_candidate_stimuli": 3, "vector_revisions": 9,
        })
        rows = self.manifest["requirement_coverage"]
        self.assertEqual(len({row["requirement_id"] for row in rows}), 3378)
        self.assertEqual(sum(row["status"] == "missing" for row in rows), 3375)
        self.assertEqual({row["status"] for row in rows}, {"missing", "candidate-stimuli-only"})
        expected = {item["vector_revision_id"] for item in self.manifest["vectors"]}
        self.assertEqual({identifier for row in rows for identifier in row["vector_revision_ids"]}, expected)
        body = dict(self.manifest)
        digest = body.pop("manifest_digest_sha256")
        self.assertEqual(sha256(canonical_bytes(body)).hexdigest(), digest)

    def test_oracle_or_arbitrary_attribution_cannot_enter_family_input(self):
        family = deepcopy(self.families[0])
        family["expected_result"] = {"matched": True}
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            compile_vector_manifest(self.inputs, [family])
        del family["expected_result"]
        family["operation_id"] = self.families[-1]["operation_id"]
        with self.assertRaisesRegex(ConformanceDataError, "vector-attribution"):
            compile_vector_manifest(self.inputs, [family])

    def test_manifestation_scope_cannot_be_omitted_or_substituted(self):
        family = deepcopy(self.families[-1])
        family["manifestation_id"] = None
        with self.assertRaisesRegex(ConformanceDataError, "select an in-scope manifestation"):
            compile_vector_manifest(self.inputs, [family])
        family["manifestation_id"] = self.families[0]["manifestation_id"]
        with self.assertRaisesRegex(ConformanceDataError, "different feature"):
            compile_vector_manifest(self.inputs, [family])

    def test_finite_enumeration_is_exact_and_fail_closed_at_the_bound(self):
        family = deepcopy(self.families[0])
        family["axes"] = {}
        alphabet = ["61", "62"]
        family["finite_subjects"] = {"encoding": "octets", "alphabet_hex": alphabet, "min_length": 0, "max_length": 2}
        manifest = compile_vector_manifest(self.inputs, [family])
        self.assertEqual(
            {item["stimulus"]["subjects"][0]["hex"] for item in manifest["vectors"]},
            {"", "61", "62", "6161", "6162", "6261", "6262"},
        )
        family["finite_subjects"]["max_length"] = 12
        with self.assertRaisesRegex(ConformanceDataError, "vector-family-size"):
            compile_vector_manifest(self.inputs, [family])
        family["finite_subjects"]["alphabet_hex"] = ["61", "6162"]
        with self.assertRaisesRegex(ConformanceDataError, "vector-finite-alphabet"):
            compile_vector_manifest(self.inputs, [family])

    def test_unicode_bytes_preserve_equivalent_spellings_and_malformed_input(self):
        family = deepcopy(self.families[-1])
        family["axes"]["pattern"] = [
            {"encoding": "utf-8", "hex": "c3a9"},
            {"encoding": "utf-8", "hex": "65cc81"},
        ]
        self.assertEqual(compile_vector_manifest(self.inputs, [family])["counts"]["vector_revisions"], 2)
        family["axes"]["pattern"].append({"encoding": "utf-8", "hex": "c3"})
        with self.assertRaisesRegex(ConformanceDataError, "vector-input-domain"):
            compile_vector_manifest(self.inputs, [family])
        family["domain"] = "encoded-code-units"
        self.assertEqual(compile_vector_manifest(self.inputs, [family])["counts"]["vector_revisions"], 3)
        family["axes"]["pattern"][-1]["hex"] += "\n"
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            compile_vector_manifest(self.inputs, [family])

    def test_changed_denominator_content_cannot_reuse_digest(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            path = Path("snapshot.json")
            body = {"requirements": []}
            digest = sha256(canonical_bytes(body)).hexdigest()
            snapshot = {**body, "snapshot_id": "fixture", "snapshot_digest_sha256": digest}
            reference = {"path": path.as_posix(), "artifact_id": "fixture", "digest_sha256": digest}
            (root / path).write_bytes(canonical_bytes(snapshot))
            self.assertEqual(_load_snapshot(root, path, reference), snapshot)
            snapshot["requirements"].append("altered")
            (root / path).write_bytes(canonical_bytes(snapshot))
            with self.assertRaisesRegex(ConformanceDataError, "vector-denominator-drift"):
                _load_snapshot(root, path, reference)

    def test_line_start_candidate_cases_distinguish_three_model_mutations(self):
        # This hand-written table is scoped to the ASCII literal following the
        # POSIX start anchor with newline handling disabled. It is test data.
        expected = {b"a": (0, 1), b"ab": (0, 1), b"ba": None, b"\na": None, b"": None}
        stimuli = [item["stimulus"] for item in self.manifest["vectors"] if item["stimulus"]["pattern"]["hex"] == "5e61"]
        subjects = {bytes.fromhex(stimulus["subjects"][0]["hex"]) for stimulus in stimuli}
        self.assertEqual(subjects, set(expected))
        for subject, span in expected.items():
            self.assertEqual((0, 1) if subject.startswith(b"a") else None, span)

        def accepts_interior(subject):
            start = subject.find(b"a")
            return None if start < 0 else (start, start + 1)

        def enables_newline_anchor(subject):
            if subject.startswith(b"a"):
                return (0, 1)
            newline = subject.find(b"\na")
            return None if newline < 0 else (newline + 1, newline + 2)

        def consumes_anchor(subject):
            return (0, 2) if subject.startswith(b"ab") else expected[subject]

        for mutant in (accepts_interior, enables_newline_anchor, consumes_anchor):
            with self.subTest(mutant=mutant.__name__):
                self.assertTrue(any(mutant(subject) != expected[subject] for subject in subjects))
