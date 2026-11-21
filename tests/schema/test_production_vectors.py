from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from itertools import product
from pathlib import Path
import sys
import tempfile
import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.interaction_allocations import ALLOCATIONS_PATH, verify_interaction_allocations
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.production_campaign_design import BASIS_PATH, bind_candidate_bases, build_production_campaign_design
from regex_conformance_schema.production_preflight import REQUEST_SCHEMA, _project_request, build_production_preflight
from regex_conformance_schema.production_vectors import (
    _load_snapshot,
    compile_vector_manifest,
    load_vector_compiler_inputs,
)
from regex_conformance_schema.scientific_identity import CATALOG_PATH
from regex_conformance_schema.vector_manifest_verification import verify_vector_manifest


class ProductionVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.families = [load_strict(path) for path in sorted((ROOT / "vectors/families").glob("*.json"))]
        by_key = {family["key"]: family for family in cls.families}
        cls.anchor = by_key["line-start-negative"]
        cls.escapes = by_key["numeric-escape-diagnostics"]
        cls.inputs = load_vector_compiler_inputs(ROOT)
        cls.manifest = compile_vector_manifest(cls.inputs, cls.families)

    def test_verifier_reconciles_pinned_manifest(self):
        digest = self.manifest["manifest_digest_sha256"]
        self.assertEqual(verify_vector_manifest(self.inputs, self.manifest, self.families, expected_digest=digest), self.manifest["counts"])
        with self.assertRaisesRegex(ConformanceDataError, "vector-manifest-digest"):
            verify_vector_manifest(self.inputs, self.manifest, self.families, expected_digest="0" * 64)

    def assert_manifest_mutation_rejected(self, manifest, expected_error):
        del manifest["manifest_digest_sha256"]
        digest = sha256(canonical_bytes(manifest)).hexdigest()
        manifest["manifest_digest_sha256"] = digest
        with self.assertRaisesRegex(ConformanceDataError, expected_error):
            verify_vector_manifest(self.inputs, manifest, self.families, expected_digest=digest)

    def test_verifier_rejects_rehashed_denominator_omission(self):
        manifest = deepcopy(self.manifest)
        manifest["requirement_coverage"].pop()
        manifest["counts"]["requirements"] -= 1
        self.assert_manifest_mutation_rejected(manifest, "vector-manifest-requirement-set")

    def test_verifier_rejects_rehashed_certification_claim(self):
        manifest = deepcopy(self.manifest)
        manifest["certified"] = True
        self.assert_manifest_mutation_rejected(manifest, "vector-manifest-scope")

    def test_verifier_rejects_rehashed_stimulus_change_and_coherent_omission(self):
        manifest = deepcopy(self.manifest)
        manifest["vectors"][0]["stimulus"]["pattern"]["hex"] += "61"
        self.assert_manifest_mutation_rejected(manifest, "vector-manifest-revision")
        manifest = deepcopy(self.manifest)
        missing = manifest["families"][0]["vector_revision_ids"].pop()
        manifest["vectors"] = [item for item in manifest["vectors"] if item["vector_revision_id"] != missing]
        for row in manifest["requirement_coverage"]:
            if missing in row["vector_revision_ids"]:
                row["vector_revision_ids"].remove(missing)
        manifest["counts"]["vector_revisions"] -= 1
        self.assert_manifest_mutation_rejected(manifest, "vector-manifest-family-cardinality")

    def test_verifier_rejects_rehashed_family_swap_and_duplicate_revision(self):
        manifest = deepcopy(self.manifest)
        families = {row["key"]: row for row in manifest["families"]}
        split = families["cpython-split-capture-edges"]
        other = families["cpython-split-empty-word-boundary"]
        split["vector_revision_ids"], other["vector_revision_ids"] = other["vector_revision_ids"], split["vector_revision_ids"]
        self.assert_manifest_mutation_rejected(manifest, "vector-manifest-stimulus-scope")
        manifest = deepcopy(self.manifest)
        manifest["vectors"].insert(0, deepcopy(manifest["vectors"][0]))
        self.assert_manifest_mutation_rejected(manifest, "vector-manifest-order")

    def test_candidate_manifest_accounts_for_the_whole_denominator(self):
        self.assertEqual(self.manifest, compile_vector_manifest(self.inputs, list(reversed(self.families))))
        self.assertEqual(self.manifest["counts"], {
            "requirements": 3378,
            "requirements_with_candidate_stimuli": 58,
            "requirements_with_unresolved_interaction_identities": 4,
            "vector_revisions": 528,
        })
        rows = self.manifest["requirement_coverage"]
        self.assertEqual(len({row["requirement_id"] for row in rows}), 3378)
        self.assertEqual(sum(row["status"] == "missing" for row in rows), 3316)
        self.assertEqual({row["status"] for row in rows}, {
            "missing", "candidate-stimuli-only", "interaction-identity-unresolved",
        })
        expected = {item["vector_revision_id"] for item in self.manifest["vectors"]}
        self.assertEqual({identifier for row in rows for identifier in row["vector_revision_ids"]}, expected)
        body = dict(self.manifest)
        digest = body.pop("manifest_digest_sha256")
        self.assertEqual(sha256(canonical_bytes(body)).hexdigest(), digest)

    def test_quantifier_partitions_cover_the_exact_finite_subject_domain(self):
        controls = {
            "zero-or-more": ("a*", range(6)), "one-or-more": ("a+", range(1, 6)),
            "optional": ("a?", range(2)), "exact": ("a{2}", range(2, 3)),
            "bounded": ("a{1,3}", range(1, 4)), "lower-bounded": ("a{2,}", range(2, 6)),
            "upper-bounded": ("a{,2}", range(3)),
        }
        family_ids = {row["key"]: row["vector_revision_ids"] for row in self.manifest["families"]}
        stimuli = {row["vector_revision_id"]: row["stimulus"] for row in self.manifest["vectors"]}
        all_subjects = {
            b"".join(word) for width in range(6) for word in product((b"a", b"b"), repeat=width)
        }
        for name, (pattern, lengths) in controls.items():
            accepted = {b"a" * length for length in lengths}
            for role, expected_set in (("positive", accepted), ("negative", all_subjects - accepted)):
                with self.subTest(quantifier=name, role=role):
                    cases = [stimuli[key] for key in family_ids[f"cpython-{name}-quantifier-{role}"]]
                    self.assertEqual({bytes.fromhex(item["pattern"]["hex"]).decode() for item in cases}, {pattern})
                    self.assertEqual({bytes.fromhex(item["subjects"][0]["hex"]) for item in cases}, expected_set)
                    self.assertEqual(len(cases), len(expected_set))

    def test_missing_interaction_identity_remains_in_requirement_accounting(self):
        blocked = [
            row for row in self.manifest["requirement_coverage"]
            if row["status"] == "interaction-identity-unresolved"
        ]
        self.assertEqual(len(blocked), 4)
        self.assertEqual(len({key for row in blocked for key in row["blocking_interaction_keys"]}), 2)
        self.assertTrue(all(not row["vector_revision_ids"] for row in blocked))
        requirement = self.inputs.requirements[blocked[0]["requirement_id"]]
        family = {
            **self.anchor,
            "requirement_id": requirement["scientific_id"],
            "operation_id": requirement["required_operation_scientific_ids"][0],
        }
        with self.assertRaisesRegex(ConformanceDataError, "vector-interaction-identity-unresolved"):
            compile_vector_manifest(self.inputs, [family])

    def test_interaction_allocations_bind_exact_obligations_and_unique_assigned_ids(self):
        record = load_strict(ROOT / ALLOCATIONS_PATH)
        authority = {
            "catalog": load_strict(ROOT / CATALOG_PATH), "obligation_ref": self.inputs.obligation_snapshot,
            "obligations": self.inputs.obligations, "registry": self.inputs.registry,
        }
        allocated = verify_interaction_allocations(ROOT, record, **authority)
        self.assertEqual(len(allocated), 4)
        self.assertEqual(sum(bool(row["attribution"]["interaction_ids"]) for row in self.manifest["families"]), 8)

        for error in ("interaction-allocation-reuse", "interaction-allocation-relation"):
            with self.subTest(error=error):
                changed = deepcopy(record)
                first, second = changed["bindings"][:2]
                if error == "interaction-allocation-reuse":
                    second["scientific_id"] = first["scientific_id"]
                else:
                    second["obligation_id"] = first["obligation_id"]
                del changed["allocation_digest_sha256"]
                changed["allocation_digest_sha256"] = sha256(canonical_bytes(changed)).hexdigest()
                with self.assertRaisesRegex(ConformanceDataError, error):
                    verify_interaction_allocations(ROOT, changed, **authority)

    def test_campaign_design_pins_candidate_inputs_and_remains_ineligible(self):
        args = {"expected_manifest_digest": self.manifest["manifest_digest_sha256"]}
        design = build_production_campaign_design(ROOT, self.inputs, self.manifest, self.families, **args)
        reversed_design = build_production_campaign_design(ROOT, self.inputs, self.manifest, list(reversed(self.families)), **args)
        self.assertEqual(design, reversed_design)
        self.assertEqual(design["candidate_selection_count"], 16)
        self.assertEqual({row["adapter_operation"] for row in design["candidate_bindings"]}, {"compile", "full-match", "search"})
        self.assertEqual(design["native_span_unit"], "octet")
        self.assertIsNone(design["production_execution_denominator"])
        self.assertFalse(design["execution_ready"])

    def test_campaign_basis_rejects_omission_and_invalid_paired_control(self):
        basis = load_strict(ROOT / BASIS_PATH)
        omission = deepcopy(basis)
        omission["families"].pop()
        with self.assertRaisesRegex(ConformanceDataError, "candidate-basis-coverage"):
            bind_candidate_bases(ROOT, self.inputs, self.manifest, omission)
        scope = next(row for row in basis["families"] if row["comparison_family"] is not None)
        scope["profile_scope"] = "unsupported-substitution"
        with self.assertRaisesRegex(ConformanceDataError, "candidate-basis-comparison"):
            bind_candidate_bases(ROOT, self.inputs, self.manifest, basis)

    def test_exact_output_requires_typed_value_and_matching_operation(self):
        basis = load_strict(ROOT / BASIS_PATH)
        row = next(item for item in basis["families"] if item["family_key"] == "cpython-split-capture-edges")
        expected = row.pop("expected_output")
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            bind_candidate_bases(ROOT, self.inputs, self.manifest, basis)
        row["expected_output"] = ""
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            bind_candidate_bases(ROOT, self.inputs, self.manifest, basis)
        row["expected_outcome"] = "replacement-output"
        with self.assertRaisesRegex(ConformanceDataError, "candidate-basis-output-scope"):
            bind_candidate_bases(ROOT, self.inputs, self.manifest, basis)
        row["expected_output"] = expected
        row["expected_outcome"] = "split-output"
        row["oracle_revision_id"] = "made-up"
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            bind_candidate_bases(ROOT, self.inputs, self.manifest, basis)

    def test_preflight_preserves_pattern_bytes_and_never_creates_evidence(self):
        sys.path.insert(0, str(ROOT / "adapters/python"))
        try:
            from regex_conformance_adapters.model import ExecuteRequest
        finally:
            sys.path.pop(0)
        preflight = build_production_preflight(
            ROOT, self.inputs, self.manifest, self.families,
            expected_manifest_digest=self.manifest["manifest_digest_sha256"],
        )
        self.assertFalse(preflight["execution_ready"])
        self.assertIsNone(preflight["production_execution_denominator"])
        self.assertEqual(len(preflight["request_previews"]), 16)
        self.assertEqual(len(preflight["requirements"]), 3378)
        self.assertTrue(all(not row["execution_eligible"] and not row["c4_credit_from_preflight"] for row in preflight["requirements"]))
        stimuli = {row["vector_revision_id"]: row["stimulus"] for row in self.manifest["vectors"]}
        for preview in preflight["request_previews"]:
            identifier = preview["vector_revision_id"]
            stimulus = stimuli[identifier]
            request = ExecuteRequest.from_record(preview["request_preview"])
            self.assertEqual(request.trace_reference, identifier)
            self.assertEqual(request.pattern.value, bytes.fromhex(stimulus["pattern"]["hex"]))
            if request.operation == "compile":
                self.assertEqual(stimulus["subjects"], [])
                self.assertEqual(preview["subject_slot"], "compile-placeholder")
                self.assertEqual(request.subjects[0].value, b"")
            else:
                self.assertEqual(preview["subject_slot"], "semantic-subject")
                self.assertEqual(request.subjects[0].value, bytes.fromhex(stimulus["subjects"][0]["hex"]))

    def test_transport_refuses_unmapped_stimulus_fields(self):
        schema = load_strict(ROOT / REQUEST_SCHEMA)
        changes = {
            "subjects": ("production-transport-subjects", []),
            "initial_state": ("production-transport-state", {"occurrence": 2, "start_offset": 0}),
            "options": ("production-transport-option", [{"name": "utf", "value": 1}]),
            "replacement": ("production-transport-input", {"encoding": "octets", "hex": ""}),
            "domain": ("production-transport-encoding", "encoded-code-units"),
        }
        for field, (error, value) in changes.items():
            with self.subTest(field=field):
                vector = deepcopy(next(item for item in self.manifest["vectors"] if item["stimulus"]["subjects"]))
                vector["stimulus"][field] = value
                with self.assertRaisesRegex(ConformanceDataError, error):
                    _project_request(vector, "search", {}, schema)

    def test_encoded_units_preserve_unpaired_surrogates_but_reject_partial_units(self):
        family = deepcopy(self.anchor)
        family["domain"] = "encoded-code-units"
        family["axes"] = {}
        family["inputs"]["pattern"] = {"encoding": "utf-16-le", "hex": "6100"}
        family["inputs"]["subjects"] = [{"encoding": "utf-16-le", "hex": "00d8"}]
        manifest = compile_vector_manifest(self.inputs, [family])
        verify_vector_manifest(self.inputs, manifest, [family], expected_digest=manifest["manifest_digest_sha256"])
        self.assertEqual(manifest["vectors"][0]["stimulus"]["subjects"], family["inputs"]["subjects"])
        for malformed in ({"encoding": "utf-16-le", "hex": "d8"}, {"encoding": "utf-32-be", "hex": "0000"}):
            family["inputs"]["subjects"] = [malformed]
            with self.assertRaisesRegex(ConformanceDataError, "vector-input-domain"):
                compile_vector_manifest(self.inputs, [family])

    def test_cpython_output_candidates_distinguish_semantic_mutations(self):
        by_key = {row["family_key"]: row for row in load_strict(ROOT / BASIS_PATH)["families"]}
        families = {row["key"]: row for row in self.manifest["families"]}
        stimuli = {row["vector_revision_id"]: row["stimulus"] for row in self.manifest["vectors"]}
        boundary_stimulus = stimuli[families["cpython-split-empty-word-boundary"]["vector_revision_ids"][0]]
        replacement_stimulus = stimuli[families["cpython-replacement-number-delimiter"]["vector_revision_ids"][0]]
        unsplit = bytes.fromhex(boundary_stimulus["subjects"][0]["hex"]).decode("utf-8")
        literal = bytes.fromhex(replacement_stimulus["replacement"]["hex"]).decode("utf-8")
        captured = by_key["cpython-split-capture-edges"]["expected_output"]
        boundary = by_key["cpython-split-empty-word-boundary"]["expected_output"]
        numbered = by_key["cpython-replacement-number-delimiter"]["expected_output"]
        self.assertEqual(captured, ["", "...", "words", ", ", "words", "...", ""])
        self.assertEqual(boundary, ["", "Words", ", ", "words", ", ", "words", "."])
        self.assertEqual(numbered, "b0xb0")
        cases = {
            "discard-captured-delimiters": (captured[::2], captured),
            "discard-split-edge-fields": (captured[1:-1], captured),
            "ignore-all-zero-width-delimiters": ([unsplit], boundary),
            "drop-leading-empty-split-field": (boundary[1:], boundary),
            "treat-replacement-as-literal": (f"{literal}x{literal}", numbered),
            "consume-following-replacement-digit": (numbered.replace("0", ""), numbered),
        }
        for name, (mutated, expected) in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(mutated, expected)

    def test_absolute_anchor_cases_distinguish_line_anchors_and_literal_search(self):
        bases = {row["family_key"]: row for row in load_strict(ROOT / BASIS_PATH)["families"]}
        families = {row["key"]: row for row in self.manifest["families"]}
        stimuli = {row["vector_revision_id"]: row["stimulus"] for row in self.manifest["vectors"]}
        for label, models in (
            ("subject-start", (lambda value: value.startswith("a"), lambda value: "\na" in value)),
            ("strict-subject-end", (lambda value: value.endswith("a"), lambda value: value.endswith("a\n"))),
        ):
            exact, accepts_line_position = models
            with self.subTest(anchor=label):
                negative_subjects = []
                for role in ("positive", "negative"):
                    key = f"cpython-{label}-{role}"
                    expected = bases[key]["expected_outcome"] == "match"
                    for revision in families[key]["vector_revision_ids"]:
                        subject = bytes.fromhex(stimuli[revision]["subjects"][0]["hex"]).decode("utf-8")
                        self.assertEqual(exact(subject), expected)
                        if not expected:
                            negative_subjects.append(subject)
                self.assertTrue(any(accepts_line_position(subject) for subject in negative_subjects))
                self.assertTrue(all("a" in subject for subject in negative_subjects))

    def test_oracle_or_arbitrary_attribution_cannot_enter_family_input(self):
        family = deepcopy(self.anchor)
        family["expected_result"] = {"matched": True}
        with self.assertRaisesRegex(ConformanceDataError, "schema-validation-failed"):
            compile_vector_manifest(self.inputs, [family])
        del family["expected_result"]
        family["operation_id"] = self.escapes["operation_id"]
        with self.assertRaisesRegex(ConformanceDataError, "vector-attribution"):
            compile_vector_manifest(self.inputs, [family])

    def test_manifestation_scope_cannot_be_omitted_or_substituted(self):
        family = deepcopy(self.escapes)
        family["manifestation_id"] = None
        with self.assertRaisesRegex(ConformanceDataError, "select an in-scope manifestation"):
            compile_vector_manifest(self.inputs, [family])
        family["manifestation_id"] = self.anchor["manifestation_id"]
        with self.assertRaisesRegex(ConformanceDataError, "different feature"):
            compile_vector_manifest(self.inputs, [family])

    def test_finite_enumeration_is_exact_and_fail_closed_at_the_bound(self):
        family = deepcopy(self.anchor)
        family["axes"] = {}
        alphabet = ["61", "62"]
        family["finite_subjects"] = {"encoding": "octets", "alphabet_hex": alphabet, "min_length": 0, "max_length": 2}
        manifest = compile_vector_manifest(self.inputs, [family])
        self.assertEqual(verify_vector_manifest(
            self.inputs, manifest, [family], expected_digest=manifest["manifest_digest_sha256"],
        ), manifest["counts"])
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
        family = deepcopy(self.escapes)
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

    def test_numbered_reference_controls_detect_class_only_and_literal_mutations(self):
        expected = {b"aa": True, b"bb": True, b"ab": False, b"ba": False}
        subjects = {
            bytes.fromhex(item["stimulus"]["subjects"][0]["hex"])
            for item in self.manifest["vectors"] if item["stimulus"]["pattern"]["hex"] == "285b61625d295c31"
        }
        self.assertEqual(subjects, set(expected))
        for subject in subjects:
            self.assertEqual(subject[0] == subject[1], expected[subject])
        self.assertTrue(any(all(byte in b"ab" for byte in subject) != expected[subject] for subject in subjects))
        self.assertTrue(any(subject.endswith(b"1") != expected[subject] for subject in subjects))
