from __future__ import annotations

import unittest

from support import ROOT
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


class StrictJsonTests(unittest.TestCase):
    def test_rfc8785_core_example_matches_exact_published_bytes(self) -> None:
        manifest = load_strict(ROOT / "tests" / "fixtures" / "identity" / "manifest.json")
        value = next(case["input"] for case in manifest["cases"] if case["case_id"] == "rfc8785-core")
        expected_hex = (
            "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c"
            "226e756d62657273223a5b3333333333333333332e333333333333332c3165"
            "2b33302c342e352c302e3030322c31652d32375d2c22737472696e67223a22"
            "e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
        )
        self.assertEqual(canonical_bytes(value).hex(), expected_hex)

    def test_duplicate_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "duplicate-json-key"):
            load_strict(ROOT / "tests" / "fixtures" / "invalid" / "duplicate-key.json")

    def test_nonfinite_numbers_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "invalid-json-number"):
            load_strict(ROOT / "tests" / "fixtures" / "invalid" / "nonfinite.json")

    def test_lone_surrogates_are_rejected(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "invalid-unicode"):
            load_strict(ROOT / "tests" / "fixtures" / "invalid" / "lone-surrogate.json")

    def test_negative_zero_has_jcs_representation_zero(self) -> None:
        self.assertEqual(canonical_bytes({"value": -0.0}), b'{"value":0}')
