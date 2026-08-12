from __future__ import annotations

import unittest

from support import profile
from regex_conformance_schema.errors import ConformanceDataError


class IdentityProfileTests(unittest.TestCase):
    def test_sequence_order_is_preserved_and_set_is_sorted_and_deduplicated(self) -> None:
        projected = profile("ordered-values.v1.json").project(
            {"label": "alpha", "pattern": "a", "sequence": ["beta", "alpha"], "tags": ["zeta", "alpha", "zeta"]}
        )
        self.assertEqual(projected["sequence"], ["beta", "alpha"])
        self.assertEqual(projected["tags"], ["alpha", "zeta"])

    def test_canonical_text_normalizes_but_raw_text_does_not(self) -> None:
        projected = profile("ordered-values.v1.json").project(
            {"label": "cafe\u0301", "pattern": "cafe\u0301", "sequence": [], "tags": []}
        )
        self.assertEqual(projected["label"], "café")
        self.assertEqual(projected["pattern"], "cafe\u0301")

    def test_missing_null_and_empty_remain_distinct(self) -> None:
        identity = {"label": "a", "pattern": "", "sequence": [], "tags": []}
        self.assertNotIn("flag", profile("ordered-values.v2.json").project(identity))
        with self.assertRaisesRegex(ConformanceDataError, "wrong-type"):
            profile("ordered-values.v2.json").project({**identity, "flag": None})

    def test_unknown_fields_fail_closed(self) -> None:
        with self.assertRaisesRegex(ConformanceDataError, "unknown-field"):
            profile("ordered-values.v1.json").project(
                {"label": "a", "pattern": "a", "sequence": [], "tags": [], "surprise": 1}
            )

    def test_safe_integer_boundary(self) -> None:
        base = {
            "blob": "",
            "day": "2026-08-12",
            "decimal": "1",
            "flag": False,
            "instant": "2026-08-12T00:00:00.000Z",
            "nothing": None,
            "token": "token",
            "uuid": "01890f3e-b253-7cc3-98c4-dc0c0c07398f",
        }
        self.assertEqual(profile("canonical-values.v1.json").project({**base, "safe": -9007199254740991})["safe"], -9007199254740991)
        with self.assertRaisesRegex(ConformanceDataError, "unsafe-integer"):
            profile("canonical-values.v1.json").project({**base, "safe": -9007199254740992})
