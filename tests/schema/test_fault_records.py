from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_TOOLING = ROOT / "schemas" / "tooling" / "python"
CONTROL_PLANE = ROOT / "control-plane" / "python"
for source in (SCHEMA_TOOLING, CONTROL_PLANE):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.faults import load_and_validate_fault_records
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.schema import validate_instance


class FaultRecordTests(unittest.TestCase):
    def _root(self, directory: str) -> Path:
        root = Path(directory)
        (root / "schemas" / "json").mkdir(parents=True)
        (root / "reports" / "small-scale").mkdir(parents=True)
        shutil.copy(
            ROOT / "schemas" / "json" / "fault-classification-report.schema.json",
            root / "schemas" / "json" / "fault-classification-report.schema.json",
        )
        shutil.copy(
            ROOT / "reports" / "small-scale" / "fault-classification.json",
            root / "reports" / "small-scale" / "fault-classification.json",
        )
        return root

    def test_repository_accounts_for_exact_fault_reference_matrix(self) -> None:
        counts = load_and_validate_fault_records(
            ROOT, validate_instance=validate_instance
        )
        self.assertEqual(counts, {
            "fault_classification_cases": 7,
            "fault_classification_reports": 1,
        })

    def test_reference_substitution_and_unknown_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            path = root / "reports" / "small-scale" / "fault-classification.json"
            value = load_strict(path)
            value["cases"][0]["assessment"]["reason_code"] = "substituted-reason"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "fault reference report differs"):
                load_and_validate_fault_records(root, validate_instance=validate_instance)

        value = load_strict(ROOT / "reports" / "small-scale" / "fault-classification.json")
        value["unknown"] = True
        with self.assertRaises(ConformanceDataError):
            validate_instance(
                value,
                load_strict(
                    ROOT / "schemas" / "json" / "fault-classification-report.schema.json"
                ),
                source="mutated fault report",
            )


if __name__ == "__main__":
    unittest.main()
