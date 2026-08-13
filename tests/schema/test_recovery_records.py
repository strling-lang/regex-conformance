from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.recovery import load_and_validate_recovery_records
from regex_conformance_schema.schema import validate_instance


class RecoveryRecordTests(unittest.TestCase):
    def _root(self, directory: str) -> Path:
        root = Path(directory)
        (root / "schemas" / "json").mkdir(parents=True)
        (root / "reports" / "small-scale").mkdir(parents=True)
        shutil.copy(
            ROOT / "schemas" / "json" / "restart-resume-qualification.schema.json",
            root / "schemas" / "json" / "restart-resume-qualification.schema.json",
        )
        shutil.copy(
            ROOT / "reports" / "small-scale" / "restart-resume-qualification.json",
            root / "reports" / "small-scale" / "restart-resume-qualification.json",
        )
        return root

    def test_repository_accounts_for_exact_recovery_matrix(self) -> None:
        counts = load_and_validate_recovery_records(
            ROOT, validate_instance=validate_instance
        )
        self.assertEqual(counts, {
            "restart_resume_cases": 14,
            "restart_resume_reports": 1,
        })

    def test_reference_substitution_and_unknown_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            path = root / "reports" / "small-scale" / "restart-resume-qualification.json"
            value = load_strict(path)
            value["cases"][0]["expected_action"] = "retry"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ConformanceDataError, "report differs"):
                load_and_validate_recovery_records(root, validate_instance=validate_instance)

        value = load_strict(
            ROOT / "reports" / "small-scale" / "restart-resume-qualification.json"
        )
        value["unknown"] = True
        with self.assertRaises(ConformanceDataError):
            validate_instance(
                value,
                load_strict(
                    ROOT / "schemas" / "json" / "restart-resume-qualification.schema.json"
                ),
                source="mutated recovery report",
            )


if __name__ == "__main__":
    unittest.main()
