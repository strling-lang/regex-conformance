from __future__ import annotations

import contextlib
import io
import json
import unittest

from support import ROOT
from regex_conformance_schema.cli import run


class CliTests(unittest.TestCase):
    def invoke(self, *arguments: str):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = run(["--root", str(ROOT), *arguments])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_validate_repository_emits_structured_success(self) -> None:
        code, stdout, stderr = self.invoke("validate-repository")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(stdout)["ok"])
        self.assertEqual(stderr, "")

    def test_invalid_identifier_emits_structured_failure(self) -> None:
        code, stdout, stderr = self.invoke("validate-id", "rcid:v1:bad")
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertEqual(json.loads(stderr)["error"]["code"], "invalid-identifier")
