from __future__ import annotations

import ast
from io import BytesIO
from pathlib import Path
import unittest

from support import ROOT, manifest, request, validate_schema
from regex_conformance_adapters.jsonio import encode_frame
from regex_conformance_adapters.manifest import load_manifest
from regex_conformance_adapters.server import AdapterServer
from test_protocol_compliance import StubBackend


class CrashingBackend(StubBackend):
    def execute(self, value):
        raise RuntimeError("seeded non-protocol failure")


class AdapterThinnessTests(unittest.TestCase):
    def test_governed_release_manifests_self_verify_and_bind_exact_coordinates(self) -> None:
        packages = [load_manifest(ROOT, key) for key in ("mysql-regex", "pcre2-ordinary", "python-re")]
        self.assertEqual({item.selection_key for item in packages}, {"mysql-regex", "pcre2-ordinary", "python-re"})
        self.assertEqual(len({item.adapter_id for item in packages}), 3)
        self.assertEqual(len({item.adapter_release_id for item in packages}), 3)
        self.assertEqual(len({item.manifest_id for item in packages}), 3)

    def test_adapter_sources_have_no_verdict_or_orchestration_dependencies(self) -> None:
        packages = [load_manifest(ROOT, key) for key in ("mysql-regex", "pcre2-ordinary", "python-re")]
        source_paths: set[Path] = set()
        for package in packages:
            record_path = ROOT / "adapters" / "manifests" / f"{package.selection_key}.v1.json"
            import json

            record = json.loads(record_path.read_text(encoding="utf-8"))
            source_paths.update(ROOT / item["path"] for item in record["source_files"])

        forbidden_symbols = {
            "applicability",
            "campaign",
            "expected_answer",
            "expectation",
            "matrix",
            "normative",
            "pass_fail",
            "scheduler",
            "shard",
            "verdict",
        }
        forbidden_modules = {"applicability", "campaign", "control_plane", "matrix", "scheduler", "warehouse"}
        for path in sorted(source_paths):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            symbols = {
                node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
            } | {
                node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            } | {
                node.name for node in ast.walk(tree) if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            }
            self.assertFalse(symbols & forbidden_symbols, f"orchestration/verdict symbol in {path}")
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    modules = [node.module or ""]
                else:
                    continue
                for module in modules:
                    self.assertFalse(set(module.split(".")) & forbidden_modules, f"forbidden dependency {module} in {path}")

    def test_unhandled_backend_exception_is_failed_infrastructure_not_target_rejection(self) -> None:
        backend = CrashingBackend()
        response = AdapterServer(backend).execute(request(backend.manifest))
        validate_schema(response, "adapter-response.schema.json")
        self.assertEqual(response["status"], "failed")
        self.assertEqual(response["failure"]["layer"], "invocation")
        self.assertEqual(response["failure"]["code"], "adapter-unhandled-exception")
        self.assertIsNone(response["observation"])

    def test_execute_frame_before_handshake_fails_closed_without_output(self) -> None:
        backend = StubBackend()
        incoming = BytesIO(encode_frame(request(manifest("python-re"))))
        outgoing = BytesIO()
        with self.assertRaisesRegex(Exception, "handshake offer"):
            AdapterServer(backend).serve(incoming, outgoing)
        self.assertEqual(outgoing.getvalue(), b"")


if __name__ == "__main__":
    unittest.main()
