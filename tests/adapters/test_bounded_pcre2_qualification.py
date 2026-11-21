from __future__ import annotations

from copy import deepcopy
from io import BytesIO
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from support import ROOT


RUNNER = runpy.run_path(str(ROOT / "tools/adapters/qualify_pcre2.py"))
build_plan = RUNNER["build_plan"]
verify_responses = RUNNER["verify_responses"]
FACTS = [{"name": "engine-version", "value": "10.47"}]


def response(probe: dict) -> dict:
    request = probe["request"]
    expectation = probe["qualification_expectation"]
    operation = request["operation"]
    compile_only = operation["name"] == "compile"
    native_error = None
    if expectation == {"compile_status": "rejected"}:
        native_error = {
            "class": "pcre2-compile-error", "code": 115, "diagnostic": None,
            "message": "reference to unavailable capture", "phase": "compile", "position": 4,
        }
    observation = {
        "absences": [], "compile_status": "accepted", "cursor": None,
        "execution_status": "not-requested" if compile_only else "completed",
        "materialization": {"pattern_domain": "octets", "subject_domains": ["octets"]},
        "match_state": "not-applicable", "matches": [], "native_error": native_error,
        "operation": operation, "outputs": {"kind": "none", "values": []},
        "runtime_identity": {"facts": deepcopy(FACTS)}, **expectation,
    }
    return {
        "adapter_release_manifest_id": request["adapter_release_manifest_id"],
        "profile_id": request["profile_id"], "target_release_id": request["target_release_id"],
        "correlation_id": request["correlation_id"], "trace_reference": request["trace_reference"],
        "schema_version": "adapter-response.v1", "message_type": "execute-result",
        "canonical_authority": False, "semantic_authority": False, "failure": None,
        "status": "completed", "observation": observation,
    }


class BoundedPcre2QualificationTests(unittest.TestCase):
    def setUp(self):
        self.plan = build_plan(ROOT)
        self.responses = [response(probe) for probe in self.plan["probes"]]

    def test_bound_population_and_independent_order(self):
        self.assertEqual(self.plan, build_plan(ROOT))
        self.assertEqual(len(self.plan["probes"]), 11)
        self.assertEqual(self.plan["maximum_environment_realizations"], 1)
        self.assertEqual(self.plan["production_logical_executions"], 0)
        actual = verify_responses(ROOT, self.plan, self.responses, FACTS)
        self.assertEqual(len({row["scientific_id"] for row in actual}), 8)
        self.assertEqual({row["state"] for row in actual}, {"verified-in-qualification"})
        self.assertEqual(actual, verify_responses(ROOT, self.plan, list(reversed(self.responses)), FACTS))

    def test_omission_duplicate_scope_and_plan_mutations_are_rejected(self):
        wrong_trace = deepcopy(self.responses)
        wrong_trace[0]["trace_reference"] = "outside-plan"
        wrong_runtime = deepcopy(self.responses)
        wrong_runtime[0]["observation"]["runtime_identity"]["facts"][0]["value"] = "10.46"
        wrong_operation = deepcopy(self.responses)
        wrong_operation[0]["observation"]["operation"] = {"name": "search", "version": "1.0.0"}
        for records, reason in (
            (self.responses[1:], "pcre2-qualification-population"),
            ([*self.responses, self.responses[0]], "pcre2-qualification-response-duplicate"),
            (wrong_trace, "pcre2-qualification-scope"),
            (wrong_runtime, "pcre2-qualification-scope"),
            (wrong_operation, "pcre2-qualification-scope"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(Exception, reason):
                verify_responses(ROOT, self.plan, records, FACTS)
        changed = deepcopy(self.plan)
        changed["probes"][0]["qualification_expectation"]["match_state"] = "no-match"
        with self.assertRaisesRegex(Exception, "pcre2-qualification-plan"):
            verify_responses(ROOT, changed, self.responses, FACTS)

    def test_wrong_native_rejection_and_infrastructure_leave_assertions_open(self):
        records = {row["correlation_id"]: row for row in self.responses}
        records["reference-absent"]["observation"]["native_error"]["code"] = 114
        records["restricted-fold-ascii"].update(
            status="failed", observation=None,
            failure={"code": "runtime-failed", "diagnostic": None, "kind": "adapter-invocation",
                     "layer": "invocation", "message": "runtime unavailable"},
        )
        result = verify_responses(ROOT, self.plan, list(records.values()), FACTS)
        self.assertEqual({row["catalog_key"] for row in result if row["state"] == "unresolved"}, {
            "feature.invalid-group-reference", "manifestation.invalid-group-reference.pcre2-api",
            "feature.simple-case-folding", "modifier.caseless-restrict",
        })

    def test_unprotected_source_and_wrong_worker_refuse_before_realization(self):
        guard = RUNNER["_require_protected_worker"]
        with patch.dict(guard.__globals__, {"_git": lambda *args: "branch\nmain\nmain"}):
            with self.assertRaisesRegex(ValueError, "exact protected main"):
                guard("main")
        with patch.dict(guard.__globals__, {"_git": lambda *args: "main\nmain\nmain" if args[0] == "rev-parse" else ""}):
            with patch("platform.system", return_value="Windows"):
                with self.assertRaisesRegex(ValueError, "Ubuntu 24.04 x86-64"):
                    guard("main")

    def test_modified_archive_rejected_before_signature_execution(self):
        archive = SimpleNamespace(open=lambda _: BytesIO(b"modified archive"))
        with patch("subprocess.run") as command:
            with self.assertRaisesRegex(ValueError, "differs from recipe size or digest"):
                RUNNER["OfflineRelease"](self.plan, archive, archive, archive)
            command.assert_not_called()
