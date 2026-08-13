from __future__ import annotations

from unittest.mock import patch
import unittest

from support import manifest, octets, request, scalar, validate_schema
from regex_conformance_adapters.model import ExecuteRequest
from regex_conformance_adapters.python_re import PythonReBackend
from regex_conformance_adapters.server import AdapterServer


class PythonReAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.version = patch("regex_conformance_adapters.python_re.platform.python_version", return_value="3.14.6")
        self.unicode = patch("regex_conformance_adapters.python_re.unicodedata.unidata_version", "16.0.0")
        self.version.start()
        self.unicode.start()
        self.addCleanup(self.version.stop)
        self.addCleanup(self.unicode.stop)
        self.backend = PythonReBackend(manifest("python-re"))

    def response(self, value):
        result = AdapterServer(self.backend).execute(value)
        validate_schema(result, "adapter-response.schema.json")
        return result

    def test_unicode_spans_remain_native_scalar_indices(self) -> None:
        result = self.response(request(self.backend.manifest, pattern=scalar("😀"), subject=scalar("A😀B")))
        span = result["observation"]["matches"][0]["span"]
        self.assertEqual((span["start"], span["end"], span["basis"]), (1, 2, "unicode-scalar"))

    def test_octet_nul_input_and_indices_are_preserved(self) -> None:
        result = self.response(
            request(self.backend.manifest, pattern=octets(b"\x00a"), subject=octets(b"x\x00ay"))
        )
        match = result["observation"]["matches"][0]
        self.assertEqual((match["span"]["start"], match["span"]["end"]), (1, 3))
        self.assertEqual(match["span"]["basis"], "octet")
        self.assertEqual(match["captures"][0]["value"]["data"], "AGE")

    def test_compile_rejection_is_a_completed_native_observation(self) -> None:
        result = self.response(request(self.backend.manifest, pattern=scalar("(")))
        self.assertEqual(result["status"], "completed")
        observation = result["observation"]
        self.assertEqual(observation["compile_status"], "rejected")
        self.assertEqual(observation["execution_status"], "not-requested")
        self.assertEqual(observation["native_error"]["phase"], "compile")

    def test_unmatched_capture_remains_distinct_from_empty_capture(self) -> None:
        result = self.response(
            request(
                self.backend.manifest,
                operation="capture-extraction",
                pattern=scalar("(a)?(b*)"),
                subject=scalar(""),
                observations=["capture-history", "captures", "match-state", "runtime-identity", "spans"],
            )
        )
        captures = result["observation"]["matches"][0]["captures"]
        self.assertEqual(captures[1]["participation"], "unmatched")
        self.assertIsNone(captures[1]["value"])
        self.assertEqual(captures[2]["participation"], "matched")
        self.assertEqual(captures[2]["value"]["text"], "")

    def test_zero_length_find_all_terminates_with_native_progress(self) -> None:
        value = request(
            self.backend.manifest,
            operation="find-all",
            pattern=scalar(""),
            subject=scalar("ab"),
            observations=["captures", "cursor", "match-state", "runtime-identity", "spans"],
        )
        value["initial_state"]["occurrence"] = 2
        result = self.response(value)
        spans = [item["span"] for item in result["observation"]["matches"]]
        self.assertEqual([(item["start"], item["end"]) for item in spans], [(1, 1), (2, 2)])
        self.assertTrue(result["observation"]["cursor"]["exhausted"])

    def test_replacement_and_split_outputs_remain_typed(self) -> None:
        replacement = self.response(
            request(
                self.backend.manifest,
                operation="replace-all",
                pattern=scalar("a+"),
                subject=scalar("baaac"),
                replacement=scalar("X"),
                observations=["match-state", "replacement-output", "runtime-identity"],
            )
        )
        self.assertEqual(replacement["observation"]["outputs"]["values"][0]["text"], "bXc")
        split = self.response(
            request(
                self.backend.manifest,
                operation="split",
                pattern=scalar(","),
                subject=scalar("a,b,c"),
                observations=["match-state", "runtime-identity", "split-output"],
            )
        )
        self.assertEqual([item["text"] for item in split["observation"]["outputs"]["values"]], ["a", "b", "c"])

    def test_split_semantic_limit_is_distinct_from_result_resource_bound(self) -> None:
        explicit = request(
            self.backend.manifest,
            operation="split",
            pattern=scalar(","),
            subject=scalar("a,b,c"),
            options=[{"name": "maximum-splits", "value": 1}],
            observations=["match-state", "runtime-identity", "split-output"],
        )
        result = self.response(explicit)
        self.assertEqual(
            [item["text"] for item in result["observation"]["outputs"]["values"]],
            ["a", "b,c"],
        )

        bounded = request(
            self.backend.manifest,
            operation="split",
            pattern=scalar(","),
            subject=scalar("a,b,c"),
            observations=["match-state", "runtime-identity", "split-output"],
        )
        bounded["limits"]["maximum_matches"] = 1
        result = self.response(bounded)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["failure"]["code"], "result-limit-exceeded")

    def test_type_mixing_and_unknown_options_are_unsupported(self) -> None:
        mixed = self.response(request(self.backend.manifest, pattern=scalar("a"), subject=octets(b"a")))
        self.assertEqual(mixed["status"], "unsupported")
        unknown = request(
            self.backend.manifest,
            options=[{"name": "engine-feature", "value": True}],
        )
        result = self.response(unknown)
        self.assertEqual(result["status"], "unsupported")

        replacement = request(
            self.backend.manifest,
            operation="replace-all",
            replacement=scalar("X"),
        )
        replacement["initial_state"]["start_offset"] = 1
        result = self.response(replacement)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["failure"]["code"], "initial-state-unsupported")

        split = request(self.backend.manifest, operation="split")
        split["initial_state"]["occurrence"] = 2
        result = self.response(split)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["failure"]["code"], "initial-state-unsupported")

        full_match = request(
            self.backend.manifest,
            operation="full-match",
            pattern=scalar("a+"),
            subject=scalar("aaa"),
        )
        full_match["initial_state"]["occurrence"] = 2
        result = self.response(full_match)
        self.assertEqual(result["observation"]["match_state"], "no-match")

    def test_runtime_identity_mismatch_fails_before_target_invocation(self) -> None:
        backend = PythonReBackend(manifest("python-re"))
        with patch("regex_conformance_adapters.python_re.platform.python_version", return_value="3.14.5"):
            with self.assertRaisesRegex(Exception, "runtime-identity-mismatch"):
                backend.runtime_identity()

    def test_materialized_request_never_accepts_hidden_callback_code(self) -> None:
        value = request(self.backend.manifest)
        value["callback_fixture"] = {"fixture_id": "literal", "parameters": [], "source": "arbitrary()"}
        result = self.response(value)
        self.assertEqual(result["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
