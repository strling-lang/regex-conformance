from __future__ import annotations

from io import BytesIO
import struct
import unittest

from support import manifest, offer, request, scalar, validate_schema
from regex_conformance_adapters.backend import RuntimeIdentity, ThinBackend
from regex_conformance_adapters.errors import BackendFailure
from regex_conformance_adapters.jsonio import encode_frame, read_frame, strict_loads
from regex_conformance_adapters.model import Datum, ExecuteRequest, span_record
from regex_conformance_adapters.server import AdapterServer


class StubBackend(ThinBackend):
    supported_operations = frozenset({"search"})
    supported_options = frozenset()
    supported_environment_inputs = frozenset()
    supported_domains = frozenset({"unicode-scalars"})

    def __init__(self, *, fail: bool = False) -> None:
        package = manifest(
            "python-re",
            capabilities=(
                "datum-unicode-scalars",
                "native-index-unicode-scalar",
                "observation-match-state",
                "observation-runtime-identity",
                "observation-spans",
                "operation-search",
            ),
        )
        super().__init__(package)
        self.fail = fail

    def runtime_identity(self) -> RuntimeIdentity:
        return RuntimeIdentity((("runtime-kind", "stub"),))

    def execute(self, value: ExecuteRequest):
        self.validate_request(value)
        if self.fail:
            raise BackendFailure("stub-failure", "seeded adapter invocation failure")
        observation = self.base_observation(value)
        observation["compile_status"] = "accepted"
        observation["execution_status"] = "completed"
        observation["match_state"] = "match"
        matched = Datum("unicode-scalars", "aaa", "unicode-scalar-values", None, None).to_record()
        span = span_record(
            1,
            4,
            basis="unicode-scalar",
            provenance="stub native span",
            encoding="unicode-scalar-values",
        )
        observation["matches"] = [
            {
                "captures": [
                    {
                        "history": [],
                        "index": 0,
                        "name": None,
                        "participation": "matched",
                        "span": span,
                        "value": matched,
                    }
                ],
                "ordinal": 0,
                "span": span,
            }
        ]
        return observation


class AdapterProtocolComplianceTests(unittest.TestCase):
    def test_handshake_binds_package_runtime_capabilities_and_limits(self) -> None:
        backend = StubBackend()
        result = AdapterServer(backend)._handshake(
            offer(required=["observation-spans", "operation-search"])
        )
        validate_schema(result, "adapter-handshake.schema.json")
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(result["adapter_release_manifest_id"], backend.manifest.manifest_id)
        self.assertEqual(result["runtime_identity"]["profile_id"], backend.manifest.profile_id)
        self.assertEqual(len(result["transcript_sha256"]), 64)
        self.assertFalse(result["canonical_authority"])
        self.assertFalse(result["semantic_authority"])

    def test_major_mismatch_and_unknown_required_capability_fail_closed(self) -> None:
        for proposed in (offer(major=2), offer(required=["operation-network-lookup"])):
            result = AdapterServer(StubBackend())._handshake(proposed)
            validate_schema(result, "adapter-handshake.schema.json")
            self.assertEqual(result["outcome"], "rejected")
            self.assertIsNone(result["adapter_release_manifest_id"])
            self.assertIsNone(result["runtime_identity"])

    def test_optional_unknown_capability_is_not_silently_selected(self) -> None:
        proposed = offer()
        proposed["optional_capabilities"] = ["operation-network-lookup"]
        result = AdapterServer(StubBackend())._handshake(proposed)
        validate_schema(result, "adapter-handshake.schema.json")
        self.assertEqual(result["outcome"], "accepted")
        self.assertNotIn("operation-network-lookup", result["capabilities"])

    def test_execute_response_preserves_native_shape_without_authority_claim(self) -> None:
        backend = StubBackend()
        response = AdapterServer(backend).execute(request(backend.manifest))
        validate_schema(response, "adapter-response.schema.json")
        self.assertEqual(response["status"], "completed")
        self.assertEqual(response["observation"]["match_state"], "match")
        self.assertEqual(response["observation"]["matches"][0]["span"]["basis"], "unicode-scalar")
        self.assertNotIn("verdict", response)
        self.assertFalse(response["canonical_authority"])
        self.assertFalse(response["semantic_authority"])

    def test_expected_answer_matrix_and_unknown_fields_are_rejected_before_invocation(self) -> None:
        backend = StubBackend()
        value = request(backend.manifest)
        for forbidden in ("expected_answer", "matrix", "applicability", "scheduler", "secret"):
            mutated = dict(value)
            mutated[forbidden] = "forbidden"
            response = AdapterServer(backend).execute(mutated)
            validate_schema(response, "adapter-response.schema.json")
            self.assertEqual(response["status"], "rejected")
            self.assertEqual(response["failure"]["layer"], "protocol")

    def test_unsupported_domain_and_operation_are_explicit_not_target_results(self) -> None:
        backend = StubBackend()
        code_units = {
            "domain": "code-units",
            "encoding": "utf-16",
            "endianness": "little",
            "unit_width_bits": 16,
            "units": [0xD800],
        }
        cases = (
            request(backend.manifest, pattern=code_units, subject=code_units),
            request(backend.manifest, operation="split"),
        )
        for value in cases:
            response = AdapterServer(backend).execute(value)
            validate_schema(response, "adapter-response.schema.json")
            self.assertEqual(response["status"], "unsupported")
            self.assertIsNone(response["observation"])
            self.assertEqual(response["failure"]["layer"], "materialization")

    def test_invocation_exception_is_an_adapter_failure_not_regex_rejection(self) -> None:
        backend = StubBackend(fail=True)
        response = AdapterServer(backend).execute(request(backend.manifest))
        validate_schema(response, "adapter-response.schema.json")
        self.assertEqual(response["status"], "failed")
        self.assertEqual(response["failure"]["layer"], "invocation")
        self.assertIsNone(response["observation"])

    def test_framed_session_requires_handshake_and_emits_only_frames(self) -> None:
        backend = StubBackend()
        incoming = BytesIO(encode_frame(offer()) + encode_frame(request(backend.manifest)))
        outgoing = BytesIO()
        self.assertEqual(AdapterServer(backend).serve(incoming, outgoing), 0)
        outgoing.seek(0)
        handshake = read_frame(outgoing)
        response = read_frame(outgoing)
        self.assertIsNone(read_frame(outgoing))
        assert handshake is not None and response is not None
        validate_schema(handshake, "adapter-handshake.schema.json")
        validate_schema(response, "adapter-response.schema.json")

    def test_duplicate_keys_truncated_frames_and_oversize_declarations_fail(self) -> None:
        with self.assertRaisesRegex(Exception, "duplicate JSON key"):
            strict_loads(b'{"schema_version":"x","schema_version":"y"}')
        with self.assertRaisesRegex(Exception, "declared length"):
            read_frame(BytesIO(struct.pack(">I", 8) + b"{}"))
        with self.assertRaisesRegex(Exception, "exceeds"):
            read_frame(BytesIO(struct.pack(">I", 1_048_577)))

    def test_noncanonical_capability_order_and_ambiguous_ranges_reject(self) -> None:
        backend = StubBackend()
        unsorted = offer(required=["operation-search", "observation-spans"])
        unsorted["required_capabilities"] = ["operation-search", "observation-spans"]
        with self.assertRaisesRegex(Exception, "deterministic lexical order"):
            AdapterServer(backend)._handshake(unsorted)
        inverted = offer()
        inverted["protocol"] = {"major": 1, "maximum_minor": 0, "minimum_minor": 1}
        with self.assertRaisesRegex(Exception, "inverted"):
            AdapterServer(backend)._handshake(inverted)

    def test_malformed_base64_and_isolated_surrogate_fail_materialization(self) -> None:
        backend = StubBackend()
        malformed = request(backend.manifest)
        malformed["pattern"] = {
            "data": "A",
            "domain": "octets",
            "encoding": None,
            "endianness": None,
            "unit_width_bits": 8,
        }
        response = AdapterServer(backend).execute(malformed)
        self.assertEqual(response["status"], "rejected")
        surrogate = request(backend.manifest, pattern=scalar("ok"))
        surrogate["pattern"]["text"] = "\ud800"
        response = AdapterServer(backend).execute(surrogate)
        self.assertEqual(response["status"], "rejected")


if __name__ == "__main__":
    unittest.main()
