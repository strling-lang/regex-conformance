"""Stateful capability handshake and framed adapter session."""

from __future__ import annotations

import hashlib
from typing import Any, BinaryIO

from .backend import AdapterBackend
from .errors import AdapterError, BackendFailure, UnsupportedRequest
from .jsonio import (
    MAX_FRAME_BYTES,
    MAX_LIST_ITEMS,
    MAX_MESSAGE_COUNT,
    MAX_NESTING_DEPTH,
    canonical_bytes,
    read_frame,
    write_frame,
)
from .model import ExecuteRequest, exact_object, require_integer, sorted_unique_strings

HANDSHAKE_SCHEMAS = frozenset(
    {"adapter-handshake-offer.v1", "adapter-handshake-result.v1", "adapter-request.v1", "adapter-response.v1"}
)


def _limits() -> dict[str, int]:
    return {
        "maximum_frame_bytes": MAX_FRAME_BYTES,
        "maximum_list_items": MAX_LIST_ITEMS,
        "maximum_message_count": MAX_MESSAGE_COUNT,
        "maximum_nesting_depth": MAX_NESTING_DEPTH,
    }


class AdapterServer:
    def __init__(self, backend: AdapterBackend) -> None:
        self.backend = backend
        self._negotiated = False

    def _handshake(self, value: Any) -> dict[str, Any]:
        record = exact_object(
            value,
            {
                "correlation_id",
                "limits",
                "message_type",
                "offered_schema_versions",
                "optional_capabilities",
                "protocol",
                "required_capabilities",
                "schema_version",
            },
            "handshake offer",
        )
        correlation = record["correlation_id"]
        if not isinstance(correlation, str) or not correlation or len(correlation) > 128:
            raise AdapterError("handshake-correlation-invalid", "handshake correlation ID is invalid")
        if record["schema_version"] != "adapter-handshake-offer.v1" or record["message_type"] != "handshake-offer":
            raise AdapterError("handshake-version-invalid", "first frame must be a v1 handshake offer")
        protocol = exact_object(record["protocol"], {"major", "maximum_minor", "minimum_minor"}, "protocol offer")
        major = require_integer(protocol["major"], "protocol major", 0, 65535)
        minimum_minor = require_integer(protocol["minimum_minor"], "protocol minimum minor", 0, 65535)
        maximum_minor = require_integer(protocol["maximum_minor"], "protocol maximum minor", 0, 65535)
        if minimum_minor > maximum_minor:
            raise AdapterError("protocol-range-invalid", "offered protocol minor range is inverted")
        offered_schemas = sorted_unique_strings(record["offered_schema_versions"], "offered schema versions")
        required = sorted_unique_strings(record["required_capabilities"], "required capabilities")
        optional = sorted_unique_strings(record["optional_capabilities"], "optional capabilities")
        if set(required) & set(optional):
            raise AdapterError("capability-offer-ambiguous", "required and optional capabilities overlap")
        offered_limits = exact_object(
            record["limits"],
            {"maximum_frame_bytes", "maximum_list_items", "maximum_message_count", "maximum_nesting_depth"},
            "offered limits",
        )
        for name, maximum in _limits().items():
            require_integer(offered_limits[name], f"offered {name}", 1, maximum)
        failure: tuple[str, str] | None = None
        capabilities = set(self.backend.manifest.capabilities)
        if major != self.backend.manifest.protocol_major:
            failure = ("protocol-major-mismatch", "adapter and caller have no compatible protocol major")
        elif maximum_minor < self.backend.manifest.minimum_minor or minimum_minor > self.backend.manifest.maximum_minor:
            failure = ("protocol-minor-mismatch", "adapter and caller have no compatible protocol minor")
        elif not HANDSHAKE_SCHEMAS.issubset(offered_schemas):
            failure = ("schema-set-mismatch", "caller did not offer every required v1 message schema")
        elif not set(required).issubset(capabilities):
            failure = ("required-capability-unknown", "adapter does not implement every required capability")
        if failure is None:
            selected_capabilities = tuple(sorted(set(required) | (set(optional) & capabilities)))
            runtime = self.backend.runtime_identity()
            result: dict[str, Any] = {
                "adapter_release_manifest_id": self.backend.manifest.manifest_id,
                "canonical_authority": False,
                "capabilities": list(selected_capabilities),
                "correlation_id": correlation,
                "failure": None,
                "limits": {
                    name: min(offered_limits[name], maximum) for name, maximum in _limits().items()
                },
                "message_type": "handshake-result",
                "outcome": "accepted",
                "runtime_identity": {
                    **runtime.to_record(),
                    "profile_id": self.backend.manifest.profile_id,
                    "target_release_id": self.backend.manifest.target_release_id,
                },
                "schema_version": "adapter-handshake-result.v1",
                "selected_protocol": {"major": 1, "minor": 0},
                "semantic_authority": False,
                "transcript_sha256": "",
            }
            self._negotiated = True
        else:
            result = {
                "adapter_release_manifest_id": None,
                "canonical_authority": False,
                "capabilities": [],
                "correlation_id": correlation,
                "failure": {"code": failure[0], "message": failure[1]},
                "limits": _limits(),
                "message_type": "handshake-result",
                "outcome": "rejected",
                "runtime_identity": None,
                "schema_version": "adapter-handshake-result.v1",
                "selected_protocol": None,
                "semantic_authority": False,
                "transcript_sha256": "",
            }
        transcript = {"offer": record, "result": {key: member for key, member in result.items() if key != "transcript_sha256"}}
        result["transcript_sha256"] = hashlib.sha256(canonical_bytes(transcript)).hexdigest()
        return result

    def _failure_response(self, request: ExecuteRequest | None, error: AdapterError) -> dict[str, Any]:
        manifest = self.backend.manifest
        return {
            "adapter_release_manifest_id": manifest.manifest_id,
            "canonical_authority": False,
            "correlation_id": "invalid-request" if request is None else request.correlation_id,
            "failure": {
                "code": error.code,
                "diagnostic": None,
                "kind": error.kind,
                "layer": error.layer,
                "message": error.message[:1024],
            },
            "message_type": "execute-result",
            "observation": None,
            "profile_id": manifest.profile_id,
            "schema_version": "adapter-response.v1",
            "semantic_authority": False,
            "status": (
                "unsupported"
                if isinstance(error, UnsupportedRequest)
                else "failed"
                if isinstance(error, BackendFailure)
                else "rejected"
            ),
            "target_release_id": manifest.target_release_id,
            "trace_reference": None if request is None else request.trace_reference,
        }

    def execute(self, value: Any) -> dict[str, Any]:
        request: ExecuteRequest | None = None
        try:
            request = ExecuteRequest.from_record(value)
            observation = self.backend.execute(request)
            return {
                "adapter_release_manifest_id": self.backend.manifest.manifest_id,
                "canonical_authority": False,
                "correlation_id": request.correlation_id,
                "failure": None,
                "message_type": "execute-result",
                "observation": observation,
                "profile_id": self.backend.manifest.profile_id,
                "schema_version": "adapter-response.v1",
                "semantic_authority": False,
                "status": "completed",
                "target_release_id": self.backend.manifest.target_release_id,
                "trace_reference": request.trace_reference,
            }
        except AdapterError as error:
            return self._failure_response(request, error)
        except Exception as error:
            wrapped = BackendFailure(
                "adapter-unhandled-exception",
                f"adapter invocation failed with {type(error).__name__}",
                "invocation",
                "adapter-invocation",
            )
            return self._failure_response(request, wrapped)

    def serve(self, input_stream: BinaryIO, output_stream: BinaryIO) -> int:
        count = 0
        while True:
            frame = read_frame(input_stream)
            if frame is None:
                return 0 if self._negotiated else 2
            count += 1
            if count > MAX_MESSAGE_COUNT:
                raise AdapterError("message-count-exceeded", "session exceeds the negotiated message limit")
            if not self._negotiated:
                write_frame(output_stream, self._handshake(frame))
                if not self._negotiated:
                    return 2
                continue
            write_frame(output_stream, self.execute(frame))
