"""Protocol-complete response fixtures for evidence publication tests."""

from __future__ import annotations

from typing import Any


def completed_response(logical: dict[str, Any]) -> dict[str, Any]:
    request = logical["request"]
    pattern_domain = request["pattern"]["domain"]
    basis = "octet" if pattern_domain == "octets" else "unicode-scalar"
    encoding = None if pattern_domain == "octets" else "unicode-scalar-values"
    width = 8 if pattern_domain == "octets" else None
    span = {
        "api_provenance": "evidence qualification fixture",
        "base_origin": 0,
        "basis": basis,
        "encoding": encoding,
        "end": 0,
        "endianness": None,
        "interval": "half-open",
        "origin_subject": 0,
        "sentinel": "none",
        "start": 0,
        "unit_width_bits": width,
    }
    return {
        "adapter_release_manifest_id": request["adapter_release_manifest_id"],
        "canonical_authority": False,
        "correlation_id": logical["logical_execution_id"],
        "failure": None,
        "message_type": "execute-result",
        "observation": {
            "absences": [],
            "compile_status": "accepted",
            "cursor": None,
            "execution_status": "completed",
            "materialization": {
                "pattern_domain": pattern_domain,
                "subject_domains": [item["domain"] for item in request["subjects"]],
            },
            "match_state": "match",
            "matches": [{"captures": [], "ordinal": 0, "span": span}],
            "native_error": None,
            "operation": request["operation"],
            "outputs": {"kind": "none", "values": []},
            "runtime_identity": {
                "facts": [{"name": "fixture", "value": "evidence-qualification-v1"}]
            },
        },
        "profile_id": request["profile_id"],
        "schema_version": "adapter-response.v1",
        "semantic_authority": False,
        "status": "completed",
        "target_release_id": request["target_release_id"],
        "trace_reference": request["trace_reference"],
    }
