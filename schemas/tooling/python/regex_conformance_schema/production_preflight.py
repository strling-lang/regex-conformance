"""Project verified campaign candidates into offline adapter requests."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from hashlib import sha256
from pathlib import Path

from .errors import fail
from .jsonio import canonical_bytes, load_strict
from .production_campaign_design import build_production_campaign_design
from .production_vectors import VectorCompilerInputs
from .schema import validate_instance


REQUEST_SCHEMA = Path("schemas/json/adapter-request.schema.json")
PCRE2_BOOLEAN_OPTIONS = {"caseless", "dotall", "extended", "multiline", "ucp", "ungreedy", "utf"}
DEFAULT_STATE = {"occurrence": 1, "start_offset": 0}


def _octets(value: bytes) -> dict:
    return {
        "data": urlsafe_b64encode(value).decode("ascii").rstrip("="),
        "domain": "octets",
        "encoding": None,
        "endianness": None,
        "unit_width_bits": 8,
    }


def _project_request(vector: dict, operation: str, design: dict, schema: dict) -> dict:
    identifier = vector["vector_revision_id"]
    stimulus = vector["stimulus"]
    subjects = stimulus["subjects"]
    if len(subjects) != (0 if operation == "compile" else 1):
        fail("production-transport-subjects", "compile requires zero semantic subjects; matching requires one", identifier)
    if stimulus["replacement"] is not None or stimulus["callback_fixture"] is not None:
        fail("production-transport-input", "this adapter projection has no replacement or callback mapping", identifier)
    state = stimulus["initial_state"] or DEFAULT_STATE
    if state != DEFAULT_STATE or any(type(value) is not int for value in state.values()):
        fail("production-transport-state", "this proposed campaign only maps the adapter's neutral initial state", identifier)
    options = stimulus["options"]
    if any(item["name"] not in PCRE2_BOOLEAN_OPTIONS or type(item["value"]) is not bool for item in options):
        fail("production-transport-option", "option lacks an exact PCRE2 boolean mapping", identifier)
    data = [stimulus["pattern"], *subjects]
    if stimulus["domain"] not in {"octets", "unicode-scalars"}:
        fail("production-transport-encoding", "this projection only accepts octets and Unicode scalars", identifier)
    pattern = bytes.fromhex(stimulus["pattern"]["hex"])
    utf_enabled = pattern.startswith(b"(*UTF)") or {"name": "utf", "value": True} in options
    if any(item["encoding"] == "utf-8" for item in data) and not utf_enabled:
        fail("production-transport-encoding", "Unicode scalar stimuli require explicit PCRE2 UTF mode", identifier)
    request = {
        "schema_version": "adapter-request.v1",
        "message_type": "execute",
        "correlation_id": f"candidate-{identifier.rsplit(':', 1)[-1]}",
        "trace_reference": identifier,
        "adapter_release_manifest_id": design["proposed_adapter_manifest_id"],
        "profile_id": design["proposed_profile_id"],
        "target_release_id": design["proposed_release_id"],
        "operation": {"name": operation, "version": "1.0.0"},
        "pattern": _octets(pattern),
        # The protocol requires a slot. PCRE2's compile path returns before reading the slot.
        "subjects": [_octets(bytes.fromhex(item["hex"])) for item in subjects] or [_octets(b"")],
        "replacement": None,
        "callback_fixture": None,
        "options": options,
        "environment_inputs": [],
        "initial_state": state,
        "requested_observations": stimulus["requested_observations"],
        "limits": stimulus["deterministic_limits"],
    }
    validate_instance(request, schema, source=identifier)
    return request


def build_production_preflight(
    root: Path, inputs: VectorCompilerInputs, manifest: dict, families: list[dict], *, expected_manifest_digest: str,
) -> dict:
    """Bind transport previews and denominator accounting without realizing a runtime."""
    design = build_production_campaign_design(
        root, inputs, manifest, families, expected_manifest_digest=expected_manifest_digest,
    )
    by_id = {row["vector_revision_id"]: row for row in manifest["vectors"]}
    schema = load_strict(root / REQUEST_SCHEMA)
    selected = [
        {
            "vector_revision_id": identifier,
            "semantic_requirement_id": binding["requirement_id"],
            "subject_slot": "compile-placeholder" if binding["adapter_operation"] == "compile" else "semantic-subject",
            "request_preview": _project_request(by_id[identifier], binding["adapter_operation"], design, schema),
        }
        for binding in design["candidate_bindings"] for identifier in binding["vector_revision_ids"]
    ]
    if len(selected) != design["candidate_selection_count"]:
        fail("production-transport-duplicates", "a vector revision would produce duplicate requests")
    readiness = [
        {
            **row,
            "required_oracle_capability": inputs.requirements[row["requirement_id"]]["expected_oracle_capability"],
            "oracle_binding_status": "candidate-premise-only" if row["vector_revision_ids"] else "no-candidate",
            "applicability_status": "production-profile-facts-unavailable",
            "execution_eligible": False,
            "official_observation_state": "unobserved",
            "c4_credit_from_preflight": False,
        }
        for row in manifest["requirement_coverage"]
    ]
    body = {
        "schema_version": "first-production-campaign-preflight.v1",
        "classification": "offline-request-previews",
        "execution_ready": False,
        "production_execution_denominator": None,
        "candidate_manifest_sha256": expected_manifest_digest,
        "design_digest_sha256": design["design_digest_sha256"],
        "adapter_request_schema_sha256": sha256(canonical_bytes(schema)).hexdigest(),
        "obligation_snapshot": inputs.obligation_snapshot,
        "requirement_snapshot": inputs.requirement_snapshot,
        "requirements": readiness,
        "request_previews": sorted(selected, key=lambda item: item["vector_revision_id"]),
        "single_attempt_limit_sums": {
            key: sum(item["request_preview"]["limits"][key] for item in selected)
            for key in ("maximum_diagnostic_bytes", "maximum_matches", "maximum_output_bytes", "wall_time_ms")
        },
        "outstanding_inputs": design["outstanding_inputs"],
    }
    return {**body, "preflight_digest_sha256": sha256(canonical_bytes(body)).hexdigest()}
