"""Build and check the bounded PCRE2 capability qualification scope."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from pathlib import Path

from .errors import fail
from .jsonio import load_strict
from .production_campaign_design import ADAPTER_PATH, RECIPE_PATH
from .production_oracle import digest
from .schema import validate_instance
from .scientific_identity import CATALOG_PATH


SIGNER = "A95536204A3BB489715231282A98E77EB6F24CA8"
SELECTION = "pcre2-ordinary"
CASES = (
    ("reference-equal", "full-match", rb"(q)\1", b"qq", "match_state", "match"),
    ("reference-unequal", "full-match", rb"(q)\1", b"qr", "match_state", "no-match"),
    ("reference-present", "compile", rb"(q)\1", b"", "compile_status", "accepted"),
    ("reference-absent", "compile", rb"(q)\2", b"", "compile_status", "rejected"),
    ("escape-octal", "full-match", rb"\11", b"\t", "match_state", "match"),
    ("escape-backreference", "full-match", b"()" * 10 + rb"(q)\11", b"qq", "match_state", "match"),
    ("escape-not-octal-above-threshold", "full-match", b"()" * 10 + rb"(q)\11", b"q\t", "match_state", "no-match"),
    ("local-restriction-exits-group", "full-match", b"(*UTF)(?i)(?r:K)K", "K\N{KELVIN SIGN}".encode(), "match_state", "match"),
    ("local-restriction-inside-group", "full-match", b"(*UTF)(?i)(?r:K)K", "\N{KELVIN SIGN}K".encode(), "match_state", "no-match"),
    ("restricted-fold-ascii", "full-match", b"(*UTF)(?ir)s", b"S", "match_state", "match"),
    ("restricted-fold-cross-domain", "full-match", b"(*UTF)(?ir)s", "\N{LATIN SMALL LETTER LONG S}".encode(), "match_state", "no-match"),
)
REFERENCES = ["reference-equal", "reference-unequal"]
INVALID = ["reference-present", "reference-absent"]
LOCAL = ["local-restriction-exits-group", "local-restriction-inside-group"]
FOLD = ["restricted-fold-ascii", "restricted-fold-cross-domain"]
ASSERTIONS = {
    "feature.numbered-backreference": REFERENCES,
    "manifestation.numbered-backreference.pcre2-pattern": REFERENCES,
    "feature.invalid-group-reference": INVALID,
    "manifestation.invalid-group-reference.pcre2-api": INVALID,
    "feature.numeric-escape-disambiguation": ["escape-octal", "escape-backreference", "escape-not-octal-above-threshold"],
    "feature.inline-modifier-directive": LOCAL,
    "feature.simple-case-folding": FOLD,
    "modifier.caseless-restrict": LOCAL + FOLD,
}
FIELDS = {
    "feature": "profile.feature_scientific_ids",
    "manifestation": "profile.manifestation_scientific_ids",
    "modifier": "profile.modifier_scientific_ids",
}


def _octets(data: bytes) -> dict:
    return {
        "data": urlsafe_b64encode(data).decode("ascii").rstrip("="),
        "domain": "octets", "encoding": None, "endianness": None, "unit_width_bits": 8,
    }


def build_plan(root: Path) -> dict:
    recipe = load_strict(root / RECIPE_PATH)
    adapter = load_strict(root / ADAPTER_PATH)
    profile_id = recipe["target_profile_id"]
    release_id = recipe["target_release_id"]
    if (
        recipe["selection_key"] != SELECTION or recipe["strategy"] != "native-source-build"
        or adapter["identity"]["profile"] != profile_id
        or adapter["identity"]["target_release"] != release_id
    ):
        fail("pcre2-qualification-coordinate", "recipe and adapter do not bind the same ordinary PCRE2 profile")
    policy = load_strict(root / "schemas/json/adapter-request.schema.json")
    catalog = load_strict(root / CATALOG_PATH)
    identities = {row["canonical_key"]: row["scientific_id"] for row in catalog["bindings"] if row["status"] == "active"}
    assertions = [
        {"field": FIELDS[key.split(".")[0]], "scientific_id": identities[key], "catalog_key": key, "probes": probes}
        for key, probes in sorted(ASSERTIONS.items())
    ]
    cases = []
    for key, op, pattern, subject, field, value in CASES:
        declared = {"compile_status": "rejected"} if value == "rejected" else {field: value}
        request = {
            "schema_version": "adapter-request.v1", "message_type": "execute", "correlation_id": key,
            "trace_reference": f"pcre2-capability-qualification:{key}",
            "adapter_release_manifest_id": adapter["adapter_release_manifest_id"], "profile_id": profile_id,
            "target_release_id": release_id, "operation": {"name": op, "version": "1.0.0"},
            "pattern": _octets(pattern), "subjects": [_octets(subject)], "replacement": None, "callback_fixture": None,
            "options": [], "environment_inputs": [], "initial_state": {"occurrence": 1, "start_offset": 0},
            "requested_observations": ["compile-diagnostics", "native-errors"] if op == "compile" else ["match-state"],
            "limits": {"maximum_diagnostic_bytes": 4096, "maximum_matches": 1, "maximum_output_bytes": 4096, "wall_time_ms": 1000},
        }
        validate_instance(request, policy, source=key)
        cases.append({"request": request, "qualification_expectation": declared})
    body = {
        "schema_version": "pcre2-bounded-capability-plan.v1",
        "classification": "qualification-only", "selection_key": SELECTION,
        "profile_id": profile_id, "target_release_id": release_id,
        "recipe_revision_id": recipe["recipe_revision_id"],
        "adapter_manifest_id": adapter["adapter_release_manifest_id"],
        "adapter_source_sha256": adapter["identity"]["source_digest"],
        "platform": recipe["construction"]["platform"],
        "resource_limits": recipe["isolation_policy"]["resource_limits"],
        "source_artifacts": recipe["artifacts"], "publisher_fingerprint": SIGNER,
        "environment_smoke_probe_ids": recipe["smoke_probe_ids"],
        "operations": ["compile", "full-match", "search"],
        "source_document": {
            "url": "https://github.com/PCRE2Project/pcre2/blob/f454e231fe5006dd7ff8f4693fd2b8eb94333429/doc/pcre2pattern.3",
            "sha256": "46ce364a99ffe363930c64bef9668074da4ac801debd39f0d927523e7dbebff0",
        },
        "probes": cases, "capability_assertions": assertions, "maximum_environment_realizations": 1,
        "production_logical_executions": 0,
    }
    return {**body, "plan_digest_sha256": digest(body)}


def verify_responses(root: Path, plan: dict, responses: list[dict], runtime_facts: list[dict]) -> list[dict]:
    """Validate exact qualification responses and leave failed capabilities unresolved."""
    if plan != build_plan(root):
        fail("pcre2-qualification-plan", "qualification plan differs from exact reconstruction")
    response_schema = load_strict(root / "schemas/json/adapter-response.schema.json")
    by_key = {}
    requests = {row["request"]["correlation_id"]: row["request"] for row in plan["probes"]}
    for response in responses:
        validate_instance(response, response_schema, source="capability response")
        key = response["correlation_id"]
        if key in by_key:
            fail("pcre2-qualification-response-duplicate", "duplicate response", key)
        if key not in requests:
            fail("pcre2-qualification-population", "unexpected probe key", key)
        request = requests[key]
        observation = response["observation"]
        if (
            response["profile_id"] != plan["profile_id"] or response["target_release_id"] != plan["target_release_id"]
            or response["adapter_release_manifest_id"] != plan["adapter_manifest_id"]
            or response["trace_reference"] != request["trace_reference"]
            or (observation is not None and (
                observation["operation"] != request["operation"]
                or observation["runtime_identity"]["facts"] != runtime_facts
                or observation["materialization"] != {"pattern_domain": "octets", "subject_domains": ["octets"]}
            ))
        ):
            fail("pcre2-qualification-scope", "response identity differs from the scoped adapter or runtime", key)
        by_key[key] = response
    expected = {row["request"]["correlation_id"]: row["qualification_expectation"] for row in plan["probes"]}
    if by_key.keys() != expected.keys():
        fail("pcre2-qualification-population", "received probe keys do not match the whole bounded plan")
    verified = set()
    for key, outcome in expected.items():
        response = by_key[key]
        observation = response["observation"]
        error = None if observation is None else observation["native_error"]
        if (
            response["status"] == "completed" and observation is not None
            and all(observation[field] == value for field, value in outcome.items())
            and (
                (error is not None and error["phase"] == "compile" and error["code"] == 115)
                if outcome == {"compile_status": "rejected"} else error is None
            )
        ):
            verified.add(key)
    return [
        {
            **assertion,
            "state": "verified-in-qualification" if set(assertion["probes"]) <= verified else "unresolved",
            "response_sha256": {key: digest(by_key[key]) for key in assertion["probes"]},
        }
        for assertion in plan["capability_assertions"]
    ]
