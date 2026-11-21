"""Adversarial synthetic lineage tests. These fixtures carry no empirical authority."""

from base64 import b64encode
from copy import deepcopy
import sys
import unittest

from support import ROOT
from regex_conformance_schema import execution_provenance as legacy
from regex_conformance_schema import execution_provenance_v3 as successor
from regex_conformance_schema.errors import ConformanceDataError
from regex_conformance_schema.jsonio import canonical_bytes, load_strict
from regex_conformance_schema.pcre2_production_adjudication import (
    compare_production_lineage, production_trace_reference, request_semantics,
)
from regex_conformance_schema.production_oracle import digest

for source in ("campaigns", "matrix", "scheduler"):
    sys.path.insert(0, str(ROOT / source / "python"))
import regex_conformance_scale.evidence_pack_v3 as pack_v3


def frame(message, *, truncate=False):
    payload = canonical_bytes(message)
    return b64encode(len(payload).to_bytes(4, "big") + (payload[:-1] if truncate else payload)).decode()


class NativeExecutionLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = successor.successor_policy(ROOT)
        cls.historical = load_strict(ROOT / legacy.FIXTURE_PATH)

    def native_fixture(self, *, rejected=False, match=False):
        operation = {"name": "full-match" if match else "compile", "version": "1.0.0"}
        native_error = {"class": "compile-error", "code": 115, "diagnostic": None,
                        "message": "synthetic native rejection", "phase": "compile", "position": 1} if rejected else None
        observed = {
            "operation": operation, "compile_status": "rejected" if rejected else "accepted",
            "execution_status": "completed" if match else "not-requested",
            "match_state": "no-match" if match else "not-applicable", "native_error": native_error,
            "absences": [], "cursor": None, "matches": [],
            "materialization": {"pattern_domain": "octets", "subject_domains": ["octets"]},
            "outputs": {"kind": "none", "values": []},
            "runtime_identity": {"facts": [{"name": "engine-version", "value": "10.47"}]},
        }
        outcome = "no-match" if match else ("compile-rejection" if rejected else "compile-acceptance")
        attempt = legacy._attempt(self.policy["policy_revision_sha256"], 1, 1, 1, outcome="no-match",
                                  terminal=True, semantic_result=observed)
        attempt["schema_version"] = successor.ATTEMPT_VERSION
        terminality = attempt["terminality"]
        terminality["outcome_class"] = outcome
        terminality["scientific_result_signature"] = legacy.result_signature(outcome, observed)
        common = {
            "adapter_release_manifest_id": attempt["execution_context"]["adapter_release_manifest_id"],
            "correlation_id": attempt["physical_run_id"].rsplit(":", 1)[1],
            "trace_reference": production_trace_reference(attempt["physical_run_id"]),
            "profile_id": legacy._u("profile", 1), "target_release_id": legacy._u("release", 1),
        }
        datum = {"data": "YQ", "domain": "octets", "encoding": None, "endianness": None, "unit_width_bits": 8}
        request = {
            **common, "schema_version": "adapter-request.v1", "message_type": "execute", "callback_fixture": None,
            "environment_inputs": [], "initial_state": {"occurrence": 1, "start_offset": 0},
            "limits": {"maximum_diagnostic_bytes": 4096, "maximum_matches": 4,
                       "maximum_output_bytes": 4096, "wall_time_ms": 1000},
            "operation": operation, "options": [], "pattern": datum, "replacement": None,
            "requested_observations": ["compile-diagnostics"], "subjects": [datum],
        }
        response = {**common, "schema_version": "adapter-response.v1", "message_type": "execute-result",
                    "status": "completed", "failure": None, "canonical_authority": False,
                    "semantic_authority": False, "observation": observed}
        return attempt, request, response

    def seal(self, attempt, request, response, *, truncate=False):
        receipt = self.receipt(attempt, request, response, truncate=truncate)
        record = self.make_set([attempt])
        return record, {attempt["physical_run_id"]: receipt}

    def receipt(self, attempt, request, response, *, truncate=False):
        terminality = attempt["terminality"]
        terminality["scientific_result_signature"] = legacy.result_signature(
            terminality["outcome_class"], terminality["semantic_result"],
        )
        receipt = {
            "schema_version": successor.NATIVE_EVIDENCE_VERSION,
            "attempt_binding_sha256": successor.receipt_binding(attempt), "request_frame": frame(request),
            "response_frame": frame(response, truncate=truncate),
        }
        attempt["native_evidence_sha256"] = digest(receipt)
        attempt["terminality"]["fault_attribution"]["evidence_reference"] = {
            **legacy._reference("native-receipt", 1), "sha256": digest(receipt),
        }
        return receipt

    def make_set(self, attempts):
        lineage = legacy._lineage(ROOT, attempts)
        for obs in lineage["observations"]:
            obs["schema_version"] = successor.OBSERVATION_VERSION
            obs["observation_content_id"] = successor.observation_content_id(ROOT, obs)
        record = {**self.historical, "schema_version": successor.LINEAGE_VERSION,
                  "execution_policy_revision_sha256": self.policy["policy_revision_sha256"], "lineages": [lineage]}
        disp = lineage["disposition"]
        record["counts"] = {
            "logical_execution_count": 1, "physical_attempt_count": len(attempts),
            "terminal_observation_count": len(lineage["observations"]), **{
                key: disp[key] for key in ("inconclusive_attempt_count", "recovered_attempt_count",
                                         "repeat_measurement_attempt_count", "retry_attempt_count", "terminal_attempt_count")
            },
        }
        record["lineage_set_sha256"] = successor.lineage_set_sha256(record)
        return record

    def test_native_acceptance_rejection_and_matching_have_distinct_identities(self):
        accepted, rejected, no_match = (
            self.seal(*self.native_fixture(**variant)) for variant in ({}, {"rejected": True}, {"match": True})
        )
        observations = []
        for record, receipts in (accepted, rejected, no_match):
            self.assertEqual(successor.validate_lineage_set(ROOT, record, native_evidence=receipts)["terminal_observation_count"], 1)
            observations.append(record["lineages"][0]["observations"][0])
        self.assertEqual([row["outcome_class"] for row in observations], ["compile-acceptance", "compile-rejection", "no-match"])
        self.assertEqual(len({row["observation_content_id"] for row in observations}), 3)
        self.assertNotEqual(successor.observation_content_id(ROOT, observations[0]), legacy.observation_content_id(ROOT, observations[0]))

    def test_rehashed_false_native_receipts_and_forged_outcome_are_rejected(self):
        for mutation in ("truncated", "not-started", "bad-checkpoint", "invalid-protocol", "wrong-operation",
                         "wrong-correlator", "wrong-adapter", "missing-receipt", "forged-match", "response-inconsistent"):
            with self.subTest(mutation=mutation), self.assertRaises(ConformanceDataError):
                attempt, req, res = self.native_fixture()
                terminal = attempt["terminality"]
                if mutation == "not-started":
                    terminal["target_process_status"]["target_started"] = False
                elif mutation == "bad-checkpoint":
                    terminal["protocol_status"]["last_checkpoint"] = "target-invocation-started"
                elif mutation == "invalid-protocol":
                    terminal["protocol_valid"] = False
                elif mutation == "wrong-operation":
                    req["operation"] = {"name": "search", "version": "1.0.0"}
                elif mutation == "wrong-correlator":
                    res["correlation_id"] = "wrong-correlation"
                elif mutation == "wrong-adapter":
                    res["adapter_release_manifest_id"] = legacy._h("adapter-release-manifest", 99)
                elif mutation == "forged-match":
                    terminal["outcome_class"] = "match"
                    terminal["scientific_result_signature"] = legacy.result_signature("match", terminal["semantic_result"])
                elif mutation == "response-inconsistent":
                    res["observation"] = {**res["observation"], "match_state": "match"}
                record, receipts = self.seal(attempt, req, res, truncate=mutation == "truncated")
                successor.validate_lineage_set(ROOT, record, native_evidence={} if mutation == "missing-receipt" else receipts)

    def test_invariants_and_version_routing_survive_rehash(self):
        record, receipts = self.seal(*self.native_fixture())
        for mutation in ("duplicate", "prefix", "stale-identity", "stale-signature", "ordinal", "observation-count", "policy", "historical-route"):
            changed = deepcopy(record)
            entry = changed["lineages"][0]
            obs = entry["observations"][0]
            if mutation == "duplicate":
                entry["observations"].append(deepcopy(obs))
            elif mutation == "prefix":
                obs["attempt_set_reference"]["attempts_total"] = 2
                obs["observation_content_id"] = successor.observation_content_id(ROOT, obs)
            elif mutation == "stale-identity":
                obs["observation_content_id"] = legacy._h("observation-content", 999)
            elif mutation == "stale-signature":
                entry["attempts"][0]["terminality"]["scientific_result_signature"]["sha256"] = "b" * 64
            elif mutation == "ordinal":
                entry["attempts"][0]["attempt_ordinal"] = 2
            elif mutation == "observation-count":
                changed["counts"]["terminal_observation_count"] = 2
            elif mutation == "policy":
                changed["execution_policy_revision_sha256"] = self.historical["execution_policy_revision_sha256"]
            else:
                changed["schema_version"] = "execution-lineage-set.v1"
            changed["lineage_set_sha256"] = successor.lineage_set_sha256(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ConformanceDataError):
                successor.validate_lineage_set(ROOT, changed, native_evidence=receipts)
        self.assertEqual(successor.validate_lineage_set(ROOT, self.historical),
                         legacy.validate_lineage_set(ROOT, self.historical))
        with self.assertRaises(ConformanceDataError):
            successor.validate_lineage_set(ROOT, record)

    def test_compact_v3_round_trips_successor_receipts_and_detects_corruption(self):
        lineage, receipts = self.seal(*self.native_fixture())
        blocks = [
            pack_v3.RetainedBlock("physical_attempt_facts", "execution-lineage-set-v2", 0, lineage),
            pack_v3.RetainedBlock("diagnostics", "native-execution-evidence-v1", 0, receipts),
        ]
        def build(values):
            return pack_v3.build_evidence_pack(
                values, campaign_manifest_sha256="f" * 64,
                counts={"logical_executions": 1, "observations": 1, "physical_attempts": 1},
                canonical_input_derivation="synthetic-native-lineage-test",
            )
        pack = build(blocks)
        self.assertEqual(pack, build(reversed(blocks)))
        decoded = {block.role: block.value for block in pack_v3.decode_evidence_pack(pack.manifest, pack.objects)}
        self.assertEqual(decoded, {block.role: block.value for block in blocks})
        successor.validate_lineage_set(ROOT, decoded["execution-lineage-set-v2"], native_evidence=decoded["native-execution-evidence-v1"])
        objects = dict(pack.objects)
        key = next(iter(objects))
        objects[key] = objects[key][:-1]
        with self.assertRaises(pack_v3.EvidencePackV3Error):
            pack_v3.decode_evidence_pack(pack.manifest, objects)

    def test_repeats_retain_conflicts_and_never_supply_a_new_logical_completion(self):
        first, accept_request, accept_response = self.native_fixture()
        _, reject_request, reject_response = self.native_fixture(rejected=True)
        second = legacy._attempt(
            self.policy["policy_revision_sha256"], 1, 2, 2,
            outcome="compile-rejection", terminal=True, semantic_result=reject_response["observation"],
            purpose="qualification-repeat", predecessor=first["physical_run_id"],
            repeat_reason="qualification-repeat", predecessor_observation=first["terminality"]["produced_observation_id"],
        )
        second["schema_version"] = successor.ATTEMPT_VERSION
        for frame_body in (reject_request, reject_response):
            frame_body["correlation_id"] = second["physical_run_id"].rsplit(":", 1)[1]
            frame_body["trace_reference"] = production_trace_reference(second["physical_run_id"])
        first_receipt = self.receipt(first, accept_request, accept_response)
        for authorization in ("qualification-specific", "automatic"):
            repeat = deepcopy(second)
            repeat["repeat"]["authorization_kind"] = authorization
            receipts = {first["physical_run_id"]: first_receipt,
                        repeat["physical_run_id"]: self.receipt(repeat, reject_request, reject_response)}
            result = self.make_set([first, repeat])
            if authorization == "automatic":
                with self.assertRaises(ConformanceDataError):
                    successor.validate_lineage_set(ROOT, result, native_evidence=receipts)
            else:
                counts = successor.validate_lineage_set(ROOT, result, native_evidence=receipts)
                self.assertEqual((counts["logical_execution_count"], counts["terminal_observation_count"]), (1, 2))
                disposition = result["lineages"][0]["disposition"]
                self.assertEqual(disposition["distinct_terminal_result_signature_count"], 2)
                self.assertEqual(disposition["satisfaction_attempt_id"], first["physical_run_id"])

    def test_successor_comparison_requires_exact_production_envelope_and_request(self):
        attempt, request, response = self.native_fixture()
        facts = {"engine-version": "10.47", "library-sha256": "c" * 64, "runtime-kind": "pcre2"}
        response["observation"]["runtime_identity"]["facts"] = [{"name": k, "value": v} for k, v in facts.items()]
        for mutation in (None, "qualification", "stimulus", "environment", "profile", "release", "vector", "applicability", "campaign"):
            physical, req, res = deepcopy((attempt, request, response))
            context = deepcopy(physical["execution_context"])
            vector = context["vector_revision_id"]
            row = {
                "coordinate": {"vector_revision_id": vector}, "applicability_state": "applicable",
                "request_preview_sha256": digest(request), "observation_field": "compile_status",
                "oracle_binding_id": "synthetic", "oracle_class": "O6",
                "comparison": {"kind": "equals", "expected": "accepted"},
            }
            plan = {"schema_version": "pcre2-production-comparison-plan.v2",
                    "profile_revision_id": context["profile_revision_id"],
                    "environment_fingerprint_id": context["environment_fingerprint_id"],
                    "adapter_manifest_id": context["adapter_release_manifest_id"], "runtime_facts": facts,
                    "execution_policy_revision_sha256": self.policy["policy_revision_sha256"], "comparisons": [row]}
            plan["plan_digest_sha256"] = digest(plan)
            assignment = {**context, "logical_execution_id": physical["logical_execution_id"],
                          "request_preview_sha256": digest(request), "request_semantic_sha256": digest(request_semantics(request)),
                          "resource_budget": physical["resource_budget"]}
            proposal = {"comparison_plan_digest_sha256": plan["plan_digest_sha256"], "campaign_manifest_id": context["campaign_manifest_id"],
                        "logical_assignments": [assignment], "execution_caps": {"physical_attempts": 1, "automatic_retries": 0, "automatic_repeats": 0}}
            proposal["proposal_digest_sha256"] = digest(proposal)
            if mutation == "qualification":
                req["trace_reference"] = res["trace_reference"] = "pcre2-capability-qualification:synthetic"
            elif mutation == "stimulus":
                req["pattern"]["data"] = "Yg"
            elif mutation:
                key = {"environment": "environment_realization_id", "profile": "profile_revision_id",
                       "release": "target_release_revision_id", "vector": "vector_revision_id",
                       "applicability": "applicability_coordinate_id", "campaign": "campaign_manifest_id"}[mutation]
                old = physical["execution_context"][key]
                physical["execution_context"][key] = old[:-1] + ("a" if old[-1] != "a" else "b")
            record, receipts = self.seal(physical, req, res)
            admission = {
                "schema_version": "pcre2-production-evidence-admission.v2",
                "classification": "authorized-production-evidence-admission",
                "proposal_digest_sha256": proposal["proposal_digest_sha256"],
                "comparison_plan_digest_sha256": plan["plan_digest_sha256"],
                "campaign_manifest_id": context["campaign_manifest_id"], "lineage_set_sha256": record["lineage_set_sha256"],
                "logical_assignments": proposal["logical_assignments"], "native_evidence_set_sha256": digest(receipts),
                "environment_realization_id": context["environment_realization_id"],
                "admitted_observation_content_ids": [record["lineages"][0]["observations"][0]["observation_content_id"]],
            }
            admission["admission_digest_sha256"] = digest(admission)
            pins = {"expected_plan_digest": plan["plan_digest_sha256"], "expected_admission_digest": admission["admission_digest_sha256"],
                    "expected_proposal_digest": proposal["proposal_digest_sha256"]}
            if mutation:
                with self.subTest(mutation=mutation), self.assertRaises(ConformanceDataError):
                    compare_production_lineage(ROOT, plan, record, admission, proposal=proposal, native_evidence=receipts, **pins)
            else:
                trace = compare_production_lineage(ROOT, plan, record, admission, proposal=proposal, native_evidence=receipts, **pins)
                self.assertEqual(trace["rows"][0]["state"], "agreement")
                self.assertEqual((trace["issued_claims"], trace["production_credit"]), (0, 0))
