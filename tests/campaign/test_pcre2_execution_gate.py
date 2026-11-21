"""Offline tests for the exact PCRE2 execution gate and serial journal."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[2]
for source in ("campaigns/python", "matrix/python", "scheduler/python", "schemas/tooling/python"):
    sys.path.insert(0, str(ROOT / source))

from regex_conformance_scale.pcre2_execution_gate import Pcre2ExecutionGate, Pcre2ExecutionGateError
from regex_conformance_schema.execution_provenance import _u
from regex_conformance_schema.jsonio import canonical_bytes
from regex_conformance_schema.pcre2_production_adjudication import request_semantics


def digest(value):
    return sha256(canonical_bytes(value)).hexdigest()


class BoundedExecutionGateTests(unittest.TestCase):
    def setUp(self):
        self.campaign = "rcid:v1:campaign-manifest:h:jcs-sha256-v1:" + "1" * 64
        self.source = {"source_sha": "b" * 40, "envelope_sha": "a" * 40, "local_certification_root": "c" * 64}
        self.worker = {
            "trust_class": "trusted_executioner", "os": "Ubuntu 24.04", "architecture": "x86-64",
            "environment_fingerprint_id": "rcid:v1:environment-fingerprint:h:jcs-sha256-v1:" + "d" * 64,
            "environment_realization_id": _u("environment-realization", 1),
            "network_during_execution": False, "process_tree_containment": True,
            "maximum_target_processes": 1, "resource_admission_passed": True,
        }
        self.caps = {
            "logical_executions": 16, "physical_attempts": 16, "automatic_retries": 0, "automatic_repeats": 0,
            "concurrency": 1, "target_wall_time_total_ms": 16_000, "local_evidence_bytes": 16_777_216, "remote_writes": 0,
        }
        operation = {"name": "compile", "version": "1.0.0"}
        budget = {"wall_time_ms": 1000, "cpu_time_ms": 1000, "process_count": 1,
                  "memory_bytes": 268_435_456, "stdout_bytes": 65_536, "stderr_bytes": 4096}
        request = {"operation": operation, "limits": {"wall_time_ms": 1000}, "correlation_id": "preview"}
        self.rows = [
            {"logical_execution_id": f"logical-{index}", "vector_revision_id": f"vector-{index}",
             "campaign_manifest_id": self.campaign, "environment_fingerprint_id": self.worker["environment_fingerprint_id"],
             "operation": operation, "request_preview": request, "request_preview_sha256": digest(request),
             "request_semantic_sha256": digest(request_semantics(request)), "resource_budget": budget}
            for index in range(16)
        ]
        self.proposal = {
            "schema_version": "pcre2-production-campaign-proposal.v1", "classification": "offline-proposal-not-execution-authority",
            "execution_authorized": False, "production_credit": 0, "source_sha": self.source["source_sha"],
            "protected_envelope_sha": self.source["envelope_sha"], "local_certification_root": self.source["local_certification_root"],
            "execution_policy_revision_sha256": "e" * 64, "campaign_manifest_id": self.campaign,
            "worker": {"scope": {"environment_fingerprint_id": self.worker["environment_fingerprint_id"]}},
            "logical_assignments": self.rows, "execution_caps": self.caps,
        }

    def verified_gate(self, *, proposal=None, worker=None, verified_source=None, tamper_admission=False):
        proposal = self.proposal if proposal is None else proposal
        worker = self.worker if worker is None else worker
        proposal_digest = digest(proposal)
        expected = {
            "schema_version": "pcre2-production-execution-admission.v1",
            "classification": "trusted-execution-admission", "execution_authorized": True,
            "proposal_digest_sha256": proposal_digest, "campaign_manifest_id": self.campaign,
            "source": self.source, "worker_attestation_sha256": digest(self.worker),
            "environment_realization_id": self.worker["environment_realization_id"],
            "execution_lineage_version": "execution-lineage-set.v2", "execution_policy_revision_sha256": "e" * 64,
            "logical_execution_ids": [row["logical_execution_id"] for row in self.rows], "caps": self.caps,
        }
        admission_digest = digest(expected)
        if tamper_admission:
            expected["logical_execution_ids"] = expected["logical_execution_ids"][:-1]
            expected["execution_admission_sha256"] = digest(expected)
        else:
            expected["execution_admission_sha256"] = admission_digest
        return Pcre2ExecutionGate.verify(
            ROOT, canonical_bytes({**proposal, "proposal_digest_sha256": proposal_digest}) + b"\n",
            canonical_bytes(expected) + b"\n", expected_proposal=proposal_digest, expected_admission=admission_digest,
            verified_source=verified_source or self.source, verified_worker=worker,
        )

    def test_rehashed_substitutions_cannot_admit_an_assignment(self):
        mutations = (
            {"worker": {**self.worker, "network_during_execution": True}},
            {"verified_source": {**self.source, "source_sha": "9" * 40}},
            {"proposal": {**self.proposal, "logical_assignments": self.rows[:-1]}},
            {"proposal": {**self.proposal, "execution_caps": {**self.caps, "physical_attempts": 17}}},
            {"tamper_admission": True},
        )
        for kwargs in mutations:
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(Pcre2ExecutionGateError):
                self.verified_gate(**kwargs)

    def test_serial_reservation_and_closing_are_create_once(self):
        gate = self.verified_gate()
        with TemporaryDirectory() as temporary:
            journal = Path(temporary) / self.campaign.rsplit(":", 1)[1]
            journal.mkdir()
            with self.assertRaises(Pcre2ExecutionGateError):
                gate.reserve_next(ROOT, journal, 1)
            reservation, request = gate.reserve_next(ROOT, journal, 0)
            self.assertEqual(reservation["request_sha256"], digest(request))
            self.assertEqual(digest(request_semantics(request)), self.rows[0]["request_semantic_sha256"])
            with self.assertRaises(Pcre2ExecutionGateError):
                gate.reserve_next(ROOT, journal, 0)
            capture = {
                "reservation_sha256": digest(reservation), "physical_run_id": reservation["physical_run_id"],
                "disposition": "inconclusive-attempt",
            }
            with self.assertRaises(Pcre2ExecutionGateError):
                gate.close(journal, 0, {**capture, "physical_run_id": "wrong"})
            gate.close(journal, 0, capture)
            with self.assertRaises(Pcre2ExecutionGateError):
                gate.close(journal, 0, deepcopy(capture))
            second, _ = gate.reserve_next(ROOT, journal, 1)
            self.assertNotEqual(reservation["physical_run_id"], second["physical_run_id"])
