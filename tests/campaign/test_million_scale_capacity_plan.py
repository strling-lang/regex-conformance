from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import unittest

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
for source in (
    ROOT / "campaigns" / "python",
    ROOT / "matrix" / "python",
    ROOT / "scheduler" / "python",
    ROOT / "schemas" / "tooling" / "python",
):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_scale.capacity_plan import (
    MillionScaleCapacityPlanError,
    build_million_scale_capacity_plan,
    verify_million_scale_capacity_plan,
)
from regex_conformance_schema.jsonio import canonical_bytes, load_strict


SCHEMA = ROOT / "schemas/json/million-scale-capacity-plan.schema.json"
REPORT = ROOT / "reports/scale/million-scale-capacity-plan.json"


class MillionScaleCapacityPlanTests(unittest.TestCase):
    def test_report_is_deterministic_schema_valid_and_matches_tracked(self) -> None:
        first = build_million_scale_capacity_plan(ROOT)
        second = build_million_scale_capacity_plan(ROOT)
        self.assertEqual(first, second)
        Draft202012Validator(
            load_strict(SCHEMA), format_checker=FormatChecker()
        ).validate(first)
        self.assertEqual(canonical_bytes(load_strict(REPORT)), canonical_bytes(first))
        verify_million_scale_capacity_plan(ROOT, first)

        digest_input = deepcopy(first)
        claimed = digest_input.pop("plan_digest_sha256")
        self.assertEqual(hashlib.sha256(rfc8785.dumps(digest_input)).hexdigest(), claimed)

    def test_source_bindings_and_measured_scale_arithmetic_are_exact(self) -> None:
        report = build_million_scale_capacity_plan(ROOT)
        for binding in report["source_bindings"]:
            self.assertEqual(
                hashlib.sha256((ROOT / binding["path"]).read_bytes()).hexdigest(),
                binding["sha256"],
            )

        workload = report["workload_plan"]
        self.assertEqual(
            sum(item["logical_execution_count"] for item in workload["profiles"]),
            1_000_000,
        )
        self.assertEqual(
            sum(item["result_shard_count"] for item in workload["profiles"]),
            4_003,
        )
        for item in workload["profiles"]:
            self.assertEqual(
                item["result_shard_count"],
                (item["logical_execution_count"] + 249) // 250,
            )
        self.assertEqual(
            report["p19_measured_basis"]["attempts"],
            {
                "infrastructure_failure_attempts": 500,
                "logical_executions_with_one_attempt": 99_500,
                "logical_executions_with_two_attempts": 500,
                "physical_attempts": 100_500,
            },
        )

    def test_storage_request_cost_and_resource_guardrails_reconcile(self) -> None:
        report = build_million_scale_capacity_plan(ROOT)
        publication = report["publication_plan"]
        storage = publication["storage_budget"]
        self.assertEqual(
            storage["expected_remote_bytes"],
            (
                report["p19_measured_basis"]["artifact_bytes"]["evidence"]
                + report["p19_measured_basis"]["artifact_bytes"]["logical_segments"]
            )
            * 10,
        )
        self.assertLess(storage["expected_remote_bytes"], storage["conservative_remote_bytes"])
        self.assertLess(storage["conservative_remote_bytes"], storage["soft_stop_remote_bytes"])
        self.assertLess(storage["soft_stop_remote_bytes"], storage["hard_remote_bytes"])
        self.assertEqual(storage["hard_remote_bytes"], 10_000_000_000)
        self.assertFalse(storage["compression_credit_assumed"])
        self.assertFalse(storage["warehouse_publication_permitted"])
        self.assertEqual(publication["request_budget"]["normal_list_requests"], 0)
        self.assertLessEqual(
            publication["object_budget"]["hard_total_object_ceiling"],
            publication["request_budget"]["class_a_hard_ceiling"],
        )
        hard_cost = report["cost_envelope"]["hard_monthly_upper_micro_usd"]
        self.assertEqual(
            hard_cost["first_month_total"],
            hard_cost["storage"]
            + hard_cost["class_a_operations"]
            + hard_cost["class_b_operations"],
        )

        capacity = report["execution_capacity"]
        memory = capacity["memory"]
        self.assertEqual(
            memory["campaign_working_set_upper_bytes"],
            capacity["compute"]["default_local_worker_concurrency"]
            * memory["worker_upper_bytes"]
            + memory["controller_and_provider_upper_bytes"],
        )
        self.assertEqual(
            memory["minimum_available_bytes"],
            memory["campaign_working_set_upper_bytes"]
            + memory["protected_reserve_bytes"],
        )
        disk = capacity["disk"]
        self.assertEqual(
            disk["admission_store_capacity_bytes"],
            disk["environment_cache_hard_bytes"]
            + disk["protected_spool_hard_bytes"]
            + disk["analytical_cache_hard_bytes"]
            + disk["build_execution_scratch_hard_bytes"]
            + disk["protected_free_space_floor_bytes"],
        )

    def test_schema_and_semantic_verifier_reject_authority_or_budget_forgery(self) -> None:
        validator = Draft202012Validator(
            load_strict(SCHEMA), format_checker=FormatChecker()
        )
        report = build_million_scale_capacity_plan(ROOT)
        for mutation in ("execution", "docker", "storage"):
            forged = deepcopy(report)
            if mutation == "execution":
                forged["classification"]["million_scale_execution_authorized"] = True
            elif mutation == "docker":
                forged["classification"]["docker_authorized"] = True
            else:
                forged["publication_plan"]["storage_budget"][
                    "hard_remote_bytes"
                ] = 10_000_000_001
            self.assertTrue(list(validator.iter_errors(forged)), mutation)
            with self.assertRaises(MillionScaleCapacityPlanError):
                verify_million_scale_capacity_plan(ROOT, forged)


if __name__ == "__main__":
    unittest.main()
