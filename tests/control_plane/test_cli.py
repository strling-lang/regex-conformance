from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2] if "tests" in Path(__file__).parts else None
if ROOT is None or not (ROOT / "control-plane").exists():
    ROOT = Path("/root/personal/strling-lang/regex-conformance")
sys.path.insert(0, str(ROOT / "control-plane" / "python"))

from regex_conformance_control_plane.cache_manager import TransferManager  # noqa: E402
from regex_conformance_control_plane.cli import main, parser  # noqa: E402
from regex_conformance_control_plane.command_models import CommandDocument, CommandIssue  # noqa: E402
from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices  # noqa: E402
from regex_conformance_control_plane.event_models import EventDraft  # noqa: E402
from regex_conformance_control_plane.event_store import EventJournal  # noqa: E402
from regex_conformance_control_plane.resource_models import ResourceEstimate, TransferForecast  # noqa: E402
from regex_conformance_control_plane.state_models import SecretMaterialError, canonical_json  # noqa: E402


def opid(namespace: str, sequence: int) -> str:
    return f"opid:v1:{namespace}:u7:019ff82c-9517-76fb-a67d-{sequence:012x}"


class Value:
    def __init__(self, value: dict[str, object], **attributes: object) -> None:
        self.value = value
        for key, selected in attributes.items():
            setattr(self, key, selected)

    def to_dict(self) -> dict[str, object]:
        return self.value


class StubControl:
    def __init__(self, *, admission: str = "admitted", realized: str = "ready") -> None:
        self.calls: list[tuple[str, object]] = []
        self.admission = admission
        self.realized = realized

    def plan_environment(self, recipe: object, provider: str) -> Value:
        self.calls.append(("plan_environment", (recipe.to_dict(), provider)))
        return Value({"state": "planned", "transaction_id": opid("environment", 1)}, state="planned")

    def plan_environment_resources(self, record: object, **values: object) -> Value:
        self.calls.append(("plan_environment_resources", values))
        return Value({"mutation_permitted": False, "operation_kind": "environment"})

    def inspect_machine(self, configuration: object) -> Value:
        self.calls.append(("inspect_machine", configuration))
        return Value({"status": "healthy"}, status="healthy")

    def preflight_resources(self, plan: object, inventory: object) -> Value:
        self.calls.append(("preflight_resources", None))
        return Value({"outcome": self.admission, "stage": "preflight"}, outcome=self.admission)

    def admit_environment_from_preflight(self, record: object, report: object) -> Value:
        self.calls.append(("admit_environment_from_preflight", None))
        return Value({"state": "admitted", "transaction_id": opid("environment", 1)}, state="admitted")

    def realize_environment(self, record: object) -> Value:
        self.calls.append(("realize_environment", None))
        return Value({"state": self.realized, "transaction_id": opid("environment", 1)}, state=self.realized)

    def plan_resources(self, **values: object) -> Value:
        self.calls.append(("plan_resources", values))
        self.last_resource_values = values
        return Value({"mutation_permitted": False, "operation_id": values["operation_id"]})

    def inventory_cache(self, entries: tuple[object, ...], *, observed_at: str | None = None) -> Value:
        self.calls.append(("inventory_cache", (entries, observed_at)))
        return Value({"entry_count": len(entries), "observed_at": observed_at or entries[0].observed_at})

    def inspect_local_state(self) -> Value:
        return Value({"canonical_authority": False, "epoch": 7})

    def inspect_local_state_health(self) -> dict[str, object]:
        return {"status": "ready"}

    def inspect_event_journal_health(self) -> dict[str, object]:
        return {"status": "ready"}

    def inspect_progress(self, stream_id: str) -> Value:
        return Value({"stream_id": stream_id, "status": "running"})


def recipe() -> dict[str, object]:
    return {
        "recipe_revision_id": "rcid:v1:environment-recipe-revision:h:jcs-sha256-v1:" + "a" * 64,
        "target_profile_id": "rcid:v1:profile-revision:h:jcs-sha256-v1:" + "1" * 64,
        "target_release_id": "rcid:v1:release-revision:h:jcs-sha256-v1:" + "2" * 64,
        "strategy": "native-host",
        "artifacts": [
            {
                "name": "runtime",
                "sha256": "3" * 64,
                "size_bytes": 10,
                "media_type": "native-binary",
                "locators": ["fixture://runtime"],
            }
        ],
        "expected_runtime_facts": [{"name": "runtime-version", "value": "1.0"}],
        "expected_configuration": [{"name": "timezone", "value": "UTC"}],
        "required_capabilities": ["process-limits"],
        "smoke_probe_ids": ["adapter-handshake"],
        "isolation_policy_digest": "4" * 64,
        "network_policy": "offline",
    }


def write_json(root: Path, name: str, value: object) -> Path:
    path = root / name
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    return path


def invoke(arguments: list[str], control: object) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = main(arguments, controller=control, environment={}, stdout=stdout, stderr=stderr)
    return code, stdout.getvalue(), stderr.getvalue()


class CliSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        schema = json.loads((ROOT / "schemas" / "json" / "control-plane-command.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        cls.validator = Draft202012Validator(schema)

    def validate(self, value: dict[str, object]) -> None:
        errors = list(self.validator.iter_errors(value))
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def test_command_document_is_deterministic_secret_safe_and_noncanonical(self) -> None:
        one = CommandDocument.build(command="campaign plan", action="plan", dry_run=True, changed=False, payload={"z": 2, "a": 1})
        two = CommandDocument.build(command="campaign plan", action="plan", dry_run=True, changed=False, payload={"a": 1, "z": 2})
        self.assertEqual(one.payload_sha256, two.payload_sha256)
        self.validate(one.to_dict())
        self.assertFalse(one.to_dict()["canonical_authority"])
        with self.assertRaises(SecretMaterialError):
            CommandDocument.build(command="campaign plan", action="plan", dry_run=True, changed=False, payload={"access_token": "never"})
        with self.assertRaisesRegex(ValueError, "dry-run"):
            CommandDocument.build(command="env acquire", action="execute", dry_run=True, changed=True)
        with self.assertRaisesRegex(ValueError, "require an issue"):
            CommandDocument.build(command="env acquire", action="execute", outcome="failed", dry_run=False, changed=True)
        with self.assertRaisesRegex(ValueError, "single-line"):
            CommandIssue("unsafe-message", "input", "terminal\tescape")

    def test_environment_dry_run_and_execution_share_plan_but_guard_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_json(Path(directory), "recipe.json", recipe())
            dry_control = StubControl()
            code, output, error = invoke(
                ["env", "acquire", "--recipe", str(path), "--provider", "fixture-native", "--machine-provider", "fixture-native", "--format", "json"],
                dry_control,
            )
            self.assertEqual((code, error), (0, ""))
            dry = json.loads(output)
            self.validate(dry)
            self.assertTrue(dry["dry_run"])
            self.assertFalse(dry["changed"])
            self.assertEqual([item[0] for item in dry_control.calls], ["plan_environment", "plan_environment_resources", "inspect_machine", "preflight_resources"])

            guarded = StubControl()
            code, output, error = invoke(
                ["env", "acquire", "--recipe", str(path), "--provider", "fixture-native", "--machine-provider", "fixture-native", "--execute", "--format", "json"],
                guarded,
            )
            self.assertEqual((code, output), (2, ""))
            self.validate(json.loads(error))
            self.assertEqual(guarded.calls, [])

            executing = StubControl()
            code, output, error = invoke(
                ["env", "acquire", "--recipe", str(path), "--provider", "fixture-native", "--machine-provider", "fixture-native", "--execute", "--yes", "--format", "json"],
                executing,
            )
            self.assertEqual((code, error), (0, ""))
            executed = json.loads(output)
            self.validate(executed)
            self.assertTrue(executed["changed"])
            self.assertFalse(executed["dry_run"])
            self.assertEqual([item[0] for item in executing.calls[:4]], [item[0] for item in dry_control.calls])
            self.assertEqual([item[0] for item in executing.calls[-2:]], ["admit_environment_from_preflight", "realize_environment"])

    def test_environment_refusal_and_failed_verification_preserve_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_json(Path(directory), "recipe.json", recipe())
            refused = StubControl(admission="rejected")
            code, output, error = invoke(
                ["env", "acquire", "--recipe", str(path), "--provider", "fixture-native", "--machine-provider", "fixture-native", "--execute", "--yes", "--format", "json"],
                refused,
            )
            self.assertEqual((code, output), (2, ""))
            document = json.loads(error)
            self.validate(document)
            self.assertEqual(document["outcome"], "rejected")
            self.assertFalse(document["changed"])
            self.assertNotIn("realize_environment", [item[0] for item in refused.calls])

            failed = StubControl(realized="failed")
            code, output, error = invoke(
                ["env", "acquire", "--recipe", str(path), "--provider", "fixture-native", "--machine-provider", "fixture-native", "--execute", "--yes", "--format", "json"],
                failed,
            )
            self.assertEqual((code, output), (3, ""))
            document = json.loads(error)
            self.validate(document)
            self.assertTrue(document["changed"])
            self.assertEqual(document["payload"]["environment"]["state"], "failed")

            class CrashingControl(StubControl):
                def realize_environment(self, record: object) -> Value:
                    self.calls.append(("realize_environment", None))
                    raise RuntimeError("unexpected provider crash")

            code, output, error = invoke(
                ["env", "acquire", "--recipe", str(path), "--provider", "fixture-native", "--machine-provider", "fixture-native", "--execute", "--yes", "--format", "json"],
                CrashingControl(),
            )
            self.assertEqual((code, output), (3, ""))
            document = json.loads(error)
            self.validate(document)
            self.assertTrue(document["changed"])
            self.assertEqual(document["issues"][0]["code"], "environment-execution-failed")

    def test_human_and_json_views_bind_the_same_payload_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_json(Path(directory), "recipe.json", recipe())
            code, output, error = invoke(["env", "plan", "--recipe", str(path), "--provider", "fixture-native", "--format", "json"], StubControl())
            self.assertEqual((code, error), (0, ""))
            document = json.loads(output)
            code, human, error = invoke(["env", "plan", "--recipe", str(path), "--provider", "fixture-native"], StubControl())
            self.assertEqual((code, error), (0, ""))
            self.assertIn(document["payload_sha256"], human)
            self.assertIn("Action: plan (dry run)", human)

    def test_campaign_plan_decodes_typed_forecasts_and_rejects_duplicate_json(self) -> None:
        request = {
            "operation_id": opid("campaign", 10),
            "estimates": [{"name": "spool", "pool_kind": "result_spool", "unit": "bytes", "expected": 10, "upper_bound": 20, "confidence": "estimated", "source": "fixture", "diagnostic": None}],
            "transfers": [{"name": "publish", "direction": "upload", "expected_bytes": 5, "upper_bound_bytes": 8, "confidence": "bounded", "source": "fixture", "diagnostic": None}],
            "provider_name": None,
            "provider_strategy": None,
            "required_capabilities": [],
            "eligible_trust_classes": ["development"],
            "requested_concurrency": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = write_json(root, "campaign.json", request)
            control = StubControl()
            code, output, error = invoke(["campaign", "plan", "--request", str(path), "--format", "json"], control)
            self.assertEqual((code, error), (0, ""))
            self.validate(json.loads(output))
            self.assertIsInstance(control.last_resource_values["estimates"][0], ResourceEstimate)
            self.assertIsInstance(control.last_resource_values["transfers"][0], TransferForecast)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"operation_id":1,"operation_id":2}', encoding="utf-8")
            code, output, error = invoke(["campaign", "plan", "--request", str(duplicate), "--format", "json"], StubControl())
            self.assertEqual((code, output), (2, ""))
            self.assertEqual(json.loads(error)["issues"][0]["code"], "invalid-command-input")

            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (1024 * 1024 + 1))
            code, output, error = invoke(["campaign", "plan", "--request", str(oversized), "--format=json"], StubControl())
            self.assertEqual((code, output), (2, ""))
            document = json.loads(error)
            self.validate(document)
            self.assertIn("1 MiB", document["issues"][0]["message"])

            secret = write_json(root, "secret.json", {"access_token": "must-not-escape"})
            code, output, error = invoke(["campaign", "plan", "--request", str(secret), "--format=json"], StubControl())
            self.assertEqual((code, output), (2, ""))
            self.assertNotIn("must-not-escape", error)
            self.validate(json.loads(error))

    def test_cache_inventory_is_typed_and_nonmutating(self) -> None:
        entry = {
            "cache_key": "runtime-cache", "kind": "artifact", "content_id": None, "sha256": "a" * 64,
            "relative_path": "objects/runtime", "size_bytes": 10, "reclaimable_bytes": 10,
                "accounting_basis": "logical", "provider_name": "fixture", "retention_class": "reacquirable",
            "pinned": False, "active_leases": [], "future_dependencies": [], "dependencies": [],
            "last_used_at": "2026-08-13T00:00:00Z", "reacquisition_time_seconds": 1,
            "reacquisition_cost_microunits": 0, "reconstruction_difficulty": 1, "upstream_fragility": 1,
            "verification_status": "verified", "verified_at": "2026-08-13T00:00:00Z",
            "observed_at": "2026-08-13T00:00:00Z", "source": "fixture", "staleness_seconds": 60,
            "registry_authority": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = write_json(Path(directory), "cache.json", {"entries": [entry]})
            control = StubControl()
            code, output, error = invoke(["cache", "inventory", "--entries", str(path), "--format", "json"], control)
            self.assertEqual((code, error), (0, ""))
            document = json.loads(output)
            self.validate(document)
            self.assertEqual(document["action"], "inspect")
            self.assertFalse(document["changed"])
            self.assertEqual(document["payload"]["inventory"]["entry_count"], 1)

    def test_evidence_transfer_plan_uses_real_validation_and_never_mutates(self) -> None:
        class NullDoctor:
            def inspect(self, configuration: object) -> object:
                raise AssertionError("doctor is not used")

        with tempfile.TemporaryDirectory() as directory:
            manager = TransferManager(Path(directory) / "transfers")
            control = ControlPlaneController(ControlPlaneServices(machine_doctor=NullDoctor(), transfer_manager=manager))
            arguments = ["evidence", "plan-transfer", "--operation", "upload", "--locator", "fixture://evidence", "--sha256", "a" * 64, "--size-bytes", "10", "--relative-path", "evidence/item", "--format", "json"]
            code, output, error = invoke(arguments, control)
            self.assertEqual((code, error), (0, ""))
            document = json.loads(output)
            self.validate(document)
            self.assertTrue(document["dry_run"])
            self.assertEqual(document["payload"]["transfer"]["state"], "planned")
            arguments[arguments.index("fixture://evidence")] = "https://user:password@example.invalid/evidence"
            code, output, error = invoke(arguments, control)
            self.assertEqual((code, output), (2, ""))
            self.assertEqual(json.loads(error)["outcome"], "rejected")

    def test_event_output_is_canonical_jsonl_and_unavailable_services_are_explicit(self) -> None:
        class NullDoctor:
            def inspect(self, configuration: object) -> object:
                raise AssertionError("doctor is not used")

        with tempfile.TemporaryDirectory() as directory:
            journal = EventJournal.open(Path(directory) / "events.sqlite3")
            stored = journal.publish(
                EventDraft(
                    stream_id=opid("transfer", 20), operation_kind="transfer", event_type="progress",
                    phase="transfer", status="running", current=1, total=2, unit="bytes", message="fixture progress",
                )
            )
            control = ControlPlaneController(ControlPlaneServices(machine_doctor=NullDoctor(), event_journal=journal))
            code, output, error = invoke(["worker", "events", "--format", "event"], control)
            self.assertEqual((code, error), (0, ""))
            self.assertEqual(json.loads(output), stored.event.to_dict())
            self.assertEqual(output.strip(), canonical_json(stored.event.to_dict()).decode("utf-8"))
            journal.close()

            unavailable = ControlPlaneController(ControlPlaneServices(machine_doctor=NullDoctor()))
            code, output, error = invoke(["worker", "state", "--format", "json"], unavailable)
            self.assertEqual((code, output), (4, ""))
            document = json.loads(error)
            self.validate(document)
            self.assertEqual(document["outcome"], "unavailable")

            class RuntimeFailure(StubControl):
                def inspect_local_state(self) -> Value:
                    raise RuntimeError("provider said not configured during an actual failure")

            code, output, error = invoke(["worker", "state", "--format=json"], RuntimeFailure())
            self.assertEqual((code, output), (3, ""))
            document = json.loads(error)
            self.validate(document)
            self.assertEqual(document["outcome"], "failed")

    def test_cli_surface_lists_only_backed_current_groups_and_rejects_compact_event_output(self) -> None:
        help_text = parser().format_help()
        for group in ("doctor", "machine", "env", "cache", "campaign", "worker", "evidence"):
            self.assertIn(group, help_text)
        for future in ("registry", "coverage", "report"):
            self.assertNotIn(future, help_text)
        code, output, error = invoke(["worker", "events", "--format", "event", "--compact"], StubControl())
        self.assertEqual((code, output), (2, ""))
        self.validate(json.loads(error))


if __name__ == "__main__":
    unittest.main()
