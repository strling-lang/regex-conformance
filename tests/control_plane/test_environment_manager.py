from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane" / "python"
SCHEMA_TOOLING = ROOT / "schemas" / "tooling" / "python"
for source in (CONTROL_PLANE, SCHEMA_TOOLING):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_control_plane.controller import ControlPlaneController, ControlPlaneServices
from regex_conformance_control_plane.environment_fingerprint import (
    ENVIRONMENT_FINGERPRINT_SCHEMA_FAMILY_ID,
    EnvironmentFingerprinter,
)
from regex_conformance_control_plane.environment_manager import EnvironmentManager, InvalidLifecycleTransition
from regex_conformance_control_plane.environment_models import (
    AdmissionDecision,
    ArtifactObservation,
    ArtifactRequirement,
    EnvironmentRecipe,
    NamedValue,
    ProviderAcquisition,
    ProviderCapability,
    ProviderDescriptor,
    ProviderDiagnosis,
    ProviderOutcome,
    ProviderPlan,
    RuntimeIdentity,
    SmokeObservation,
)
from regex_conformance_control_plane.environment_providers import ProviderOperationError, ProviderRegistry
from regex_conformance_schema.identity import NamespaceRegistry, build_content_identity
from regex_conformance_schema.jsonio import load_strict
from regex_conformance_schema.profile import IdentityProfile

FIXTURES = ROOT / "tests" / "control_plane" / "fixtures" / "environment_lifecycles.json"
LIFECYCLE_SCHEMA = ROOT / "schemas" / "json" / "environment-lifecycle.schema.json"
FINGERPRINT_PROFILE = ROOT / "schemas" / "identity-profiles" / "environment-fingerprint.v1.json"
NAMESPACE_REGISTRY = ROOT / "registries" / "identity" / "namespaces.v1.json"


class FixedClock:
    def __init__(self) -> None:
        self.value = datetime.fromisoformat("2026-08-12T23:00:00+00:00")

    def now(self) -> datetime:
        result = self.value
        self.value += timedelta(milliseconds=1)
        return result


class FixedIds:
    def __init__(self, start: int = 1) -> None:
        self.value = start

    def new_environment_transaction_id(self) -> str:
        value = f"opid:v1:environment:u7:019ff82c-9517-76fb-a67d-c461e914{self.value:04x}"
        self.value += 1
        return value


class NullDoctor:
    def inspect(self, configuration: object) -> object:
        raise AssertionError("machine doctor is not used by environment lifecycle tests")


def provider_descriptor(case: dict[str, object]) -> ProviderDescriptor:
    provider = case["provider"]
    return ProviderDescriptor(
        name=str(provider["name"]),
        strategy=str(provider["strategy"]),
        implementation_digest=str(provider["implementation_digest"]),
        capabilities=tuple(
            ProviderCapability(str(item["name"]), str(item["status"]), item.get("diagnostic"))
            for item in provider["capabilities"]
        ),
    )


def recipe(case: dict[str, object]) -> EnvironmentRecipe:
    value = case["recipe"]
    return EnvironmentRecipe(
        recipe_revision_id=str(value["recipe_revision_id"]),
        target_profile_id=str(value["target_profile_id"]),
        target_release_id=str(value["target_release_id"]),
        strategy=str(value["strategy"]),
        artifacts=tuple(
            ArtifactRequirement(
                name=str(item["name"]),
                sha256=str(item["sha256"]),
                size_bytes=int(item["size_bytes"]),
                media_type=str(item["media_type"]),
                locators=tuple(item["locators"]),
            )
            for item in value["artifacts"]
        ),
        expected_runtime_facts=tuple(NamedValue(str(item["name"]), str(item["value"])) for item in value["expected_runtime_facts"]),
        expected_configuration=tuple(NamedValue(str(item["name"]), str(item["value"])) for item in value["expected_configuration"]),
        required_capabilities=tuple(value["required_capabilities"]),
        smoke_probe_ids=tuple(value["smoke_probe_ids"]),
        isolation_policy_digest=str(value["isolation_policy_digest"]),
        network_policy=str(value["network_policy"]),
    )


class FixtureProvider:
    def __init__(
        self,
        case: dict[str, object],
        root: Path,
        *,
        failure_stage: str | None = None,
        corrupt_artifact: str | None = None,
        runtime_override: tuple[str, str] | None = None,
        smoke_failure: str | None = None,
        unsupported_capability: str | None = None,
        rollback_succeeds: bool = True,
        release_succeeds: bool = True,
        symlink_artifact: str | None = None,
        diagnosis_raises: bool = False,
    ) -> None:
        self.case = case
        self.root = root
        self.failure_stage = failure_stage
        self.corrupt_artifact = corrupt_artifact
        self.runtime_override = runtime_override
        self.smoke_failure = smoke_failure
        self.rollback_succeeds = rollback_succeeds
        self.release_succeeds = release_succeeds
        self.symlink_artifact = symlink_artifact
        self.diagnosis_raises = diagnosis_raises
        descriptor = provider_descriptor(case)
        if unsupported_capability is not None:
            capabilities = tuple(
                replace(item, status="unsupported", diagnostic="disabled by adversarial fixture")
                if item.name == unsupported_capability
                else item
                for item in descriptor.capabilities
            )
            descriptor = replace(descriptor, capabilities=capabilities)
        self._descriptor = descriptor
        self.calls: list[str] = []
        self.transaction_roots: dict[str, Path] = {}

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    def plan(self, selected_recipe: EnvironmentRecipe) -> ProviderPlan:
        self.calls.append("plan")
        values = self.case["plan"]
        return ProviderPlan(
            provider_name=self.descriptor.name,
            plan_token=f"{self.descriptor.strategy}:{selected_recipe.recipe_revision_id}",
            expected_download_bytes=int(values["expected_download_bytes"]),
            expected_expanded_bytes=int(values["expected_expanded_bytes"]),
            expected_scratch_bytes=int(values["expected_scratch_bytes"]),
            diagnostics=(f"fixture strategy {self.descriptor.strategy}",),
        )

    def acquire(
        self,
        selected_recipe: EnvironmentRecipe,
        plan: ProviderPlan,
        transaction_id: str,
    ) -> ProviderAcquisition:
        self.calls.append("acquire")
        transaction_root = self.root / transaction_id.rsplit(":", 1)[-1]
        transaction_root.mkdir(parents=True)
        self.transaction_roots[transaction_id] = transaction_root
        observations: list[ArtifactObservation] = []
        fixture_artifacts = {str(item["name"]): item for item in self.case["recipe"]["artifacts"]}
        for index, requirement in enumerate(selected_recipe.artifacts):
            artifact = fixture_artifacts[requirement.name]
            path = transaction_root / requirement.name
            content = str(artifact["content"])
            if self.corrupt_artifact == requirement.name:
                content += "substituted"
            path.write_text(content, encoding="utf-8")
            if self.symlink_artifact == requirement.name:
                target = transaction_root / f"{requirement.name}-target"
                path.replace(target)
                path.symlink_to(target)
            observations.append(ArtifactObservation(requirement.name, str(path)))
            if self.failure_stage == "partial-acquire" and index == 0:
                raise ProviderOperationError(
                    "partial-acquisition",
                    "provider stopped after a partial acquisition",
                    cleanup_handle=self._raw_handle(transaction_id),
                    diagnostics=("partial bytes retained until rollback",),
                )
        return ProviderAcquisition(self._raw_handle(transaction_id), tuple(observations))

    def construct(
        self,
        selected_recipe: EnvironmentRecipe,
        acquisition: ProviderAcquisition,
        transaction_id: str,
    ) -> str:
        self.calls.append("construct")
        if self.failure_stage == "construct":
            raise ProviderOperationError("construction-failed", "fixture construction failed", acquisition.handle)
        suffix = "installed" if self.descriptor.strategy == "native-host" else "image"
        return f"{acquisition.handle}:{suffix}"

    def inspect_runtime(
        self,
        selected_recipe: EnvironmentRecipe,
        handle: str,
        transaction_id: str,
    ) -> RuntimeIdentity:
        self.calls.append("inspect-runtime")
        if self.failure_stage == "runtime-inspection":
            raise ProviderOperationError("runtime-inspection-failed", "runtime inspection failed", handle)
        facts = list(selected_recipe.expected_runtime_facts)
        if self.runtime_override is not None:
            name, value = self.runtime_override
            facts = [replace(item, value=value) if item.name == name else item for item in facts]
        facts.append(NamedValue("provider-surface", self.descriptor.strategy))
        return RuntimeIdentity(
            strategy=self.descriptor.strategy,
            provider_implementation_digest=self.descriptor.implementation_digest,
            facts=tuple(facts),
            relevant_configuration=selected_recipe.expected_configuration,
            isolation_policy_digest=selected_recipe.isolation_policy_digest,
            network_policy=selected_recipe.network_policy,
        )

    def smoke_verify(
        self,
        selected_recipe: EnvironmentRecipe,
        handle: str,
        transaction_id: str,
    ) -> tuple[SmokeObservation, ...]:
        self.calls.append("smoke")
        return tuple(
            SmokeObservation(
                probe_id,
                probe_id != self.smoke_failure,
                "seeded smoke failure" if probe_id == self.smoke_failure else None,
            )
            for probe_id in selected_recipe.smoke_probe_ids
        )

    def release(self, handle: str, transaction_id: str) -> ProviderOutcome:
        self.calls.append("release")
        if not self.release_succeeds:
            return ProviderOutcome(False, ("seeded release failure",))
        self._remove_transaction(transaction_id)
        return ProviderOutcome(True, ("release verified",))

    def rollback(self, handle: str | None, transaction_id: str) -> ProviderOutcome:
        self.calls.append("rollback")
        if not self.rollback_succeeds:
            return ProviderOutcome(False, ("seeded rollback failure",))
        self._remove_transaction(transaction_id)
        return ProviderOutcome(True, ("rollback verified",))

    def diagnose(self, handle: str | None, transaction_id: str) -> ProviderDiagnosis:
        self.calls.append("diagnose")
        if self.diagnosis_raises:
            raise OSError("seeded diagnosis outage")
        status = "healthy" if transaction_id in self.transaction_roots else "unavailable"
        return ProviderDiagnosis(status, (f"fixture provider {self.descriptor.name}",))

    def _raw_handle(self, transaction_id: str) -> str:
        return f"{self.descriptor.strategy}:{transaction_id.rsplit(':', 1)[-1]}"

    def _remove_transaction(self, transaction_id: str) -> None:
        path = self.transaction_roots.pop(transaction_id, None)
        if path is not None:
            shutil.rmtree(path)
        if self.root.exists() and not any(self.root.iterdir()):
            self.root.rmdir()


def controller(provider: FixtureProvider, *, id_start: int = 1) -> ControlPlaneController:
    manager = EnvironmentManager(
        ProviderRegistry((provider,)),
        clock=FixedClock(),
        id_generator=FixedIds(id_start),
    )
    return ControlPlaneController(ControlPlaneServices(NullDoctor(), manager))


def admitted_plan(control: ControlPlaneController, selected_recipe: EnvironmentRecipe, provider_name: str):
    planned = control.plan_environment(selected_recipe, provider_name)
    return control.admit_environment(planned, AdmissionDecision(True, "fixture-admission", "fixture capacity approved"))


class EnvironmentManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = json.loads(FIXTURES.read_text(encoding="utf-8"))
        cls.validator = Draft202012Validator(
            json.loads(LIFECYCLE_SCHEMA.read_text(encoding="utf-8")),
            format_checker=FormatChecker(),
        )
        cls.registry = NamespaceRegistry.load(NAMESPACE_REGISTRY)
        cls.profile = IdentityProfile.from_record(load_strict(FINGERPRINT_PROFILE))

    def validate(self, value: dict[str, object]) -> None:
        errors = sorted(self.validator.iter_errors(value), key=lambda error: list(error.absolute_path))
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def test_two_materially_different_providers_share_verified_lifecycle(self) -> None:
        expected_states = [
            "planned",
            "admitted",
            "acquiring",
            "verifying_artifacts",
            "artifacts_verified",
            "constructing",
            "constructed",
            "verifying_runtime",
            "runtime_verified",
            "verifying_smoke",
            "smoke_verified",
            "fingerprinting",
            "ready",
        ]
        seen_strategies = set()
        for case in self.cases:
            with self.subTest(case=case["case"]), tempfile.TemporaryDirectory() as directory:
                provider = FixtureProvider(case, Path(directory) / "provider-state")
                control = controller(provider)
                selected_recipe = recipe(case)
                planned = control.plan_environment(selected_recipe, provider.descriptor.name)
                self.assertEqual(planned.state, "planned")
                self.assertFalse(provider.root.exists(), "planning must not mutate provider state")
                self.assertFalse(planned.plan.mutation_permitted)
                admitted = control.admit_environment(
                    planned,
                    AdmissionDecision(True, "fixture-admission", "fixture capacity approved"),
                )
                ready = control.realize_environment(admitted)
                self.assertEqual(ready.state, "ready")
                self.assertEqual([item.to_state for item in ready.transitions], expected_states)
                self.assertEqual(ready.failure, None)
                self.assertEqual(ready.environment_fingerprint_id, case["expected_fingerprint_id"])
                self.assertNotIn("path", json.dumps(ready.to_dict()))
                self.validate(ready.to_dict())
                diagnosis = control.diagnose_environment(ready)
                self.assertEqual(diagnosis.provider_status, "healthy")
                released = control.release_environment(ready)
                self.assertEqual(released.state, "released")
                self.assertEqual(released.environment_fingerprint_id, ready.environment_fingerprint_id)
                self.assertFalse(provider.root.exists())
                self.validate(released.to_dict())
                seen_strategies.add(provider.descriptor.strategy)
        self.assertEqual(seen_strategies, {"native-host", "oci"})

    def test_fingerprint_is_transaction_independent_and_matches_certified_identity_tooling(self) -> None:
        case = self.cases[1]
        fingerprints = []
        ready_records = []
        with tempfile.TemporaryDirectory() as directory:
            for index in (1, 2):
                provider = FixtureProvider(case, Path(directory) / f"provider-{index}")
                control = controller(provider, id_start=index)
                ready = control.realize_environment(admitted_plan(control, recipe(case), provider.descriptor.name))
                fingerprints.append(ready.environment_fingerprint_id)
                ready_records.append(ready)
        self.assertEqual(fingerprints[0], fingerprints[1])
        self.assertEqual(fingerprints[0], case["expected_fingerprint_id"])
        ready = ready_records[0]
        result = EnvironmentFingerprinter().fingerprint(
            recipe=ready.recipe,
            provider=ready.provider,
            artifacts=ready.verified_artifacts,
            runtime=ready.runtime_identity,
            smoke=ready.smoke_observations,
        )
        certified = build_content_identity(
            registry=self.registry,
            profile=self.profile,
            namespace="environment-fingerprint",
            identity_schema_family_id=ENVIRONMENT_FINGERPRINT_SCHEMA_FAMILY_ID,
            identity_schema_version="1.0.0",
            identity=result.identity,
        )
        self.assertEqual(result.canonical_utf8, certified["canonical_utf8"])
        self.assertEqual(result.environment_fingerprint_id, certified["content_id"])

    def test_capability_mismatch_rejects_before_provider_plan_or_mutation(self) -> None:
        case = self.cases[1]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state", unsupported_capability="network-control")
            planned = controller(provider).plan_environment(recipe(case), provider.descriptor.name)
            self.assertEqual(planned.state, "rejected")
            self.assertEqual(planned.failure.code, "provider-capability-mismatch")
            self.assertEqual(provider.calls, [])
            self.assertFalse(provider.root.exists())
            self.validate(planned.to_dict())

    def test_digest_substitution_never_becomes_ready_and_is_rolled_back(self) -> None:
        case = self.cases[0]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state", corrupt_artifact="runtime")
            control = controller(provider)
            failed = control.realize_environment(admitted_plan(control, recipe(case), provider.descriptor.name))
            self.assertEqual(failed.state, "failed")
            self.assertEqual(failed.failure.classification, "verification")
            self.assertEqual(failed.failure.code, "artifact-identity-mismatch")
            self.assertTrue(failed.rollback.succeeded)
            self.assertIsNone(failed.environment_fingerprint_id)
            self.assertFalse(provider.root.exists())
            self.validate(failed.to_dict())

    def test_partial_acquisition_is_provider_failure_and_preserves_rollback_evidence(self) -> None:
        case = self.cases[1]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state", failure_stage="partial-acquire")
            control = controller(provider)
            failed = control.realize_environment(admitted_plan(control, recipe(case), provider.descriptor.name))
            self.assertEqual(failed.state, "failed")
            self.assertEqual(failed.failure.classification, "provider")
            self.assertEqual(failed.failure.code, "partial-acquisition")
            self.assertIn("partial bytes retained until rollback", failed.diagnostics)
            self.assertEqual(provider.calls, ["plan", "acquire", "rollback"])
            self.assertFalse(provider.root.exists())

    def test_runtime_identity_and_smoke_mismatches_never_become_ready(self) -> None:
        case = self.cases[0]
        scenarios = [
            ({"runtime_override": ("runtime-version", "9.9")}, "runtime-identity-mismatch"),
            ({"smoke_failure": "adapter-handshake"}, "smoke-verification-failed"),
        ]
        for options, code in scenarios:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                provider = FixtureProvider(case, Path(directory) / "provider-state", **options)
                control = controller(provider)
                failed = control.realize_environment(admitted_plan(control, recipe(case), provider.descriptor.name))
                self.assertEqual(failed.state, "failed")
                self.assertEqual(failed.failure.code, code)
                self.assertTrue(failed.rollback.succeeded)
                self.assertIsNone(failed.environment_fingerprint_id)

    def test_unsafe_symlink_artifact_is_rejected_and_cleaned(self) -> None:
        case = self.cases[0]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state", symlink_artifact="runtime")
            control = controller(provider)
            failed = control.realize_environment(admitted_plan(control, recipe(case), provider.descriptor.name))
            self.assertEqual(failed.failure.code, "artifact-path-unsafe")
            self.assertEqual(failed.state, "failed")
            self.assertFalse(provider.root.exists())

    def test_failed_rollback_preserves_cleanup_required_state(self) -> None:
        case = self.cases[0]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(
                case,
                Path(directory) / "provider-state",
                corrupt_artifact="runtime",
                rollback_succeeds=False,
            )
            control = controller(provider)
            failed = control.realize_environment(admitted_plan(control, recipe(case), provider.descriptor.name))
            self.assertEqual(failed.state, "cleanup_required")
            self.assertTrue(failed.failure.cleanup_required)
            self.assertFalse(failed.rollback.succeeded)
            self.assertTrue(provider.root.exists())
            self.validate(failed.to_dict())

    def test_admission_denial_and_pre_mutation_cancellation_do_not_call_provider(self) -> None:
        case = self.cases[0]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state")
            control = controller(provider)
            planned = control.plan_environment(recipe(case), provider.descriptor.name)
            denied = control.admit_environment(planned, AdmissionDecision(False, "fixture-denial", "insufficient disk"))
            self.assertEqual(denied.state, "rejected")
            self.assertEqual(denied.failure.classification, "admission")
            cancelled = control.cancel_environment(planned, "operator cancelled before acquisition")
            self.assertEqual(cancelled.state, "cancelled")
            self.assertEqual(provider.calls, ["plan"])
            self.assertFalse(provider.root.exists())

    def test_release_failure_does_not_pretend_environment_was_removed(self) -> None:
        case = self.cases[1]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state", release_succeeds=False)
            control = controller(provider)
            ready = control.realize_environment(admitted_plan(control, recipe(case), provider.descriptor.name))
            failed = control.release_environment(ready)
            self.assertEqual(failed.state, "release_failed")
            self.assertTrue(failed.failure.cleanup_required)
            self.assertTrue(provider.root.exists())
            self.validate(failed.to_dict())

    def test_diagnosis_failure_is_reported_as_unknown_without_mutating_lifecycle(self) -> None:
        case = self.cases[0]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state", diagnosis_raises=True)
            control = controller(provider)
            planned = control.plan_environment(recipe(case), provider.descriptor.name)
            diagnosis = control.diagnose_environment(planned)
            self.assertEqual(diagnosis.provider_status, "unknown")
            self.assertIn("seeded diagnosis outage", diagnosis.diagnostics[-1])
            self.assertEqual(planned.state, "planned")

    def test_invalid_transitions_and_duplicate_provider_identity_fail_closed(self) -> None:
        case = self.cases[0]
        with self.assertRaisesRegex(ValueError, "canonical token"):
            NamedValue("provider_surface", "noncanonical")
        with self.assertRaisesRegex(ValueError, "canonical token"):
            ProviderOperationError("noncanonical_code", "provider error")
        with self.assertRaisesRegex(ValueError, "safe integer"):
            replace(recipe(case).artifacts[0], size_bytes=2**53)
        with self.assertRaisesRegex(ValueError, "boolean"):
            AdmissionDecision(1, "invalid-admission", "integer is not a boolean")
        with tempfile.TemporaryDirectory() as directory:
            first = FixtureProvider(case, Path(directory) / "first")
            second = FixtureProvider(case, Path(directory) / "second")
            with self.assertRaisesRegex(ValueError, "duplicate provider"):
                ProviderRegistry((first, second))
            control = controller(first)
            planned = control.plan_environment(recipe(case), first.descriptor.name)
            with self.assertRaisesRegex(InvalidLifecycleTransition, "cannot realize"):
                control.realize_environment(planned)
            with self.assertRaisesRegex(InvalidLifecycleTransition, "cannot release"):
                control.release_environment(planned)

    def test_controller_without_environment_service_fails_explicitly(self) -> None:
        case = self.cases[0]
        control = ControlPlaneController(ControlPlaneServices(NullDoctor()))
        with self.assertRaisesRegex(RuntimeError, "not configured"):
            control.plan_environment(recipe(case), "fixture-native")

    def test_schema_rejects_false_ready_and_mutating_plan_claims(self) -> None:
        case = self.cases[0]
        with tempfile.TemporaryDirectory() as directory:
            provider = FixtureProvider(case, Path(directory) / "provider-state")
            control = controller(provider)
            planned = control.plan_environment(recipe(case), provider.descriptor.name).to_dict()
            planned["state"] = "ready"
            self.assertTrue(list(self.validator.iter_errors(planned)))
            planned["state"] = "planned"
            planned["plan"]["mutation_permitted"] = True
            self.assertTrue(list(self.validator.iter_errors(planned)))

            ready = control.realize_environment(
                admitted_plan(control, recipe(case), provider.descriptor.name)
            )
            for field, value in (
                ("verified_artifacts", []),
                ("smoke_observations", []),
                ("admission", {"admitted": False, "decision_id": "forged", "reason": "forged"}),
            ):
                with self.subTest(field=field):
                    forged = json.loads(json.dumps(ready.to_dict()))
                    forged[field] = value
                    self.assertTrue(list(self.validator.iter_errors(forged)))
            failed_smoke = json.loads(json.dumps(ready.to_dict()))
            failed_smoke["smoke_observations"][0]["passed"] = False
            failed_smoke["smoke_observations"][0]["diagnostic"] = "forged failure"
            self.assertTrue(list(self.validator.iter_errors(failed_smoke)))
            with self.assertRaisesRegex(ValueError, "verified artifacts"):
                replace(ready, verified_artifacts=())
            with self.assertRaisesRegex(ValueError, "smoke observations"):
                replace(ready, smoke_observations=())


if __name__ == "__main__":
    unittest.main()
