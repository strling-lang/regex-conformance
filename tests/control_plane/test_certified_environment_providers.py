from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
for source in (ROOT / "control-plane" / "python", ROOT / "schemas" / "tooling" / "python"):
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))

from regex_conformance_control_plane.certified_environments import (
    CertifiedRecipeDefinition,
    CpythonArchiveProvider,
    MysqlOciProvider,
    Pcre2SourceProvider,
    VerifiedHttpsFetcher,
    _SafeRedirectHandler,
    _merge_values,
    _safe_extract,
    build_certified_providers,
    load_certified_recipes,
    load_qualification_recipes,
)
from regex_conformance_control_plane.environment_manager import BASE_READY_CAPABILITIES, EnvironmentManager
from regex_conformance_control_plane.environment_models import (
    AdmissionDecision,
    ArtifactRequirement,
    EnvironmentRecipe,
    NamedValue,
    ProviderPlan,
)
from regex_conformance_control_plane.environment_providers import ProviderOperationError, ProviderRegistry


class StaticFetcher:
    def __init__(self, content: bytes, *, fail: bool = False) -> None:
        self.content = content
        self.fail = fail

    def fetch(self, requirement: ArtifactRequirement, destination: Path) -> None:
        destination.write_bytes(self.content)
        if self.fail:
            raise ProviderOperationError("interrupted-download", "seeded transfer interruption")


def process_result(*, outcome: str = "completed", exit_code: int = 0, stdout: bytes = b"") -> SimpleNamespace:
    return SimpleNamespace(
        outcome=outcome,
        exit_code=exit_code,
        stdout=stdout,
        stderr=b"",
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
    )


class ScriptedSupervisor:
    def __init__(self, *results: SimpleNamespace) -> None:
        self.results = list(results)
        self.commands: list[tuple[str, ...]] = []

    def run(self, command: tuple[str, ...], **_: object) -> SimpleNamespace:
        self.commands.append(command)
        if not self.results:
            raise AssertionError("unexpected contained command")
        return self.results.pop(0)


def tiny_definition(content: bytes, *, selection: str = "python-re", image: str | None = None) -> CertifiedRecipeDefinition:
    digest = hashlib.sha256(content).hexdigest()
    lifecycle = EnvironmentRecipe(
        recipe_revision_id="rcid:v1:environment-recipe-revision:h:jcs-sha256-v1:" + "1" * 64,
        target_profile_id="rcid:v1:profile:u7:019ff999-0000-7000-8000-000000000001",
        target_release_id="rcid:v1:release:u7:019ff999-0000-7000-8000-000000000002",
        strategy="oci-service" if selection == "mysql-regex" else "native-runtime",
        artifacts=(ArtifactRequirement("cpython-runtime", digest, len(content), "gzip-tar", ("https://github.com/exact",)),),
        expected_runtime_facts=(NamedValue("runtime-version", "1.0.0"),),
        expected_configuration=(NamedValue("locale", "C.UTF-8"),),
        required_capabilities=("offline-runtime",),
        smoke_probe_ids=("runtime-smoke",),
        isolation_policy_digest="2" * 64,
        network_policy="phase-separated",
    )
    parameters = [{"name": "image-reference", "value": image}] if image is not None else [{"name": "runtime-entrypoint", "value": "bin/python3.14"}]
    record = {
        "selection_key": selection,
        "provider_name": "mysql-oci" if selection == "mysql-regex" else "cpython-archive",
        "construction": {
            "download_upper_bound_bytes": len(content),
            "expanded_upper_bound_bytes": 1024 * 1024,
            "scratch_upper_bound_bytes": 1024 * 1024,
            "hermeticity": "immutable-oci-manifest" if selection == "mysql-regex" else "immutable-binary-artifact",
            "parameters": parameters,
        },
        "isolation_policy": {"resource_limits": {"wall_time_ms": 1000, "stdout_bytes": 1024, "stderr_bytes": 1024, "memory_bytes": None, "cpu_time_seconds": None}},
    }
    return CertifiedRecipeDefinition(Path("fixture.json"), record, lifecycle)


def make_archive(path: Path, members: list[tuple[str, bytes]], *, symlink: tuple[str, str] | None = None) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755 if name.endswith("python3.14") else 0o644
            archive.addfile(info, io.BytesIO(content))
        if symlink is not None:
            info = tarfile.TarInfo(symlink[0])
            info.type = tarfile.SYMTYPE
            info.linkname = symlink[1]
            archive.addfile(info)


class CertifiedEnvironmentProviderTests(unittest.TestCase):
    def test_repository_recipes_select_only_typed_provider_implementations(self) -> None:
        definitions = load_certified_recipes(ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            providers = build_certified_providers(definitions, Path(temporary))
        self.assertEqual({type(item) for item in providers}, {Pcre2SourceProvider, CpythonArchiveProvider, MysqlOciProvider})
        for provider in providers:
            supported = {item.name for item in provider.descriptor.capabilities if item.status == "supported"}
            self.assertTrue(BASE_READY_CAPABILITIES.issubset(supported))

    def test_qualification_recipe_selects_the_typed_dfa_provider(self) -> None:
        definitions = load_qualification_recipes(ROOT)
        self.assertEqual([item.selection_key for item in definitions], ["pcre2-dfa"])
        with tempfile.TemporaryDirectory() as temporary:
            providers = build_certified_providers(definitions, Path(temporary))
        self.assertEqual(len(providers), 1)
        self.assertIsInstance(providers[0], Pcre2SourceProvider)
        self.assertEqual(
            definitions[0].lifecycle.smoke_probe_ids,
            ("pcre2-dfa-symbol", "pcre2-version"),
        )

    def test_dfa_smoke_probe_requires_the_exported_public_matcher_symbol(self) -> None:
        definition = load_qualification_recipes(ROOT)[0]
        transaction = "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000007"
        for symbols, expected in ((b"000 T pcre2_dfa_match_8\n", True), (b"000 T pcre2_match_8\n", False)):
            supervisor = ScriptedSupervisor(
                process_result(stdout=b"10.47\n"),
                process_result(stdout=symbols),
            )
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                root = state / transaction.rsplit(":", 1)[-1]
                library = root / "install" / "lib" / "libpcre2-8.so.0.14.0"
                library.parent.mkdir(parents=True)
                library.write_bytes(b"fixture")
                provider = build_certified_providers(
                    (definition,), state, supervisor=supervisor
                )[0]
                observations = {
                    item.probe_id: item for item in provider.smoke_verify(
                        definition.lifecycle, str(root), transaction
                    )
                }
                self.assertTrue(observations["pcre2-version"].passed)
                self.assertEqual(observations["pcre2-dfa-symbol"].passed, expected)

    def test_pcre_recipe_and_provider_require_one_loadable_shared_library(self) -> None:
        definition = next(item for item in load_certified_recipes(ROOT) if item.selection_key == "pcre2-ordinary")
        parameters = definition.parameters
        configuration = {item.name: item.value for item in definition.lifecycle.expected_configuration}
        self.assertEqual(parameters["cmake-build-shared-libs"], "ON")
        self.assertEqual(configuration["library-linkage"], "shared")

        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary) / "install"
            library_directory = install / "lib"
            library_directory.mkdir(parents=True)
            (library_directory / "libpcre2-8.a").write_bytes(b"static")
            with self.assertRaisesRegex(ProviderOperationError, "shared library was not installed"):
                Pcre2SourceProvider._library(install)

            shared = library_directory / "libpcre2-8.so.0.13.0"
            shared.write_bytes(b"shared")
            (library_directory / "libpcre2-8.so").symlink_to(shared.name)
            self.assertEqual(Pcre2SourceProvider._library(install), shared.resolve())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            install = root / "install"
            library_directory = install / "lib"
            library_directory.mkdir(parents=True)
            outside = root / "outside.so"
            outside.write_bytes(b"outside")
            (library_directory / "libpcre2-8.so").symlink_to(outside)
            with self.assertRaisesRegex(ProviderOperationError, "outside the install root"):
                Pcre2SourceProvider._library(install)

    def test_mysql_recipe_pins_global_regex_time_limit(self) -> None:
        definition = next(item for item in load_certified_recipes(ROOT) if item.selection_key == "mysql-regex")
        configuration = {item.name: item.value for item in definition.lifecycle.expected_configuration}
        self.assertEqual(definition.parameters["regexp-time-limit-ms"], "1000")
        self.assertEqual(configuration["regexp-time-limit-ms"], "1000")
        self.assertIn("mysql-regexp-time-limit", definition.lifecycle.smoke_probe_ids)


    def test_planning_is_nonmutating_and_binds_provider_implementation(self) -> None:
        definition = load_certified_recipes(ROOT)[0]
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "absent"
            provider = build_certified_providers((definition,), state)[0]
            plan = provider.plan(definition.lifecycle)
            self.assertIsInstance(plan, ProviderPlan)
            self.assertFalse(plan.mutation_permitted)
            self.assertFalse(state.exists())
            self.assertTrue(plan.plan_token.startswith("sha256:"))
            self.assertEqual(len(provider.descriptor.implementation_digest), 64)

    def test_interrupted_acquisition_and_artifact_substitution_rollback_cleanly(self) -> None:
        content = b"pinned"
        definition = tiny_definition(content)
        for fetcher, expected_code in ((StaticFetcher(content, fail=True), "interrupted-download"), (StaticFetcher(b"wrong"), "artifact-identity-mismatch")):
            with self.subTest(expected_code=expected_code), tempfile.TemporaryDirectory() as temporary:
                provider = CpythonArchiveProvider(definition, Path(temporary), fetcher=fetcher)
                manager = EnvironmentManager(ProviderRegistry((provider,)))
                planned = manager.plan(definition.lifecycle, provider.descriptor.name)
                admitted = manager.admit(planned, AdmissionDecision(True, "fixture-admission", "fixture resources admitted"))
                realized = manager.realize(admitted)
                self.assertEqual(realized.state, "failed")
                self.assertEqual(realized.failure.code, expected_code)
                self.assertTrue(realized.rollback.succeeded)
                self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_safe_extraction_rejects_traversal_escaping_link_and_expansion_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            traversal = root / "traversal.tar.gz"
            make_archive(traversal, [("../escape", b"x")])
            with self.assertRaisesRegex(ProviderOperationError, "escaped"):
                _safe_extract(traversal, root / "out-one", 1024)
            link = root / "link.tar.gz"
            make_archive(link, [("safe", b"x")], symlink=("escape-link", "../../outside"))
            with self.assertRaisesRegex(ProviderOperationError, "link escaped"):
                _safe_extract(link, root / "out-two", 1024)
            pressure = root / "pressure.tar.gz"
            make_archive(pressure, [("large", b"x" * 2048)])
            with self.assertRaisesRegex(ProviderOperationError, "expanded-size"):
                _safe_extract(pressure, root / "out-three", 1024)

    def test_safe_extraction_allows_only_a_directory_root_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "root-marker.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                marker = tarfile.TarInfo(".")
                marker.type = tarfile.DIRTYPE
                archive.addfile(marker)
            _safe_extract(archive_path, root / "output", 1024)
            self.assertTrue((root / "output").is_dir())

    def test_python_archive_setup_script_is_preserved_but_never_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.tar.gz"
            make_archive(archive, [("bin/python3.14", b"#!/bin/sh\nexit 0\n"), ("setup.sh", b"touch should-not-exist\n")])
            content = archive.read_bytes()
            definition = tiny_definition(content)
            state = root / "state"
            provider = CpythonArchiveProvider(definition, state, fetcher=StaticFetcher(content))
            transaction = "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000003"
            acquisition = provider.acquire(definition.lifecycle, provider.plan(definition.lifecycle), transaction)
            handle = provider.construct(definition.lifecycle, acquisition, transaction)
            metadata = json.loads((Path(handle) / "provider-state.json").read_text())
            self.assertEqual(metadata["setup_script_policy"], "present-but-never-executed")
            self.assertFalse((Path(handle) / "runtime" / "should-not-exist").exists())
            self.assertTrue(provider.rollback(handle, transaction).succeeded)

    def test_oci_provider_rejects_noncertified_manifest_before_docker_execution(self) -> None:
        definition = tiny_definition(b"manifest", selection="mysql-regex", image="mysql:latest")
        with tempfile.TemporaryDirectory() as temporary:
            provider = MysqlOciProvider(
                definition,
                Path(temporary),
                fetcher=StaticFetcher(b"manifest"),
                supervisor=ScriptedSupervisor(process_result(stdout=b"")),
            )
            transaction = "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000004"
            acquisition = provider.acquire(definition.lifecycle, provider.plan(definition.lifecycle), transaction)
            with self.assertRaisesRegex(ProviderOperationError, "certified platform manifest"):
                provider.construct(definition.lifecycle, acquisition, transaction)
            self.assertTrue(provider.rollback(acquisition.handle, transaction).succeeded)

    def test_oci_client_limits_remain_distinct_from_target_container_limits(self) -> None:
        definition = next(item for item in load_certified_recipes(ROOT) if item.selection_key == "mysql-regex")
        with tempfile.TemporaryDirectory() as temporary:
            provider = MysqlOciProvider(definition, Path(temporary))
            self.assertEqual(definition.limits.memory_bytes, 1073741824)
            self.assertIsNone(provider._cli_limits().memory_bytes)
            self.assertIsNone(provider._cli_limits().cpu_time_seconds)
            self.assertEqual(provider._cli_limits().wall_time_ms, definition.limits.wall_time_ms)

    def test_oci_image_identity_accepts_classic_and_containerd_inspection_shapes(self) -> None:
        definition = next(item for item in load_certified_recipes(ROOT) if item.selection_key == "mysql-regex")
        with tempfile.TemporaryDirectory() as temporary:
            provider = MysqlOciProvider(definition, Path(temporary))
            common = {
                "RepoDigests": [f"mysql@{provider._IMAGE_MANIFEST_DIGEST}"],
                "Os": "linux",
                "Architecture": "amd64",
            }
            self.assertEqual(
                provider._verify_image_identity(
                    {**common, "Id": provider._IMAGE_CONFIG_DIGEST},
                    "classic-handle",
                ),
                provider._IMAGE_CONFIG_DIGEST,
            )
            self.assertEqual(
                provider._verify_image_identity(
                    {
                        **common,
                        "Id": provider._IMAGE_MANIFEST_DIGEST,
                        "Descriptor": {"digest": provider._IMAGE_MANIFEST_DIGEST},
                    },
                    "containerd-handle",
                ),
                provider._IMAGE_CONFIG_DIGEST,
            )
            for inspection in (
                {**common, "Id": "sha256:" + "0" * 64},
                {**common, "Id": provider._IMAGE_MANIFEST_DIGEST},
                {
                    **common,
                    "Id": provider._IMAGE_CONFIG_DIGEST,
                    "Descriptor": {"digest": "sha256:" + "0" * 64},
                },
                {"Id": provider._IMAGE_CONFIG_DIGEST, "RepoDigests": []},
            ):
                with self.subTest(inspection=inspection), self.assertRaisesRegex(
                    ProviderOperationError,
                    "pinned manifest/config pair",
                ):
                    provider._verify_image_identity(inspection, "rejected-handle")

    def test_mysql_readiness_must_survive_temporary_initialization_server_handoff(self) -> None:
        definition = next(item for item in load_certified_recipes(ROOT) if item.selection_key == "mysql-regex")
        temporary_server = [process_result(), process_result(), process_result(exit_code=1)]
        final_server = [process_result() for _ in range(MysqlOciProvider._STABLE_READINESS_OBSERVATIONS)]
        supervisor = ScriptedSupervisor(*temporary_server, *final_server)
        with tempfile.TemporaryDirectory() as temporary:
            provider = MysqlOciProvider(definition, Path(temporary), supervisor=supervisor)
            with (
                patch(
                    "regex_conformance_control_plane.certified_environments.time.monotonic",
                    side_effect=[0, *range(len(temporary_server) + len(final_server))],
                ),
                patch("regex_conformance_control_plane.certified_environments.time.sleep") as sleep,
            ):
                provider._wait_for_stable_service("strling-rc-" + "0" * 32, temporary)

        self.assertEqual(len(supervisor.commands), len(temporary_server) + len(final_server))
        self.assertTrue(
            all(command[:3] == ("docker", "exec", "strling-rc-" + "0" * 32) for command in supervisor.commands)
        )
        self.assertEqual(sleep.call_count, len(supervisor.commands) - 1)

    def test_https_fetcher_rejects_insecure_or_unapproved_locators_without_network(self) -> None:
        fetcher = VerifiedHttpsFetcher()
        for locator in ("http://github.com/runtime", "https://example.invalid/runtime", "https://github.com:444/runtime"):
            requirement = ArtifactRequirement("runtime", "0" * 64, 1, "gzip-tar", (locator,))
            with self.subTest(locator=locator), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(ProviderOperationError, "allowlist"):
                    fetcher.fetch(requirement, Path(temporary) / "artifact")

    def test_cross_host_redirect_strips_authorization_and_same_host_preserves_it(self) -> None:
        handler = _SafeRedirectHandler()
        source = urllib.request.Request(
            "https://registry-1.docker.io/v2/library/mysql/blobs/sha256:abc",
            headers={"Authorization": "Bearer secret"},
        )
        cross_host = handler.redirect_request(
            source, None, 302, "Found", {}, "https://production.cloudfront.docker.com/exact"
        )
        self.assertIsNotNone(cross_host)
        self.assertIsNone(cross_host.get_header("Authorization"))
        same_host = handler.redirect_request(
            source, None, 302, "Found", {}, "https://registry-1.docker.io/v2/library/mysql/blobs/sha256:def"
        )
        self.assertEqual(same_host.get_header("Authorization"), "Bearer secret")

    def test_required_runtime_values_must_be_observed_not_copied(self) -> None:
        required = (NamedValue("locale", "C.UTF-8"),)
        with self.assertRaisesRegex(ProviderOperationError, "did not observe required values"):
            _merge_values(required, [])
        with self.assertRaisesRegex(ProviderOperationError, "more than once"):
            _merge_values(required, [required[0], required[0]])
        self.assertEqual(_merge_values(required, [required[0]]), required)

    def test_recipe_substitution_and_nontransaction_cleanup_handles_fail_closed(self) -> None:
        definition = tiny_definition(b"pinned")
        with tempfile.TemporaryDirectory() as temporary:
            provider = CpythonArchiveProvider(definition, Path(temporary), fetcher=StaticFetcher(b"pinned"))
            substituted = EnvironmentRecipe(
                **{**definition.lifecycle.__dict__, "target_release_id": "rcid:v1:release:u7:019ff999-0000-7000-8000-000000000099"}
            )
            with self.assertRaisesRegex(ProviderOperationError, "different recipe"):
                provider.plan(substituted)
            outcome = provider.rollback(str(Path(temporary)), "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000005")
            self.assertFalse(outcome.succeeded)
            nested = Path(temporary) / "019ff999-0000-7000-8000-000000000005" / "install"
            nested_outcome = provider.rollback(str(nested), "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000005")
            self.assertFalse(nested_outcome.succeeded)
            other_transaction = "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000006"
            other_root = Path(temporary) / other_transaction.rsplit(":", 1)[-1]
            other_root.mkdir()
            cross_transaction = provider.rollback(
                str(other_root), "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000005"
            )
            self.assertFalse(cross_transaction.succeeded)
            self.assertTrue(other_root.is_dir())
            self.assertTrue(provider.rollback(str(other_root), other_transaction).succeeded)

    def test_state_root_symlinks_resolve_and_dangling_transaction_links_fail_cleanup(self) -> None:
        definition = tiny_definition(b"pinned")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "state-target"
            target.mkdir()
            alias = root / "state-alias"
            alias.symlink_to(target, target_is_directory=True)
            provider = CpythonArchiveProvider(definition, alias, fetcher=StaticFetcher(b"pinned"))
            self.assertEqual(provider.state_root, target.resolve())
            transaction = "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000007"
            transaction_root = target / transaction.rsplit(":", 1)[-1]
            transaction_root.symlink_to(root / "missing", target_is_directory=True)
            outcome = provider.rollback(None, transaction)
            self.assertFalse(outcome.succeeded)
            self.assertTrue(transaction_root.is_symlink())

    def test_docker_listing_failure_preserves_state_and_malformed_inspection_is_typed(self) -> None:
        definition = next(item for item in load_certified_recipes(ROOT) if item.selection_key == "mysql-regex")
        transaction = "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000008"
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            transaction_root = state / transaction.rsplit(":", 1)[-1]
            transaction_root.mkdir()
            failed = ScriptedSupervisor(process_result(exit_code=1))
            provider = MysqlOciProvider(definition, state, supervisor=failed)
            outcome = provider.rollback(str(transaction_root), transaction)
            self.assertFalse(outcome.succeeded)
            self.assertTrue(transaction_root.is_dir())
            self.assertEqual(failed.commands[0][:3], ("docker", "ps", "--all"))

        malformed = ScriptedSupervisor(process_result(stdout=b"not-json"))
        with tempfile.TemporaryDirectory() as temporary:
            provider = MysqlOciProvider(definition, Path(temporary), supervisor=malformed)
            with self.assertRaisesRegex(ProviderOperationError, "valid JSON"):
                provider._image_inspection(definition.parameters["image-reference"])

    def test_absent_docker_container_allows_exact_state_cleanup(self) -> None:
        definition = next(item for item in load_certified_recipes(ROOT) if item.selection_key == "mysql-regex")
        transaction = "opid:v1:environment:u7:019ff999-0000-7000-8000-000000000009"
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            transaction_root = state / transaction.rsplit(":", 1)[-1]
            transaction_root.mkdir()
            supervisor = ScriptedSupervisor(process_result(stdout=b""))
            provider = MysqlOciProvider(definition, state, supervisor=supervisor)
            self.assertTrue(provider.rollback(str(transaction_root), transaction).succeeded)
            self.assertFalse(transaction_root.exists())
            self.assertEqual(supervisor.commands[0][:3], ("docker", "ps", "--all"))


if __name__ == "__main__":
    unittest.main()
