"""Typed providers for the three governed P17 minimal environment recipes.

Recipes select one of the implementations in this module; they never supply
arbitrary commands.  Acquired bytes and realized state live outside Git and the
EnvironmentManager independently verifies every acquired artifact.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import tarfile
import time
from typing import Any, Protocol
import urllib.error
import urllib.parse
import urllib.request

import rfc8785

from .containment import ContainedExecutionResult, ContainedProcessSupervisor, ExecutionLimits
from .environment_manager import BASE_READY_CAPABILITIES
from .environment_models import (
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
from .environment_providers import EnvironmentProvider, ProviderOperationError

_ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
        "github-production-release-asset-2e65be.s3.amazonaws.com",
        "registry-1.docker.io",
        "production.cloudfront.docker.com",
        "auth.docker.io",
    }
)
_OCI_ACCEPT = (
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.docker.distribution.manifest.list.v2+json,"
    "application/vnd.oci.image.manifest.v1+json,"
    "application/vnd.docker.distribution.manifest.v2+json"
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _strict_load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    if not isinstance(value, dict):
        raise ValueError(f"recipe must be a JSON object: {path}")
    return value


@dataclass(frozen=True)
class CertifiedRecipeDefinition:
    path: Path
    record: dict[str, Any]
    lifecycle: EnvironmentRecipe

    @classmethod
    def load(cls, path: Path) -> "CertifiedRecipeDefinition":
        record = _strict_load(path)
        policy = record["isolation_policy"]
        lifecycle = EnvironmentRecipe(
            recipe_revision_id=record["recipe_revision_id"],
            target_profile_id=record["target_profile_id"],
            target_release_id=record["target_release_id"],
            strategy=record["strategy"],
            artifacts=tuple(
                ArtifactRequirement(
                    item["name"], item["sha256"], item["size_bytes"], item["media_type"], tuple(item["locators"])
                )
                for item in record["artifacts"]
            ),
            expected_runtime_facts=tuple(NamedValue(item["name"], item["value"]) for item in record["expected_runtime_facts"]),
            expected_configuration=tuple(NamedValue(item["name"], item["value"]) for item in record["expected_configuration"]),
            required_capabilities=tuple(record["required_capabilities"]),
            smoke_probe_ids=tuple(record["smoke_probe_ids"]),
            isolation_policy_digest=policy["digest"],
            network_policy="phase-separated",
        )
        return cls(path.resolve(), record, lifecycle)

    @property
    def selection_key(self) -> str:
        return str(self.record["selection_key"])

    @property
    def provider_name(self) -> str:
        return str(self.record["provider_name"])

    @property
    def construction(self) -> dict[str, Any]:
        return self.record["construction"]

    @property
    def parameters(self) -> dict[str, str]:
        return {item["name"]: item["value"] for item in self.construction["parameters"]}

    @property
    def limits(self) -> ExecutionLimits:
        values = self.record["isolation_policy"]["resource_limits"]
        return ExecutionLimits(
            wall_time_ms=values["wall_time_ms"],
            stdout_bytes=values["stdout_bytes"],
            stderr_bytes=values["stderr_bytes"],
            memory_bytes=values["memory_bytes"],
            cpu_time_seconds=values["cpu_time_seconds"],
        )


def load_certified_recipes(repository_root: Path) -> tuple[CertifiedRecipeDefinition, ...]:
    paths = sorted((repository_root / "environments" / "recipes").glob("*.json"))
    definitions = tuple(CertifiedRecipeDefinition.load(path) for path in paths)
    if {item.selection_key for item in definitions} != {"mysql-regex", "pcre2-ordinary", "python-re"}:
        raise ValueError("certified recipe set must exactly cover the governed vertical slice")
    if len({item.lifecycle.recipe_revision_id for item in definitions}) != len(definitions):
        raise ValueError("certified recipe revisions must be unique")
    return tuple(sorted(definitions, key=lambda item: item.selection_key))


class ArtifactFetcher(Protocol):
    def fetch(self, requirement: ArtifactRequirement, destination: Path) -> None: ...


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        _validate_download_url(newurl)
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        source_host = urllib.parse.urlparse(request.full_url).hostname
        target_host = urllib.parse.urlparse(newurl).hostname
        if redirected is not None and source_host != target_host:
            redirected.remove_header("Authorization")
        return redirected


def _validate_download_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _ALLOWED_DOWNLOAD_HOSTS
        or parsed.port not in (None, 443)
        or parsed.username
        or parsed.password
    ):
        raise ProviderOperationError("artifact-locator-denied", "artifact locator left the governed HTTPS host allowlist")


class VerifiedHttpsFetcher:
    """Fetch bounded bytes from allowlisted HTTPS and Docker Registry endpoints."""

    def __init__(self, *, timeout_seconds: int = 120) -> None:
        self._timeout = timeout_seconds
        self._opener = urllib.request.build_opener(_SafeRedirectHandler())
        self._registry_token: str | None = None

    def fetch(self, requirement: ArtifactRequirement, destination: Path) -> None:
        if len(requirement.locators) != 1:
            raise ProviderOperationError("artifact-locator-ambiguous", "certified recipes require one exact artifact locator")
        locator = requirement.locators[0]
        _validate_download_url(locator)
        headers = {"Accept": _OCI_ACCEPT} if requirement.media_type in {"oci-index", "oci-manifest"} else {}
        if urllib.parse.urlparse(locator).hostname == "registry-1.docker.io":
            headers["Authorization"] = f"Bearer {self._docker_token()}"
        request = urllib.request.Request(locator, headers=headers, method="GET")
        partial = destination.with_suffix(destination.suffix + ".part")
        try:
            with self._opener.open(request, timeout=self._timeout) as response, partial.open("xb") as stream:
                total = 0
                while True:
                    chunk = response.read(min(1024 * 1024, requirement.size_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > requirement.size_bytes:
                        raise ProviderOperationError("artifact-size-exceeded", "artifact exceeded its pinned size during transfer")
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if total != requirement.size_bytes:
                raise ProviderOperationError("artifact-size-mismatch", "artifact transfer ended at a non-pinned size")
            os.replace(partial, destination)
        except ProviderOperationError:
            partial.unlink(missing_ok=True)
            raise
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            partial.unlink(missing_ok=True)
            raise ProviderOperationError(
                "artifact-transfer-failed", f"artifact transfer failed: {type(error).__name__}"
            ) from error

    def _docker_token(self) -> str:
        if self._registry_token is not None:
            return self._registry_token
        query = urllib.parse.urlencode(
            {"service": "registry.docker.io", "scope": "repository:library/mysql:pull"}
        )
        url = f"https://auth.docker.io/token?{query}"
        _validate_download_url(url)
        request = urllib.request.Request(url, method="GET")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(64 * 1024)
            payload = json.loads(raw)
            token = payload.get("token")
        except (OSError, urllib.error.URLError, ValueError, AttributeError) as error:
            raise ProviderOperationError("registry-auth-failed", "Docker Registry token acquisition failed") from error
        if not isinstance(token, str) or not token or len(token) > 16 * 1024:
            raise ProviderOperationError("registry-auth-failed", "Docker Registry returned an invalid bearer token")
        self._registry_token = token
        return token


def _implementation_digest() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _safe_value(value: bytes, label: str) -> str:
    try:
        text = value.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ProviderOperationError("runtime-output-invalid", f"{label} output was not UTF-8") from error
    if not text or len(text) > 16_384 or any(character == "\x00" for character in text):
        raise ProviderOperationError("runtime-output-invalid", f"{label} output was empty or unbounded")
    return text


class CertifiedEnvironmentProvider:
    machine_provider_name = "native"

    def __init__(
        self,
        definition: CertifiedRecipeDefinition,
        state_root: Path,
        *,
        fetcher: ArtifactFetcher | None = None,
        supervisor: ContainedProcessSupervisor | None = None,
    ) -> None:
        self.definition = definition
        self.state_root = state_root.expanduser().resolve(strict=False)
        self._fetcher = fetcher or VerifiedHttpsFetcher()
        self._supervisor = supervisor or ContainedProcessSupervisor(maximum_concurrency=1)
        capabilities = tuple(
            ProviderCapability(name, "supported")
            for name in sorted(BASE_READY_CAPABILITIES | set(definition.lifecycle.required_capabilities))
        )
        self._descriptor = ProviderDescriptor(
            definition.provider_name,
            definition.lifecycle.strategy,
            _implementation_digest(),
            capabilities,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    def health_check(self) -> ProviderDiagnosis:
        return ProviderDiagnosis("healthy", ("provider implementation loaded",))

    def plan(self, recipe: EnvironmentRecipe) -> ProviderPlan:
        self._require_recipe(recipe)
        construction = self.definition.construction
        token = _canonical_digest(
            {
                "provider": self.descriptor.to_dict(),
                "recipe_revision_id": recipe.recipe_revision_id,
                "construction": construction,
            }
        )
        return ProviderPlan(
            provider_name=self.descriptor.name,
            plan_token=f"sha256:{token}",
            expected_download_bytes=construction["download_upper_bound_bytes"],
            expected_expanded_bytes=construction["expanded_upper_bound_bytes"],
            expected_scratch_bytes=construction["scratch_upper_bound_bytes"],
            diagnostics=(f"hermeticity={construction['hermeticity']}",),
        )

    def acquire(self, recipe: EnvironmentRecipe, plan: ProviderPlan, transaction_id: str) -> ProviderAcquisition:
        self._require_recipe(recipe)
        root = self._transaction_root(transaction_id)
        try:
            root.mkdir(parents=True, exist_ok=False)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            observations: list[ArtifactObservation] = []
            for requirement in recipe.artifacts:
                destination = artifacts / f"{requirement.name}.artifact"
                self._fetcher.fetch(requirement, destination)
                observations.append(ArtifactObservation(requirement.name, str(destination)))
            self._write_metadata(root, {"transaction_id": transaction_id, "selection_key": self.definition.selection_key})
            return ProviderAcquisition(str(root), tuple(observations))
        except ProviderOperationError as error:
            raise ProviderOperationError(error.code, error.message, str(root), error.diagnostics) from error
        except OSError as error:
            raise ProviderOperationError(
                "acquisition-state-failed", f"could not create transaction state: {type(error).__name__}", str(root)
            ) from error

    def construct(self, recipe: EnvironmentRecipe, acquisition: ProviderAcquisition, transaction_id: str) -> str:
        raise NotImplementedError

    def inspect_runtime(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> RuntimeIdentity:
        raise NotImplementedError

    def smoke_verify(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> tuple[SmokeObservation, ...]:
        raise NotImplementedError

    def release(self, handle: str, transaction_id: str) -> ProviderOutcome:
        try:
            self._cleanup_provider_state(self._handle_root(handle, transaction_id), transaction_id)
            return ProviderOutcome(True, ("realized environment released; immutable download cache policy is provider-local",))
        except (OSError, ProviderOperationError) as error:
            return ProviderOutcome(False, (str(error) or type(error).__name__,))

    def rollback(self, handle: str | None, transaction_id: str) -> ProviderOutcome:
        try:
            root = self._transaction_root(transaction_id) if handle is None else self._handle_root(handle, transaction_id)
            self._cleanup_provider_state(root, transaction_id)
            return ProviderOutcome(True, ("partial environment transaction removed",))
        except (OSError, ProviderOperationError) as error:
            return ProviderOutcome(False, (str(error) or type(error).__name__,))

    def diagnose(self, handle: str | None, transaction_id: str) -> ProviderDiagnosis:
        root = self._transaction_root(transaction_id) if handle is None else self._handle_root(handle, transaction_id)
        if root.exists() and not root.is_symlink():
            return ProviderDiagnosis("healthy", ("transaction state is present",))
        if root.is_symlink():
            return ProviderDiagnosis("degraded", ("transaction state is an unsafe symlink",))
        return ProviderDiagnosis("unavailable", ("transaction state is absent",))

    def _require_recipe(self, recipe: EnvironmentRecipe) -> None:
        if recipe.to_dict() != self.definition.lifecycle.to_dict():
            raise ProviderOperationError("recipe-provider-mismatch", "provider was invoked with a different recipe revision")

    def _transaction_root(self, transaction_id: str) -> Path:
        suffix = transaction_id.rsplit(":", 1)[-1]
        if len(suffix) != 36 or any(character not in "0123456789abcdef-" for character in suffix):
            raise ProviderOperationError("transaction-identity-invalid", "provider transaction identity is invalid")
        return self.state_root / suffix

    def _handle_root(self, handle: str, transaction_id: str) -> Path:
        candidate = Path(handle).absolute()
        try:
            candidate.relative_to(self.state_root)
        except ValueError as error:
            raise ProviderOperationError("provider-handle-unsafe", "provider handle escaped the configured state root") from error
        if candidate == self.state_root or candidate.is_symlink():
            raise ProviderOperationError("provider-handle-unsafe", "provider handle is broad or symbolic")
        if candidate.parent != self.state_root:
            raise ProviderOperationError("provider-handle-unsafe", "provider handle is not an exact transaction root")
        if candidate != self._transaction_root(transaction_id):
            raise ProviderOperationError("provider-handle-unsafe", "provider handle belongs to a different transaction")
        return candidate

    def _cleanup_provider_state(self, root: Path, transaction_id: str) -> None:
        if root != self._transaction_root(transaction_id):
            raise ProviderOperationError("provider-cleanup-unsafe", "cleanup root belongs to a different transaction")
        if root.is_symlink():
            raise ProviderOperationError("provider-cleanup-unsafe", "transaction root is symbolic")
        if root.exists():
            if not root.is_dir():
                raise ProviderOperationError("provider-cleanup-unsafe", "transaction root is not a regular directory")
            shutil.rmtree(root)

    @staticmethod
    def _write_metadata(root: Path, update: dict[str, Any]) -> None:
        path = root / "provider-state.json"
        current = _strict_load(path) if path.exists() else {}
        current.update(update)
        encoded = rfc8785.dumps(current) + b"\n"
        temporary = root / "provider-state.json.tmp"
        with temporary.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    @staticmethod
    def _metadata(root: Path) -> dict[str, Any]:
        return _strict_load(root / "provider-state.json")

    def _run(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
        stdin: bytes | None = None,
        limits: ExecutionLimits | None = None,
    ) -> ContainedExecutionResult:
        result = self._supervisor.run(
            command,
            limits=limits or self.definition.limits,
            cwd=None if cwd is None else str(cwd),
            environment=environment,
            stdin=stdin,
        )
        if result.outcome != "completed" or result.exit_code != 0:
            raise ProviderOperationError(
                "contained-command-failed",
                f"contained provider command failed: outcome={result.outcome}, exit={result.exit_code}",
                diagnostics=(
                    f"stdout-sha256={result.stdout_sha256}",
                    f"stderr-sha256={result.stderr_sha256}",
                ),
            )
        return result

    @staticmethod
    def _runtime_identity(
        recipe: EnvironmentRecipe,
        descriptor: ProviderDescriptor,
        facts: list[NamedValue],
        configuration: list[NamedValue],
    ) -> RuntimeIdentity:
        return RuntimeIdentity(
            strategy=recipe.strategy,
            provider_implementation_digest=descriptor.implementation_digest,
            facts=_merge_values(recipe.expected_runtime_facts, facts),
            relevant_configuration=_merge_values(recipe.expected_configuration, configuration),
            isolation_policy_digest=recipe.isolation_policy_digest,
            network_policy=recipe.network_policy,
        )


def _merge_values(required: tuple[NamedValue, ...], observed: list[NamedValue]) -> tuple[NamedValue, ...]:
    expected = {item.name: item for item in required}
    values: dict[str, NamedValue] = {}
    for item in observed:
        if item.name in values:
            raise ProviderOperationError("runtime-identity-duplicate", f"observed {item.name} more than once")
        previous = expected.get(item.name)
        if previous is not None and previous.value != item.value:
            raise ProviderOperationError("runtime-identity-conflict", f"observed {item.name} conflicts with the recipe")
        values[item.name] = item
    missing = sorted(set(expected) - set(values))
    if missing:
        raise ProviderOperationError(
            "runtime-identity-incomplete", f"provider did not observe required values: {', '.join(missing)}"
        )
    return tuple(values[name] for name in sorted(values))


def _safe_extract(archive_path: Path, destination: Path, expanded_limit: int) -> None:
    if destination.exists() or destination.is_symlink():
        raise ProviderOperationError("archive-destination-unsafe", "archive destination already exists")
    destination.mkdir()
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) > 100_000:
                raise ProviderOperationError("archive-member-limit", "archive contains too many members")
            total = 0
            for member in members:
                path = PurePosixPath(member.name)
                root_marker = not path.parts
                if root_marker and member.isdir():
                    continue
                if path.is_absolute() or root_marker or ".." in path.parts or "\x00" in member.name:
                    raise ProviderOperationError("archive-path-unsafe", "archive member escaped the destination")
                if member.isdev() or member.isfifo():
                    raise ProviderOperationError("archive-member-unsafe", "archive contains a device or FIFO")
                if member.isfile():
                    total += member.size
                    if total > expanded_limit:
                        raise ProviderOperationError("archive-expanded-limit", "archive exceeds the expanded-size bound")
                if member.issym() or member.islnk():
                    link = PurePosixPath(member.linkname)
                    combined = (path.parent / link) if member.issym() else link
                    if link.is_absolute() or ".." in combined.parts:
                        raise ProviderOperationError("archive-link-unsafe", "archive link escaped the destination")
            archive.extractall(destination, filter="data")
    except ProviderOperationError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ProviderOperationError("archive-extraction-failed", f"safe archive extraction failed: {type(error).__name__}") from error


def _native_environment(root: Path, *, library: Path | None = None) -> dict[str, str]:
    values = {
        "HOME": str(root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "TZ": "UTC",
    }
    (root / "home").mkdir(exist_ok=True)
    if library is not None:
        values["LD_LIBRARY_PATH"] = str(library)
    return values


class Pcre2SourceProvider(CertifiedEnvironmentProvider):
    def health_check(self) -> ProviderDiagnosis:
        missing = [name for name in ("cmake", "gcc", "make") if shutil.which(name) is None]
        return ProviderDiagnosis("unavailable" if missing else "healthy", tuple(f"missing executable: {name}" for name in missing) or ("CMake toolchain visible",))

    def construct(self, recipe: EnvironmentRecipe, acquisition: ProviderAcquisition, transaction_id: str) -> str:
        self._require_recipe(recipe)
        root = self._handle_root(acquisition.handle, transaction_id)
        source_archive = next(Path(item.path) for item in acquisition.artifacts if item.name == "pcre2-source")
        source_root = root / "source"
        _safe_extract(source_archive, source_root, self.definition.construction["expanded_upper_bound_bytes"])
        source = source_root / "pcre2-10.47"
        if source.is_symlink() or not (source / "CMakeLists.txt").is_file():
            raise ProviderOperationError("source-layout-mismatch", "PCRE2 archive did not contain the pinned source root", str(root))
        build = root / "build"
        install = root / "install"
        environment = _native_environment(root)
        configure = (
            "cmake", "-S", str(source), "-B", str(build),
            f"-DCMAKE_INSTALL_PREFIX={install}", "-DCMAKE_BUILD_TYPE=Release",
            "-DPCRE2_BUILD_PCRE2_8=ON", "-DPCRE2_BUILD_PCRE2_16=OFF", "-DPCRE2_BUILD_PCRE2_32=OFF",
            "-DPCRE2_BUILD_PCRE2GREP=ON", "-DPCRE2_BUILD_TESTS=OFF",
            "-DPCRE2_NEWLINE=LF", "-DPCRE2_SUPPORT_JIT=ON", "-DPCRE2_SUPPORT_UNICODE=ON",
        )
        self._run(configure, cwd=root, environment=environment)
        self._run(("cmake", "--build", str(build), "--parallel", "2"), cwd=root, environment=environment)
        self._run(("cmake", "--install", str(build)), cwd=root, environment=environment)
        for expected in (install / "bin" / "pcre2-config", install / "bin" / "pcre2grep"):
            if expected.is_symlink() or not expected.is_file():
                raise ProviderOperationError("constructed-runtime-missing", "PCRE2 construction omitted a required executable", str(root))
        self._write_metadata(root, {"install": str(install), "state": "constructed"})
        return str(root)

    @staticmethod
    def _library(install: Path) -> Path:
        candidates = sorted(
            item for item in install.rglob("libpcre2-8.*")
            if item.name == "libpcre2-8.a" or ".so" in item.name
        )
        regular = next((item.resolve() for item in candidates if item.resolve().is_file()), None)
        if regular is None:
            raise ProviderOperationError("runtime-library-missing", "PCRE2 8-bit static or shared library was not installed")
        try:
            regular.relative_to(install.resolve())
        except ValueError as error:
            raise ProviderOperationError("runtime-library-unsafe", "PCRE2 library resolved outside the install root") from error
        return regular

    def inspect_runtime(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> RuntimeIdentity:
        root = self._handle_root(handle, transaction_id)
        install = root / "install"
        regular = self._library(install)
        environment = _native_environment(root, library=regular.parent)
        version = _safe_value(self._run((str(install / "bin" / "pcre2-config"), "--version"), environment=environment).stdout, "PCRE2 version")
        if version != "10.47":
            raise ProviderOperationError("runtime-version-mismatch", "PCRE2 runtime version did not match 10.47", handle)
        cache = (root / "build" / "CMakeCache.txt").read_text(encoding="utf-8")
        required_cache = (
            "CMAKE_BUILD_TYPE:STRING=Release", "PCRE2_BUILD_PCRE2_8:BOOL=ON",
            "PCRE2_BUILD_PCRE2_16:BOOL=OFF", "PCRE2_BUILD_PCRE2_32:BOOL=OFF",
            "PCRE2_NEWLINE:STRING=LF", "PCRE2_SUPPORT_JIT:BOOL=ON", "PCRE2_SUPPORT_UNICODE:BOOL=ON",
        )
        if any(value not in cache for value in required_cache):
            raise ProviderOperationError("runtime-configuration-mismatch", "PCRE2 build cache did not prove the pinned configuration", handle)
        compiler = _safe_value(self._run(("gcc", "--version"), environment=environment).stdout, "GCC").splitlines()[0]
        cmake = _safe_value(self._run(("cmake", "--version"), environment=environment).stdout, "CMake").splitlines()[0]
        glibc = _safe_value(self._run(("ldd", "--version"), environment=environment).stdout, "glibc").splitlines()[0]
        architecture = "x86-64" if platform.machine().casefold() in {"x86_64", "amd64"} else platform.machine()
        facts = [
            NamedValue("architecture", architecture), NamedValue("engine-version", version),
            NamedValue("library-sha256", hashlib.sha256(regular.read_bytes()).hexdigest()), NamedValue("runtime-kind", "pcre2"),
        ]
        configuration = [
            NamedValue("build-type", "Release"), NamedValue("cmake-version", cmake),
            NamedValue("code-unit-widths", "8"), NamedValue("compiler-version", compiler),
            NamedValue("glibc-version", glibc), NamedValue("jit", "enabled"),
            NamedValue("locale", environment["LC_ALL"]), NamedValue("newline", "LF"),
            NamedValue("timezone", environment["TZ"]), NamedValue("unicode", "enabled"),
        ]
        return self._runtime_identity(recipe, self.descriptor, facts, configuration)

    def smoke_verify(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> tuple[SmokeObservation, ...]:
        root = self._handle_root(handle, transaction_id)
        install = root / "install"
        regular = self._library(install)
        environment = _native_environment(root, library=regular.parent)
        observations: list[SmokeObservation] = []
        try:
            version = _safe_value(self._run((str(install / "bin" / "pcre2-config"), "--version"), environment=environment).stdout, "PCRE2 version")
            observations.append(SmokeObservation("pcre2-version", version == "10.47", None if version == "10.47" else "unexpected version"))
        except ProviderOperationError:
            observations.append(SmokeObservation("pcre2-version", False, "version probe failed"))
        try:
            self._run((str(install / "bin" / "pcre2grep"), "-q", "a+"), environment=environment, stdin=b"baaac\n")
            observations.append(SmokeObservation("pcre2-ordinary-match", True))
        except ProviderOperationError:
            observations.append(SmokeObservation("pcre2-ordinary-match", False, "ordinary match probe failed"))
        return tuple(sorted(observations, key=lambda item: item.probe_id))


class CpythonArchiveProvider(CertifiedEnvironmentProvider):
    def construct(self, recipe: EnvironmentRecipe, acquisition: ProviderAcquisition, transaction_id: str) -> str:
        self._require_recipe(recipe)
        root = self._handle_root(acquisition.handle, transaction_id)
        archive = next(Path(item.path) for item in acquisition.artifacts if item.name == "cpython-runtime")
        runtime = root / "runtime"
        _safe_extract(archive, runtime, self.definition.construction["expanded_upper_bound_bytes"])
        executable = runtime / "bin" / "python3.14"
        if executable.is_symlink() or not executable.is_file():
            raise ProviderOperationError("constructed-runtime-missing", "CPython archive omitted bin/python3.14", str(root))
        setup = runtime / "setup.sh"
        if setup.is_symlink() or not setup.is_file():
            raise ProviderOperationError("runtime-layout-mismatch", "CPython portable archive omitted its setup marker", str(root))
        self._write_metadata(root, {"setup_script_policy": "present-but-never-executed"})
        self._write_metadata(root, {"runtime": str(runtime), "state": "constructed"})
        return str(root)

    def _python(self, root: Path, code: str) -> ContainedExecutionResult:
        runtime = root / "runtime"
        environment = _native_environment(root, library=runtime / "lib")
        environment.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"})
        return self._run((str(runtime / "bin" / "python3.14"), "-I", "-c", code), environment=environment)

    def inspect_runtime(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> RuntimeIdentity:
        root = self._handle_root(handle, transaction_id)
        code = (
            "import json,os,platform,sys,sysconfig,unicodedata;"
            "print(json.dumps({'configuration':{'locale':os.environ.get('LC_ALL'),"
            "'runtime-layout':'actions-python-versions-portable','timezone':os.environ.get('TZ')},"
            "'facts':{'architecture':platform.machine(),'cache-tag':sys.implementation.cache_tag,"
            "'implementation':sys.implementation.name,'python-version':platform.python_version(),"
            "'soabi':sysconfig.get_config_var('SOABI'),'unicode-version':unicodedata.unidata_version}},sort_keys=True))"
        )
        try:
            payload = json.loads(_safe_value(self._python(root, code).stdout, "CPython identity"))
        except (ValueError, TypeError) as error:
            raise ProviderOperationError("runtime-identity-invalid", "CPython identity output was invalid") from error
        required_facts = {item.name: item.value for item in recipe.expected_runtime_facts}
        required_configuration = {item.name: item.value for item in recipe.expected_configuration}
        if payload != {"configuration": required_configuration, "facts": required_facts}:
            raise ProviderOperationError("runtime-version-mismatch", "CPython runtime or configuration did not match", handle)
        runtime = root / "runtime"
        facts = [NamedValue(name, str(value)) for name, value in sorted(payload["facts"].items())]
        facts.append(NamedValue("executable-sha256", hashlib.sha256((runtime / "bin" / "python3.14").read_bytes()).hexdigest()))
        configuration = [NamedValue(name, str(value)) for name, value in sorted(payload["configuration"].items())]
        return self._runtime_identity(recipe, self.descriptor, facts, configuration)

    def smoke_verify(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> tuple[SmokeObservation, ...]:
        root = self._handle_root(handle, transaction_id)
        probes = {
            "python-version": "import platform,sys;sys.exit(platform.python_version()!='3.14.6')",
            "python-re-match": "import re,sys;sys.exit(re.fullmatch(r'a+','aaa') is None)",
            "python-replacement": "import re,sys;sys.exit(re.sub(r'a+','X','baaac')!='bXc')",
        }
        result: list[SmokeObservation] = []
        for name in sorted(probes):
            try:
                self._python(root, probes[name])
                result.append(SmokeObservation(name, True))
            except ProviderOperationError:
                result.append(SmokeObservation(name, False, "isolated CPython smoke probe failed"))
        return tuple(result)


class MysqlOciProvider(CertifiedEnvironmentProvider):
    machine_provider_name = "docker"

    def _cli_limits(self, wall_time_ms: int | None = None) -> ExecutionLimits:
        values = self.definition.limits
        return ExecutionLimits(
            wall_time_ms or values.wall_time_ms,
            values.stdout_bytes,
            values.stderr_bytes,
        )

    def health_check(self) -> ProviderDiagnosis:
        if shutil.which("docker") is None:
            return ProviderDiagnosis("unavailable", ("docker executable is absent",))
        limits = ExecutionLimits(30_000, 65_536, 65_536)
        try:
            self._run(("docker", "version", "--format", "{{.Server.Version}}"), limits=limits)
        except ProviderOperationError:
            return ProviderDiagnosis("unavailable", ("Docker daemon health check failed",))
        return ProviderDiagnosis("healthy", ("Docker daemon answered a bounded health check",))

    def _container_name(self, transaction_id: str) -> str:
        self._transaction_root(transaction_id)
        return "strling-rc-" + transaction_id.rsplit(":", 1)[-1].replace("-", "")


    def construct(self, recipe: EnvironmentRecipe, acquisition: ProviderAcquisition, transaction_id: str) -> str:
        self._require_recipe(recipe)
        root = self._handle_root(acquisition.handle, transaction_id)
        image = self.definition.parameters["image-reference"]
        if image != "mysql@sha256:870634c634aae968ea1a93e5c094a14e00c692da2ee9bed956b3dfcc7bd08cb0":
            raise ProviderOperationError("oci-reference-mismatch", "MySQL recipe did not name the certified platform manifest", str(root))
        self._run(("docker", "pull", image), limits=self._cli_limits())
        inspection = self._image_inspection(image)
        if inspection.get("Id") != "sha256:9cffaceb9b62d4280247acdb2324b380d2b36208ae34dfe9f0afb62eeaf70f08":
            raise ProviderOperationError("oci-config-substitution", "pulled image config digest did not match the recipe", str(root))
        if (inspection.get("Os"), inspection.get("Architecture")) != ("linux", "amd64"):
            raise ProviderOperationError("oci-platform-mismatch", "pulled image was not linux/amd64", str(root))
        container = self._container_name(transaction_id)
        self._write_metadata(root, {"container": container, "image": image, "state": "pull-complete"})
        command = (
            "docker", "run", "--detach", "--name", container, "--network", "none",
            "--memory", "1073741824", "--memory-swap", "1073741824", "--pids-limit", "256", "--cpus", "2",
            "--tmpfs", "/var/lib/mysql:rw,noexec,nosuid,size=805306368",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=67108864",
            "--env", "MYSQL_ALLOW_EMPTY_PASSWORD=yes", "--env", "LANG=C.UTF-8", "--env", "TZ=UTC",
            image, "--skip-log-bin", "--character-set-server=utf8mb4", "--collation-server=utf8mb4_0900_ai_ci",
        )
        self._run(command, limits=self._cli_limits())
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            check = self._supervisor.run(
                ("docker", "exec", container, "mysqladmin", "ping", "-uroot", "--silent"),
                limits=ExecutionLimits(10_000, 65_536, 65_536),
            )
            if check.outcome == "completed" and check.exit_code == 0:
                self._write_metadata(root, {"state": "constructed"})
                return str(root)
            time.sleep(1)
        raise ProviderOperationError("service-readiness-timeout", "MySQL service did not become ready within 180 seconds", str(root))

    def _image_inspection(self, image: str) -> dict[str, Any]:
        raw = _safe_value(self._run(("docker", "image", "inspect", image, "--format", "{{json .}}"), limits=ExecutionLimits(30_000, 262_144, 65_536)).stdout, "image inspection")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProviderOperationError("oci-inspection-invalid", "Docker image inspection was not valid JSON") from error
        if not isinstance(value, dict):
            raise ProviderOperationError("oci-inspection-invalid", "Docker image inspection was not an object")
        return value

    def _container_inspection(self, container: str) -> dict[str, Any]:
        raw = _safe_value(self._run(("docker", "container", "inspect", container, "--format", "{{json .}}"), limits=self._cli_limits(30_000)).stdout, "container inspection")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ProviderOperationError("oci-inspection-invalid", "Docker container inspection was not valid JSON") from error
        if not isinstance(value, dict):
            raise ProviderOperationError("oci-inspection-invalid", "Docker container inspection was not an object")
        return value

    def _sql(self, transaction_id: str, statement: str) -> str:
        container = self._container_name(transaction_id)
        result = self._run(
            ("docker", "exec", container, "mysql", "-uroot", "--batch", "--skip-column-names", "--execute", statement),
            limits=ExecutionLimits(30_000, 262_144, 262_144),
        )
        return _safe_value(result.stdout, "MySQL query")

    def inspect_runtime(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> RuntimeIdentity:
        root = self._handle_root(handle, transaction_id)
        image = self.definition.parameters["image-reference"]
        container = self._container_name(transaction_id)
        expected_metadata = {
            "container": container,
            "image": image,
            "selection_key": self.definition.selection_key,
            "state": "constructed",
            "transaction_id": transaction_id,
        }
        if self._metadata(root) != expected_metadata:
            raise ProviderOperationError("provider-state-mismatch", "MySQL provider metadata did not match the transaction", handle)
        inspection = self._image_inspection(image)
        container_inspection = self._container_inspection(container)
        host = container_inspection.get("HostConfig", {})
        tmpfs = host.get("Tmpfs", {})
        limits_projection = {
            "memory": host.get("Memory"),
            "memory_swap": host.get("MemorySwap"),
            "nano_cpus": host.get("NanoCpus"),
            "network_mode": host.get("NetworkMode"),
            "pids_limit": host.get("PidsLimit"),
            "tmpfs": tmpfs,
        }
        if (host.get("Memory"), host.get("MemorySwap"), host.get("NanoCpus"), host.get("PidsLimit"), host.get("NetworkMode")) != (1073741824, 1073741824, 2000000000, 256, "none"):
            raise ProviderOperationError("runtime-containment-mismatch", "MySQL daemon-side resource or network limits differed", handle)
        if set(tmpfs) != {"/tmp", "/var/lib/mysql"} or any("noexec" not in value or "nosuid" not in value or "size=" not in value for value in tmpfs.values()):
            raise ProviderOperationError("runtime-containment-mismatch", "MySQL tmpfs containment differed", handle)
        query = self._sql(transaction_id, "SELECT VERSION(), @@character_set_server, @@collation_server")
        fields = query.split("\t")
        if fields != ["8.4.10", "utf8mb4", "utf8mb4_0900_ai_ci"]:
            raise ProviderOperationError("runtime-version-mismatch", "MySQL runtime identity or configuration differed", handle)
        image_env = inspection.get("Config", {}).get("Env", [])
        container_env = container_inspection.get("Config", {}).get("Env", [])
        env_by_name = {item.split("=", 1)[0]: item.split("=", 1)[1] for item in container_env if "=" in item}
        mysql_package = next((item.split("=", 1)[1] for item in image_env if item.startswith("MYSQL_VERSION=")), "")
        if mysql_package != "8.4.10-1.el9":
            raise ProviderOperationError("runtime-package-mismatch", "MySQL image package identity differed", handle)
        provenance = {
            "authority": "oracle-mysql",
            "url": "https://github.com/mysql/mysql-server/blob/mysql-8.4.10/cmake/icu.cmake",
            "claim": "bundled-icu-version",
        }
        if provenance not in self.definition.record["provenance"]:
            raise ProviderOperationError("runtime-provenance-mismatch", "MySQL ICU provenance binding was absent", handle)
        facts = [
            NamedValue("architecture", str(inspection["Architecture"])), NamedValue("icu-version", "77.1"),
            NamedValue("image-config-digest", str(inspection["Id"])), NamedValue("mysql-package-version", mysql_package),
            NamedValue("mysql-version", fields[0]),
        ]
        configuration = [
            NamedValue("character-set-server", fields[1]), NamedValue("collation-server", fields[2]),
            NamedValue("container-limits-sha256", _canonical_digest(limits_projection)),
            NamedValue("container-platform", f"{inspection['Os']}-{inspection['Architecture']}"),
            NamedValue("icu-identity-basis", "verified mysql-8.4.10 bundled source dependency graph"),
            NamedValue("icu-linkage", "bundled"), NamedValue("locale", env_by_name.get("LANG", "")),
            NamedValue("timezone", env_by_name.get("TZ", "")),
        ]
        return self._runtime_identity(recipe, self.descriptor, facts, configuration)

    def smoke_verify(self, recipe: EnvironmentRecipe, handle: str, transaction_id: str) -> tuple[SmokeObservation, ...]:
        root = self._handle_root(handle, transaction_id)
        statements = {
            "mysql-version": ("SELECT VERSION()", "8.4.10"),
            "mysql-regexp-like": ("SELECT REGEXP_LIKE('baaac','a+')", "1"),
            "mysql-regexp-replace": ("SELECT REGEXP_REPLACE('baaac','a+','X')", "bXc"),
            "mysql-icu-boundary": ("SELECT REGEXP_LIKE(_utf8mb4'é', _utf8mb4'[[:alpha:]]')", "1"),
        }
        result: list[SmokeObservation] = []
        for name in sorted(statements):
            statement, expected = statements[name]
            try:
                actual = self._sql(transaction_id, statement)
                result.append(SmokeObservation(name, actual == expected, None if actual == expected else "unexpected SQL result"))
            except ProviderOperationError:
                result.append(SmokeObservation(name, False, "isolated MySQL smoke probe failed"))
        return tuple(result)

    def _cleanup_provider_state(self, root: Path, transaction_id: str) -> None:
        if root != self._transaction_root(transaction_id):
            raise ProviderOperationError("provider-cleanup-unsafe", "MySQL cleanup root belongs to a different transaction")
        container = self._container_name(transaction_id)
        listing = self._run(
            ("docker", "ps", "--all", "--quiet", "--filter", f"name=^/{container}$"),
            limits=ExecutionLimits(30_000, 65_536, 65_536),
        )
        try:
            text = listing.stdout.decode("ascii").strip()
        except UnicodeDecodeError as error:
            raise ProviderOperationError("container-inspection-invalid", "Docker container listing was not ASCII") from error
        identifiers = text.splitlines() if text else []
        if len(identifiers) > 1 or any(
            not 12 <= len(identifier) <= 64
            or any(character not in "0123456789abcdef" for character in identifier)
            for identifier in identifiers
        ):
            raise ProviderOperationError("container-inspection-invalid", "Docker returned an ambiguous container identity")
        if identifiers:
            self._run(("docker", "rm", "--force", container), limits=ExecutionLimits(60_000, 65_536, 65_536))
        super()._cleanup_provider_state(root, transaction_id)


def build_certified_providers(
    definitions: tuple[CertifiedRecipeDefinition, ...],
    state_root: Path,
    *,
    fetcher: ArtifactFetcher | None = None,
    supervisor: ContainedProcessSupervisor | None = None,
) -> tuple[EnvironmentProvider, ...]:
    implementations = {
        "pcre2-ordinary": Pcre2SourceProvider,
        "python-re": CpythonArchiveProvider,
        "mysql-regex": MysqlOciProvider,
    }
    providers: list[EnvironmentProvider] = []
    for definition in definitions:
        implementation = implementations.get(definition.selection_key)
        if implementation is None:
            raise ValueError(f"no typed provider exists for {definition.selection_key}")
        providers.append(
            implementation(definition, state_root, fetcher=fetcher, supervisor=supervisor)
        )
    return tuple(providers)
