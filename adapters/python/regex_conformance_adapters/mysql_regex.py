"""Thin MySQL SQL regex-surface invocation with hex-safe typed materialization."""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
import shutil
import subprocess
from typing import Any, Protocol

from .backend import RuntimeIdentity, ThinBackend
from .errors import BackendFailure, TargetError, UnsupportedRequest
from .manifest import AdapterManifest
from .model import Datum, ExecuteRequest, absence, span_record

CONTAINER = re.compile(r"^strling-rc-[0-9a-f]{32}$")
MYSQL_ERROR = re.compile(rb"(?:^|\n)ERROR ([0-9]+)(?: \([^)]+\))? at line [0-9]+: (.*?)(?:\n|$)", re.DOTALL)
CONNECTION_ERRORS = frozenset({2002, 2003, 2006, 2013})


@dataclass(frozen=True)
class SqlResult:
    exit_code: int
    stdout: bytes
    stderr: bytes


class SqlExecutor(Protocol):
    def run(self, statement: str, *, wall_time_ms: int, output_bytes: int, diagnostic_bytes: int) -> SqlResult: ...


class DockerSqlExecutor:
    def __init__(self, container: str) -> None:
        if CONTAINER.fullmatch(container) is None:
            raise BackendFailure("container-identity-invalid", "MySQL adapter container identity is invalid")
        executable = shutil.which("docker")
        if executable is None:
            raise BackendFailure("docker-unavailable", "Docker CLI is unavailable")
        self.container = container
        self.executable = executable

    @staticmethod
    def _environment() -> dict[str, str]:
        values = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": os.environ.get("PATH", ""), "TZ": "UTC"}
        docker_host = os.environ.get("DOCKER_HOST")
        if docker_host is not None:
            if not docker_host.startswith("unix://"):
                raise BackendFailure("docker-endpoint-unsafe", "MySQL adapter permits only a local Unix Docker endpoint")
            values["DOCKER_HOST"] = docker_host
        return values

    def run(self, statement: str, *, wall_time_ms: int, output_bytes: int, diagnostic_bytes: int) -> SqlResult:
        if not isinstance(statement, str) or not statement or "\x00" in statement or len(statement) > 4_194_304:
            raise BackendFailure("sql-statement-invalid", "generated MySQL statement is invalid or too large")
        command = (
            self.executable,
            "exec",
            self.container,
            "mysql",
            "-uroot",
            "--batch",
            "--raw",
            "--skip-column-names",
            "--execute",
            statement,
        )
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=wall_time_ms / 1000,
                env=self._environment(),
            )
        except subprocess.TimeoutExpired as error:
            raise BackendFailure("mysql-client-timeout", "bounded MySQL client invocation timed out") from error
        except OSError as error:
            raise BackendFailure("mysql-client-launch-failed", "MySQL client invocation could not launch") from error
        stdout = completed.stdout
        stderr = completed.stderr
        if len(stdout) > output_bytes:
            raise UnsupportedRequest("output-limit-exceeded", "MySQL target output exceeds the explicit adapter bound")
        if len(stderr) > diagnostic_bytes:
            stderr = stderr[:diagnostic_bytes]
        return SqlResult(completed.returncode, stdout, stderr)


class MysqlRegexBackend(ThinBackend):
    supported_operations = frozenset({"replace-all", "replace-once", "search", "test"})
    supported_options = frozenset({"match-type"})
    supported_environment_inputs = frozenset(
        {"character-set", "collation", "regexp-time-limit-ms", "timezone"}
    )
    supported_domains = frozenset({"unicode-scalars"})

    def __init__(self, manifest: AdapterManifest, executor: SqlExecutor) -> None:
        super().__init__(manifest)
        self.executor = executor
        self._identity: RuntimeIdentity | None = None

    @staticmethod
    def _query_value(result: SqlResult) -> str:
        if result.exit_code != 0:
            raise AssertionError("query value requires successful SQL result")
        try:
            return result.stdout.decode("utf-8", "strict").rstrip("\n")
        except UnicodeDecodeError as error:
            raise BackendFailure("mysql-output-invalid", "MySQL target output is not valid UTF-8") from error

    def runtime_identity(self) -> RuntimeIdentity:
        if self._identity is None:
            result = self.executor.run(
                "SELECT VERSION(), @@GLOBAL.regexp_time_limit",
                wall_time_ms=30_000,
                output_bytes=65_536,
                diagnostic_bytes=65_536,
            )
            if result.exit_code != 0:
                raise BackendFailure("runtime-identity-failed", "MySQL runtime identity query failed")
            fields = self._query_value(result).split("\t")
            if len(fields) != 2:
                raise BackendFailure("runtime-identity-failed", "MySQL runtime identity result was malformed")
            version, regexp_limit = fields
            required = dict(self.manifest.runtime_constraints)
            if (
                version != required.get("mysql-version")
                or regexp_limit != required.get("regexp-time-limit-ms")
            ):
                raise BackendFailure(
                    "runtime-identity-mismatch",
                    "MySQL adapter observed a runtime identity outside its certified manifest constraints",
                )
            self._identity = RuntimeIdentity(
                (
                    ("icu-version-source-bound", required["icu-version-source-bound"]),
                    ("mysql-version", version),
                    ("regexp-time-limit-ms", regexp_limit),
                    ("runtime-kind", "mysql-regex"),
                )
            )
        return self._identity

    @staticmethod
    def _native(datum: Datum) -> str:
        if datum.domain != "unicode-scalars" or not isinstance(datum.value, str):
            raise UnsupportedRequest("datum-domain-unsupported", "MySQL utf8mb4 regex surface accepts Unicode scalar strings")
        return datum.value

    @staticmethod
    def _sql_text(value: str, collation: str) -> str:
        encoded = value.encode("utf-8", "strict").hex().upper()
        return f"(CONVERT(X'{encoded}' USING utf8mb4) COLLATE {collation})"

    @staticmethod
    def _match_type(options: dict[str, Any]) -> str:
        value = options.get("match-type")
        if not isinstance(value, str) or re.fullmatch(r"[cimnu]*", value) is None:
            raise UnsupportedRequest(
                "option-value-unsupported",
                "MySQL match-type must contain only native c/i/m/n/u flags",
            )
        if len(value) != len(set(value)):
            raise UnsupportedRequest("option-value-unsupported", "MySQL match-type flags must be unique")
        return value

    def _environment(self, request: ExecuteRequest) -> str:
        values = request.environment_map()
        if values.get("character-set") != "utf8mb4" or values.get("timezone") != "UTC":
            raise UnsupportedRequest(
                "environment-input-unsupported",
                "MySQL adapter requires explicit utf8mb4 and UTC environment bindings",
            )
        collation = values.get("collation")
        if collation != "utf8mb4_0900_ai_ci":
            raise UnsupportedRequest("collation-unsupported", "MySQL adapter requires the certified server collation")
        regexp_limit = values.get("regexp-time-limit-ms")
        certified_limit = dict(self.manifest.runtime_constraints).get("regexp-time-limit-ms")
        if certified_limit is None or not certified_limit.isdecimal():
            raise BackendFailure("adapter-manifest-invalid", "MySQL adapter manifest has no valid regex time limit")
        if (
            isinstance(regexp_limit, bool)
            or not isinstance(regexp_limit, int)
            or regexp_limit != int(certified_limit)
            or regexp_limit > request.wall_time_ms
        ):
            raise UnsupportedRequest(
                "regexp-time-limit-invalid",
                "MySQL regexp time limit must equal the certified daemon value and fit the supervisor wall limit",
            )
        return collation

    @staticmethod
    def _target_error(result: SqlResult) -> TargetError | None:
        if result.exit_code == 0:
            return None
        match = MYSQL_ERROR.search(result.stderr)
        if match is None:
            raise BackendFailure("mysql-client-failed", "Docker/MySQL client failed without a target SQL diagnostic")
        code = int(match.group(1))
        if code in CONNECTION_ERRORS:
            raise BackendFailure("mysql-service-unavailable", "MySQL client lost the certified target service")
        message = match.group(2).decode("utf-8", "replace").strip()
        phase = "compile" if 3680 <= code <= 3700 else "execution"
        return TargetError("mysql_sql_error", code, message or f"MySQL error {code}", phase, None, result.stderr)

    def _run(self, statement: str, request: ExecuteRequest) -> tuple[str | None, TargetError | None]:
        result = self.executor.run(
            statement,
            wall_time_ms=request.wall_time_ms,
            output_bytes=request.maximum_output_bytes,
            diagnostic_bytes=request.maximum_diagnostic_bytes,
        )
        error = self._target_error(result)
        if error is not None:
            return None, error
        return self._query_value(result), None

    def execute(self, request: ExecuteRequest) -> dict[str, Any]:
        self.runtime_identity()
        self.validate_request(request)
        if request.operation == "replace-all" and request.occurrence != 1:
            raise UnsupportedRequest(
                "initial-state-unsupported",
                "MySQL replace-all has no occurrence parameter and requires the initial occurrence",
            )
        subject = self._native(request.subjects[0])
        pattern = self._native(request.pattern)
        replacement = None if request.replacement is None else self._native(request.replacement)
        collation = self._environment(request)
        match_type = self._match_type(request.option_map())
        subject_sql = self._sql_text(subject, collation)
        pattern_sql = self._sql_text(pattern, collation)
        position = request.start_offset + 1
        occurrence = request.occurrence
        observation = self.base_observation(request)
        observation["compile_status"] = "accepted"
        observation["execution_status"] = "completed"
        if request.operation in {"replace-all", "replace-once"}:
            assert replacement is not None
            replacement_sql = self._sql_text(replacement, collation)
            native_occurrence = 0 if request.operation == "replace-all" else occurrence
            statement = (
                f"SELECT HEX(REGEXP_REPLACE({subject_sql},{pattern_sql},{replacement_sql},"
                f"{position},{native_occurrence},'{match_type}'))"
            )
            output, error = self._run(statement, request)
            if error is not None:
                return self.target_error_observation(request, error)
            assert output is not None
            try:
                decoded = bytes.fromhex(output).decode("utf-8", "strict")
            except (ValueError, UnicodeDecodeError) as decode_error:
                raise BackendFailure("mysql-output-invalid", "MySQL replacement output was not canonical UTF-8 hex") from decode_error
            observation["outputs"] = {
                "kind": "replacement",
                "values": [Datum("unicode-scalars", decoded, "unicode-scalar-values", None, None).to_record()],
            }
        statement = (
            f"SELECT REGEXP_INSTR({subject_sql},{pattern_sql},{position},{occurrence},0,'{match_type}'),"
            f"REGEXP_INSTR({subject_sql},{pattern_sql},{position},{occurrence},1,'{match_type}')"
        )
        output, error = self._run(statement, request)
        if error is not None:
            return self.target_error_observation(request, error)
        assert output is not None
        fields = output.split("\t")
        if len(fields) != 2 or any(re.fullmatch(r"[0-9]+", item) is None for item in fields):
            raise BackendFailure("mysql-output-invalid", "MySQL regex position output was malformed")
        native_start, native_end = (int(item) for item in fields)
        records: list[dict[str, Any]] = []
        if native_start != 0:
            start = native_start - 1
            end = native_end - 1
            span = span_record(
                start,
                end,
                basis="unicode-scalar",
                provenance="MySQL 8.4 REGEXP_INSTR 1-based character position",
                encoding="unicode-scalar-values",
            )
            value = subject[start:end]
            records.append(
                {
                    "captures": [
                        {
                            "history": [],
                            "index": 0,
                            "name": None,
                            "participation": "matched",
                            "span": span,
                            "value": Datum("unicode-scalars", value, "unicode-scalar-values", None, None).to_record(),
                        }
                    ],
                    "ordinal": 0,
                    "span": span,
                }
            )
        observation["matches"] = records
        observation["match_state"] = "match" if native_start != 0 else "no-match"
        observation["absences"].append(absence("matches.captures.subgroups", "not-exposed"))
        if "capture-history" in request.requested_observations:
            observation["absences"].append(absence("matches.captures.history", "not-exposed"))
        if "cursor" in request.requested_observations:
            observation["cursor"] = {
                "exhausted": not bool(records),
                "initial_offset": request.start_offset,
                "next_offset": len(subject) if not records else records[0]["span"]["end"],
            }
        else:
            observation["absences"].append(absence("cursor", "not-requested"))
        observation["absences"] = sorted(
            observation["absences"], key=lambda item: (item["field"], item["reason"])
        )
        return observation
