from __future__ import annotations

import unittest

from support import manifest, request, scalar, validate_schema
from regex_conformance_adapters.mysql_regex import MysqlRegexBackend, SqlResult
from regex_conformance_adapters.server import AdapterServer


class ScriptedSqlExecutor:
    def __init__(self, *results: SqlResult) -> None:
        self.results = list(results)
        self.statements: list[str] = []

    def run(self, statement: str, *, wall_time_ms: int, output_bytes: int, diagnostic_bytes: int) -> SqlResult:
        self.statements.append(statement)
        if not self.results:
            raise AssertionError("unexpected SQL invocation")
        return self.results.pop(0)


def success(value: str) -> SqlResult:
    return SqlResult(0, (value + "\n").encode(), b"")


def mysql_request(package, **changes):
    value = request(
        package,
        options=[{"name": "match-type", "value": "c"}],
        environment=[
            {"name": "character-set", "value": "utf8mb4"},
            {"name": "collation", "value": "utf8mb4_0900_ai_ci"},
            {"name": "regexp-time-limit-ms", "value": 1000},
            {"name": "timezone", "value": "UTC"},
        ],
        **changes,
    )
    return value


class MysqlRegexAdapterTests(unittest.TestCase):
    def response(self, executor: ScriptedSqlExecutor, value):
        backend = MysqlRegexBackend(manifest("mysql-regex"), executor)
        result = AdapterServer(backend).execute(value)
        validate_schema(result, "adapter-response.schema.json")
        return result

    def test_search_preserves_mysql_character_positions_and_backend_opacity(self) -> None:
        package = manifest("mysql-regex")
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"), success("2\t3"))
        result = self.response(
            executor,
            mysql_request(package, pattern=scalar("😀"), subject=scalar("A😀B"), observations=["captures", "match-state", "runtime-identity", "spans"]),
        )
        span = result["observation"]["matches"][0]["span"]
        self.assertEqual((span["start"], span["end"], span["basis"]), (1, 2, "unicode-scalar"))
        self.assertIn(
            {"field": "matches.captures.subgroups", "reason": "not-exposed"},
            result["observation"]["absences"],
        )

    def test_requested_occurrence_controls_match_state_without_regexp_like_shortcut(self) -> None:
        package = manifest("mysql-regex")
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"), success("0\t0"))
        value = mysql_request(package, pattern=scalar("a"), subject=scalar("a"))
        value["initial_state"]["occurrence"] = 2
        result = self.response(executor, value)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["observation"]["match_state"], "no-match")
        self.assertEqual(result["observation"]["matches"], [])
        self.assertIn(",2,0,'c')", executor.statements[-1])

    def test_pattern_and_subject_are_hex_materialized_not_sql_interpolated(self) -> None:
        package = manifest("mysql-regex")
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"), success("0\t0"))
        dangerous = "'; DROP TABLE evidence; --"
        result = self.response(executor, mysql_request(package, pattern=scalar(dangerous), subject=scalar("safe")))
        self.assertEqual(result["status"], "completed")
        statement = executor.statements[-1]
        self.assertNotIn(dangerous, statement)
        self.assertIn(dangerous.encode().hex().upper(), statement)

    def test_invalid_pattern_is_native_compile_rejection(self) -> None:
        package = manifest("mysql-regex")
        diagnostic = b"ERROR 3692 (HY000) at line 1: Mismatched parenthesis in regular expression.\n"
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"), SqlResult(1, b"", diagnostic))
        result = self.response(executor, mysql_request(package, pattern=scalar("(")))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["observation"]["compile_status"], "rejected")
        self.assertEqual(result["observation"]["native_error"]["code"], 3692)

    def test_service_connection_failure_remains_adapter_infrastructure(self) -> None:
        package = manifest("mysql-regex")
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"), SqlResult(1, b"", b"ERROR 2002 (HY000) at line 1: Cannot connect\n"))
        result = self.response(executor, mysql_request(package))
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["observation"])
        self.assertEqual(result["failure"]["code"], "mysql-service-unavailable")

    def test_replacement_output_is_typed_and_query_uses_certified_server_limit(self) -> None:
        package = manifest("mysql-regex")
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"), success("625863"), success("2\t5"))
        result = self.response(
            executor,
            mysql_request(
                package,
                operation="replace-all",
                pattern=scalar("a+"),
                subject=scalar("baaac"),
                replacement=scalar("X"),
                observations=["match-state", "replacement-output", "runtime-identity"],
            ),
        )
        self.assertEqual(result["observation"]["outputs"]["values"][0]["text"], "bXc")
        self.assertEqual(executor.statements[0], "SELECT VERSION(), @@GLOBAL.regexp_time_limit")
        self.assertTrue(all("SET " not in statement for statement in executor.statements))
        self.assertIn(
            {"name": "regexp-time-limit-ms", "value": "1000"},
            result["observation"]["runtime_identity"]["facts"],
        )

    def test_missing_behavioral_environment_or_match_type_is_unsupported(self) -> None:
        package = manifest("mysql-regex")
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"))
        result = self.response(executor, request(package))
        self.assertEqual(result["status"], "unsupported")
        value = mysql_request(package)
        next(item for item in value["environment_inputs"] if item["name"] == "regexp-time-limit-ms")["value"] = 999
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"))
        result = self.response(executor, value)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(executor.statements, ["SELECT VERSION(), @@GLOBAL.regexp_time_limit"])
        executor = ScriptedSqlExecutor(success("8.4.10\t999"))
        result = self.response(executor, mysql_request(package))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["failure"]["code"], "runtime-identity-mismatch")
        self.assertEqual(executor.statements, ["SELECT VERSION(), @@GLOBAL.regexp_time_limit"])

        value = mysql_request(package, operation="replace-all", replacement=scalar("X"))
        value["initial_state"]["occurrence"] = 2
        executor = ScriptedSqlExecutor(success("8.4.10\t1000"))
        result = self.response(executor, value)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(executor.statements, ["SELECT VERSION(), @@GLOBAL.regexp_time_limit"])

    def test_compile_only_and_capture_extraction_are_not_fabricated(self) -> None:
        package = manifest("mysql-regex")
        for operation in ("compile", "capture-extraction"):
            executor = ScriptedSqlExecutor(success("8.4.10\t1000"))
            result = self.response(executor, mysql_request(package, operation=operation))
            self.assertEqual(result["status"], "unsupported")
            self.assertIsNone(result["observation"])


if __name__ == "__main__":
    unittest.main()
