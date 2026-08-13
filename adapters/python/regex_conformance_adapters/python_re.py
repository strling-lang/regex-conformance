"""Thin CPython ``re`` invocation and native result serialization."""

from __future__ import annotations

from itertools import islice
import platform
import re
import sys
import unicodedata
from typing import Any

from .backend import RuntimeIdentity, ThinBackend
from .errors import BackendFailure, TargetError, UnsupportedRequest
from .manifest import AdapterManifest
from .model import Datum, ExecuteRequest, absence, span_record


class PythonReBackend(ThinBackend):
    supported_operations = frozenset(
        {
            "capture-extraction",
            "compile",
            "find-all",
            "full-match",
            "next-match",
            "replace-all",
            "replace-once",
            "search",
            "split",
            "test",
        }
    )
    supported_options = frozenset(
        {"ascii", "dotall", "ignore-case", "maximum-splits", "multiline", "unicode", "verbose"}
    )
    supported_environment_inputs = frozenset({"locale", "timezone"})
    supported_domains = frozenset({"octets", "unicode-scalars"})

    def __init__(self, manifest: AdapterManifest) -> None:
        super().__init__(manifest)
        self._identity: RuntimeIdentity | None = None

    def runtime_identity(self) -> RuntimeIdentity:
        if self._identity is None:
            facts = (
                ("implementation", sys.implementation.name),
                ("python-version", platform.python_version()),
                ("unicode-version", unicodedata.unidata_version),
            )
            observed = dict(facts)
            required = dict(self.manifest.runtime_constraints)
            for name in ("implementation", "python-version", "unicode-version"):
                if observed.get(name) != required.get(name):
                    raise BackendFailure(
                        "runtime-identity-mismatch",
                        f"CPython adapter observed {name}={observed.get(name)!r}, expected {required.get(name)!r}",
                    )
            self._identity = RuntimeIdentity(facts)
        return self._identity

    @staticmethod
    def _flag_value(options: dict[str, Any]) -> int:
        flags = 0
        mapping = {
            "ascii": re.ASCII,
            "dotall": re.DOTALL,
            "ignore-case": re.IGNORECASE,
            "multiline": re.MULTILINE,
            "unicode": re.UNICODE,
            "verbose": re.VERBOSE,
        }
        for name, value in options.items():
            if name == "maximum-splits":
                continue
            if not isinstance(value, bool):
                raise UnsupportedRequest("option-value-unsupported", f"Python re option {name!r} requires a boolean")
            if value:
                flags |= mapping[name]
        return flags

    @staticmethod
    def _native_value(datum: Datum) -> bytes | str:
        if datum.domain not in {"octets", "unicode-scalars"} or not isinstance(datum.value, (bytes, str)):
            raise UnsupportedRequest("datum-domain-unsupported", "CPython re accepts only bytes or Unicode scalar strings")
        return datum.value

    @staticmethod
    def _datum(value: bytes | str) -> Datum:
        if isinstance(value, bytes):
            return Datum("octets", value, None, None, 8)
        return Datum("unicode-scalars", value, "unicode-scalar-values", None, None)

    @staticmethod
    def _basis(value: bytes | str) -> tuple[str, str | None, int | None]:
        if isinstance(value, bytes):
            return "octet", None, 8
        return "unicode-scalar", "unicode-scalar-values", None

    def _match_record(
        self,
        match: re.Match[bytes] | re.Match[str],
        *,
        subject: bytes | str,
        ordinal: int,
        capture_history_requested: bool,
    ) -> tuple[dict[str, Any], bool]:
        basis, encoding, width = self._basis(subject)
        provenance = f"CPython {platform.python_version()} re.Match.span"
        names = {index: name for name, index in match.re.groupindex.items()}
        captures: list[dict[str, Any]] = []
        history_not_exposed = False
        for index in range(match.re.groups + 1):
            start, end = match.span(index)
            if start < 0:
                captures.append(
                    {
                        "history": [],
                        "index": index,
                        "name": names.get(index),
                        "participation": "unmatched",
                        "span": None,
                        "value": None,
                    }
                )
                continue
            value = match.group(index)
            assert isinstance(value, (bytes, str))
            span = span_record(
                start,
                end,
                basis=basis,
                provenance=provenance,
                encoding=encoding,
                unit_width_bits=width,
            )
            captures.append(
                {
                    "history": [],
                    "index": index,
                    "name": names.get(index),
                    "participation": "matched",
                    "span": span,
                    "value": self._datum(value).to_record(),
                }
            )
            if capture_history_requested and index > 0:
                history_not_exposed = True
        return {
            "captures": captures,
            "ordinal": ordinal,
            "span": span_record(
                match.start(),
                match.end(),
                basis=basis,
                provenance=provenance,
                encoding=encoding,
                unit_width_bits=width,
            ),
        }, history_not_exposed

    def _compile(self, request: ExecuteRequest) -> tuple[re.Pattern[bytes] | re.Pattern[str] | None, TargetError | None]:
        pattern = self._native_value(request.pattern)
        flags = self._flag_value(request.option_map())
        try:
            return re.compile(pattern, flags), None
        except re.error as error:
            diagnostic = str(error).encode("utf-8", "replace")
            return None, TargetError(
                type(error).__name__,
                getattr(error, "msg", None),
                str(error),
                "compile",
                getattr(error, "pos", None),
                diagnostic,
            )

    def _selected_matches(
        self,
        compiled: re.Pattern[bytes] | re.Pattern[str],
        request: ExecuteRequest,
        subject: bytes | str,
    ) -> list[re.Match[bytes] | re.Match[str]]:
        if request.operation == "full-match":
            if request.occurrence != 1:
                return []
            candidate = compiled.fullmatch(subject, request.start_offset)
            return [] if candidate is None else [candidate]
        iterator = compiled.finditer(subject, request.start_offset)
        if request.operation in {"find-all"}:
            start = request.occurrence - 1
            return list(islice(iterator, start, start + request.maximum_matches))
        occurrence = request.occurrence
        for index, candidate in enumerate(iterator, start=1):
            if index == occurrence:
                return [candidate]
        return []

    def execute(self, request: ExecuteRequest) -> dict[str, Any]:
        self.runtime_identity()
        self.validate_request(request)
        subject = self._native_value(request.subjects[0])
        pattern = self._native_value(request.pattern)
        if type(pattern) is not type(subject):
            raise UnsupportedRequest("datum-domain-mismatch", "CPython re pattern and subject domains must match")
        if request.replacement is not None and type(self._native_value(request.replacement)) is not type(subject):
            raise UnsupportedRequest("datum-domain-mismatch", "CPython re replacement and subject domains must match")
        if (
            request.operation in {"replace-all", "replace-once", "split"}
            and (request.start_offset != 0 or request.occurrence != 1)
        ):
            raise UnsupportedRequest(
                "initial-state-unsupported",
                "CPython re replacement and split APIs cannot preserve non-default initial state",
            )
        compiled, compile_error = self._compile(request)
        if compile_error is not None:
            return self.target_error_observation(request, compile_error)
        assert compiled is not None
        observation = self.base_observation(request)
        observation["compile_status"] = "accepted"
        if request.operation == "compile":
            observation["match_state"] = "not-applicable"
            observation["absences"] = [
                absence("cursor", "not-requested"),
                absence("matches", "not-requested"),
                absence("outputs", "not-requested"),
            ]
            return observation
        observation["execution_status"] = "completed"
        if request.operation in {"replace-all", "replace-once"}:
            assert request.replacement is not None
            replacement = self._native_value(request.replacement)
            count = 0 if request.operation == "replace-all" else 1
            try:
                replaced = compiled.sub(replacement, subject, count=count)
            except re.error as error:
                return self.target_error_observation(
                    request,
                    TargetError(type(error).__name__, getattr(error, "msg", None), str(error), "execution", getattr(error, "pos", None), str(error).encode()),
                )
            output_size = len(replaced if isinstance(replaced, bytes) else replaced.encode("utf-8"))
            if output_size > request.maximum_output_bytes:
                raise UnsupportedRequest("output-limit-exceeded", "replacement output exceeds the explicit adapter bound")
            observation["outputs"] = {"kind": "replacement", "values": [self._datum(replaced).to_record()]}
            matches = self._selected_matches(compiled, request, subject)
        elif request.operation == "split":
            split_limit = request.option_map().get("maximum-splits", 0)
            if (
                isinstance(split_limit, bool)
                or not isinstance(split_limit, int)
                or not 0 <= split_limit <= request.maximum_matches
            ):
                raise UnsupportedRequest(
                    "option-value-unsupported",
                    "Python re maximum-splits must be an integer from zero through maximum-matches",
                )
            native_limit = split_limit if split_limit > 0 else request.maximum_matches + 1
            pieces = compiled.split(subject, maxsplit=native_limit)
            if split_limit == 0 and len(pieces) > request.maximum_matches + 1:
                raise UnsupportedRequest("result-limit-exceeded", "split result exceeds the explicit match bound")
            output_size = sum(len(item if isinstance(item, bytes) else item.encode("utf-8")) for item in pieces)
            if output_size > request.maximum_output_bytes:
                raise UnsupportedRequest("output-limit-exceeded", "split output exceeds the explicit adapter bound")
            observation["outputs"] = {"kind": "split", "values": [self._datum(item).to_record() for item in pieces]}
            matches = self._selected_matches(compiled, request, subject)
        else:
            matches = self._selected_matches(compiled, request, subject)
        records: list[dict[str, Any]] = []
        history_not_exposed = False
        for ordinal, match in enumerate(matches):
            member, missing_history = self._match_record(
                match,
                subject=subject,
                ordinal=ordinal,
                capture_history_requested="capture-history" in request.requested_observations,
            )
            records.append(member)
            history_not_exposed = history_not_exposed or missing_history
        observation["matches"] = records
        observation["match_state"] = "match" if records else "no-match"
        if request.operation in {"next-match", "find-all"} or "cursor" in request.requested_observations:
            if records:
                final = records[-1]["span"]
                next_offset = final["end"] if final["end"] > final["start"] else min(final["end"] + 1, len(subject))
                exhausted = final["end"] == len(subject) and final["start"] == final["end"]
            else:
                next_offset = len(subject)
                exhausted = True
            observation["cursor"] = {
                "exhausted": exhausted,
                "initial_offset": request.start_offset,
                "next_offset": next_offset,
            }
        else:
            observation["absences"].append(absence("cursor", "not-requested"))
        if history_not_exposed:
            observation["absences"].append(absence("matches.captures.history", "not-exposed"))
        observation["absences"] = sorted(observation["absences"], key=lambda item: (item["field"], item["reason"]))
        return observation
