"""Thin PCRE2 8-bit DFA-matcher binding through the public C ABI."""

from __future__ import annotations

import ctypes
import hashlib
from typing import Any

from .backend import RuntimeIdentity
from .errors import BackendFailure, TargetError, UnsupportedRequest
from .model import Datum, ExecuteRequest, absence, span_record
from .pcre2 import (
    PCRE2_ANCHORED,
    PCRE2_ENDANCHORED,
    PCRE2_ERROR_NOMATCH,
    Pcre2Backend,
)


class Pcre2DfaBackend(Pcre2Backend):
    """Expose the behaviorally distinct ``pcre2_dfa_match_8`` surface."""

    supported_operations = frozenset({"compile", "full-match", "search", "test"})
    _WORKSPACE_COUNT = 4096
    _MAXIMUM_ALTERNATIVES = 1024

    def _bind(self) -> None:
        super()._bind()
        self._dfa_match_data_create = self._library.pcre2_match_data_create_8
        self._dfa_match_data_create.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        self._dfa_match_data_create.restype = ctypes.c_void_p
        self._dfa_match = self._library.pcre2_dfa_match_8
        self._dfa_match.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_size_t,
        ]
        self._dfa_match.restype = ctypes.c_int

    def runtime_identity(self) -> RuntimeIdentity:
        if self._identity is None:
            buffer = ctypes.create_string_buffer(128)
            result = self._config(11, ctypes.cast(buffer, ctypes.c_void_p))
            if result < 0:
                raise BackendFailure("runtime-identity-failed", "PCRE2 version query failed")
            version = buffer.value.decode("ascii", "strict").split()[0]
            required = dict(self.manifest.runtime_constraints)
            if set(required) != {"engine-version", "matcher-api"}:
                raise BackendFailure(
                    "runtime-identity-mismatch",
                    "PCRE2 DFA manifest must bind exactly engine-version and matcher-api",
                )
            if version != required["engine-version"] or required["matcher-api"] != "pcre2-dfa-match-8":
                raise BackendFailure(
                    "runtime-identity-mismatch",
                    f"PCRE2 DFA runtime constraints {required!r} do not match engine {version!r}",
                )
            self._identity = RuntimeIdentity(
                (
                    ("engine-version", version),
                    ("library-sha256", hashlib.sha256(self.library_path.read_bytes()).hexdigest()),
                    ("matcher-api", "pcre2-dfa-match-8"),
                    ("runtime-kind", "pcre2"),
                )
            )
        return self._identity

    def _match_records(
        self,
        code: int,
        request: ExecuteRequest,
        subject: bytes,
        compile_options: int,
    ) -> tuple[list[dict[str, Any]], int, bool, TargetError | None]:
        del compile_options
        if request.occurrence != 1:
            raise UnsupportedRequest(
                "occurrence-unsupported", "PCRE2 DFA alternatives require the initial occurrence"
            )
        if request.maximum_matches > self._MAXIMUM_ALTERNATIVES:
            raise UnsupportedRequest(
                "match-limit-unsupported",
                f"PCRE2 DFA alternative bound exceeds {self._MAXIMUM_ALTERNATIVES}",
            )
        match_data = self._dfa_match_data_create(request.maximum_matches, None)
        if not match_data:
            raise BackendFailure("match-data-allocation-failed", "PCRE2 DFA match-data allocation failed")
        subject_buffer = self._buffer(subject)
        workspace = (ctypes.c_int * self._WORKSPACE_COUNT)()
        options = PCRE2_ANCHORED | PCRE2_ENDANCHORED if request.operation == "full-match" else 0
        try:
            result = self._dfa_match(
                code,
                ctypes.cast(subject_buffer, ctypes.c_void_p),
                len(subject),
                request.start_offset,
                options,
                match_data,
                None,
                workspace,
                self._WORKSPACE_COUNT,
            )
            if result == PCRE2_ERROR_NOMATCH:
                return [], request.start_offset, True, None
            if result <= 0:
                message = (
                    "PCRE2 DFA result vector was too small"
                    if result == 0
                    else self._message(result)
                )
                return [], request.start_offset, False, TargetError(
                    "pcre2_dfa_match_error",
                    result,
                    message,
                    "execution",
                    request.start_offset,
                    message.encode("utf-8"),
                )
            ovector = self._ovector(match_data)
            records: list[dict[str, Any]] = []
            for ordinal in range(result):
                start = int(ovector[ordinal * 2])
                end = int(ovector[ordinal * 2 + 1])
                native_span = span_record(
                    start,
                    end,
                    basis="octet",
                    provenance="PCRE2 8-bit pcre2_dfa_match alternatives",
                    unit_width_bits=8,
                )
                records.append(
                    {
                        "captures": [
                            {
                                "history": [],
                                "index": 0,
                                "name": None,
                                "participation": "matched",
                                "span": native_span,
                                "value": Datum("octets", subject[start:end], None, None, 8).to_record(),
                            }
                        ],
                        "ordinal": ordinal,
                        "span": native_span,
                    }
                )
            return records, max(item["span"]["end"] for item in records), False, None
        finally:
            self._match_data_free(match_data)

    def execute(self, request: ExecuteRequest) -> dict[str, Any]:
        observation = super().execute(request)
        if observation["compile_status"] == "accepted" and request.operation != "compile":
            observation["absences"].append(absence("matches.captures.subgroups", "not-exposed"))
            observation["absences"] = sorted(
                observation["absences"], key=lambda item: (item["field"], item["reason"])
            )
        return observation
