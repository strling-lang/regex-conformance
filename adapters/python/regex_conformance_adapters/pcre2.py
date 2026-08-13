"""Thin PCRE2 8-bit ordinary-matcher binding through the public C ABI."""

from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
from typing import Any

from .backend import RuntimeIdentity, ThinBackend
from .errors import BackendFailure, TargetError, UnsupportedRequest
from .manifest import AdapterManifest
from .model import Datum, ExecuteRequest, absence, span_record

PCRE2_ANCHORED = 0x80000000
PCRE2_ENDANCHORED = 0x20000000
PCRE2_CASELESS = 0x00000008
PCRE2_DOTALL = 0x00000020
PCRE2_EXTENDED = 0x00000080
PCRE2_MULTILINE = 0x00000400
PCRE2_UCP = 0x00020000
PCRE2_UNGREEDY = 0x00040000
PCRE2_UTF = 0x00080000
PCRE2_NOTEMPTY_ATSTART = 0x00000008
PCRE2_ERROR_NOMATCH = -1
PCRE2_INFO_CAPTURECOUNT = 4
PCRE2_INFO_NAMECOUNT = 17
PCRE2_INFO_NAMEENTRYSIZE = 18
PCRE2_INFO_NAMETABLE = 19
PCRE2_CONFIG_VERSION = 11
PCRE2_UNSET = ctypes.c_size_t(-1).value


class Pcre2Backend(ThinBackend):
    supported_operations = frozenset(
        {"capture-extraction", "compile", "find-all", "full-match", "next-match", "search", "test"}
    )
    supported_options = frozenset(
        {"caseless", "dotall", "extended", "multiline", "ucp", "ungreedy", "utf"}
    )
    supported_environment_inputs = frozenset({"locale", "newline", "timezone"})
    supported_domains = frozenset({"octets"})

    def __init__(self, manifest: AdapterManifest, library: Path) -> None:
        super().__init__(manifest)
        original = library.expanduser()
        if not original.is_absolute() or original.is_symlink():
            raise BackendFailure("runtime-library-unsafe", "PCRE2 adapter requires an absolute non-link library path")
        resolved = original.resolve(strict=True)
        if not resolved.is_file() or "libpcre2-8.so" not in resolved.name:
            raise BackendFailure("runtime-library-invalid", "PCRE2 adapter did not receive an 8-bit shared library")
        self.library_path = resolved
        try:
            self._library = ctypes.CDLL(str(resolved))
        except OSError as error:
            raise BackendFailure("runtime-library-load-failed", "PCRE2 shared library could not be loaded") from error
        self._bind()
        self._identity: RuntimeIdentity | None = None

    def _bind(self) -> None:
        self._compile = self._library.pcre2_compile_8
        self._compile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
        ]
        self._compile.restype = ctypes.c_void_p
        self._code_free = self._library.pcre2_code_free_8
        self._code_free.argtypes = [ctypes.c_void_p]
        self._code_free.restype = None
        self._match_data_create = self._library.pcre2_match_data_create_from_pattern_8
        self._match_data_create.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._match_data_create.restype = ctypes.c_void_p
        self._match_data_free = self._library.pcre2_match_data_free_8
        self._match_data_free.argtypes = [ctypes.c_void_p]
        self._match_data_free.restype = None
        self._match = self._library.pcre2_match_8
        self._match.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_size_t,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._match.restype = ctypes.c_int
        self._ovector = self._library.pcre2_get_ovector_pointer_8
        self._ovector.argtypes = [ctypes.c_void_p]
        self._ovector.restype = ctypes.POINTER(ctypes.c_size_t)
        self._pattern_info = self._library.pcre2_pattern_info_8
        self._pattern_info.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        self._pattern_info.restype = ctypes.c_int
        self._error_message = self._library.pcre2_get_error_message_8
        self._error_message.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        self._error_message.restype = ctypes.c_int
        self._config = self._library.pcre2_config_8
        self._config.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        self._config.restype = ctypes.c_int

    def runtime_identity(self) -> RuntimeIdentity:
        if self._identity is None:
            buffer = ctypes.create_string_buffer(128)
            result = self._config(PCRE2_CONFIG_VERSION, ctypes.cast(buffer, ctypes.c_void_p))
            if result < 0:
                raise BackendFailure("runtime-identity-failed", "PCRE2 version query failed")
            version = buffer.value.decode("ascii", "strict").split()[0]
            required = dict(self.manifest.runtime_constraints)
            if version != required.get("engine-version"):
                raise BackendFailure(
                    "runtime-identity-mismatch",
                    f"PCRE2 adapter observed engine-version={version!r}, expected {required.get('engine-version')!r}",
                )
            self._identity = RuntimeIdentity(
                (
                    ("engine-version", version),
                    ("library-sha256", hashlib.sha256(self.library_path.read_bytes()).hexdigest()),
                    ("runtime-kind", "pcre2"),
                )
            )
        return self._identity

    @staticmethod
    def _native(datum: Datum) -> bytes:
        if datum.domain != "octets" or not isinstance(datum.value, bytes):
            raise UnsupportedRequest("datum-domain-unsupported", "PCRE2 8-bit adapter accepts octets only")
        return datum.value

    @staticmethod
    def _buffer(value: bytes) -> ctypes.Array[ctypes.c_char]:
        return ctypes.create_string_buffer(value, len(value) + 1)

    @staticmethod
    def _compile_options(values: dict[str, Any]) -> int:
        flags = {
            "caseless": PCRE2_CASELESS,
            "dotall": PCRE2_DOTALL,
            "extended": PCRE2_EXTENDED,
            "multiline": PCRE2_MULTILINE,
            "ucp": PCRE2_UCP,
            "ungreedy": PCRE2_UNGREEDY,
            "utf": PCRE2_UTF,
        }
        result = 0
        for name, value in values.items():
            if not isinstance(value, bool):
                raise UnsupportedRequest("option-value-unsupported", f"PCRE2 option {name!r} requires a boolean")
            if value:
                result |= flags[name]
        return result

    def _message(self, code: int) -> str:
        buffer = ctypes.create_string_buffer(1024)
        size = self._error_message(code, ctypes.cast(buffer, ctypes.c_void_p), len(buffer))
        if size < 0:
            return f"PCRE2 error {code}"
        return buffer.raw[:size].decode("utf-8", "replace")

    def _compiled(self, request: ExecuteRequest) -> tuple[int | None, TargetError | None, int]:
        pattern = self._native(request.pattern)
        options = self._compile_options(request.option_map())
        pattern_buffer = self._buffer(pattern)
        error_code = ctypes.c_int()
        error_offset = ctypes.c_size_t()
        code = self._compile(
            ctypes.cast(pattern_buffer, ctypes.c_void_p),
            len(pattern),
            options,
            ctypes.byref(error_code),
            ctypes.byref(error_offset),
            None,
        )
        if not code:
            message = self._message(error_code.value)
            return None, TargetError(
                "pcre2_compile_error",
                error_code.value,
                message,
                "compile",
                error_offset.value,
                message.encode("utf-8"),
            ), options
        return int(code), None, options

    def _capture_count(self, code: int) -> int:
        count = ctypes.c_uint32()
        if self._pattern_info(code, PCRE2_INFO_CAPTURECOUNT, ctypes.byref(count)) < 0:
            raise BackendFailure("pattern-info-failed", "PCRE2 capture count query failed")
        return count.value

    def _names(self, code: int) -> dict[int, str]:
        count = ctypes.c_uint32()
        size = ctypes.c_uint32()
        table = ctypes.c_void_p()
        if self._pattern_info(code, PCRE2_INFO_NAMECOUNT, ctypes.byref(count)) < 0:
            raise BackendFailure("pattern-info-failed", "PCRE2 name count query failed")
        if count.value == 0:
            return {}
        if self._pattern_info(code, PCRE2_INFO_NAMEENTRYSIZE, ctypes.byref(size)) < 0:
            raise BackendFailure("pattern-info-failed", "PCRE2 name entry size query failed")
        if self._pattern_info(code, PCRE2_INFO_NAMETABLE, ctypes.byref(table)) < 0 or table.value is None:
            raise BackendFailure("pattern-info-failed", "PCRE2 name table query failed")
        raw = ctypes.string_at(table.value, count.value * size.value)
        result: dict[int, str] = {}
        for index in range(count.value):
            entry = raw[index * size.value : (index + 1) * size.value]
            number = int.from_bytes(entry[:2], "big")
            result[number] = entry[2:].split(b"\0", 1)[0].decode("utf-8", "replace")
        return result

    @staticmethod
    def _advance_after_empty(subject: bytes, offset: int, utf: bool) -> int:
        if offset >= len(subject):
            return offset
        offset += 1
        if utf:
            while offset < len(subject) and subject[offset] & 0xC0 == 0x80:
                offset += 1
        return offset

    def _match_records(
        self,
        code: int,
        request: ExecuteRequest,
        subject: bytes,
        compile_options: int,
    ) -> tuple[list[dict[str, Any]], int, bool, TargetError | None]:
        match_data = self._match_data_create(code, None)
        if not match_data:
            raise BackendFailure("match-data-allocation-failed", "PCRE2 match-data allocation failed")
        subject_buffer = self._buffer(subject)
        capture_count = self._capture_count(code)
        names = self._names(code)
        records: list[dict[str, Any]] = []
        wanted_occurrence = request.occurrence
        offset = request.start_offset
        empty_retry = False
        exhausted = False
        seen = 0
        try:
            while len(records) < request.maximum_matches:
                match_options = 0
                if request.operation == "full-match":
                    match_options |= PCRE2_ANCHORED | PCRE2_ENDANCHORED
                if empty_retry:
                    match_options |= PCRE2_NOTEMPTY_ATSTART | PCRE2_ANCHORED
                result = self._match(
                    code,
                    ctypes.cast(subject_buffer, ctypes.c_void_p),
                    len(subject),
                    offset,
                    match_options,
                    match_data,
                    None,
                )
                if result == PCRE2_ERROR_NOMATCH:
                    if empty_retry:
                        next_offset = self._advance_after_empty(subject, offset, bool(compile_options & PCRE2_UTF))
                        if next_offset == offset:
                            exhausted = True
                            break
                        offset = next_offset
                        empty_retry = False
                        continue
                    exhausted = True
                    break
                if result < 0:
                    message = self._message(result)
                    return records, offset, exhausted, TargetError(
                        "pcre2_match_error", result, message, "execution", offset, message.encode("utf-8")
                    )
                ovector = self._ovector(match_data)
                start = int(ovector[0])
                end = int(ovector[1])
                seen += 1
                include = seen >= wanted_occurrence
                captures: list[dict[str, Any]] = []
                for index in range(capture_count + 1):
                    capture_start = int(ovector[index * 2])
                    capture_end = int(ovector[index * 2 + 1])
                    if capture_start == PCRE2_UNSET or capture_end == PCRE2_UNSET:
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
                    else:
                        captures.append(
                            {
                                "history": [],
                                "index": index,
                                "name": names.get(index),
                                "participation": "matched",
                                "span": span_record(
                                    capture_start,
                                    capture_end,
                                    basis="octet",
                                    provenance="PCRE2 8-bit pcre2_get_ovector_pointer",
                                    unit_width_bits=8,
                                ),
                                "value": Datum("octets", subject[capture_start:capture_end], None, None, 8).to_record(),
                            }
                        )
                if include:
                    records.append(
                        {
                            "captures": captures,
                            "ordinal": len(records),
                            "span": span_record(
                                start,
                                end,
                                basis="octet",
                                provenance="PCRE2 8-bit pcre2_get_ovector_pointer",
                                unit_width_bits=8,
                            ),
                        }
                    )
                if request.operation not in {"find-all"}:
                    break
                offset = end
                empty_retry = start == end
                if offset == len(subject) and empty_retry:
                    # One anchored non-empty retry is still required at the terminal offset.
                    continue
            return records, offset, exhausted, None
        finally:
            self._match_data_free(match_data)

    def execute(self, request: ExecuteRequest) -> dict[str, Any]:
        self.runtime_identity()
        self.validate_request(request)
        code, compile_error, compile_options = self._compiled(request)
        if compile_error is not None:
            return self.target_error_observation(request, compile_error)
        assert code is not None
        try:
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
            subject = self._native(request.subjects[0])
            records, offset, exhausted, match_error = self._match_records(code, request, subject, compile_options)
            if match_error is not None:
                return self.target_error_observation(request, match_error)
            observation["execution_status"] = "completed"
            observation["matches"] = records
            observation["match_state"] = "match" if records else "no-match"
            if request.operation in {"find-all", "next-match"} or "cursor" in request.requested_observations:
                observation["cursor"] = {
                    "exhausted": exhausted,
                    "initial_offset": request.start_offset,
                    "next_offset": offset,
                }
            else:
                observation["absences"].append(absence("cursor", "not-requested"))
            if "capture-history" in request.requested_observations and self._capture_count(code) > 0:
                observation["absences"].append(absence("matches.captures.history", "not-exposed"))
            observation["absences"] = sorted(
                observation["absences"], key=lambda item: (item["field"], item["reason"])
            )
            return observation
        finally:
            self._code_free(code)
