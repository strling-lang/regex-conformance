"""Bounded immutable publication of Evidence Pack v2 objects to Cloudflare R2."""

from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping, Protocol, Sequence
from urllib import error, parse, request


SOFT_STOP_BYTES = 8_000_000_000
HARD_CAP_BYTES = 10_000_000_000
_ACCOUNT = re.compile(r"^[0-9a-f]{32}$")
_BUCKET = re.compile(r"^(?=.{3,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")
_OBJECT_KEY = re.compile(
    r"^regex-conformance/evidence-pack-v2/[a-z0-9/_-]+/[0-9a-f]{64}\.(?:json|xz)$"
)


class PublicationError(RuntimeError):
    """Publication failed without exposing credential-bearing state."""


class CapacityAdmissionError(PublicationError):
    """A publication would cross an admitted retained-byte boundary."""


class R2TransportError(PublicationError):
    def __init__(self, code: str, *, status: int | None = None, indeterminate: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.indeterminate = indeterminate


@dataclass(frozen=True)
class R2Configuration:
    account_id: str
    bucket_name: str
    endpoint: str
    region: str
    access_key_id: str
    secret_access_key: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "R2Configuration":
        values = os.environ if environment is None else environment
        names = {
            "account_id": "STRLING_R2_ACCOUNT_ID",
            "bucket_name": "STRLING_R2_BUCKET_NAME",
            "endpoint": "STRLING_R2_ENDPOINT",
            "region": "STRLING_R2_REGION",
            "access_key_id": "STRLING_R2_ACCESS_KEY_ID",
            "secret_access_key": "STRLING_R2_SECRET_ACCESS_KEY",
        }
        missing = [name for name in names.values() if not values.get(name)]
        if missing:
            raise PublicationError("r2-configuration-missing:" + ",".join(sorted(missing)))
        config = cls(**{field: values[name] for field, name in names.items()})
        config.validate()
        return config

    def validate(self) -> None:
        if not _ACCOUNT.fullmatch(self.account_id):
            raise PublicationError("r2-account-id-invalid")
        if not _BUCKET.fullmatch(self.bucket_name):
            raise PublicationError("r2-bucket-name-invalid")
        parsed = parse.urlsplit(self.endpoint)
        hostname = (parsed.hostname or "").lower()
        permitted_hosts = {
            f"{self.account_id}.r2.cloudflarestorage.com",
            f"{self.account_id}.eu.r2.cloudflarestorage.com",
            f"{self.account_id}.fedramp.r2.cloudflarestorage.com",
        }
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or parsed.port not in {None, 443}
            or hostname not in permitted_hosts
        ):
            raise PublicationError("r2-endpoint-invalid")
        if self.region != "auto":
            raise PublicationError("r2-region-must-be-auto")
        if not self.access_key_id or not self.secret_access_key:
            raise PublicationError("r2-credential-empty")


@dataclass(frozen=True)
class PutResult:
    created: bool
    etag: str | None


@dataclass(frozen=True)
class GetResult:
    data: bytes
    etag: str | None


class ObjectTransport(Protocol):
    def put_if_absent(self, key: str, data: bytes, *, content_type: str) -> PutResult: ...

    def get_exact(self, key: str) -> GetResult: ...


class R2HttpTransport:
    """Small standard-library AWS Signature V4 client for exact PUT/GET only."""

    def __init__(
        self,
        configuration: R2Configuration,
        *,
        timeout_seconds: int = 30,
        opener: Any | None = None,
    ) -> None:
        configuration.validate()
        if timeout_seconds < 1 or timeout_seconds > 120:
            raise PublicationError("r2-timeout-out-of-range")
        self.configuration = configuration
        self.timeout_seconds = timeout_seconds
        self.opener = opener or request.build_opener()

    @staticmethod
    def _sign(key: bytes, value: str) -> bytes:
        return hmac.new(key, value.encode("utf-8"), hashlib.sha256).digest()

    def _signed_headers(
        self,
        method: str,
        key: str,
        data: bytes,
        headers: Mapping[str, str],
        instant: datetime,
    ) -> tuple[str, dict[str, str]]:
        parsed = parse.urlsplit(self.configuration.endpoint)
        host = parsed.netloc
        encoded_key = parse.quote(key, safe="/-_.~")
        canonical_uri = "/" + parse.quote(self.configuration.bucket_name, safe="-_.~") + "/" + encoded_key
        timestamp = instant.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        day = timestamp[:8]
        payload_digest = hashlib.sha256(data).hexdigest()
        signed = {
            "host": host,
            "x-amz-content-sha256": payload_digest,
            "x-amz-date": timestamp,
            **{name.lower(): " ".join(value.strip().split()) for name, value in headers.items()},
        }
        names = ";".join(sorted(signed))
        canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in sorted(signed))
        canonical_request = "\n".join(
            (method, canonical_uri, "", canonical_headers, names, payload_digest)
        )
        scope = f"{day}/{self.configuration.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            (
                "AWS4-HMAC-SHA256",
                timestamp,
                scope,
                hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
            )
        )
        date_key = self._sign(("AWS4" + self.configuration.secret_access_key).encode("utf-8"), day)
        region_key = self._sign(date_key, self.configuration.region)
        service_key = self._sign(region_key, "s3")
        signing_key = self._sign(service_key, "aws4_request")
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        authorization = (
            "AWS4-HMAC-SHA256 "
            f"Credential={self.configuration.access_key_id}/{scope},"
            f"SignedHeaders={names},Signature={signature}"
        )
        url = self.configuration.endpoint.rstrip("/") + canonical_uri
        outgoing = {name: value for name, value in signed.items() if name != "host"}
        outgoing["Authorization"] = authorization
        outgoing["Host"] = host
        return url, outgoing

    def _open(
        self,
        method: str,
        key: str,
        data: bytes,
        headers: Mapping[str, str],
    ) -> tuple[int, bytes, str | None]:
        url, signed = self._signed_headers(
            method, key, data, headers, datetime.now(timezone.utc)
        )
        outbound = request.Request(
            url,
            data=data if method == "PUT" else None,
            headers=signed,
            method=method,
        )
        try:
            with self.opener.open(outbound, timeout=self.timeout_seconds) as response:
                payload = response.read()
                return response.status, payload, response.headers.get("ETag")
        except error.HTTPError as failure:
            # Do not retain or stringify the exception because it may carry the
            # signed request.  Only the status/classification crosses layers.
            if failure.code == 412 and method == "PUT":
                return 412, b"", failure.headers.get("ETag")
            raise R2TransportError(
                f"r2-http-{failure.code}",
                status=failure.code,
                indeterminate=failure.code >= 500,
            ) from None
        except (error.URLError, TimeoutError, OSError):
            raise R2TransportError("r2-network-indeterminate", indeterminate=True) from None

    def put_if_absent(self, key: str, data: bytes, *, content_type: str) -> PutResult:
        digest = hashlib.md5(data, usedforsecurity=False).digest()
        status, _, etag = self._open(
            "PUT",
            key,
            data,
            {
                "content-md5": b64encode(digest).decode("ascii"),
                "content-type": content_type,
                "if-none-match": "*",
                "x-amz-storage-class": "STANDARD",
            },
        )
        if status == 412:
            return PutResult(False, etag)
        if status not in {200, 201}:
            raise R2TransportError(f"r2-put-status-{status}", status=status)
        return PutResult(True, etag)

    def get_exact(self, key: str) -> GetResult:
        status, data, etag = self._open("GET", key, b"", {})
        if status != 200:
            raise R2TransportError(f"r2-get-status-{status}", status=status)
        return GetResult(data, etag)


@dataclass(frozen=True)
class PublicationItem:
    key: str
    data: bytes
    evidence_class: str
    manifest: bool = False

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def validate(self) -> None:
        if not _OBJECT_KEY.fullmatch(self.key) or ".." in self.key.split("/"):
            raise PublicationError("publication-key-invalid")
        if not isinstance(self.data, bytes):
            raise PublicationError("publication-data-must-be-bytes")
        filename = self.key.rsplit("/", 1)[-1]
        claimed = filename.split(".", 1)[0]
        if not _DIGEST.fullmatch(claimed) or claimed != self.sha256:
            raise PublicationError("publication-key-is-not-exact-content-address")
        if (self.manifest and not filename.endswith(".json")) or (
            not self.manifest and not filename.endswith(".xz")
        ):
            raise PublicationError("publication-key-extension-differs-from-role")
        if not _TOKEN.fullmatch(self.evidence_class):
            raise PublicationError("publication-evidence-class-invalid")


def publication_items_from_evidence_pack(pack: Any) -> list[PublicationItem]:
    """Project a certified pack into its manifest-last publication plan."""

    try:
        objects = list(pack.objects)
        manifest_key = str(pack.manifest_key)
        manifest_bytes = pack.manifest_bytes
    except (AttributeError, TypeError) as error:
        raise PublicationError("evidence-pack-publication-interface-invalid") from error
    items = [
        PublicationItem(
            key=item.key,
            data=item.data,
            evidence_class=item.evidence_class,
        )
        for item in objects
    ]
    items.append(
        PublicationItem(
            key=manifest_key,
            data=manifest_bytes,
            evidence_class="manifests_integrity",
            manifest=True,
        )
    )
    for item in items:
        item.validate()
    return items


class PublicationReceiptLedger:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                object_key TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                evidence_class TEXT NOT NULL,
                etag TEXT,
                verified_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS request_counts (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                class_a INTEGER NOT NULL CHECK(class_a >= 0),
                class_b INTEGER NOT NULL CHECK(class_b >= 0),
                list_requests INTEGER NOT NULL CHECK(list_requests = 0)
            );
            INSERT OR IGNORE INTO request_counts(singleton, class_a, class_b, list_requests)
            VALUES (1, 0, 0, 0);
            CREATE TABLE IF NOT EXISTS publication_attempts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                object_key TEXT NOT NULL,
                attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
                outcome TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );
            """
        )

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "PublicationReceiptLedger":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def receipt(self, key: str) -> tuple[str, int, str] | None:
        row = self.connection.execute(
            "SELECT sha256, size_bytes, evidence_class FROM receipts WHERE object_key = ?",
            (key,),
        ).fetchone()
        return None if row is None else (str(row[0]), int(row[1]), str(row[2]))

    @property
    def retained_bytes(self) -> int:
        row = self.connection.execute("SELECT COALESCE(SUM(size_bytes), 0) FROM receipts").fetchone()
        assert row is not None
        return int(row[0])

    @property
    def retained_bytes_by_evidence_class(self) -> dict[str, int]:
        rows = self.connection.execute(
            "SELECT evidence_class, SUM(size_bytes) FROM receipts GROUP BY evidence_class ORDER BY evidence_class"
        ).fetchall()
        return {str(row[0]): int(row[1]) for row in rows}

    @property
    def request_counts(self) -> dict[str, int]:
        row = self.connection.execute(
            "SELECT class_a, class_b, list_requests FROM request_counts WHERE singleton = 1"
        ).fetchone()
        assert row is not None
        return {"class_a": int(row[0]), "class_b": int(row[1]), "list": int(row[2])}

    @property
    def receipt_count(self) -> int:
        row = self.connection.execute("SELECT COUNT(*) FROM receipts").fetchone()
        assert row is not None
        return int(row[0])

    def increment_request(self, request_class: str, hard_limit: int) -> None:
        column = {"class_a": "class_a", "class_b": "class_b"}.get(request_class)
        if column is None:
            raise PublicationError("publisher-never-permits-list-requests")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.connection.execute(
                f"SELECT {column} FROM request_counts WHERE singleton = 1"
            ).fetchone()
            assert current is not None
            if int(current[0]) + 1 > hard_limit:
                raise PublicationError(f"{request_class}-request-budget-exhausted")
            self.connection.execute(
                f"UPDATE request_counts SET {column} = {column} + 1 WHERE singleton = 1"
            )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def record_attempt(self, key: str, attempt_number: int, outcome: str) -> None:
        if not _TOKEN.fullmatch(outcome):
            raise PublicationError("publication-attempt-outcome-invalid")
        self.connection.execute(
            "INSERT INTO publication_attempts(object_key, attempt_number, outcome, recorded_at) VALUES (?, ?, ?, ?)",
            (key, attempt_number, outcome, datetime.now(timezone.utc).isoformat(timespec="milliseconds")),
        )

    def record_receipt(self, item: PublicationItem, etag: str | None) -> None:
        safe_etag = None if etag is None else etag[:256]
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            previous = self.connection.execute(
                "SELECT sha256, size_bytes, evidence_class FROM receipts WHERE object_key = ?",
                (item.key,),
            ).fetchone()
            expected = (item.sha256, len(item.data), item.evidence_class)
            if previous is not None and tuple(previous) != expected:
                raise PublicationError("publication-receipt-conflicts-with-content")
            self.connection.execute(
                """
                INSERT OR IGNORE INTO receipts(
                    object_key, sha256, size_bytes, evidence_class, etag, verified_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    item.key,
                    item.sha256,
                    len(item.data),
                    item.evidence_class,
                    safe_etag,
                    datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                ),
            )
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise


class EvidencePackPublisher:
    def __init__(
        self,
        transport: ObjectTransport,
        ledger: PublicationReceiptLedger,
        *,
        soft_stop_bytes: int = SOFT_STOP_BYTES,
        hard_cap_bytes: int = HARD_CAP_BYTES,
        class_a_request_limit: int = 1_000_000,
        class_b_request_limit: int = 1_000_000,
        maximum_attempts: int = 2,
        soft_stop_authorized: bool = False,
    ) -> None:
        if not 0 < soft_stop_bytes < hard_cap_bytes <= HARD_CAP_BYTES:
            raise PublicationError("publisher-capacity-limits-invalid")
        if class_a_request_limit < 1 or class_b_request_limit < 1:
            raise PublicationError("publisher-request-limits-invalid")
        if maximum_attempts not in {1, 2, 3}:
            raise PublicationError("publisher-attempt-limit-invalid")
        self.transport = transport
        self.ledger = ledger
        self.soft_stop_bytes = soft_stop_bytes
        self.hard_cap_bytes = hard_cap_bytes
        self.class_a_request_limit = class_a_request_limit
        self.class_b_request_limit = class_b_request_limit
        self.maximum_attempts = maximum_attempts
        self.soft_stop_authorized = soft_stop_authorized

    def _admit(self, items: Sequence[PublicationItem]) -> None:
        unseen_bytes = 0
        for item in items:
            item.validate()
            receipt = self.ledger.receipt(item.key)
            if receipt is None:
                unseen_bytes += len(item.data)
            elif receipt != (item.sha256, len(item.data), item.evidence_class):
                raise PublicationError("publication-plan-conflicts-with-receipt")
        projected = self.ledger.retained_bytes + unseen_bytes
        if projected > self.hard_cap_bytes:
            raise CapacityAdmissionError("publication-would-exceed-absolute-hard-cap")
        if projected >= self.soft_stop_bytes and not self.soft_stop_authorized:
            raise CapacityAdmissionError("publication-reaches-operational-soft-stop")

    def publish(self, items: Sequence[PublicationItem]) -> dict[str, Any]:
        if not items or sum(item.manifest for item in items) != 1 or not items[-1].manifest:
            raise PublicationError("publication-plan-must-end-with-exactly-one-manifest")
        if len({item.key for item in items}) != len(items):
            raise PublicationError("publication-plan-contains-duplicate-keys")
        self._admit(items)
        created = recovered = skipped = 0
        for item in items:
            receipt = self.ledger.receipt(item.key)
            if receipt is not None:
                skipped += 1
                continue
            complete = False
            for attempt_number in range(1, self.maximum_attempts + 1):
                try:
                    self.ledger.increment_request("class_a", self.class_a_request_limit)
                    put = self.transport.put_if_absent(
                        item.key,
                        item.data,
                        content_type=("application/json" if item.manifest else "application/x-xz"),
                    )
                    self.ledger.increment_request("class_b", self.class_b_request_limit)
                    fetched = self.transport.get_exact(item.key)
                    if len(fetched.data) != len(item.data) or hashlib.sha256(fetched.data).hexdigest() != item.sha256:
                        self.ledger.record_attempt(item.key, attempt_number, "readback-integrity-failed")
                        raise PublicationError("publication-readback-integrity-failed")
                    self.ledger.record_receipt(item, fetched.etag or put.etag)
                    outcome = "created" if put.created else "recovered-existing"
                    self.ledger.record_attempt(item.key, attempt_number, outcome)
                    created += int(put.created)
                    recovered += int(not put.created)
                    complete = True
                    break
                except R2TransportError as failure:
                    self.ledger.record_attempt(
                        item.key,
                        attempt_number,
                        "transport-indeterminate" if failure.indeterminate else "transport-failed",
                    )
                    if not failure.indeterminate or attempt_number == self.maximum_attempts:
                        raise PublicationError(failure.code) from None
            if not complete:
                raise PublicationError("publication-attempts-exhausted")
        counts = self.ledger.request_counts
        if counts["list"] != 0:
            raise PublicationError("publication-list-request-invariant-violated")
        return {
            "class_a_requests": counts["class_a"],
            "class_b_requests": counts["class_b"],
            "created_objects": created,
            "list_requests": counts["list"],
            "receipt_count": self.ledger.receipt_count,
            "recovered_existing_objects": recovered,
            "retained_bytes": self.ledger.retained_bytes,
            "retained_bytes_by_evidence_class": self.ledger.retained_bytes_by_evidence_class,
            "skipped_verified_receipts": skipped,
        }
