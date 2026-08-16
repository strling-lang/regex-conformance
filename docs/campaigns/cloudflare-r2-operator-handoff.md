# Cloudflare R2 operator handoff

This handoff defines the configuration boundary for the accepted production Evidence Pack v2
publisher. It authorizes only the smallest manual non-corpus integration
canary after local gates pass; it does not authorize a material corpus upload.
Do not paste any credential value into Git, Notion, an issue, a pull request, a
terminal transcript, or this task.

## Official provider contract

Cloudflare exposes R2 through the S3-compatible endpoint
`https://<ACCOUNT_ID>.r2.cloudflarestorage.com`; S3 clients use region `auto`.
EU or FedRAMP jurisdiction buckets instead use
`https://<ACCOUNT_ID>.<JURISDICTION>.r2.cloudflarestorage.com`, and a bucket's
jurisdiction cannot later be changed. Automatic placement with no jurisdiction
is the default recommendation unless the Program Owner has a data-residency
requirement. See Cloudflare's [API overview](https://developers.cloudflare.com/r2/api/)
and [data-location reference](https://developers.cloudflare.com/r2/reference/data-location/).

R2 Account API tokens produce an Access Key ID and Secret Access Key. An
Object Read & Write token can be restricted to specified buckets. This is the
smallest Cloudflare permission that supports future `PutObject`, exact-key
`GetObject`, and recovery; the permission also includes list capability, but
the publisher's normal path must not use it. An account token is preferred to a
user token for automation because its lifecycle is tied to the account rather
than an individual user. See Cloudflare's [R2 token reference](https://developers.cloudflare.com/r2/api/tokens/)
and [S3 setup](https://developers.cloudflare.com/r2/get-started/s3/).

The bucket stays private, uses Standard storage, has no custom public domain,
and has no public `r2.dev` access. No public contributor credential is created.
The future publisher uses the direct S3 API so Cloudflare's strong consistency
applies without a cache layer.

## One-time Cloudflare setup

1. In **Storage & databases → R2 → Overview**, create one dedicated private
   Standard bucket. Use a 3–63 character lowercase alphanumeric/hyphen name
   that starts and ends with an alphanumeric character. Record the exact name;
   do not put another project's objects in this bucket.
2. Leave placement Automatic unless an explicit residency requirement exists.
   If a jurisdiction is selected, record it and use its jurisdiction endpoint.
3. Perform one bounded provisioning check that the new dedicated bucket is
   empty. Thereafter, exclusive writer access plus the durable publication
   ledger is the byte-accounting authority; routine full-bucket scans are not
   allowed.
4. Open **Manage R2 API Tokens**, create an **Account API token**, choose
   **Object Read & Write**, and apply it to this specific bucket only.
5. Copy the Access Key ID and Secret Access Key when Cloudflare displays them.
   Store them directly in the destinations below. The secret cannot be viewed
   again after this step.

Bucket names are private by default and follow the current constraints in
Cloudflare's [bucket guide](https://developers.cloudflare.com/r2/buckets/create-buckets/).

## Exact configuration interface

Configure these GitHub Actions repository secrets:

| Secret | Value class |
| --- | --- |
| `STRLING_R2_ACCESS_KEY_ID` | Cloudflare R2 Access Key ID |
| `STRLING_R2_SECRET_ACCESS_KEY` | Cloudflare R2 Secret Access Key |

Configure these GitHub Actions repository variables:

| Variable | Exact value |
| --- | --- |
| `STRLING_R2_ACCOUNT_ID` | Cloudflare account ID containing the dedicated bucket |
| `STRLING_R2_BUCKET_NAME` | Exact dedicated private bucket name |
| `STRLING_R2_ENDPOINT` | Exact default or jurisdiction-specific HTTPS S3 endpoint |
| `STRLING_R2_REGION` | `auto` |

GitHub documents that secrets must be explicitly mapped into a workflow and
that non-sensitive configuration belongs in variables. See
[GitHub Actions secrets](https://docs.github.com/en/actions/concepts/security/secrets)
and [GitHub Actions variables](https://docs.github.com/en/actions/concepts/workflows-and-actions/variables).
The trusted manual canary maps only the two secrets into its protected job,
job, mask derived sensitive values, and run only from trusted protected
revisions. Public-contributor code and untrusted pull requests receive neither
the secrets nor a credential-bearing execution path.

For the local Executioner, store the same two secret values in the operating
system credential store and inject them only into the trusted publisher's
process environment under the same names. Supply the four non-secret values as
local runtime configuration under the same names. Do not commit an `.env` file
or persist secrets in shell profiles. If the local credential store cannot
inject directly, stop and design a reviewed ACL-restricted adapter outside the
repository; do not improvise a plaintext file.

The publication integration verifies that `STRLING_R2_ENDPOINT` contains the
configured account ID, uses HTTPS, and matches any selected jurisdiction before
making a request. It must never log the access key, secret, authorization
header, signed URL, or full exception object if that object can retain request
headers.

## Guardrails the operator acknowledges

- The bucket's project hard cap is 10,000,000,000 bytes; the publisher soft
  stops at 8,000,000,000 bytes.
- Standard storage is mandatory. Infrequent Access and retrieval/minimum
  duration charges are outside this plan.
- The bucket remains private and dedicated, with no independent writers.
- No warehouse, cache, credentials, execution scratch, or public-contributor
  output is uploaded. Exact diagnostics and raw governed performance samples
  required by Evidence Pack v2 are authoritative evidence and remain eligible.
- Normal recovery uses the durable local manifest and exact keys: no repeated
  `LIST`, polling, redundant `HEAD`/`GET`, or broad read-back scan.
- Content-addressed `PutObject` uses `If-None-Match: *`; every new object gets
  one exact read-back SHA-256/size verification; the final manifest is last.
- Crossing a byte, object, request, runtime, retry, RAM, disk, or freshness
  limit pauses or refuses work. It never triggers evidence deletion or a cap
  workaround.
- The six-figure campaign's task-specific authorization expired. This setup does not grant Docker
  authority.
- Configuration and secrets authorize only the bounded manual canary. Material
  publication remains gated by the certified task/campaign workflow and the
  publisher's byte/request admission controls.

## Integration confirmation

Before dispatch, verify only the six configuration names in the
`strling-lang/regex-conformance` repository; never retrieve their values. The
manual workflow must run from `main`, retain read-only repository permissions,
use a hosted runner, and emit only safe object/report digests and request
counts. Success requires two exact immutable objects, immediate read-back,
receipt idempotence, fresh-ledger recovery, and zero LIST requests. Those two
stable canary objects are retained and reused; no cleanup request is necessary.
