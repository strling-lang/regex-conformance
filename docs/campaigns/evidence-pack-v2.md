# Evidence Pack v2

Evidence Pack v2 is the production authoritative raw-evidence representation
adopted by D103. It stores empirical information, not repeated JSON envelopes.
Exact observations and physical attempts remain independent facts even when
they point to the same content-addressed input, result, diagnostic, or
provenance object. Parquet, warehouses, summaries, percentiles, and charts are
regenerable analytics and are not pack authority.

The measured certification report is
[`reports/scale/evidence-pack-v2-certification.json`](../../reports/scale/evidence-pack-v2-certification.json).
Rebuild it read-only from the immutable P19 campaign root with:

```sh
python tools/campaigns/compile_evidence_pack_v2.py --evidence-root <P19-campaign-root> --check
```

An optional `--pack-output` may materialize the measured raw pack only to a
root outside the repository. Existing content-addressed bytes are never
replaced.

## Physical representation

The manifest names independent SHA-256-addressed XZ objects and is published
last. Object roles include shared canonical execution definitions, exact result
templates, diagnostic payloads and envelopes, provenance contexts, the compact
typed token dictionary, and columnar blocks for logical executions,
observations, physical attempts, diagnostic availability, and raw performance
samples. Long RCIDs, UUIDs, hashes, timestamps, enum strings, and repeated
metadata use typed dictionary references. The pack preserves enough
information to regenerate every legacy canonical member and its applicable
content identity.

The immutable manifest conforms to
`evidence-pack-v2-manifest.schema.json`. Attempt diagnostics conform to the
ordered 35-field `attempt-diagnostic-envelope.v2` contract. Each field records
one of four two-bit availability states: unavailable, observed, derived, or
observed absence/not-applicability. A successful attempt with no diagnostic is
therefore a compact fact. Emitted stdout, stderr, native diagnostics, and error
payloads may be exact content-addressed values, so identical blobs are stored
once without merging their attempts.

`raw-performance-samples.v2` stores non-negative integer arrays in bytes,
counts, or nanoseconds. It distinguishes governed benchmarks from ordinary
operational timing. Averages, percentiles, confidence intervals, rankings, and
cross-engine claims remain derived.

## Measured P19 certification

The production encoder measured all 807 immutable P19 members (386,855,397
bytes), 100,000 logical observations, and 100,500 physical attempts. The pack
is 3,318,573 bytes across 208 objects including its manifest:

| Evidence class | Retained bytes |
| --- | ---: |
| Canonical inputs | 266,500 |
| Semantic results | 143,408 |
| Physical-attempt facts | 152,848 |
| Diagnostics | 69,352 |
| Performance/resource samples | 13,300 |
| Manifests/integrity | 314,973 |
| Shared dictionary/CAS | 2,358,192 |

That is 33.185730000 bytes per logical execution and 33.020626866 bytes per
physical attempt. Certification performed two identical encodings, exact
source-byte reconstruction, applicable legacy identity/hash recomputation,
corruption injection, distinct-attempt and distinct-observation checks, and
random lookup bounded to at most 35 object reads. Both non-crediting P19
infrastructure-attempt segments remain present.

The certified identities are:

- pack digest: `d236a89599e85b1b1dfaadc8e09cd2907fe4f351d782c068ff7ed5aa58365a06`;
- manifest SHA-256: `6811186f105199f03cc65fad90edc4f9af318ac17ed52c2a42a52a08cb07530d`;
- report digest: `112ce2a3d2496680ed3132372047b979b2375d6a04a6fc7f7eab7ea4bf7d4bee`.

## D103 capacity and platform admission

The full-universe forecast preserves the P20-T01A historical denominators and
adds the D103 1.25 governed-canary multiplier. It also reserves retry growth,
expanded diagnostic and raw-performance growth, 500 MB for triggered targeted
platform expansion, and 500 MB for general program growth.

| Case | Retained bytes |
| --- | ---: |
| Lower | 1,144,491,043 |
| Expected | 2,828,274,280 |
| Conservative | 6,757,260,454 |

The conservative case includes 150,292,902 logical executions, 157,807,548
physical attempts, and 312,832 objects. It leaves 1,242,739,546 bytes below the
8 GB operational soft stop and 3,242,739,546 bytes below the 10 GB absolute
hard cap.

Every materially plausible platform/backend dimension receives a governed
canary. Diagnostic-only, infrastructure-noise, or performance-only differences
do not expand semantic coverage. A material semantic difference identifies its
exact profile/feature/operation/backend scope, computes incremental pack bytes,
and must pass capacity admission before only that scope expands. An admission
at or above 8 GB requires Program Owner review; one above 10 GB is rejected.

## Publication contract

`r2_publication.py` turns a certified pack into a manifest-last plan. It uses
immutable content-addressed keys, conditional creation, Standard storage,
immediate exact GET/SHA-256/size verification, and a synchronous SQLite receipt
ledger. Capacity and request admission occur before the first request. Normal
operation and recovery never use LIST. Only a failed or indeterminate request
is retried; a pre-existing key is accepted only after exact read-back.

The manual trusted workflow publishes two stable non-corpus canary objects to
prove authentication, write, read-back, idempotence, and fresh-ledger exact-key
recovery. Repeated canaries reuse the same keys and do not grow retained bytes.
It is not a material evidence publication path and cannot run from a pull
request or non-`main` revision.
