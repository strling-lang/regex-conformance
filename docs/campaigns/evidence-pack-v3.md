# Compact Evidence Pack v3

Evidence Pack v3 is the authoritative raw-evidence representation for future
regex conformance campaigns. It replaces the previous container layout without
altering any completed immutable pack. Its measured capacity certification is
[`evidence-pack-v3-capacity-certification.json`](../../reports/scale/evidence-pack-v3-capacity-certification.json).

Raw evidence means exact empirical information and provenance, not repeated
JSON envelopes or randomly assigned bookkeeping labels. The format preserves
each logical execution, observation, and physical attempt as an independent
fact even when many facts reference the same exact input, result, diagnostic,
or environment value.

## Retained-fact contract

Every future pack retains or deterministically reconstructs:

- canonical logical inputs and the immutable compiler/definition binding used
  to derive them;
- one independently identifiable observation for every credited logical
  execution;
- every physical attempt, attempt number, retry, infrastructure failure, and
  interruption;
- exact match, capture, capture-history, span, replacement, split, native-error,
  and operation results;
- emitted and exceptional diagnostic payloads and their truncation, redaction,
  timeout, containment, and attribution facts; routine clean process envelopes
  are represented by a success marker plus an ordered stdout-fact commitment;
- raw performance and resource values;
- profile, release, backend, adapter, runtime, environment, vector, campaign,
  partition, and shard provenance;
- anomaly, discrepancy, replication, validity, trust, and transition
  relationships; and
- content identities, a closed manifest, per-block hashes, and compression
  checks sufficient for independent corruption detection and reconstruction.

Analytical warehouses, Parquet files, aggregates, percentiles, confidence
intervals, charts, and rankings remain derived and regenerable. They are not
authoritative raw evidence.

## Representation

The root manifest names immutable SHA-256-addressed XZ blocks. A typed binary
token table stores hashes, identifiers, timestamps, enums, object shapes, and
other repeated values compactly. UUIDv7 values in legacy reconstruction mode
use timestamp deltas plus packed 74-bit random fields. Production blocks use
global cross-partition content pools, common-case columnar streams, sparse
exception streams, and four-partition lookup groups. Exact result and
diagnostic equality permits physical deduplication but never asserts semantic
equivalence or merges independent observations.

Canonical logical rows are regenerated from the hash-bound campaign manifest,
canonical definitions, and versioned compiler. The production encoder proved
that regeneration reproduces all 4,003 million-campaign logical segments and
exactly 1,000,000 inputs. A lookup reads the root manifest and at most two
content blocks; whole-corpus decompression and bucket listing are unnecessary.

Observation and attempt identities are deterministic content identities:

```text
observation = SHA-256(campaign manifest, partition, shard, logical index)
attempt = SHA-256(campaign manifest, partition, shard, logical index, attempt number)
```

The attempt number prevents a retry from collapsing into its predecessor. The
partition, shard, and logical coordinate prevents two independent observations
from collapsing merely because their result payloads are byte-identical.

## Exact byte-cost model

The completed million-scale staging corpus contains 64 manifests, 2,450 unique
content-addressed objects, 1,000,000 logical observations, and 1,016,750
physical attempts. Evidence Pack v2 retains 36,643,494 unique bytes:

| Evidence class | v2 bytes |
| --- | ---: |
| Canonical inputs and logical facts | 3,227,228 |
| Semantic results | 1,231,820 |
| Physical attempts | 1,530,632 |
| Diagnostics | 685,972 |
| Performance/resource samples | 111,224 |
| Manifests/integrity | 4,943,166 |
| Shared dictionary/CAS | 24,913,452 |

The 6,042 object-descriptor occurrences carry 20,347 member-path occurrences.
Those paths alone occupy 2,192,757 UTF-8 bytes, and their JSON structures
occupy 2,264,538 bytes. The 64 dictionaries contain 2,109,147 strings, of which
2,089,677 are unique. Most importantly, 2,016,750 assigned UUIDv7 labels carry
at least 149,239,500 random bits (18,654,938 bytes) that cannot compress away.
Those random labels do not add empirical information: the immutable execution
coordinates already distinguish the observations and attempts.

Result, diagnostic, performance, attempt, and provenance values are treated as
empirical information even when they happen to repeat. Paths, repeated schema
and environment text, assigned labels, per-partition dictionaries, descriptor
JSON, and compression framing are structural representation costs.

## Lossless redesign checkpoint

Before changing the retained-information contract, an exact legacy
reconstruction format was measured. It applies global dictionaries and CAS
pools, UUIDv7 bit packing, cross-partition block grouping, exact logical-input
derivation, and root/per-block integrity while retaining enough information to
recreate every v2 manifest and object byte-for-byte.

| Metric | Evidence Pack v2 | Exact-lossless redesign | Savings |
| --- | ---: | ---: | ---: |
| Measured million retained bytes | 36,643,494 | 24,612,119 | 12,031,375 |
| Bytes per logical execution | 36.643494000 | 24.612119000 | 12.031375000 |
| Lower combined forecast | 8,091,359,853 | 5,699,645,219 | 2,391,714,634 |
| Expected combined forecast | 27,412,922,254 | 19,316,952,120 | 8,095,970,134 |
| Conservative combined forecast | 77,638,551,735 | 55,028,414,206 | 22,610,137,529 |

The million measurement saves 32.833591142%. The conservative structural
saving is 29.122307183%. Deterministic second encoding, exact manifest/object
reconstruction, SHA-256 recomputation, XZ corruption injection, and three-read
lookup all passed. The six-figure campaign comparison reconstructed all 807 source members in
2,701,259 bytes, 18.601790589% below its Evidence Pack v2 representation.

The exact-lossless conservative program would still exceed the 10 GB hard cap
by 45,028,414,206 bytes. A retention-contract decision was therefore required.

## Minimum retained-information change

The future production contract no longer stores exactly four kinds of
information:

1. randomly assigned UUIDv7 labels for observations;
2. randomly assigned UUIDv7 labels for physical attempts; and
3. paths, manifest facts, and object hashes whose only meaning is the byte
   layout of a hypothetical Evidence Pack v2 container; and
4. repeated fields in a routine clean process envelope: completed outcome,
   exit code zero, null diagnostic, empty stderr digest/count, false authority
   flags, and directly stored per-process stdout digest/count.

The measured million pack drops 1,000,000 observation labels, 1,016,750
attempt labels, 64 old-container manifest facts, and the repeated fields from
42,473 routine clean process records. It does **not** drop any execution,
observation, attempt, semantic result, performance sample, provenance
relationship, anomaly, retry, interruption, release, profile, vector, backend,
facility, feature, historical line, platform canary, or non-routine diagnostic.

The capability loss is precise: a future v3 pack cannot reproduce the random
UUID strings or the old v2 byte layout. A particular routine process stdout
digest or length is not directly retained. A success marker restores the
constant clean-envelope fields; independently regenerating canonical stdout can
restore the omitted per-process fields, and one ordered whole-pack SHA-256
commitment, record count, and aggregate byte count verify the complete
regenerated stdout stream.
Stable coordinate-derived identities replace the random labels, and v3
block/root identities replace the old container identity. Existing v2 evidence
remains immutable and exactly decodable.

| Change | Measured million saving | Conservative forecast saving | Capability lost |
| --- | ---: | ---: | --- |
| Replace assigned observation/attempt UUIDv7 labels with derived identities and adopt v3 container identity | 21,742,894 | 47,245,878,197 | Random label strings and hypothetical v2 container-byte reproduction only |
| Summarize routine clean process envelopes; preserve one ordered stdout commitment | 1,493,103 from the restored v3 measurement | 7,107,004,686 in the feature-complete forecast | Direct per-process lookup of a routine stdout digest/count; independent regeneration is required to restore it |

The routine-process rule was selected only after a less consequential
availability-grid candidate was measured. That candidate reduced the million
pack to 2,534,691 bytes but left the feature-complete conservative forecast at
12,966,651,733 bytes, so it was insufficient. Removing diagnostics,
performance samples, attempts, semantic results, historical vectors, platform
canaries, releases, profiles, features, or facilities was rejected.

## Final capacity forecast

The production implementation measures 1,376,122 bytes for the million corpus,
or 1.376122000 bytes per logical execution and 1.353451685 bytes per physical
attempt, across 87 objects including the manifest. The conservative forecast
includes the completed qualification packs, 10% diagnostic growth, 5%
performance growth, and a 1,000,000,000-byte targeted/general reserve.

The deterministic measured-pack manifest is
`08f0ccc30a02ebaaca82259ca28940d1c6702508a84b1d3bdc7780c8e0dabcce`;
its content digest is
`209825c04cf89afc3344b7ca1f594c0741aebda7cd4255fb21409c1552556971`.

| Case | Logical executions | Physical attempts | Objects / Class A / Class B | Retained bytes | Soft-stop headroom | Hard-cap headroom |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Lower | 242,584,122 | 242,584,122 | 21,005 | 359,989,652 | 7,640,010,348 | 9,640,010,348 |
| Expected | 785,450,951 | 789,378,214 | 67,703 | 1,158,107,579 | 6,841,892,421 | 8,841,892,421 |
| Conservative | 2,000,652,267 | 2,100,684,892 | 172,193 | **4,234,896,306** | **3,765,103,694** | **5,765,103,694** |

Normal LIST requests are zero. The semantic-feature-complete denominator is
larger than the older declared-cutoff denominator in the table: its current
conservative forecast is 7,452,076,843 bytes with 547,923,157 bytes below the
soft stop. Every campaign still requires exact pre-publication admission and
must fail closed before the 8 GB operational stop or 10 GB absolute cap. This
certification authorizes neither execution nor publication.

## Validation

The compact report and arithmetic are deterministic:

```powershell
.\.venv\Scripts\python.exe tools\campaigns\certify_compact_evidence.py --check
.\.venv\Scripts\python.exe -m unittest tests.campaign.test_evidence_pack_v3 -v
```

An operator with the completed read-only staging tree can rebuild the entire
million corpus under the production encoder and independently compare every
measured class:

```powershell
.\.venv\Scripts\python.exe tools\campaigns\certify_compact_evidence.py `
  --check `
  --million-staging <external-evidence-pack-v2-staging>
```

An optional `--pack-output` must resolve outside Git. It creates only a
disposable local v3 representation and performs no Cloudflare request.
