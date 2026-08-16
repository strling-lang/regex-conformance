# Factorized Raw Evidence Representation

P20-T01B measures whether the P20 storage problem is caused by irreducible
empirical information or by repeating that information in verbose JSON. It is
an evidence-representation investigation, not a campaign, evidence correction,
retention change, or publication operation.

The measured source is the immutable P19 Session 05 corpus bound by evidence
manifest SHA-256
`a2d8d1c460d7822bc2212df41d41842e02202961caad7bc17ca1b68204ae07fa`:

- 402 canonical logical-input segments;
- 404 result/attempt segments, including the two non-crediting
  infrastructure-failure segments;
- one final evidence manifest;
- 100,000 logical executions, 100,500 physical attempts, and 100,000 accepted
  observations; and
- 386,855,397 canonical source bytes across 807 members.

The source root was read only. No P19 member, recovery ledger, report, or
manifest was modified. No target ran, no Docker or credential authority was
used, and no material R2 publication occurred.

## Measured representations

| Representation | Retained bytes | Bytes per logical execution |
| --- | ---: | ---: |
| Canonical JSON members | 386,855,397 | 3,868.553970 |
| Independent gzip-9 members | 31,926,001 | 319.260010 |
| Previously certified P20-T01A tar+gzip-9 | 31,742,126 | 317.421260 |
| Fresh deterministic PAX tar+gzip-9 | 31,742,032 | 317.420320 |
| Deterministic PAX tar+XZ-9 | 16,946,152 | 169.461520 |
| Factorized deterministic binary+XZ-9 | **2,906,175** | **29.061750** |

The 94-byte difference between the previously certified and freshly reproduced
gzip archives is wrapper/container metadata. Both contain the same 807 exact
canonical members; the prior certified value remains the P20-T01A baseline.

The strongest archive allocates its retained bytes as follows:

| Evidence class | Bytes |
| --- | ---: |
| Canonical logical input | 244,843 |
| Raw results and physical attempts | 312,056 |
| Minimal manifest integrity | 159 |
| Shared dictionaries and random-lookup index | 2,349,117 |
| **Total** | **2,906,175** |

Its experimental content identity is
`986633e1c6644a6ca07d84a6256efc72cd12b535ff1f819d37d410bbfcc47348`.
This names reproducible bytes; it records no publication claim.

## Lossless factoring model

The format stores facts once and reconstructs their required repetitions:

1. The 100,000 logical records reference 26 shared logical-coordinate
   templates plus compact planned-repetition ordinals. Logical execution RCIDs
   are recomputed with the accepted JCS identity profile.
2. The 100,000 observations reference 26 exact result-core templates. Fields
   such as logical identity, profile, release, trace, adapter release, and
   process record are omitted only when their exact derivation is proved.
3. Physical attempts and observations use column arrays for local logical
   indexes, UUIDv7 physical/observation IDs, timestamps, infrastructure
   failures, result-template indexes, and process records. Attempt ordinals and
   target-versus-infrastructure outcomes remain independently reconstructible.
4. Profile, release, environment, adapter, vector, provenance, enum, key, and
   other strings share one sorted dictionary. RCID digests, ordinary SHA-256
   digests, UUIDs, and millisecond UTC timestamps have deterministic compact
   binary encodings; records use local varint references and 41 shared object
   shapes.
5. Non-null infrastructure diagnostic payloads are content-deduplicated. Empty
   stream hashes and other repeated diagnostic metadata share dictionary
   entries. Exact per-process stream hashes, byte counts, and all 4,249 raw
   wall-time samples remain present.
6. Observation-content, result-segment, evidence-manifest, and logical content
   identities are recomputed. Canonical member SHA-256 values and paths are
   emitted again from reconstructed bytes. The compact manifest segment catalog
   stores the one integrity/index copy required for lookup and manifest
   reconstruction.
7. Fifty-three XZ-9 payload blocks are independently committed by compressed
   and uncompressed SHA-256. A root footer commits the complete archive.
   Lookup inflates one block for logical/manifest members and at most a result
   block plus its indexed logical block for a result member.

The model retains the distinction between a missing property and a present
empty value. This matters for both attempt-only infrastructure segments, whose
provenance correctly omits `isolated_target_processes`.

## Cross-version and delta investigation

The codec content-addresses result templates globally, so independently
executed versions with identical factored exact results would share one
template without losing their separate release/profile/provenance records.
The P19 corpus contains three independently executed release identities but no
same-facility multi-version comparison that produced an eligible shared exact
result. Measured cross-release sharing credit is therefore zero. The forecast
does not invent a cross-version compression benefit that this corpus cannot
demonstrate, and it does not use a lossy result delta.

## Certification

The compiler performed all of the following before accepting the measurement:

- two independent encodings produced identical archive bytes;
- all 807 members reconstructed byte-for-byte, including the canonical trailing
  newline;
- all reconstructed content-addressed filenames and SHA-256 values matched;
- 100,000 logical identities, 100,000 observation-content identities, 404
  result-segment identities, and the evidence-manifest identity recomputed;
- the two infrastructure segments remained non-crediting and all 500 physical
  infrastructure-failure attempts remained present;
- one logical member, one result member, and the manifest passed indexed random
  lookup with at most two payload blocks inflated; and
- a deliberate archive bit flip was rejected by the integrity checks.

The tracked report is
[`reports/scale/factorized-raw-evidence-forecast.json`](../../reports/scale/factorized-raw-evidence-forecast.json),
with report digest
`0786480ce5651aaba76e8de77addab34b90987438443c2ca82035154bdad8328`.
It is a compact derived measurement and forecast. It does not replace or
outrank the immutable P19 evidence.

## Unchanged-denominator forecast

The P20-T01A denominators and retry assumptions are unchanged:

| Case | Logical executions | Physical attempts | Total retained bytes |
| --- | ---: | ---: | ---: |
| Lower | 34,399,590 | 34,399,590 | 1,002,084,402 |
| Expected | 129,715,224 | 130,363,801 | 3,961,145,162 |
| Conservative | 360,702,963 | 378,738,112 | 13,115,924,170 |

The expected result remains 4,038,854,838 bytes below the 8 GB soft stop. The
conservative result remains 3,115,924,170 bytes above the 10 GB hard cap after
the established 15% diagnostic reserve, 1 GB fixed reserve, and separate P19
qualification archive. Therefore the strongest lossless representation does
not resolve R014 or P20-T01A. P20-T02 remains Planned.

## Required second-stage review

No option below is implemented. Each changes or removes scientific capability
and requires a new Program Owner decision.

| Owner review rank | Savings rank | Quantified option | Conservative retained bytes | Savings | Fits 10 GB |
| ---: | ---: | --- | ---: | ---: | :---: |
| 1 | 3 | Keep at most 71.42% of the historical full-vector increment (transition-directed break-even) | 9,999,935,227 | 3,115,988,943 | Yes |
| 2 | 1 | Replace 3.00 platform/architecture expansion with established 1.25 canary expansion | 6,049,997,036 | 7,065,927,134 | Yes |
| 3 | 2 | Uniform execution/repetition retention of at most 74.27% (mathematical upper envelope) | 9,999,244,653 | 3,116,679,517 | Yes |
| 4 | 4 | Remove the 15% routine diagnostic reserve | 11,535,965,301 | 1,579,958,869 | No |
| 5 | 5 | Remove every process wall-time sample, full-corpus upper bound | 13,064,128,097 | 51,796,073 | No |
| 6 | 6 | Remove minimal manifest integrity entirely | 13,115,264,625 | 659,545 | No |
| 7 | 7 | Further derive logical inputs from canonical definitions | 13,115,924,170 | 0 | No change |

Owner review rank weighs storage relief against scientific/reference loss; the
separate savings rank makes the raw byte ordering visible. The targeted
historical break-even is first because it is the smallest demonstrated fitting
change and preferentially removes historical coverage multiplication, although
it does not by itself prove that a valid transition set exists. The platform
option saves more but loses a complete conservative platform/architecture
reference matrix until canaries trigger expansion. The uniform-repetition
number is only a capacity boundary because P20-T01A does not expose a
benchmark-only denominator; applying it to other obligations would remove
coverage. Diagnostic or timing removal does not fit alone and weakens anomaly
or performance evidence. Manifest removal violates the evidence contract for
negligible gain. Logical-input derivation is already fully realized without
loss.

The Program Owner must choose an explicitly quantified change, commission a
different bounded investigation, or preserve the blocker. Paid R2 and storage
limit increases remain unapproved; material R2 publication remains prohibited.

## Reproduction

The compact report can be checked without the external corpus:

```sh
python tools/campaigns/compile_factorized_evidence_forecast.py --check
```

An operator with the immutable P19 root can repeat the full read-only
measurement and exact reconstruction:

```sh
python tools/campaigns/compile_factorized_evidence_forecast.py \
  --evidence-root /absolute/path/to/100k-qualification-20260814-3a2df1d8 \
  --check
```

The optional `--archive-output` path must resolve outside Git and is intended
only for disposable local inspection. It grants no publication authority.
