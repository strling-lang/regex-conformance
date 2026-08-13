# First end-to-end campaign

The first campaign is a development-only empirical probe. It proves the complete
execution path without making a normative claim or contributing to the stable
release completion denominator.

Its authoritative Git inputs are separate and content-bound:

- `vectors/definitions/first-positive-probes.v1.json` owns the two probe vectors.
- `applicability/policies/first-positive-probes.v1.json` owns the four include
  rules and the explicit default exclusion.
- `campaigns/definitions/first-vertical-slice.v1.json` owns execution policy and
  references those sources.
- `campaigns/compiled/first-vertical-slice.v1.json` is the deterministic compiled
  manifest, all-candidate ledger, logical execution set, and shard plan.

Compile it with:

```sh
python tools/campaigns/compile_vertical_slice.py
```

Execute it with three empty directories outside the repository:

```sh
python tools/campaigns/run_vertical_slice.py \
  --state-root /tmp/strling-campaign-state \
  --evidence-dir /tmp/strling-campaign-evidence \
  --warehouse-dir /tmp/strling-campaign-warehouse \
  --trust-class development \
  --compact-report /tmp/first-campaign-report.json
```

The runner realizes and verifies each exact certified environment, applies
resource admission, invokes the corresponding thin adapter through the framed
protocol, and releases the environment. A physical attempt receives a distinct
UUIDv7 identity. Target responses become immutable content-addressed observations;
infrastructure failures remain immutable attempts but cannot satisfy the logical
denominator.

The evidence manifest reconciles planned logical executions, attempts,
observations, and result shards. The SQLite warehouse is then derived only from
that exact evidence manifest and independently checks row counts, foreign keys,
and database integrity. Raw evidence, operational state, and the warehouse stay
outside Git. Git contains only the compact report in
`reports/vertical-slice/first-campaign.json`.
