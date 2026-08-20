# Campaigns

Campaign definitions, frozen input references, compact manifests, and campaign
policy live here. Raw result shards, diagnostics, and worker spools remain in
immutable evidence or operational storage.

`small-scale-qualification.v1.json` expands the frozen architectural
vertical-slice campaign through a
digest-bound overlay. Its 48 candidates reconcile to 26 included logical
executions and 22 explicit exclusions. See the [qualification design and
reproduction procedure](../docs/campaigns/small-scale-qualification.md).

The deliberate-fault qualification surface classifies target timeout and crash separately from adapter, worker, network, and storage failures. The deliberate-faults documentation defines the closed reference cases and reproduction procedure.

The restart/resume qualification surface repeatedly interrupts the small-scale campaign across every durable boundary. It preserves old attempts, creates distinct retry runs, and treats only a verified manifest commit as durable logical completion; see docs/campaigns/restart-resume.md.

The evidence verification qualification seeds 18 malformed, truncated, substituted,
semantically impossible, and reconciliation-invalid object variants. Every variant
is immutably quarantined and excluded from warehouse admission while its clean
source evidence is preserved; see `docs/campaigns/evidence-verification.md`.

The 100K qualification plan expands all 26 eligible small-scale qualification
logical templates into
exactly 100,000 balanced planned repetitions and 402 bounded locality shards.
Git retains the compact manifest, ordered-ID commitment, exact segment hashes,
distribution proof, and design report; the 100,000 logical records materialize
as immutable content-addressed segments outside Git. See
`docs/campaigns/100k-qualification-design.md`.

The accepted factorized-evidence and governed-canary policy adopts Evidence Pack
v2 for production raw evidence. The representation
factors shared canonical inputs, exact results, diagnostics, provenance, and
typed dictionaries while retaining independent observation and physical-
attempt facts. It also defines compact expanded diagnostic and raw performance
records plus canary-triggered platform expansion. See
`docs/campaigns/evidence-pack-v2.md`.

The million-scale qualification campaign expands the frozen six-figure
denominator exactly
tenfold and divides 1,000,000 logical executions into 64 independently
verifiable hosted partitions. Each partition emits Evidence Pack v2 and an
immutable exact-coordinate recovery receipt before final no-`LIST`
reconciliation. See `docs/campaigns/million-qualification.md`.

Future production campaigns use Compact Evidence Pack v3. It globally factors
repeated values, derives observation and physical-attempt identities from
immutable execution coordinates, preserves every independent empirical fact,
and replaces only randomly assigned labels and legacy container-layout
identity. The measured declared-cutoff conservative footprint, including the
completed qualification packs and a 1 GB reserve, is 7,782,536,009 bytes. See
`docs/campaigns/evidence-pack-v3.md`.
