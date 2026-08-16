# Evidence verification and quarantine

Result verification is a fail-closed admission boundary between immutable campaign
evidence and derived analytical data. It does not decide whether a regex result is
normatively correct and it does not confer trusted-execution or certification status.

## Qualification order

For a supplied evidence manifest, the verifier checks:

1. exact content-addressed references and direct regular-file containment;
2. reference size, SHA-256, strict UTF-8 JSON, duplicate keys, and canonical bytes;
3. frozen schemas for attempts, observations, result shards, and manifests;
4. terminal response schema and semantic invariants, including match/match-list,
   span, cursor, output, absence, diagnostic, and native-unit consistency;
5. response identity, operation, and materialization against the frozen logical plan;
6. attempt/observation identity, provenance, response, shard, denominator, count,
   completion, content-ID, and root-digest reconciliation.

The first error produces one stable reason code. Diagnostics intentionally exclude
raw response content, provenance values, filesystem paths, and exception text that
could contain credentials. A content-addressed `trust-assessment.v1` object records
the result separately from the evidence it assessed.

## Dispositions

- `admitted` means integrity verification passed and the complete evidence may be
  projected into an analytical warehouse.
- `retained-incomplete` means integrity verification passed but the campaign
  denominator is incomplete. The evidence remains official evidence but cannot
  populate a qualifying complete warehouse.
- `quarantined` means structural, integrity, semantic, or reconciliation
  verification failed. The original immutable evidence remains preserved. Nothing
  is moved, overwritten, or deleted.

`analytical_admissible` is therefore independent of `certification_admissible`.
Evidence-verification qualification leaves `trust_qualification` as `not-assessed` and
`certification_admissible` as false even for clean development evidence. Later trust
and certification policy must assess protected revision, runner, environment,
adapter, provenance, replication, and operator requirements independently.

The warehouse builder calls `qualify_manifest` before creating a database and
rejects every disposition other than complete analytical admission. This ensures a
corrupt object cannot silently enter trusted analytical datasets while keeping raw
evidence authoritative.

## Seeded corruption qualification

The deterministic contract is generated with:

```sh
python tools/campaigns/compile_evidence_verification_qualification.py
```

Run the executed qualification with:

```sh
python -m unittest discover -s tests/campaign -p 'test_evidence_verifier.py' -v
```

The 18 cases cover digest and size substitution, truncation, duplicate JSON keys,
non-canonical JSON, symlink indirection, schema violations, naive timestamps,
response correlation and plan substitution, impossible match/span states,
attempt/observation disagreement, manifest root substitution, shard membership
substitution, and unknown fields. Every case must create an immutable quarantine
assessment, preserve the clean source evidence, and be refused by warehouse
construction.

The compact Git report is
`reports/small-scale/evidence-verification-qualification.json`. Raw baseline and
corrupt object copies, assessment objects, and warehouse attempts remain outside
Git.
