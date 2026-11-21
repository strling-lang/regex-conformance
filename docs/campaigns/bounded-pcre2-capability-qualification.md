# Bounded PCRE2 capability qualification

The plan covers the PCRE2 10.47 ordinary 8-bit profile on an approved Ubuntu
24.04 x86-64 worker. It binds one environment recipe, one adapter manifest,
the source archive and signature, and eleven qualification probes for the
eight scientific assertions missing from the candidate applicability traces.

Run `python tools/adapters/qualify_pcre2.py` to emit the exact plan and its
digest. Plan generation needs only the checkout and the schema tooling. It
starts no environment, invokes no adapter, and makes no cloud requests.

The trusted assignment must independently bind the protected revision, plan
digest, worker, external state root, and external evidence directory. Use the
protected pull path in [Governance](../../GOVERNANCE.md). The runner checks
that its clean checkout and both local main references agree with the assigned
revision before it opens the archive. The approved worker uses the existing
resource doctor, native source provider and contained adapter supervisor.
Provide the pinned archive, detached signature and public keyring separately.

```sh
python tools/adapters/qualify_pcre2.py --execute \
  --protected-head "$PROTECTED_HEAD" --expected-plan "$PLAN_DIGEST" \
  --archive "$ARCHIVE" --signature "$DETACHED_SIGNATURE" \
  --keyring "$PUBLISHER_KEYRING" --state-root "$WORKER_STATE" \
  --evidence-dir "$QUALIFICATION_EVIDENCE"
```

The runner compares the archive and signature bytes with the recipe and
verifies the detached signature against the pinned publisher fingerprint.
It realizes one environment, checks the adapter handshake and native error
path, checks the eleven capability responses and releases the environment.
Missing or substituted responses fail verification. A valid response with
the wrong outcome or an invocation failure keeps its dependent capability
unresolved. The evidence file records native frames and attempt information
under its content digest. These records are qualification-only.

`tools/campaigns/compile_pcre2_oracles.py` can write the comparison inventory
using `--adjudication-handoff` and `--expected-review-digest` alongside its
usual pinned release, manifest and preflight inputs. It reconciles all sixteen
oracle bindings against the corresponding open applicability trace, the exact
qualification probes and the reciprocal controls for relational comparisons.

`tools/campaigns/compile_pcre2_production_readiness.py` independently replays
the native qualification evidence against its separately pinned SHA-256 and
protected revision. It reconstructs a capability snapshot for that realized
graph, reevaluates the exact candidate predicates and binds their results to
the source-reviewed oracle bindings and preflight request digests. The output
is a comparison plan for the exact scope. It carries no execution authority.

The isolated production comparison path reuses the adjudication comparators
with field-level native projections. It requires an independently pinned
authorized production admission and validates the exact execution lineage.
Relational cases require comparable terminal observations for all controls
under the same realization. The trace cannot issue canonical claims or award
certification credit. The historical admissibility and adjudication artifacts
remain replayable through their own fixture inputs.

The v2 terminal lineage contract cannot encode a successful compile as its
own outcome. The comparison plan identifies the affected compile coordinates
explicitly. A prospective lineage revision must preserve native acceptance
and rejection separately before those coordinates can enter production.
