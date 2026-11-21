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

The next production boundary needs an admissible capability snapshot for the
realized profile, exact applicability evaluation, and an authorized campaign
assignment. The existing admissibility evaluator resolves oracle records from
the historical fixture catalog. Integrating these production oracles requires
a governed campaign-bound catalog input and exact outcome projections. The
relational cases need both terminal observations under the same realized
profile. No qualification record can substitute for either observation.
