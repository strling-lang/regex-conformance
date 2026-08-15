# 100K warehouse reconciliation

P19-T04 independently reconciles the completed P19-T02 scale campaign into a
regenerable analytical SQLite projection. It reads the certified campaign root
and recovery ledger without mutation; it does not execute a regex target,
realize an environment, use Docker, publish new raw evidence, or change a
logical completion.

## Certified input anchors

- Campaign manifest: `rcid:v1:campaign-manifest:h:jcs-sha256-v1:3a2df1d804fa11b7c6e30af6995bb88a5574ca8c89d5a32a9436a4590fbcc9a8`
- Evidence manifest: `rcid:v1:evidence-manifest:h:jcs-sha256-v1:1572476aa1b968530356d3a310ab78eb267a3d775e3f10d760ab76e600b7cb34`
- Evidence-manifest object SHA-256: `a2d8d1c460d7822bc2212df41d41842e02202961caad7bc17ca1b68204ae07fa`
- Evidence root digest: `ae4d5296b44ef3b72fb4773f4aef0fa8b02a1cab82f5b865f7fe066db96885a5`
- Scale execution report SHA-256: `b89f65fea9e58d6fe1869f9e696227f2fc46d6af4160580119129f684fee12e8`
- Recovery-ledger SHA-256: `0d2b2902df3b54732b6b4dffdb231e92fdf808159d6981900d4254872dbffad4`
- Recovery hash-chain tail: `8e4ecb970440c2305ec58618bb7e67d48906a9df181883326447636531d99408`

The durable source root remains
`100k-qualification-20260814-3a2df1d8`. The derived warehouse is kept in the
separate external directory
`p19/warehouse-reconciliation-20260814-1572476a`; it is not part of the
certified evidence root.

## Independent reconciliation

The read-only pass verifies the frozen plan and source digests, strict canonical
JSON, direct-file containment, every logical-segment and evidence-object hash,
all result-segment and observation content identities, the manifest root,
report projection, SQLite ledger integrity, the 404-entry ledger hash chain,
session outcomes, and all three planned interruption digests. It then projects
and independently reads back:

- 1 campaign;
- 402 shards;
- 404 immutable result/attempt segments;
- 100,000 unique logical executions;
- 100,500 unique physical attempts;
- 100,000 unique selected observations; and
- 3 planned interruptions.

The warehouse row commitments are:

- logical executions: `c175c8c263c1bc6a162d5b8f6f0d8212ebfde6923fd737268722ecd130b614f4`
- physical runs: `3baf2402c7dbea7f213304429d515c8203e2b95f0e65d110ce5772755b4b542a`
- selected observation content: `594714a3a19699e3afa9239f69fa817c80b1a8d3b288b013b16465a76185060b`
- result-segment objects: `5a8c437e8fd452a38496b4fb9f81b123eac054101aaf6a14b5c945f9e44e0731`

The immutable derived artifact is
`rcid:v1:artifact-set-manifest:h:jcs-sha256-v1:a88955629f97183cc65d0a0eab1e26a4fa2b21ad53d6d03b6de2bebc708e5f41`.
Its SQLite filename ends in `a8895562…e5f41.sqlite`, its schema SHA-256 is
`6002c0f9d90317b04f4e538dea04770dfa7baab6abd7ba58faeb1c7a74d29f31`,
and its database SHA-256 is
`9c498311d3410a9e02312116452b51bcac108aa788775e557b3520991902bb87`.
The tracked compact report is
`reports/scale/100k-warehouse-reconciliation.json`; its file SHA-256 is
`b05d426c4e32ea00a5cb1a8647643f97cb235f85110b312922026f6856da5df7`.

## Non-crediting recovery history

Commit ordinal 202 is the planned MySQL forced-worker-kill segment
`c851577db573d32654d76f70751f2717f12fa0abc920f9110265a60a0de57221`.
Its 250 infrastructure failures produced no observation. Attempt 2 recovered
all 250 once in result segment
`264e5b9baf3bee2656e820cf26af1fbf5ff8de83b09222974baacb6a40266100`.

Commit ordinal 362 is the independent CPython infrastructure-failure segment
`d734662713263961e83a2fd725810cb1eef5c50e9a3e64f8ae3898d8bad4a55e`.
The isolated target ended at the outer wall-time limit with exit `-15` before a
qualified observation. Those 250 rows also produced no observation. Attempt 2
recovered all 250 once in result segment
`31819cb48e1baf0a7b2030a2e0ae615c4286640587cd00a25d942e695c4bf55c`.

Both are valid append-only physical history. Retry ordinals are contiguous and
every logical execution has exactly one selected completion.

## Reproduction

From the repository root, with the existing durable campaign and a separate
external warehouse directory:

```sh
python tools/campaigns/reconcile_100k_warehouse.py \
  --campaign-root /durable/p19/100k-qualification-20260814-3a2df1d8 \
  --warehouse-root /durable/p19/warehouse-reconciliation-20260814-1572476a \
  --output reports/scale/100k-warehouse-reconciliation.json \
  --reuse-existing
```

Omit `--reuse-existing` only for the first immutable warehouse build. An
existing destination is never silently replaced. D102 expired with P19-T02;
this procedure has no Docker-daemon authority.
