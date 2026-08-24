# Coverage Shard checkpoints

Each completely certified Coverage Shard creates exactly one immutable file:

```text
coverage-shard-NNNN.v1.json
```

Numbers begin at `0001`, are contiguous, and never change meaning. Every
checkpoint binds its predecessor, frozen semantic and profile inputs, exact
profile/release accounting, immutable Evidence Pack v3 manifest, Lab and
Compatibility projection bytes, certification digest, and exact source
revision. The checkpoint content digest excludes only its own digest field.

`index.v1.json` is a deterministic projection of the complete local checkpoint
chain. Existing entries are immutable; the compiler permits only appending new
sealed checkpoints:

```powershell
.\.venv\Scripts\python.exe tools\downstream\compile_checkpoint_index.py --check
.\.venv\Scripts\python.exe tools\downstream\compile_checkpoint_index.py
```

The second command updates only the index. It never creates, rewrites, or
deletes a checkpoint or either referenced projection. A dedicated checkpoint
commit containing the new checkpoint, both projections, and updated index is
the sole Git synchronization signal for downstream consumers.
