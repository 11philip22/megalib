# Story 4C Spec: Harden Tree/Cache Coherency Against the Production Backend

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 4C from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, 4, and 4B, this is a code-bearing story. Its job is to prove that the Story 4 coherency contract still holds once the real production SQLite backend from Story 4B is the runtime path for authenticated sessions.

Story type:

- Implementation story / production hardening spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_story_4_tree_cache_coherency.md`
- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-31:

- Story 4 is complete as the core tree/cache coherency slice
- Story 4B is complete as the production persistence-backend rollout
- authenticated sessions now install the production SQLite backend at construction time
- Story 4 restart/refresh/AP behavior is already covered through the persistence seam and through targeted real-disk tests

What Story 4C still owns:

- validating that startup restore, refresh replacement, and AP-batch commit semantics are correct under the real production backend path
- finding and fixing any mismatch between seam-only behavior and real SQLite lifecycle behavior
- closing the parity gap between “coherency logic exists” and “production-backed `statecache + nodes + scsn` behavior is reliable”
- proving that this behavior holds through the real authenticated-session startup path, not only through test helpers

---

## Story Goal

Make the Story 4 tree/cache coherency contract trustworthy when the runtime uses the production SQLite backend from Story 4B.

This story should leave the system with one honest claim:

- authenticated sessions restore, refresh, and action-packet persistence through the production backend with the Story 4 coherency guarantees validated against the upstream SDK's startup/commit behavior, not by assuming a one-to-one table or type match

This story must preserve the Story 3 SPI, preserve Story 4B backend ownership, and avoid widening into transfer-runtime redesign, query/index work, sync, or backup.

---

## Why This Story Exists

Story 4 deliberately proved coherency through the persistence seam before a real backend existed.

Story 4B then made the backend real:

- authenticated sessions now get a constructor-time production runtime
- the backend has stable per-scope paths, versioned schema, recycle-on-incompatible-schema behavior, and recoverable malformed-row handling

That still leaves one parity question:

- does the coherency model behave correctly when those backend lifecycle rules are actually present?

Upstream SDK makes no distinction between “coherency in theory” and “coherency with the real DB”:

- `MegaApiImpl` constructs DB access before `MegaClient` runs
- `MegaClient::opensctable()` opens the durable cache tables before cache restore
- `fetchnodes()` only restores from DB when the cache is usable and `cachedscsn` is known
- `fetchsc()` treats malformed core restore records as restore failure and falls back to live fetch
- `sc_storeSn()` commits once at the successful `sn` sequence boundary, not per packet
- successful full cache rebuild during `fetchnodes()` replaces the durable baseline used by later restart

Relevant upstream references:

- `../sdk/src/megaapi_impl.cpp:7015`
- `../sdk/include/mega/megaclient.h:2014`
- `../sdk/include/mega/megaclient.h:2033`
- `../sdk/include/mega/megaclient.h:2106`
- `../sdk/include/mega/nodemanager.h:278`
- `../sdk/src/megaclient.cpp:15075`
- `../sdk/src/megaclient.cpp:15869`
- `../sdk/src/megaclient.cpp:15918`
- `../sdk/src/megaclient.cpp:5354`
- `../sdk/src/megaclient.cpp:5863`

Story 4C is the slice that makes Rust match that property with the production backend, not just with in-memory or test-only backends.

## Validation Findings

Overall verdict: fully grounded.

Grounded against the upstream SDK:

- `MegaApiImpl` constructs `DbAccess` before constructing `MegaClient` (`../sdk/src/megaapi_impl.cpp:7015-7033`).
- `MegaClient::opensctable()` opens the durable cache tables, attaches `NodeManager` to the shared DB domain, and begins the transaction before restore is attempted (`../sdk/src/megaclient.cpp:12233-12291`, `../sdk/include/mega/nodemanager.h:278-280`).
- `fetchnodes()` only attempts local DB restore when `sctable` exists, `cachedscsn` is known, and `fetchsc(...)` succeeds (`../sdk/src/megaclient.cpp:15869-15919`).
- `fetchsc()` returns `false` for malformed core restore records such as bad `CACHEDSCSN`, node, user, PCR, chat, set, or set-element data; that causes fallback away from local restore (`../sdk/src/megaclient.cpp:15098-15213`).
- `sc_storeSn()` commits on the `sn` sequence-number boundary, which is parsed as the end of the action-packet sequence (`../sdk/src/megaclient.cpp:5305-5308`, `../sdk/src/megaclient.cpp:5352-5365`).
- `initsc()` truncates and rewrites the durable baseline, then commits it on successful `fetchnodes()` completion (`../sdk/src/megaclient.cpp:5854-5950`).

Grounded in the current Rust implementation and tests:

- Authenticated session construction installs the production runtime before later restore/use paths: both password login and session-blob login call `install_default_persistence_runtime()` immediately after `Session::new_internal(...)` (`src/session/auth.rs:210-223`, `src/session/auth.rs:505-518`), and saved-session loading calls `restore_tree_cache_state()` immediately after `login_with_session(...)` succeeds (`src/session/core.rs:1374-1384`).
- Production runtime installation really selects the SQLite-backed persistence runtime (`src/session/core.rs:184-186`, `src/session/runtime/persistence.rs:441-448`).
- The Rust restore gate is explicit: `restore_tree_cache_state()` returns `false` unless persisted state exists, a tree snapshot exists, durable `scsn` exists, and `validate_tree_state(...)` succeeds (`src/session/core.rs:339-375`).
- Rust tree coherency validation is explicit rather than implied: `validate_tree_state(...)` rejects duplicate handles, self-parenting nodes, and parent references missing from the snapshot (`src/session/core.rs:268-295`).
- The Rust durable tree snapshot really consists of `nodes`, `pending_nodes`, `outshares`, and `pending_outshares`, and `apply_tree_state(...)` restores exactly those domains before recomputing runtime readiness/current-state flags (`src/session/core.rs:259-265`, `src/session/core.rs:297-321`).
- The Rust `refresh()` closeout path really replaces the durable baseline by calling `persist_tree_cache_state()` from `finalize_refreshed_tree_cache_state()` after recomputing readiness/current-state flags (`src/fs/operations/tree.rs:17-23`), and the restart behavior is covered by `finalized_refresh_snapshot_restores_after_restart()` (`src/fs/operations/tree.rs:739-816`).
- The Rust AP commit boundary is explicit: `handle_sc_event(ScPollerEvent::ScBatch { ... })` advances `scsn`, runs `dispatch_action_packets(...)`, and only then persists when `dispatch.durable_tree_changed` is true (`src/session/actor.rs:2584-2643`).
- The AP persistence behavior already has focused tests for successful durable-tree change, no-op batches, and failed batches preserving the previous baseline (`src/session/actor.rs:3550-3660`).
- Real-disk tree/cache restart coverage already exists for the production SQLite backend path through `install_persistence_runtime_at_for_tests(...)` plus `restore_tree_cache_state()` (`src/session/core.rs:2247-2323`).
- The production SQLite backend behavior behind Story 4B is grounded in code and tests: incompatible backend schema triggers recycle-on-open, and malformed persisted engine rows are treated as cache misses rather than fatal backend-open failures (`src/session/runtime/persistence.rs:225-358`, `src/session/runtime/persistence.rs:1128-1175`).

Grounded Rust-side equivalences used by this story:

- The story's `refresh()` wording is a Rust API name for the same semantic checkpoint that upstream expresses through `fetchnodes()` plus `initsc()`. The equivalence is semantic, not a literal function-name match (`src/fs/operations/tree.rs:42-183`, `../sdk/src/megaclient.cpp:15869-15919`, `../sdk/src/megaclient.cpp:5854-5950`).
- The story's AP "batch" wording is the Rust actor/runtime unit `ScPollerEvent::ScBatch`, used as the Rust-side equivalent of the upstream `sn`-delimited action-packet sequence boundary, not as a claim that the SDK exposes the same type name (`src/session/actor.rs:2586-2643`, `../sdk/src/megaclient.cpp:5305-5308`, `../sdk/src/megaclient.cpp:5352-5365`).
- The required restore domains `pending_nodes`, `outshares`, and `pending_outshares` are grounded as current Rust durable-model requirements because the Rust snapshot type captures and reapplies them as part of coherent restart; they are not asserted to be literal upstream table names (`src/session/core.rs:259-265`, `src/session/core.rs:301-316`).

---

## Scope

In scope:

- validate authenticated-session startup restore behavior through the production backend
- validate refresh replacement semantics through the production backend
- validate AP-batch durable commit semantics through the production backend
- validate real restart behavior after coherent refresh and coherent AP batches
- validate fallback behavior for:
  - incompatible backend schema recycle
  - malformed persisted engine/tree rows
  - stale or incomplete tree snapshots
  - failed AP batches that must not overwrite the last coherent snapshot
- make targeted fixes to transaction, flush, or fallback boundaries required to preserve Story 4 semantics under SQLite
- add focused real-disk regression coverage for the above

Out of scope:

- redesigning `PersistenceRuntime`
- changing the backend technology chosen in Story 4B
- broad schema normalization into multiple SDK-like tables
- transfer-runtime redesign
- query/index work
- sync, backup, or mount work
- new public cache-management APIs

This is a hardening-and-parity story, not a second backend story.

---

## Story 3, Story 4, And Story 4B Constraints

Story 4C must preserve these existing decisions:

- `Session` remains the engine root
- persistence runtime stays at `src/session/runtime/persistence.rs`
- Story 4 restore/refresh/AP commit boundaries remain the semantic source of truth
- Story 4B remains the owner of backend path, schema, and backend-open lifecycle rules
- no-op and memory backends remain available for unsupported/public/test contexts
- public API stays unchanged

Story 4C may fix internal behavior, but it must not reopen:

- the Story 3 durable model contract
- the Story 4 coherency model
- the Story 4B backend-choice decision

---

## SDK Parity Target

The production-backed behavior should align with the SDK in these ways:

1. Restore only after the backend is successfully opened and the cache markers are known.
2. Trust the local cache when local restore succeeds and durable `scsn` exists.
3. Treat malformed core cache payloads used for restore as cache restore failure, not as partially trusted state.
4. Treat successful full refresh/bootstrap as the new durable baseline.
5. Commit durable tree/cache state once per successful Rust AP batch / `scsn` advance, aligning with the SDK's `sn`-boundary commit rather than per-packet commits.
6. Keep backend lifecycle handling explicit:
   - backend-open and transaction-start problems are real errors
   - incompatible backend schema may recycle the backend
   - malformed persisted rows are recoverable cache misses or restore fallbacks

Rust should not mimic the SDK’s exact table layout here. It should mimic the behavioral guarantees while keeping the Story 3 durable model and the Story 4B SQLite backend shape.

---

## Additional Binding Decisions

The following choices are fixed for implementation:

1. Story 4C must validate at least one restart/restore path through the real authenticated-session construction flow in `src/session/auth.rs`, not only through `Session` test helpers.
2. Story 4C may use helper-installed production runtimes for focused regression coverage, but those tests do not replace the required authenticated-session-path coverage.
3. Story 4C may fix post-recycle restore behavior after backend schema recycle, but it must not redesign the Story 4B recycle policy itself.
4. Story 4C may change internal restore/commit timing where needed to preserve coherency, but it must not change public API shape or intentionally change externally visible command semantics.
5. Story 4C may touch `src/session/runtime/persistence.rs` only to preserve Story 4 semantics under the production path.
6. For this story, the “real authenticated-session startup path” means the code path that installs the production runtime through `src/session/auth.rs` before startup restore is attempted; helper-installed runtimes are supplemental test tools only.
7. For this story, an AP “batch” means one successful actor-side handling of `ScPollerEvent::ScBatch` in `src/session/actor.rs`, where `dispatch_action_packets(...)` returns `Ok(...)` for that batch and the batch-owned `scsn` has already been advanced in runtime state. This is the Rust story's equivalent of the upstream SDK's `sn` sequence boundary, not a literal upstream type match.

Allowed examples:

- fixing fallback classification for malformed persisted rows
- tightening flush/transaction boundaries needed for coherent restart
- fixing real-disk lifecycle mismatches between startup, refresh, and AP commit code

Disallowed examples:

- redesigning backend schema layout
- expanding `PersistenceRuntime` with unrelated new capabilities
- widening the story into generic persistence cleanup

---

## Production-Specific Failure Modes To Validate

Story 4C should treat these as the main risk list:

1. Startup restore reads engine state successfully but applies an incomplete or contradictory tree snapshot.
2. Backend schema recycle leaves stale assumptions in memory and startup still treats the old cache as valid.
3. Refresh persistence writes a new snapshot but restart observes a partial or stale baseline.
4. AP persistence writes after only part of a batch has been applied, so restart sees a state that never existed as a coherent runtime point.
5. Malformed tree rows behave differently from malformed engine rows and accidentally preserve stale tree state.
6. Real-disk restart path diverges from the seam-only helper tests already added in Stories 3 and 4.

These are the concrete failure modes the story should close.

---

## Recommended Rust Approach

Keep the implementation disciplined:

- prefer small, explicit internal helper fixes over broad refactors
- keep persistence interactions synchronous and bounded inside the current runtime model
- keep transaction or flush boundaries explicit in code, not hidden behind implicit destructors or background tasks
- keep malformed-row fallback local to persistence/restore code, not scattered across actor logic
- keep tests disk-backed where the story claims production-backed behavior

Do not:

- add ORM layers
- add async database wrappers
- couple actor bookkeeping directly to SQLite details
- widen this story into “improve all persistence ergonomics”

---

## Exact Behavioral Rules For Story 4C

These rules should be treated as binding:

1. Startup restore must run only after the production runtime is installed and authenticated identity is known.
2. Startup restore must only apply persisted tree state when both of these are true:
   - durable `scsn` exists
   - persisted tree snapshot passes coherency validation
3. Incompatible backend schema recycle must behave like an empty cache, not like a partial restore.
4. Malformed persisted tree or engine rows must behave like restore fallback, not like partial acceptance.
5. Successful `refresh()` or equivalent full baseline rebuild must replace the durable tree/cache baseline used for next restart.
6. Successful Rust AP batches may persist once after the coherent batch completes and `scsn` advances.
7. Failed AP batches must not advance the durable baseline.
8. Restart coverage must use the production backend path, not only memory or seam-only helpers.
9. A tree snapshot counts as restoreable only if all required Story 4 durable domains needed for coherent restart are present and internally valid.
10. If engine metadata loads but the tree snapshot is incomplete, contradictory, or malformed, the entire tree/cache restore must fall back cleanly instead of partially applying stale state.
11. Production-backed confidence requires at least one test that exercises authenticated-session startup installation plus restore, not only direct `Session` helper setup.
12. In the Rust Story 4 durable model, the required durable tree domains for restore success are:
   - `nodes`
   - `pending_nodes`
   - `outshares`
   - `pending_outshares`
13. “One durable commit per successful AP batch” means one durable flush boundary for one successful `ScPollerEvent::ScBatch` processing unit after `dispatch_action_packets(...)` succeeds; Rust may implement that with one SQLite transaction or one equivalent final durable flush boundary, but not with per-packet durable commits. This is intended to mirror the SDK's `sn`-boundary commit behavior, not to claim the SDK exposes the same batch abstraction.

---

## Affected Modules

- `src/session/core.rs`
- `src/fs/operations/tree.rs`
- `src/session/action_packets.rs`
- `src/session/actor.rs`
- `src/session/runtime/persistence.rs`

Tests may also live alongside the above modules.

---

## Restore-Failure Threshold

For Story 4C, restore success must be interpreted strictly.

A startup restore is successful only when:

- durable `scsn` exists
- the persisted engine snapshot loads successfully
- the persisted tree snapshot exists
- the tree snapshot passes topology/coherency validation
- `nodes` are present in a usable form
- `pending_nodes` are present in a usable form
- `outshares` are present in a usable form
- `pending_outshares` are present in a usable form

That means the following must behave as restore fallback:

- missing tree snapshot with present engine metadata
- malformed node records
- contradictory parent topology
- missing or malformed `pending_nodes`
- missing or malformed `outshares`
- missing or malformed `pending_outshares`
- backend recycle that produces an empty backend

This is intentionally SDK-like at the behavioral level:

- trust local durable cache if local restore succeeds
- otherwise fall back cleanly to fresh fetch/bootstrap

Story 4C should preserve that principle rather than trying to partially salvage contradictory tree state.

---

## Agent-Sized Tasks

### Task 4C.1

Revalidate authenticated-session startup restore against the production backend.

Expected outcomes:

- startup restore order is correct under the installed SQLite runtime
- backend recycle or malformed persisted rows fall back to fresh state cleanly
- no contradictory partial restore survives into actor/poller startup

Suggested ownership:

- `src/session/core.rs`
- `src/session/runtime/persistence.rs`

### Task 4C.2

Revalidate refresh replacement semantics against the production backend.

Expected outcomes:

- successful full refresh replaces the durable baseline used on restart
- restart after refresh sees coherent nodes, pending nodes, and share metadata
- partial-write or stale-baseline assumptions are covered by real-disk tests

Suggested ownership:

- `src/fs/operations/tree.rs`
- supporting tests in `src/session/core.rs`

### Task 4C.3

Revalidate AP-batch commit semantics against the production backend and tighten flush boundaries if needed.

Expected outcomes:

- one durable commit per successful coherent batch
- failed or partial batches do not overwrite the last coherent baseline
- SQLite transaction timing matches the Story 4 AP contract

Suggested ownership:

- `src/session/action_packets.rs`
- `src/session/actor.rs`
- `src/session/runtime/persistence.rs`

### Task 4C.4

Add production-backed restart, corruption, and divergence coverage and close the story.

Expected outcomes:

- disk-backed tests cover:
  - restart after refresh
  - restart after AP batch
  - malformed persisted rows
  - incompatible backend schema recycle
  - failed AP non-commit
- at least one test covers the authenticated-session construction path in `src/session/auth.rs` using the production backend rather than only helper-installed runtimes
- story status can move to complete with production-backed confidence

Suggested ownership:

- tests alongside `core.rs`, `tree.rs`, `actor.rs`, and `persistence.rs`
- status update in this story doc after implementation

---

## Acceptance Criteria

Story 4C is complete when all of the following are true:

1. Story 4 startup restore behavior is verified and, if needed, corrected against the production SQLite backend.
2. Story 4 refresh replacement behavior is verified and, if needed, corrected against the production SQLite backend.
3. Story 4 AP-batch commit behavior is verified and, if needed, corrected against the production SQLite backend.
4. Incompatible backend schema recycle, malformed persisted rows, and stale/incomplete tree snapshots all fall back cleanly under the production backend path.
5. Real-disk restart and corruption coverage exists for the production path rather than only seam-only helpers.
6. The epic can honestly claim production-backed tree/cache coherency parity rather than seam-only coherency.

---

## Mandatory Test Matrix

Story 4C is not complete unless the following are covered:

1. Authenticated-session startup installs the production backend and restores coherent tree/cache state when durable `scsn` and a valid tree snapshot exist.
2. Restart after successful full `refresh()` observes the refreshed durable baseline.
3. Restart after a successful actor-side `ScPollerEvent::ScBatch` observes the new durable baseline.
4. Failed actor-side `ScPollerEvent::ScBatch` does not overwrite the previously coherent durable baseline.
5. Malformed persisted tree row or snapshot causes clean fallback instead of partial restore.
6. Incompatible backend schema recycle behaves like an empty cache and does not leave stale restored tree state behind.

These are the minimum proof points for production-backed parity in this story.

Additional focused tests are welcome, but they do not replace the required matrix above.

---

## Verification Requirements

Because this is a Rust source-code story, every implementation slice must end with:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

At least one slice in the story should also run focused real-disk tests for the production backend path.

---

## Story Relationship To Later Work

Story 4C is a closeout story for the tree/cache persistence path.

Later stories should consume it like this:

- Story 5 may assume a real production persistence backend exists and that tree/cache coherency has been revalidated against it
- later sync/backup/mount stories may treat production-backed restart semantics as established for the core node/cache domain

Story 4C should not be reopened by Story 5 except where transfer persistence needs additional independent behavior.

---

## What “Production-Backed Parity” Means Here

For this story, “production-backed `statecache + nodes + scsn` parity” means behavioral parity for startup/restore and durable-baseline handling, not literal schema or type parity:

- authenticated-session startup restore is correct through the real production backend path
- durable restart correctness holds after coherent refresh and coherent AP progression
- malformed or incompatible on-disk state falls back cleanly
- the production backend preserves the Story 4 coherency contract without helper-only assumptions

It does not mean:

- Rust uses the same physical table layout as the SDK
- every SDK DB subsystem is now mirrored
- transfer, query, sync, or mount persistence parity is complete

That narrower definition is the one Story 4C must satisfy.
