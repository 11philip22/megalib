# Story 4 Spec: Build Durable Tree/Cache Coherency

Validated on 2026-03-25 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 4 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Story 2 and Story 3, this is a code-bearing story. Its job is to turn the persistence seam from Story 3 into one coherent durable tree/cache subsystem rather than a set of unrelated snapshots.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Completed as the core tree/cache coherency slice.

Tasks 4.1, 4.2, 4.3, and 4.4 are complete:

- `PersistedTreeState` is now live through capture/apply helpers in `Session`
- `PersistedEngineState.tree` is populated by coherent tree/cache capture helpers
- nodes, `pending_nodes`, `outshares`, and `pending_outshares` round-trip through the Story 3 persistence SPI in tests
- authenticated startup now attempts coherent tree/cache restore through `Session::load_internal()` before actor/poller state is derived
- missing or invalid tree snapshots fall back cleanly to the fresh authenticated session state instead of partially applying contradictory cached data
- successful `refresh()` now replaces the persisted tree/cache snapshot at the coherent post-parse boundary
- successful SC/AP batches now persist once per durable tree/share mutation batch after `scsn` advances, instead of committing per packet
- incompatible schema snapshots now fall back cleanly during restore instead of aborting startup
- refresh-roundtrip restart, pending/outshare restart preservation, and AP failure non-commit behavior are now covered by focused regression tests

This closes the Story 4 scope defined in the epic: the coherency model now exists and is wired through real bootstrap, refresh, and AP commit paths.

Production-backed parity is intentionally split into follow-on stories:

- Story 4B rolls out the real production persistence backend behind `PersistenceRuntime`
- Story 4C revalidates and fixes Story 4 behavior against that real backend so the epic can claim production-backed `statecache + nodes + scsn` parity rather than seam-only parity

---

## Story Goal

Create the Rust architectural equivalent of upstream `NodeManager + statecache + cachedscsn` by making cached node state, deferred/decrypt-later state, share metadata, and SC/AP progress markers one coherent durable subsystem.

This story should make restart semantics work like this:

1. persisted tree/cache state restores before live SC coordination resumes
2. restored markers drive catch-up behavior rather than being treated as cosmetic metadata
3. refresh and action-packet application update one durable tree/cache domain instead of separate in-memory features

The story must preserve current public behavior and must not widen into query/index, transfer runtime, sync, or backup work.

---

## Why This Story Exists

Today, Rust has substantial tree and AP logic, but it is still in-memory and loosely coupled:

- `src/fs/operations/tree.rs` fetches and parses nodes, seeds `outshares`, clears and drains `pending_nodes`, builds paths, and marks current-state flags
- `src/session/action_packets.rs` mutates `nodes`, share metadata, and deferred-key state inline during AP handling
- Story 3 added durable models for tree state and markers, but did not wire cached-node restore/apply behavior

This means the current implementation still lacks the architectural property that matters upstream:

- the SDK does not treat `nodes`, `statecache`, and `cachedscsn` as separate concerns
- `NodeManager` explicitly says the same DB file is used for the `statecache` and `nodes` tables, and both tables follow the same transaction domain, with commits triggered by action-packet sequence numbers

Relevant upstream references:

- `../sdk/include/mega/nodemanager.h:272`
- `../sdk/include/mega/megaclient.h:2009`
- `../sdk/include/mega/megaclient.h:2020`
- `../sdk/include/mega/megaclient.h:2033`

Story 4 is the story that closes that architecture gap for the Rust tree/cache runtime.

---

## Validation Findings

Verdict:

- partially grounded / speculative

Grounded against the upstream SDK:

- `NodeManager` explicitly documents that the same DB file backs `statecache` and `nodes`, and that both tables share one transaction domain committed on action-packet sequence numbers (`../sdk/include/mega/nodemanager.h:272`).
- cached startup really does restore local state before live SC catch-up resumes: `MegaClient` opens the cache, skips loading when `cachedscsn` is undefined, calls `fetchsc()` when it is present, and then sets live `scsn` from `cachedscsn` once the cached load succeeds (`../sdk/src/megaclient.cpp:15871`, `../sdk/src/megaclient.cpp:15883`, `../sdk/src/megaclient.cpp:15918`).
- commit boundaries are tied to coherent fetch/AP progress rather than per-node mutation: `initsc()` writes the initial coherent cache and commits it, `sc_storeSn()` commits on the received `scsn`, and `updatesc()` refreshes the cached `scsn` plus other state before the next DB commit (`../sdk/src/megaclient.cpp:5861`, `../sdk/src/megaclient.cpp:5948`, `../sdk/src/megaclient.cpp:5354`, `../sdk/src/megaclient.cpp:5363`, `../sdk/src/megaclient.cpp:5966`).
- durable node cache entries do include share-related state and decrypt-later material: `Node::serialize()` writes outshares/pending shares into the node blob and also preserves node-key/attribute data needed to thaw undecryptable nodes later (`../sdk/src/node.cpp:546`, `../sdk/src/node.cpp:660`, `../sdk/src/node.cpp:706`).

Partially grounded / Rust-specific design choices:

- the story's Rust `pending_nodes`, `outshares`, and `pending_outshares` snapshot shape is a reasonable way to reach upstream-equivalent restart behavior, but upstream does not expose those as separate top-level persisted structures. In C++, outshares and pending shares are serialized inside node blobs, while deferred apply-key retry tracking lives in `NodeManager::mNodePendingApplyKeys` (`../sdk/src/node.cpp:660`, `../sdk/src/node.cpp:696`, `../sdk/src/nodemanager.cpp:1510`).
- the statement that startup should trust a locally restored snapshot with valid persisted `scsn` "as an SDK rule" is slightly stronger than the evidence. The observed upstream behavior is that successful cache restore resumes from cached `scsn` without first comparing to a fresh server `sn`, but that is an implementation observation here, not a separately documented invariant (`../sdk/src/megaclient.cpp:15883`, `../sdk/src/megaclient.cpp:15918`).

Unsupported after the corrections below:

- none

---

## Scope

In scope:

- restore persisted tree/cache state from the Story 3 persistence SPI during authenticated session bootstrap
- persist durable tree state as one domain containing:
  - cached nodes
  - `pending_nodes`
  - `outshares`
  - `pending_outshares`
  - durable SC/tree markers required for coherent restart
- define explicit commit boundaries for:
  - successful `refresh()`
  - successful action-packet application that changes tree/share state and advances `scsn`
- recompute derived current-state flags after restore rather than persisting them directly
- add focused recovery and divergence tests around restart and stale-state handling

Out of scope:

- lazy node materialization
- DB-backed search/query APIs
- contact-cache persistence
- transfer runtime ownership
- sync/backup/mount features
- public API for cache selection or cache invalidation
- replacing the no-op/default persistence backend with a production DB backend in the same slice

This is a coherency story, not the full storage-engine story.

---

## Story 1 And Story 3 Constraints

Story 4 must follow these existing constraints:

- `Session` remains the engine root
- tree/query/transfer architectural boundaries from Story 1 remain intact
- persistence runtime stays at `src/session/runtime/persistence.rs`
- Story 3 remains the source of the persistence SPI and durable model shapes
- current-state booleans remain derived runtime facts, not persisted truth
- `src/public.rs` remains outside this authenticated engine/runtime work

If implementation pressure suggests changing the persistence contract itself, Story 3 must be revised first.

---

## Current-State Preservation Rules

These invariants are binding for Story 4:

1. Tree coherency is one subsystem.
   `nodes`, Rust decrypt-later state (`pending_nodes`), outshare state, `scsn`, and current-state-adjacent markers must not be persisted or restored as unrelated mini-features.

2. Derived booleans stay derived.
   Story 4 may restore the markers that drive `nodes_state_ready`, `sc_batch_catchup_done`, `state_current`, and `action_packets_current`, but it must not persist those booleans directly as authoritative state.

3. Refresh and AP apply define commit boundaries.
   Story 4 should not guess broad autosave policy. It should make the existing tree mutation boundaries persistence-aware.

4. Restored state must be safe to invalidate.
   If persisted tree state is malformed, schema-incompatible, or obviously stale against the server bootstrap, Rust must fall back cleanly rather than partially trusting contradictory state.

5. Public behavior stays stable.
   `refresh()`, browse calls, actor current-state semantics, and session load APIs must remain source-compatible.

---

## Design Decisions

### Decision 1. Treat `PersistedTreeState` plus engine markers as one cache domain

Why:

- upstream parity target is one `nodes + statecache + cachedscsn` domain
- restoring nodes without `scsn` or vice versa creates incoherent catch-up behavior

Consequence:

- Story 4 should persist and restore:
  - `PersistedTreeState`
  - `PersistedScState.scsn`
  - alert/current-state-adjacent markers already defined in Story 3 where they affect restart ordering
- code should talk about a tree/cache snapshot, not a separate “nodes save” and “marker save”

### Decision 2. Restore durable tree/cache state before SC runtime coordination resumes

Why:

- upstream cached startup restores state before live catch-up proceeds against it
- restoring after SC coordination begins creates races for `scsn`, node state, and AP high-watermark behavior

Consequence:

- Story 4 restore should happen in authenticated startup paths before actor poller state is derived from the session
- restored `scsn` becomes the authoritative starting point for catch-up decisions unless the server bootstrap proves the cache unusable
- observed SDK behavior is that if a durable tree/cache snapshot has a valid persisted `scsn` and local restore succeeds, startup resumes from that cache and catch-up proceeds from the cached `scsn` without first pre-comparing to a fresh server `sn`
- if persisted `scsn` is absent or the local restore fails, Story 4 should invalidate the restored tree/cache snapshot and fall back to the live fetch path

### Decision 3. Use refresh and AP success as the first commit boundaries

Why:

- those are the two existing places where Rust already establishes coherent tree state
- inventing finer-grained commit cadence would widen Story 4 into storage-engine design

Consequence:

- successful `refresh()` should capture and persist a coherent tree/cache snapshot
- successful AP application that changes durable tree/share state and advances `scsn` should also commit coherently
- Story 4 should follow the SDK batch-level rule: commit once per successful AP batch / `scsn` advance, not once per individual node mutation
- failure halfway through refresh/AP handling must not leave partially-applied durable state presented as current

### Decision 4. Persist Rust `pending_nodes` and outshare maps because they are part of coherency

Why:

- Rust `pending_nodes` is not incidental scratch state; it affects whether later share keys can recover nodes
- `outshares` and `pending_outshares` affect node flags and later key/work reconciliation

Consequence:

- Story 4 must persist and restore `pending_nodes`, `outshares`, and `pending_outshares`
- those are not optional “nice to have” fields in this story
- this is an architectural parity choice rather than a 1:1 upstream data-model match: in the SDK, share state is serialized inside cached node blobs and decrypt-later retry tracking is rebuilt around loaded nodes

### Decision 5. Paths remain rebuilt derived state

Why:

- node `path` is already a derived view rebuilt from the tree
- upstream parity is about coherent node/cache state, not path-string persistence

Consequence:

- persisted node records should not store derived paths
- restore must rebuild paths after loading nodes and before browse APIs depend on them

### Decision 6. Cache invalidation may be blunt in the first slice

Why:

- correct fallback matters more than clever stale-cache reuse
- Story 4 should not grow its own cache-repair framework

Consequence:

- schema mismatch, malformed node records, or impossible parent/handle relationships should invalidate the restored tree snapshot as a whole and fall back to live refresh
- explicit invalidation is acceptable if it preserves correctness and keeps scope small

---

## Proposed Coherency Boundary

Story 4 should make the durable tree/cache domain conceptually look like this:

1. bootstrap or AP logic mutates the in-memory tree/cache state
2. a narrow tree/cache capture helper turns that into one persistence-domain snapshot
3. persistence commit happens only when the in-memory state is known coherent
4. restore applies the same domain back into `Session`, then rebuilds derived path/current-state values

Important ownership split:

- `tree.rs` and `action_packets.rs` remain the places where tree/share mutations happen
- `Session` owns capture/apply helpers for durable tree/cache state
- `PersistenceRuntime` remains a storage boundary, not the owner of tree mutation policy
- the actor remains a consumer of restored/coherent tree state and a coordinator for later runtime transitions, not the owner of tree persistence policy

---

## Target Module Shape

Story 4 should consume the existing Story 3 durable types in:

- `src/session/runtime/persistence.rs`

Expected new or expanded helper surface in `Session`:

```rust
impl Session {
    pub(crate) fn capture_tree_state(&self) -> PersistedTreeState;
    pub(crate) fn apply_tree_state(&mut self, tree: PersistedTreeState) -> Result<()>;
    pub(crate) fn capture_coherent_tree_cache_state(&self) -> PersistedEngineState;
    pub(crate) fn persist_tree_cache_state(&self) -> Result<()>;
    pub(crate) fn restore_tree_cache_state(&mut self) -> Result<bool>;
}
```

Notes:

- `capture_coherent_tree_cache_state()` should include the Story 3 engine markers plus `PersistedTreeState`
- `restore_tree_cache_state()` may delegate to Story 3 engine-state restore pieces, but Story 4 must be the first story that makes `tree: Some(...)` real
- helper naming may differ slightly in code review, but the ownership split should stay the same

---

## Rust State That Becomes Durable In Story 4

Story 4 should make these live `Session` fields part of the coherent tree/cache snapshot:

- `nodes`
- `pending_nodes`
- `outshares`
- `pending_outshares`
- `scsn`
- `alerts_catchup_pending` where it affects restart/catch-up ordering

Story 4 should continue treating these as derived/non-authoritative:

- `nodes_state_ready`
- `sc_batch_catchup_done`
- `state_current`
- `action_packets_current`
- `current_seqtag`
- `current_seqtag_seen`
- `wsc_url`

---

## Restore And Commit Rules

### Restore rules

- restore only for authenticated session flows
- restore before actor/poller state is synchronized from the session
- if a valid persisted `scsn` exists and local restore succeeds, trust the restored tree/cache snapshot and resume from it
- if persisted `scsn` is absent, malformed, or the tree snapshot cannot be restored coherently, invalidate the restored tree/cache snapshot and fall back to live fetch
- apply supporting share/coherency state before expecting pending-node recovery to succeed
- apply node records, pending-node queue, and outshare maps
- rebuild node paths
- restore `scsn` and other durable markers from the same snapshot
- clear transient seqtag state
- recompute current-state booleans from restored markers and current runtime conditions

### Commit rules

- after successful `refresh()`, replace the durable tree/cache snapshot with the new coherent snapshot
- after successful AP handling that materially changes durable tree/share state and advances `scsn`, persist a coherent snapshot
- AP-driven persistence should commit once per successful batch / `scsn` advance, not per individual node mutation
- if refresh or AP handling fails before coherence is re-established, do not commit partial durable state

### Invalid/stale restore rules

- malformed snapshot => reject the whole restored tree/cache snapshot and fall back to the live fetch path
- incompatible schema => reject the whole restored tree/cache snapshot and fall back cleanly
- impossible node topology or unrecoverable handle contradictions => invalidate the restored tree/cache snapshot rather than partially trusting it
- Story 4 should not try to merge a partially-valid restored tree with live state in the first slice

---

## Initial Migration Slice

Story 4 should land in these phases.

### Phase 1. Add capture/apply helpers for tree/cache state

Deliverables:

- define capture/apply helpers for `PersistedTreeState`
- make `PersistedEngineState.tree` real in code
- make the full first live `PersistedTreeState` round-trip real, not a partial subset
- rebuild paths after restore

Done when:

- Rust can round-trip nodes, pending nodes, and outshare maps through the Story 3 SPI in tests

### Phase 2. Wire startup restore

Deliverables:

- restore coherent tree/cache state during authenticated session startup
- recompute derived flags after restore
- keep fallback behavior clean when no snapshot exists
- restore before actor/poller state is derived from the session

Done when:

- saved-session startup can return with cached tree state present before live catch-up proceeds

### Phase 3. Wire commit boundaries

Deliverables:

- commit coherent tree/cache state after successful `refresh()`
- commit coherent tree/cache state after AP changes that advance durable tree/share state

Done when:

- tree/cache persistence follows refresh/AP coherency rather than ad hoc helper calls

### Phase 4. Add focused recovery and divergence tests

Minimum coverage:

- restore after refresh round-trip
- restore with pending-node queue intact
- restore with outshare flags intact
- incompatible or malformed tree snapshot fallback
- AP-driven commit updates `scsn` and durable tree state coherently

---

## Affected Modules

Primary write scope:

- `src/fs/operations/tree.rs`
- `src/session/action_packets.rs`
- `src/session/core.rs`
- `src/session/runtime/persistence.rs`

Expected secondary scope:

- `src/fs/operations/browse.rs`
- touched test blocks in the modules above

Read-only coordination context:

- `src/session/actor.rs`
- `src/session/sc_poller.rs`
- `src/fs/node.rs`

---

## Acceptance Criteria

Story 4 is complete when:

- `PersistedEngineState.tree` is live, not just contract-only
- cached nodes can survive restart through the persistence SPI
- `pending_nodes`, `outshares`, and `pending_outshares` survive restart through the same domain
- authenticated startup restore can apply coherent tree/cache state before SC coordination resumes
- successful `refresh()` persists coherent tree/cache state
- AP-driven tree/share changes and `scsn` updates commit coherently
- derived current-state booleans are recomputed, not persisted as truth
- malformed or incompatible tree snapshots fall back safely
- no public Rust API changed

---

## Verification Plan

Required checks for Story 4:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Additional targeted validation:

- verify restored paths are rebuilt correctly from persisted node topology
- verify restored `pending_nodes` can still recover when share keys become available later
- verify AP-side mutations do not leave durable state half-committed when a mutation fails
- review diff to ensure Story 4 does not widen into query/index or transfer-runtime work

---

## Agent-Sized Task Breakdown

### Task 4.1

Objective:

- make `PersistedTreeState` live through capture/apply helpers

Write scope:

- `src/session/core.rs`
- `src/session/runtime/persistence.rs`

Done when:

- nodes, pending-node queue, and outshare maps can round-trip through the persistence SPI

### Task 4.2

Objective:

- wire startup restore for coherent tree/cache state

Write scope:

- `src/session/core.rs`
- `src/session/auth.rs`
- `src/session/actor.rs`

Done when:

- authenticated startup restores tree/cache state before SC coordination derives runtime state from the session
- restore trusts a valid local snapshot with persisted `scsn` when local restore succeeds, and falls back cleanly when it does not

### Task 4.3

Objective:

- persist coherent tree/cache state from refresh and AP boundaries

Write scope:

- `src/fs/operations/tree.rs`
- `src/session/action_packets.rs`
- `src/session/core.rs`

Done when:

- refresh and AP application define the first real durable commit boundaries

### Task 4.4

Objective:

- add restart, fallback, and divergence coverage

Write scope:

- touched module test blocks

Done when:

- the story is protected against regression in restart/coherency behavior

---

## Risks

Main risks:

- widening Story 4 into a storage-engine rewrite
- persisting current-state booleans directly and creating contradictory restart behavior
- restoring stale tree state after server bootstrap without a clear invalidation path
- persisting nodes without persisting the queue/share metadata needed to interpret them coherently
- mixing transfer-runtime or query/index work into the same slice

Risk control:

- keep commit boundaries narrow and explicit
- persist markers plus tree state as one domain
- rebuild paths and current-state flags after restore
- prefer safe invalidation/fallback over partial trust
- leave query/index and transfer-runtime work to later stories

---

## Resolved SDK-Aligned Decisions

The first implementation slice should treat these points as fixed unless Story 4 is revised:

1. Restore point:
   restore durable tree/cache state before actor/poller state is derived from `Session`

2. Snapshot trust rule:
   if persisted `scsn` exists and local restore succeeds, trust the restored snapshot and resume catch-up from it

3. Invalid snapshot rule:
   malformed or incompatible tree snapshots invalidate the whole restored tree/cache snapshot rather than being partially merged

4. First live tree domain:
   `PersistedTreeState` should be made fully live in Story 4.1, not as a minimal partial-field subset

5. Restore ordering:
   restore supporting share/coherency state before relying on pending-node recovery

6. Refresh behavior:
   successful full refresh replaces the durable tree/cache snapshot

7. AP commit rule:
   persist once per successful AP batch / `scsn` advance, not per individual node mutation

8. Ownership:
   `Session` plus tree/AP modules own tree-cache persistence policy; the actor consumes the resulting state but does not own persistence policy

---

## Recommended Next Step

Treat this document as the coding contract for Story 4.

The next implementation slice should be:

- Task 4.1 plus Task 4.2 if the write scope stays mostly inside `src/session/core.rs`, `src/session/runtime/persistence.rs`, and startup wiring
- then Task 4.3 and Task 4.4 as the follow-up slice that makes refresh/AP boundaries durable
