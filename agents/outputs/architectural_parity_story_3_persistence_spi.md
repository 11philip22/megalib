# Story 3 Spec: Introduce Persistence SPI

Validated on 2026-03-25 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 3 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Story 2, this is a code-bearing story, but it is still a foundation slice: it should introduce a real internal persistence boundary without yet attempting full durable tree parity.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_2_request_runtime.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Completed.

Current implementation status on 2026-03-25:

- Task 3.1 is complete in code
- Task 3.2 is complete in code
- Task 3.3 is complete in code
- Task 3.4 is complete in code
- the persistence runtime exists at `src/session/runtime/persistence.rs`
- `Session` owns `persistence: PersistenceRuntime` at construction time
- the first live-wired engine-state round-trip is limited to:
  - `schema_version`
  - `scsn`
  - `alerts_catchup_pending`
  - `user_alert_lsn`
  - `user_alerts`
- no-op and memory backends exist and are covered by tests
- saved-session startup now invokes persisted engine-state restore through the new boundary before returning `Session`
- resumable upload now mirrors load/save/clear through the persistence SPI while keeping the sidecar file authoritative
- focused compatibility coverage now proves empty-store transfer behavior, sidecar precedence, and non-fatal mirrored-record load failure
- Story 3 acceptance criteria are satisfied without public API changes

---

## Validation Findings

Overall verdict:

- partially grounded: the story's core persistence-boundary direction matches the upstream SDK, but a few parity rationales needed narrowing

Grounded against the upstream SDK:

- `NodeManager`, the account `statecache`/`nodes` DB, and `scsn` are one coherency domain; the SDK opens them together and commits them against `scsn` updates (`../sdk/include/mega/nodemanager.h`, `../sdk/include/mega/megaclient.h`, `../sdk/src/megaclient.cpp`)
- cached restore runs before the client resumes live SC catch-up; `fetchsc()` restores cached state, and only then does startup re-arm `scsn`/continue toward current state (`../sdk/src/megaclient.cpp`, `../sdk/src/commands.cpp`)
- transfer resume state is DB-backed and record-oriented, not operation-local-file-based; the SDK uses `tctable`, `TransferDbCommitter`, cached transfer/file records, and `MegaApiImpl::file_resume()` (`../sdk/include/mega/db.h`, `../sdk/include/mega/megaclient.h`, `../sdk/include/mega/transfer.h`, `../sdk/src/megaclient.cpp`, `../sdk/src/megaapi_impl.cpp`)
- user alerts are restored from cache on session resumption, and the SDK marks alert catch-up complete after that restore (`../sdk/src/megaclient.cpp`, `../sdk/src/useralerts.cpp`)

Partially grounded / speculative:

- the original alert-parity wording was too strong: the inspected SDK persists serialized alert records (`CACHEDALERT`), but it does not show persistence of every alert catch-up marker; separate Rust fields such as `alerts_catchup_pending` / `user_alert_lsn` are design choices, not direct upstream cache fields
- the original schema-compatibility wording was also too strong: the SDK handles DB compatibility explicitly, but typically by recycling/removing incompatible databases or invalidating cached state rather than by exposing a structured schema-version restore contract
- upstream cache scoping is tied to authenticated session or folder-link identity derived from the DB name; "after account handle is known" was narrower than what the inspected SDK proves

Unsupported as originally written:

- a direct parity claim that the SDK persists the full alert catch-up state, rather than persisted alert records plus restore-time catch-up completion, is not supported by the inspected sources

---

## Story Goal

Introduce a first-class persistence boundary at `src/session/runtime/persistence.rs` so durable engine state stops being scattered across ad hoc file helpers, actor-local coalescing, and future story-specific storage code.

This story should create the first real persistence seam between:

- authenticated engine state in `Session`
- durable local storage for engine metadata
- transfer resume state
- future durable tree/query state

The seam must preserve current public behavior and must not yet attempt to deliver `NodeManager + DB + SCSN` parity on its own.

---

## Why This Story Exists

Today, `megalib` already has multiple persistence-shaped behaviors, but they do not form one architectural subsystem:

- `Session::save()` and `Session::load()` persist only the SDK-compatible session blob
- `UploadState` persists transfer resume state in operation-local sidecar files
- `Session` and `SessionActor` hold durable-looking metadata in memory, including:
  - `scsn`
  - `user_alert_lsn`
  - `user_alerts`
  - `alerts_catchup_pending`
  - current-state flags
- tree/bootstrap code already has restart-relevant state such as `pending_nodes`

Upstream parity target:

- the SDK treats `NodeManager + DB + SCSN` as one coherency subsystem
- transfer state also lives behind storage-aware subsystems rather than operation-local files

Story 3 does not implement durable tree coherency yet. It creates the storage contract that Story 4 and Story 5 will consume.

---

## Scope

In scope:

- introduce `src/session/runtime/persistence.rs`
- define the internal persistence API and durable data models
- add at least one minimal backend suitable for tests and incremental wiring
- wire `Session` startup and explicit internal persistence helper paths through the boundary
- define persistence domains for:
  - engine metadata
  - alert metadata
  - node-cache data
  - transfer resume state
- add focused tests for empty-store, restore, and incompatible-store handling

Out of scope:

- full DB-backed implementation
- lazy node materialization
- durable tree coherency semantics equivalent to upstream `NodeManager`
- migrating every transfer state path off the current sidecar files
- changing public `Session::save()` / `Session::load()` behavior
- public APIs for selecting or configuring persistence backends

This is a persistence-boundary story, not the full durable cache story.

Implementation ownership after Story 3:

- Story 3 defines the persistence contract and may live-wire engine metadata plus alert metadata
- Story 4 owns durable cached-node, pending-node, outshare, and SCSN/tree coherency behavior
- Story 5 owns migration of transfer resume/runtime state behind the persistence SPI
- key-manager and `^!keys` local durability remain outside Story 3 unless a later story explicitly adds them

---

## Story 1 And Story 2 Constraints

Story 3 must follow the existing foundation decisions:

- persistence runtime lives at `src/session/runtime/persistence.rs`
- `Session` remains the engine root
- `src/api/client.rs` remains transport-first and unrelated to persistence policy
- `src/fs/upload_state.rs` becomes a consumer of the persistence SPI, not the center of persistence architecture
- Story 2 request-runtime ownership remains unchanged
- actor ownership of seqtag waiters and current-state lifecycle remains unchanged

If implementation pressure suggests changing those rules, Story 1 must be revised first.

---

## Current-State Preservation Rules

These invariants are binding for Story 3:

1. Public session blob persistence stays separate.
   `Session::save()` and `Session::load()` remain the SDK-compatible authentication/session-blob path. Story 3 must not silently repurpose them into a general engine snapshot format.

2. Current-state booleans are derived, not authoritative persisted state.
   `nodes_state_ready`, `sc_batch_catchup_done`, `state_current`, and `action_packets_current` should be recomputed from restored markers and later tree state, not treated as durable truth.

3. The first persistence runtime must not force public configuration changes.
   Existing login/load/session APIs must continue working without new constructor arguments or builder patterns.

4. Story 3 must not overcommit to a DB schema too early.
   The first durable models should be stable enough for Story 4 and Story 5, but they should not require immediate module reorganization or a database engine decision.

---

## Story 3 Design Decisions

### Decision 1. Separate session blob persistence from engine-state persistence

Why:

- the SDK-compatible session blob is an auth/session transport artifact
- Story 3 needs a runtime-local durability layer for engine metadata and transfer state
- merging both into one format would blur ownership and make migration harder

Consequence:

- `Session::save()` and `Session::load()` stay as they are in Story 3
- the persistence runtime gets its own internal scope and data models

### Decision 2. Persist markers, not derived current-state booleans

Why:

- `state_current` and `action_packets_current` are computed from tree/AP progress
- persisting them directly would create stale or contradictory restart state

Consequence:

- persist `scsn`, alert metadata, and later tree snapshots
- recompute current-state flags after restore

### Decision 3. Start with a no-op default backend plus a memory backend for tests

Why:

- Story 3 needs a real seam without forcing production persistence behavior immediately
- tests need a backend that can prove restore and incompatibility paths

Consequence:

- the runtime should support:
  - a no-op backend for current default behavior
  - an in-memory backend for unit/integration tests
- DB/file backends can come later without changing the calling contract

### Decision 4. Persistence runtime should be owned by `Session` at construction time

Why:

- upstream DB access is injected when the client is constructed, not bolted on by late mutation
- constructor-time ownership makes the runtime part of engine state rather than optional ambient state

Consequence:

- `Session::new_internal()` should initialize `PersistenceRuntime::disabled()`
- tests may use an internal helper or test-only constructor path to inject a memory backend
- Story 3 should not add public setters or public backend-configuration APIs

### Decision 5. Define all major persistence domains now, even if only some are wired immediately

Why:

- Story 4 needs node/cache and SC metadata
- Story 5 needs transfer resume state
- omitting those domains now would just force a second SPI redesign

Consequence:

- the initial API should include engine snapshot and transfer resume persistence
- first live wiring may stay narrow, but the contract must already name both domains

### Decision 6. Node persistence should use an internal durable model, not the public `Node` type

Why:

- the public `Node` type is not currently serializable and includes derived fields such as `path`
- persistence should not be coupled to public API structs or derived path state

Consequence:

- Story 3 should define `PersistedNodeRecord` as an internal storage model
- `path` should be rebuilt after restore
- `pending_nodes` may remain raw JSON because they are already a deferred parse/decrypt queue

### Decision 7. Story 3 should prove explicit save/load helpers, not broad autosave or shutdown-only flushing

Why:

- upstream persistence is incremental and runtime-driven, not a final teardown dump
- Story 3 is too early to decide the complete persistence cadence for tree/AP/transfer domains

Consequence:

- startup restore should be wired through the new boundary
- Story 3 should add explicit internal capture/save/apply helpers
- Story 3 should not rely on shutdown as the primary persistence mechanism
- broad autosave policy is deferred to later stories that own coherency semantics

### Decision 8. Transfer persistence keys should be typed, not raw strings

Why:

- upstream transfer persistence is account-scoped and record-oriented, not stringly typed
- a typed key avoids spreading ad hoc key formats before Story 5

Consequence:

- Story 3 should introduce an internal `TransferPersistenceKey`
- the first key type only needs upload support, but it should leave room for downloads later

### Decision 9. Persist alert cache payloads in Story 3

Why:

- upstream restores alerts from cache rather than relying only on catch-up markers
- the SDK persists serialized alert records in `CACHEDALERT` and marks `catchupdone = true` after cache restore, but the inspected code does not show persistence of every alert catch-up marker
- `megalib` already keeps alerts in memory as `Vec<Value>`

Consequence:

- Story 3 should persist alert entries and any Rust-local alert markers it needs; `user_alerts` is parity-grounded, while `alerts_catchup_pending` and `user_alert_lsn` are megalib design choices rather than direct SDK cache fields
- alert catch-up booleans remain markers, while runtime delivery state is still derived

### Decision 10. Use strict schema-version rejection in the first slice

Why:

- upstream handles DB compatibility explicitly rather than attempting partial best-effort restores
- the inspected SDK usually does that by recycling/removing incompatible DB state or invalidating cached continuity, not by surfacing a structured schema-version restore error
- partial restore on incompatible state would create difficult-to-debug contradictions

Consequence:

- Story 3 should start with `schema_version = 1`
- unknown schema versions should fail cleanly
- version mismatch should prevent partial engine-state apply
- this is a conservative Rust-side policy choice, not an exact copy of the SDK's current DB compatibility flow

### Decision 11. Restore should run only after authenticated identity is known and before SC runtime coordination starts

Why:

- the persistence scope is account-owned, so restore must not guess before authenticated identity exists
- upstream cached startup restores state before live SC catch-up resumes against that state
- restoring after SC runtime coordination starts would create ordering races for `scsn`, alerts, and current-state recomputation

Consequence:

- Story 3 restore should run only for authenticated session flows
- restore should happen after the authenticated persistence scope is known and `Session` exists
- restore should happen before SC poller state is spawned or synchronized from the restored session state
- public-link runtime remains out of scope for Story 3 persistence

### Decision 12. Test backend injection should use a `#[cfg(test)]` internal helper rather than widening production constructors

Why:

- Rust code should keep production constructors narrow unless broader construction is part of the design contract
- Story 3 needs deterministic tests, not a broader public or production-only configuration surface

Consequence:

- `Session::new_internal()` remains the production constructor path
- tests may use a `#[cfg(test)]` internal helper such as `with_persistence_for_tests(...)`
- Story 3 should not add public setters or expose backend wiring through the public API

### Decision 13. The first live-wired persisted engine-state round-trip should be minimal and binding

Why:

- Story 3 needs a narrow, verifiable first persistence slice
- Story 4 and Story 5 need the broader contract, but Story 3 should not pretend all domains are fully live
- making the first round-trip set explicit avoids widening the first PR during implementation

Consequence:

- the first implementation slice must round-trip:
  - `schema_version`
  - `scsn`
  - `alerts_catchup_pending`
  - `user_alert_lsn`
  - `user_alerts`
- tree snapshot types and transfer persistence hooks may exist in the SPI without becoming live restore/apply behavior yet
- any additional live-wired fields should require explicit justification in code review

---

## Target Module Shape

Target file:

- `src/session/runtime/persistence.rs`

Recommended initial contents:

- `PersistenceRuntime`
- `PersistenceBackend`
- `PersistenceScope`
- `PersistedEngineState`
- `PersistedScState`
- `PersistedAlertsState`
- `PersistedTreeState`
- `PersistedNodeRecord`
- `TransferPersistenceKey`
- transfer resume persistence using the current `UploadState` model
- `NoopPersistenceBackend`
- `MemoryPersistenceBackend`

Suggested exact initial API shape:

```rust
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;
use crate::fs::upload_state::UploadState;
use crate::fs::NodeType;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PersistenceScope {
    pub(crate) account_handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct TransferPersistenceKey {
    pub(crate) kind: TransferPersistenceKind,
    pub(crate) local_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum TransferPersistenceKind {
    Upload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedEngineState {
    pub(crate) schema_version: u32,
    pub(crate) sc: PersistedScState,
    pub(crate) alerts: PersistedAlertsState,
    pub(crate) tree: Option<PersistedTreeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedScState {
    pub(crate) scsn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedAlertsState {
    pub(crate) alerts_catchup_pending: bool,
    pub(crate) user_alert_lsn: Option<String>,
    pub(crate) user_alerts: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedTreeState {
    pub(crate) nodes: Vec<PersistedNodeRecord>,
    pub(crate) pending_nodes: Vec<Value>,
    pub(crate) outshares: std::collections::HashMap<String, std::collections::HashSet<String>>,
    pub(crate) pending_outshares: std::collections::HashMap<String, std::collections::HashSet<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedNodeRecord {
    pub(crate) name: String,
    pub(crate) handle: String,
    pub(crate) parent_handle: Option<String>,
    pub(crate) node_type: NodeType,
    pub(crate) size: u64,
    pub(crate) timestamp: i64,
    pub(crate) key: Vec<u8>,
    pub(crate) link: Option<String>,
    pub(crate) file_attr: Option<String>,
    pub(crate) share_key: Option<[u8; 16]>,
    pub(crate) share_handle: Option<String>,
    pub(crate) is_inshare: bool,
    pub(crate) is_outshare: bool,
    pub(crate) share_access: Option<i32>,
}

pub(crate) trait PersistenceBackend: Send + Sync {
    fn load_engine_state(&self, scope: &PersistenceScope) -> Result<Option<PersistedEngineState>>;
    fn save_engine_state(&self, scope: &PersistenceScope, state: &PersistedEngineState) -> Result<()>;
    fn clear_engine_state(&self, scope: &PersistenceScope) -> Result<()>;

    fn load_upload_state(&self, scope: &PersistenceScope, key: &TransferPersistenceKey) -> Result<Option<UploadState>>;
    fn save_upload_state(&self, scope: &PersistenceScope, key: &TransferPersistenceKey, state: &UploadState) -> Result<()>;
    fn clear_upload_state(&self, scope: &PersistenceScope, key: &TransferPersistenceKey) -> Result<()>;
}

#[derive(Debug, Clone)]
pub(crate) struct PersistenceRuntime {
    backend: Arc<dyn PersistenceBackend>,
}

impl PersistenceRuntime {
    pub(crate) fn disabled() -> Self;
    pub(crate) fn new(backend: Arc<dyn PersistenceBackend>) -> Self;
    pub(crate) fn load_engine_state(&self, scope: &PersistenceScope) -> Result<Option<PersistedEngineState>>;
    pub(crate) fn save_engine_state(&self, scope: &PersistenceScope, state: &PersistedEngineState) -> Result<()>;
    pub(crate) fn clear_engine_state(&self, scope: &PersistenceScope) -> Result<()>;
}
```

Important contract rules:

- the runtime API should stay synchronous in Story 3
- the initial backend contract should not require a new async trait dependency
- `UploadState` may remain the transfer-domain durable model in Story 3
- transfer persistence should be account-scoped through `PersistenceScope`
- the runtime should start at `schema_version = 1` and reject mismatches strictly

---

## Session Integration

Session integration for the first slice should be:

- `Session` owns `persistence: PersistenceRuntime`
- `Session::new_internal()` initializes it with `PersistenceRuntime::disabled()`
- tests may inject `MemoryPersistenceBackend` through an internal helper or test-only constructor path
- `Session` gets internal helpers for:
  - building a `PersistenceScope`
  - capturing a `PersistedEngineState`
  - saving a `PersistedEngineState`
  - applying a restored `PersistedEngineState`

Recommended helper shape:

```rust
impl Session {
    pub(crate) fn persistence_scope(&self) -> PersistenceScope;
    pub(crate) fn capture_engine_state(&self) -> PersistedEngineState;
    pub(crate) fn persist_engine_state(&self) -> Result<()>;
    pub(crate) fn apply_engine_state(&mut self, state: PersistedEngineState) -> Result<()>;
}
```

Restore/apply rules for the first slice:

- restore only after authenticated identity and persistence scope are known
- restore before SC poller state is spawned or synchronized from the `Session`
- restore `scsn`
- restore alert metadata
- restore tree snapshot only if present, but do not claim full Story 4 coherency yet
- recompute `sc_catchup` and current-state booleans from restored markers and restored tree state
- do not restore `current_seqtag` or seqtag waiters
- do not persist `wsc_url`
- do not require shutdown-time persistence to make the feature correct
- do not restore any Story 3 persistence state for `src/public.rs` / public-link runtime

---

## Proposed Persistence Domains

### Engine metadata domain

Direct upstream parity here is limited to `scsn` plus cached alert entries. Separate Rust markers such as `alerts_catchup_pending` and `user_alert_lsn` are acceptable Story 3 choices, but they are not confirmed upstream cache fields from the inspected SDK sources.

First durable fields:

- `scsn`
- `alerts_catchup_pending`
- `user_alert_lsn`
- `user_alerts`

First live-wired round-trip in Story 3:

- `schema_version`
- `scsn`
- `alerts_catchup_pending`
- `user_alert_lsn`
- `user_alerts`

Explicitly not persisted in Story 3:

- `current_seqtag`
- `current_seqtag_seen`
- `nodes_state_ready`
- `sc_batch_catchup_done`
- `state_current`
- `action_packets_current`
- actor-local counters or waiter queues

Story ownership:

- Story 3 should define and may live-wire this domain immediately
- later stories may extend it, but they should not change the separation between durable markers and derived booleans

### Tree snapshot domain

The persistence contract should already define this domain, even if Story 4 does most of the real restore/apply work.

First durable fields:

- parsed node records without derived paths
- `pending_nodes`
- `outshares`
- `pending_outshares`

Explicitly deferred:

- DB-backed search/index state
- lazy materialization
- contact cache persistence
- authring and `^!keys` local persistence

Story ownership:

- Story 3 must define this domain in the SPI and durable models
- Story 3 does not need to restore cached nodes yet
- Story 4 is the story that actually wires cached-node restore/apply behavior, `pending_nodes`, outshare state, and durable tree/SCSN coherency

### Transfer resume domain

First durable model:

- current `UploadState`

Reason:

- it already exists
- Story 5 can migrate it behind the new backend without redesigning the persistence SPI

Explicitly deferred:

- download resume state parity
- scheduler-owned transfer state
- cross-transfer queue persistence

Story ownership:

- Story 3 must define this domain in the SPI so transfer state has a stable persistence contract
- Story 3 may leave the current sidecar-file behavior in place
- Story 5 is the story that migrates real transfer consumers behind this persistence boundary

---

## Incompatible-Store Handling

Story 3 should define explicit behavior for unsupported or corrupted persisted state.

Rules:

- persisted engine state must carry a schema version
- unknown schema versions should return a structured error, not panic
- malformed persisted state should not mutate live session state partially
- the no-op backend should behave like an empty store

Recommended first-slice behavior:

- incompatible engine snapshot => return `MegaError::Custom(...)` with a clear compatibility message
- missing engine snapshot => treat as empty store
- malformed transfer resume record => treat that record as invalid, but do not poison the whole session
- use `schema_version = 1` for the first persisted engine-state format

---

## Initial Migration Slice

Story 3 should land in these phases.

### Phase 1. Introduce the module and durable models

Deliverables:

- add `src/session/runtime/persistence.rs`
- define the persistence trait, runtime, scope, and durable structs
- add no-op and memory backends

Done when:

- the crate has a named internal persistence boundary with testable backends

### Phase 2. Wire engine-state capture and restore

Deliverables:

- add `Session` helpers for capture/apply/scope
- add explicit internal engine-state save helper(s)
- initialize the runtime under `Session`
- prove restore behavior against the memory backend

Done when:

- engine metadata can round-trip through the persistence boundary without public API changes
- the round-trip set is limited to `schema_version`, `scsn`, `alerts_catchup_pending`, `user_alert_lsn`, and `user_alerts`
- restore ordering is proven before SC poller coordination begins
- cached-node restore is still explicitly deferred

### Phase 3. Define transfer-state hooks

Deliverables:

- expose upload-state load/save/clear through the persistence SPI
- leave current sidecar-file behavior in place unless the slice stays small enough to adapt one consumer

Done when:

- transfer resume persistence has a named contract even if Story 5 does most of the migration

### Phase 4. Add focused tests

Minimum coverage:

- empty store
- compatible restore
- incompatible engine snapshot
- session-side apply/recompute behavior after restore

---

## Affected Modules

Primary write scope:

- `src/session/runtime/persistence.rs`
- `src/session/core.rs`
- `src/session/mod.rs`

Recommended secondary scope:

- `src/fs/upload_state.rs`
- one or two test blocks in touched modules

Read-only coordination context:

- `src/session/actor.rs`
- `src/session/action_packets.rs`
- `src/fs/operations/tree.rs`

---

## Acceptance Criteria

Story 3 is complete when:

- `src/session/runtime/persistence.rs` exists
- `Session` owns a named persistence runtime
- the persistence contract covers:
  - engine metadata
  - alert metadata
  - tree snapshot state
  - transfer resume state
- a no-op backend exists for default behavior
- a memory backend exists for tests
- session restore logic can consume persisted engine state through the new boundary
- session persistence is driven by explicit internal helpers rather than shutdown-only behavior
- tree snapshot and transfer resume domains are present in the SPI even if live consumer wiring is deferred
- incompatible-store handling is tested
- no public Rust API changed

---

## Verification Plan

Required checks for Story 3:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Additional targeted validation:

- verify restored engine metadata recomputes current-state tracking rather than trusting persisted booleans
- verify empty-store behavior remains equivalent to current runtime startup
- review diff to ensure `Session::save()` / `Session::load()` semantics did not change

---

## Agent-Sized Task Breakdown

### Task 3.1

Objective:

- add the persistence-runtime module and durable models

Write scope:

- `src/session/runtime/persistence.rs`
- `src/session/mod.rs`
- `src/session/core.rs`

Done when:

- the persistence SPI exists and `Session` can own it

### Task 3.2

Objective:

- add no-op and memory backends plus capture/apply helpers

Write scope:

- `src/session/runtime/persistence.rs`
- `src/session/core.rs`

Done when:

- engine metadata can round-trip through the SPI in tests
- test coverage proves the `#[cfg(test)]` backend injection path without widening public constructors

### Task 3.3

Objective:

- define transfer resume persistence hooks

Write scope:

- `src/session/runtime/persistence.rs`
- `src/fs/upload_state.rs`
- optionally one narrow upload consumer if the slice stays small

Done when:

- transfer resume persistence has a stable internal contract

### Task 3.4

Objective:

- add focused compatibility and restore tests

Write scope:

- touched module test blocks

Done when:

- empty-store, restore, and incompatible-store behavior are covered

---

## Risks

Main risks:

- treating Story 3 like full durable tree parity and widening into Story 4
- persisting derived current-state booleans and creating contradictory restart state
- silently changing public session save/load semantics
- overfitting the first SPI to current upload sidecar files
- forcing a DB dependency or public configuration API too early

Risk control:

- keep session blob persistence separate
- keep default runtime behavior on a no-op backend
- persist markers and snapshots, not actor-local transient state
- use the memory backend to prove restore semantics before any real durable backend
- let Story 4 own durable tree coherency and Story 5 own transfer-runtime migration

---

## Recommended Next Step

Treat this document as the coding contract for Story 3.

The next implementation slice should be:

- Story 4 planning or execution, using Story 3 as the persistence contract baseline for durable tree/cache coherency
