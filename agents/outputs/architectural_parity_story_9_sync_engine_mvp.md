# Story 9 Spec: Implement Sync Engine MVP

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 9 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 5, 7, and 8, this is a code-bearing story. Its job is to introduce a real sync subsystem under `src/sync/` with explicit config, lifecycle, durable local-state ownership, and scan/reconcile execution, rather than leaving future sync work to grow out of transfer helpers or filesystem operations.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`
- `agents/outputs/architectural_parity_story_7_filesystem_watcher_boundary.md`
- `agents/outputs/architectural_parity_story_7b_platform_runtime_layering.md`
- `agents/outputs/architectural_parity_story_8_query_index_runtime.md`
- `agents/outputs/architectural_parity_story_10a_backup_sync_runtime.md`
- `agents/outputs/architectural_parity_story_10b_scheduled_copy_controller.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- there is no `src/sync/` module yet
- there is no typed sync config, sync id, sync run-state, or sync change-detection model
- there is no session-owned sync registry or running sync instance owner
- there is no durable per-sync local-node cache comparable to the SDK's sync state cache table
- there is no startup restore path for sync configs or running sync state
- there is no sync-specific conflict, stall, or stats model
- there is no public sync control surface in the Rust crate today
- current local and remote tree work exists only as lower layers:
  - filesystem/runtime from Story 7
  - transfer/runtime from Story 5
  - query/tree-cache/runtime from Stories 4, 4C, and 8

This means the crate has important prerequisites for sync, but still has no architectural sync subsystem.

---

## Story Goal

Establish `src/sync/` as the architectural home for a real sync runtime and land a minimal but real sync engine MVP that owns:

- sync configuration and durable identity
- sync registry/controller lifecycle
- startup restore and restart recovery
- change-detection policy selection
- scan/reconcile execution over one local root and one remote root
- sync-specific state, error, conflict, and stats reporting

The story must reuse the layers already introduced by earlier stories:

- filesystem/runtime and watcher fallback semantics from Story 7
- platform/runtime layering from Story 7B
- transfer/runtime execution from Story 5
- coherent tree/query state from Stories 4, 4C, and 8
- production persistence root ownership from Story 4B

The outcome is not “full desktop sync parity.” The outcome is “Rust now has the same kind of sync subsystem boundary the SDK has, with one live sync path proving the architecture.”

---

## Why This Story Exists

The upstream SDK does not treat sync as an optional helper growing out of transfer or tree code. It has a dedicated sync subsystem with distinct layers:

- `SyncConfig` owns durable sync configuration, run state, change-detection mode, and backup id
- `UnifiedSync` owns config plus the currently running sync instance
- `Syncs` is the controller/registry for all syncs
- `Sync` owns the running local/cloud reconcile engine
- `DirNotify` and scan services feed change detection
- each sync can own its own state cache table
- outward application updates are reported through dedicated sync callbacks and state-change notifications

Relevant upstream references:

- Core type and ownership ground truth:
  - `../sdk/include/mega/sync.h:49` `ChangeDetectionMethod`
  - `../sdk/include/mega/sync.h:72` `SyncConfig`
  - `../sdk/include/mega/sync.h:245` `buildSyncConfig(...)`
  - `../sdk/include/mega/sync.h:256` `PerSyncStats`
  - `../sdk/include/mega/sync.h:270` `UnifiedSync`
  - `../sdk/include/mega/sync.h:533` `Sync`
  - `../sdk/include/mega/sync.h:702` `statecachetable`
  - `../sdk/include/mega/sync.h:946` `SyncConfigStore`
  - `../sdk/include/mega/sync.h:1401` `Syncs`
- Creation, running-state, and persistence control paths:
  - `../sdk/src/sync.cpp:617` `buildSyncConfig(...)`
  - `../sdk/src/sync.cpp:666` `Sync::Sync(...)`
  - `../sdk/src/sync.cpp:840` `Sync::openOrCreateDb(...)`
  - `../sdk/src/sync.cpp:1151` `UnifiedSync::changeState(...)`
  - `../sdk/src/sync.cpp:1231` `UnifiedSync::resumeSync(...)`
  - `../sdk/src/sync.cpp:1242` `UnifiedSync::changeConfigLocalRoot(...)`
  - `../sdk/src/sync.cpp:4127` `Syncs::enableSyncByBackupId_inThread(...)`
  - `../sdk/src/sync.cpp:6448` `Syncs::appendNewSync_inThread(...)`
  - `../sdk/src/sync.cpp:7267` `Syncs::loadSyncConfigsOnFetchnodesComplete_inThread(...)`
  - `../sdk/src/sync.cpp:7303` `Syncs::resumeSyncsOnStateCurrent_inThread(...)`
  - `../sdk/src/sync.cpp:12422` `SyncConfigStore::read(...)`
  - `../sdk/src/sync.cpp:12477` `SyncConfigStore::write(...)`
- Change detection, reconcile-loop, and recovery behavior:
  - `../sdk/src/sync.cpp:13315` sync loop notification processing
  - `../sdk/src/sync.cpp:13343` root validation and auto-recovery checks
  - `../sdk/src/sync.cpp:13543` notification failure and full-rescan/error handling
  - `../sdk/src/sync.cpp:13847` `Syncs::setSyncsNeedFullSync(...)`
  - `../sdk/include/mega/sync.h:1791` `triggerPeriodicScanEarly(...)`
- Conflict, stall, stats, and outward sync-state reporting:
  - `../sdk/include/mega/sync.h:1121` stall model types
  - `../sdk/include/mega/sync.h:1219` per-sync stall maps and counters
  - `../sdk/include/mega/sync.h:1673` `conflictsDetected(...)`
  - `../sdk/include/mega/sync.h:1680` `stallsDetected(...)`
  - `../sdk/src/sync.cpp:13873` `Syncs::conflictsDetected(...)`
  - `../sdk/src/sync.cpp:13960` `Syncs::stallsDetected(...)`
  - `../sdk/src/megaapi_impl.cpp:14556` `MegaApiImpl::syncupdate_stats(...)`
  - `../sdk/src/megaapi_impl.cpp:14604` `MegaApiImpl::syncupdate_treestate(...)`
  - `../sdk/src/megaapi_impl.cpp:14646` `MegaApiImpl::syncs_restored(...)`
- Public API control surface parity anchors:
  - `../sdk/src/megaapi_impl.cpp:10633` `MegaApiImpl::setSyncRunState(...)`
  - `../sdk/src/megaapi_impl.cpp:10687` `MegaApiImpl::rescanSync(...)`
  - `../sdk/src/megaapi_impl.cpp:10694` `MegaApiImpl::getSyncs()`
  - `../sdk/src/megaapi_impl.cpp:23957` `MegaApiImpl::removeSyncById(...)`

Use the grouped references above as the implementation ground truth. They are intentionally narrower than a full sync.cpp reading pass, so a Rust implementation can map each Story 9 slice to the exact upstream owner and lifecycle hook before porting behavior.

The current Rust crate has none of that subsystem ownership yet. Without Story 9:

- sync configuration would have no proper home
- watcher and scan logic would likely be attached directly to filesystem helpers
- restart recovery would have no durable sync-local state boundary
- later backup work would be forced either to invent sync itself or to re-open multiple lower-layer stories

Story 9 is the slice that creates the sync subsystem instead of letting future features distort the current codebase.

---

## Scope

In scope:

- introduce `src/sync/` as the runtime home for sync
- define typed sync config, sync id, sync mode, run-state, and change-detection models
- define a session-owned sync registry/controller comparable in role to the SDK's `Syncs`
- define a running sync instance type comparable in role to `UnifiedSync` plus `Sync`
- define durable sync configuration and per-sync local-state cache ownership
- define startup restore ordering and restart recovery rules
- implement one real sync execution path over:
  - one local root
  - one remote root
  - one running sync instance
- implement scan/reconcile execution using Story 7, Story 5, and Story 8 layers
- define sync-specific state, conflict, stall, and stats models
- add a minimal additive public sync control surface
- add focused tests for:
  - config validation
  - startup restore
  - restart recovery
  - change-detection fallback
  - sync state and conflict/stall reporting

Out of scope:

- full SDK sync API parity in one slice
- backup policy and scheduling, which belong to Story 10
- mount/FUSE behavior, which belongs to Story 11
- full external-drive backup semantics in this story
- full name-conflict and stall-resolution parity in one slice
- complete notification-provider parity on every platform in one slice
- a second transfer engine or direct host-filesystem access inside `src/sync/`
- redesigning the public event/callback staging model from Stories 6 and 6B

This is a sync subsystem story, not a backup story and not a mount story.

---

## Story 1, Story 5, Story 7, Story 7B, Story 8, And Story 10 Constraints

Story 9 must preserve these existing decisions:

- sync runtime lives under `src/sync/`
- `Session` remains the engine root
- transfer execution remains under `src/fs/runtime/transfer.rs`
- filesystem and watcher behavior remain under `src/fs/runtime/filesystem.rs` and `src/platform/`
- coherent remote-tree truth continues to come from Stories 4, 4C, and 8
- backup remains a policy layer on top of sync and is deferred to Story 10
- public API changes, if any, must be additive

Practical consequence:

- Story 9 may add a session-owned sync registry/runtime
- Story 9 may add additive public control methods for creating, listing, pausing, resuming, or rescanning syncs
- Story 9 must not move raw filesystem logic back into `src/sync/` or create a second transfer scheduler
- Story 9 must not solve backup policy by treating backup as “just another sync mode with local custom logic” inside the MVP

If implementation pressure suggests copying scan logic into `src/sync/` from Story 7 or embedding transfer policy inside sync reconciliation, the design is wrong and the story should be narrowed rather than widened.

---

## SDK Parity Target

Story 9 should align with the SDK in these ways:

1. Sync has a first-class subsystem home, not an ad hoc collection of helpers.
2. Durable sync configuration is distinct from the currently running sync instance.
3. There is one registry/controller that owns multiple syncs rather than many disconnected task objects.
4. Change detection explicitly models notifications versus periodic scanning.
5. Each sync owns or coordinates its own durable local-state cache rather than reusing the engine's remote-tree cache.
6. Sync-specific state, stats, and tree-state reporting have a named internal home.
7. Startup restore and re-enable behavior are explicit lifecycle steps rather than incidental side effects.

Rust should stay idiomatic:

- do not clone the SDK's class count or thread model line by line
- do use explicit Rust-owned structs for config, registry, running sync state, and conflict/stall models
- do keep notification support optional and scan fallback explicit
- prefer additive, typed APIs over giant multi-purpose “sync manager” objects

---

## Current Sync Gaps To Close

Story 9 is specifically targeting these gaps:

1. There is no `src/sync/` home at all.
2. There is no durable sync config model.
3. There is no sync registry/controller comparable to `Syncs`.
4. There is no running sync instance comparable to `UnifiedSync` plus `Sync`.
5. There is no per-sync durable local-state cache comparable to the SDK's sync state cache.
6. There is no explicit notifications-vs-scan change-detection model.
7. There is no sync-specific conflict, stall, or stats ownership.
8. Story 10 cannot honestly build on “sync-grade primitives” until this story exists.

---

## Design Decisions

### Decision 1. `src/sync/` is the architectural root, while `Session` owns the registry instance

Why:

- Story 1 already reserved `src/sync/` for this subsystem
- sync is neither just filesystem code nor just session-state plumbing
- later backup and mount work should depend on a named sync subsystem rather than reshaping `Session` directly

Consequence:

- Story 9 should introduce `src/sync/`
- `Session` may own a `SyncRuntime` or `SyncRegistry`, but the architectural home remains `src/sync/`

### Decision 2. Separate config, registry, and running-instance ownership

Why:

- the SDK clearly separates `SyncConfig`, `UnifiedSync`, `Syncs`, and `Sync`
- durable config and currently running state have different lifecycles
- restart recovery and pause/resume semantics are much easier to reason about when the ownership split is explicit

Consequence:

- Rust should define:
  - a durable sync-config type
  - a registry/controller type that owns all known syncs
  - a running sync-instance type that owns active scan/reconcile state
- the first implementation should not collapse all of this into one struct

### Decision 3. Change detection must explicitly model notifications and periodic scan fallback

Why:

- the SDK's `ChangeDetectionMethod` distinguishes notifications from periodic scanning
- Story 7 already established that watch support is optional
- sync cannot assume native watch support is always present

Consequence:

- Story 9 should define an explicit sync change-detection enum
- the runtime should allow:
  - notification-preferred mode
  - periodic-scan mode
  - fallback from unsupported or failed watch registration to periodic scan where policy allows
- the MVP must work in scan-driven mode even if native watch support is unavailable
- if notification-preferred mode has an explicit fallback scan interval, unsupported or failed watch registration should downgrade the sync to periodic scan and surface a warning state
- if notification-preferred mode has no scan fallback configured, unrecoverable watch-registration failure should leave the sync registered but in an error or suspended state rather than silently degrading

### Decision 4. Per-sync durable local-state cache is separate from engine-state persistence

Why:

- the SDK gives each sync its own state cache table and lifecycle
- remote-tree cache and local sync state are different domains with different failure and reset semantics
- putting sync-local truth into the engine-state SQLite tables would blur responsibilities and make later recovery behavior harder

Consequence:

- Story 9 should define two distinct sync-local durability families under `src/sync/`:
  - one sync-config store analogous to the SDK's `SyncConfigStore`, containing all known sync configs and durable run-state/config metadata for the account/session
  - one per-sync local-state cache analogous to the SDK's `statecachetable`, stored separately from the engine-state tables and scoped to one sync identity
- it may reuse the Story 4B root-path family and production backend helpers, but it should not store sync-local state inside the engine-state tables
- config-store corruption/recycle and per-sync local-state-cache corruption/recycle must be scoped independently, so resetting one does not implicitly destroy the other
- the first Rust implementation should prefer:
  - one config-store SQLite DB for all sync configs
  - one dedicated per-sync SQLite DB/file for local-state cache data

### Decision 5. The sync mode model should match SDK breadth even if the MVP only live-wires one mode

Why:

- the SDK already distinguishes `TYPE_UP`, `TYPE_DOWN`, `TYPE_TWOWAY`, and `TYPE_BACKUP`
- backup later depends on sync-mode shape being ready
- changing the core enum later would create churn across config, persistence, and public control APIs

Consequence:

- Story 9 should define a typed sync-mode enum with at least:
  - upload-only
  - download-only
  - two-way
  - backup-upload or equivalent reserved backup flavor
- the MVP should live-wire `TwoWay` as the reference running mode
- non-MVP modes may return explicit unsupported/config-validation results at first, but the type shape should already exist

### Decision 6. Sync startup restore must happen after tree/query readiness and before sync exposure is considered stable

Why:

- in the SDK, sync restore happens as part of the post-fetch-nodes lifecycle, not before the engine has remote tree context
- Rust sync cannot reconcile cleanly without:
  - coherent remote tree state
  - query/index access
  - filesystem runtime availability
  - transfer runtime availability

Consequence:

- Story 9 should restore durable sync configs only after authenticated session bootstrap and remote-tree/cache readiness
- the sync registry should be populated from the sync-config store before any autoresume attempts begin
- restored configs should become visible through sync listing as soon as registry population completes
- enabled configs should then be autostarted only after state-current and lower runtime readiness are available
- configs that fail validation or startup should remain registered with explicit error and run-state information rather than being dropped
- the restore plus autoresume pass should end with one internal “syncs restored” lifecycle point for later outward event staging

### Decision 7. Sync owns conflict, stall, and stats models; outward staging remains layered

Why:

- the SDK has explicit sync stats, stall, and treestate reporting
- later outward callbacks belong in the adapter/event stories, not in sync core logic itself
- internal state must still exist now even if public event families are refined later

Consequence:

- Story 9 should define internal sync status, stall, and conflict models
- the MVP public surface may expose pull-style getters or simple control responses
- richer outward callback/event staging remains downstream of Stories 6 and 6B

### Decision 8. The first conflict, stall, and stats set must be intentionally narrow

Why:

- the SDK has broad stall/conflict coverage, but landing all of it in the MVP would turn Story 9 into a multi-story desktop sync port
- Story 10 and later event stories only need a stable internal home plus one real supported set
- the MVP needs bounded semantics for testing and restart recovery

Consequence:

- the first live sync stats set should at least track:
  - scanning
  - syncing
  - upload count
  - download count
- the first live sync conflict/stall set should be limited to:
  - local root unavailable or temporarily unavailable
  - remote root unavailable or missing
  - same-parent name clash preventing reconcile
- richer stall families, overlay-state parity, and advanced conflict taxonomies remain deferred

### Decision 9. Sync must consume lower layers, not recreate them

Why:

- Story 7 already owns local filesystem and watch boundaries
- Story 5 already owns transfer runtime
- Story 8 already owns remote query/index behavior
- recreating those inside sync would defeat the whole point of the epic

Consequence:

- sync scan logic must consume Story 7 primitives
- sync reconcile must consume Story 8 remote query/tree access and Story 5 transfer/runtime operations
- `src/sync/` should own orchestration and lifecycle, not duplicate those lower runtime contracts

### Decision 10. The first public sync surface should be small, additive, and control-oriented

Why:

- Story 9 needs a real user-facing foothold, not a hidden internal subsystem
- the SDK exposes sync lifecycle control and state without requiring every observer path to exist first
- the SDK stability bias in this crate argues for minimal additive surface rather than a broad API dump

Consequence:

- Story 9 should add the first public sync control surface on `SessionHandle`, matching the crate’s existing public-facade style and the SDK’s control-oriented sync entry points
- the required first public methods are:
  - `create_sync(...)`
  - `list_syncs()`
  - `set_sync_run_state(...)`
  - `rescan_sync(...)`
  - `remove_sync(...)`
- these methods should operate on typed sync ids, typed summaries, and typed run-state commands rather than raw strings or unstructured JSON
- it should not promise full observer, stall-resolution, or backup-centre parity in the same slice

### Decision 11. The MVP reconcile boundary must stop at create/update/delete, not move or rename inference

Why:

- the SDK’s sync reconcile and move-detection behavior is broad and deeply intertwined with mature local-state cache semantics
- move or rename inference, debris handling, and advanced conflict resolution would dramatically widen the first landing
- the epic needs one real sync path first, not a disguised full desktop sync port

Consequence:

- the MVP reconcile path should support:
  - initial bootstrap under one sync root pair
  - create, update, and delete for regular files and folders
  - steady-state rescan and replay of those same operations
- the MVP should explicitly defer:
  - move detection
  - rename inference
  - advanced debris policy
  - full conflict auto-resolution breadth

---

## Recommended Rust Shape

The first implementation slice should aim for an internal layout such as:

```text
src/sync/
  mod.rs
  config.rs
  state.rs
  runtime.rs
  instance.rs
  reconcile.rs
  persistence.rs
```

With internal roles roughly like:

- `config.rs`
  - `SyncId`
  - `SyncConfig`
  - `SyncMode`
  - `SyncChangeDetection`
- `state.rs`
  - `SyncRunState`
  - `SyncWarning`
  - `SyncStatus`
  - `SyncStats`
  - `SyncConflict`
  - `SyncStall`
- `runtime.rs`
  - session-owned sync registry/controller
- `instance.rs`
  - one running sync instance with scan/reconcile lifecycle
- `reconcile.rs`
  - sync-specific orchestration over lower filesystem/query/transfer layers
- `persistence.rs`
  - durable sync config store plus per-sync local-state cache ownership

The exact filenames may vary, but the ownership split should not.

---

## First Live Slice

The MVP should be intentionally bounded.

Required first live behavior:

1. one session can own multiple sync configs through one registry
2. one enabled `TwoWay` sync can actually run
3. sync startup restore and restart recovery work for that running mode
4. change detection works in periodic-scan mode everywhere
5. notification-preferred mode follows explicit SDK-like fallback policy:
   - degrade to periodic scan only when a fallback scan interval is configured
   - otherwise remain registered in an error or suspended state on unrecoverable watch failure
6. reconcile execution uses lower filesystem, query, and transfer layers rather than bypassing them
7. the first live reconcile path is limited to create, update, and delete for regular files and folders under one root pair

Intentionally deferred from the MVP:

- full external-drive semantics
- full backup-specific sync mode behavior
- full conflict-resolution UI/API parity
- every stall type the SDK reports today
- move and rename inference
- highly optimized watcher integration on every platform

That keeps the first sync landing honest and implementable without making the story too small to matter.

---

## Affected Modules

Primary affected modules:

- new `src/sync/`
- `src/session/core.rs`
- `src/session/actor.rs`
- `src/lib.rs`
- `src/fs/runtime/filesystem.rs`
- `src/fs/runtime/transfer.rs`
- `src/fs/runtime/query.rs`
- `src/session/runtime/persistence.rs`

Likely later consumers, but not required to fully migrate in this story:

- `src/backup/`
- `src/mount/`
- event/adapter modules from Stories 6 and 6B

Modules that should not become dumping grounds for sync logic:

- `src/fs/operations/*`
- `src/session/action_packets.rs`
- `src/session/sc_poller.rs`
- `src/public.rs`

---

## Agent-Sized Tasks

### Task 9.1. Introduce sync models and registry/controller

Land `src/sync/` with typed sync config, sync id, sync mode, run-state, and change-detection models plus a session-owned sync registry/controller.

Deliverables:

- `src/sync/` module structure
- typed config/state models
- session-owned runtime handle or registry
- no hidden filesystem or transfer policy duplication

### Task 9.2. Add durable sync config and sync-local persistence ownership

Add sync-local durability for:

- sync config restore
- enabled/disabled state
- per-sync local-state cache ownership
- restart-safe sync identity

Deliverables:

- sync-local persistence module under `src/sync/`
- one sync-config store plus one per-sync local-state cache family
- startup restore ordering integrated with authenticated session bootstrap
- sync-local storage scoped separately from engine/tree persistence

### Task 9.3. Implement one real running sync instance with scan fallback

Make one `TwoWay` sync instance run using:

- filesystem/runtime scan primitives
- optional watcher registration with periodic-scan fallback
- query/runtime access to remote tree state

Deliverables:

- running sync-instance type
- scan loop / rescan triggers
- notification-vs-scan fallback behavior following the configured SDK-like downgrade/error rule

### Task 9.4. Add reconcile execution using lower layers

Implement reconcile orchestration over:

- local filesystem/runtime
- remote query/tree runtime
- transfer/runtime

Deliverables:

- sync reconcile orchestration
- typed conflict/error/stall outcomes
- MVP reconcile bounded to create, update, and delete for regular files and folders
- no direct raw host-filesystem policy inside high-level sync orchestration

### Task 9.5. Add minimal public control surface and recovery tests

Expose a minimal additive sync control surface and prove:

- create/list/remove sync
- pause-resume or run-state control
- restart recovery
- steady-state sync
- explicit fallback when watcher support is unavailable

Deliverables:

- additive `SessionHandle` sync controls for create, list, set run state, rescan, and remove
- integration coverage for bootstrap, steady-state, and restart recovery
- focused tests for state/stats/conflict reporting

---

## Acceptance Criteria

Story 9 is complete when:

- `src/sync/` exists as the architectural home for sync runtime
- Rust has explicit sync config, sync mode, run-state, and change-detection models
- `Session` owns a real sync registry/controller rather than ad hoc task spawning
- at least one `TwoWay` sync path runs using lower filesystem/query/transfer layers
- sync durability is scoped to sync-local storage rather than being mixed into engine-state persistence tables
- startup restore and restart recovery work for enabled sync configs
- restored syncs remain listed even when autostart validation fails, with explicit error/run-state information
- unsupported or unavailable watcher behavior follows the configured notification-to-scan fallback rule
- the crate exposes a minimal additive `SessionHandle` sync control surface
- Story 10 can truthfully build on “sync-grade primitives” rather than planning around a missing subsystem

Story 9 does not require:

- every sync mode to be fully live
- full backup-centre parity
- full mount integration
- the full SDK observer surface

---

## Verification Requirements

Because this story will touch Rust code, completion requires:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Story-specific verification should also include:

- startup restore tests for persisted sync configs
- restart recovery tests for one enabled sync
- change-detection fallback tests proving periodic scan works without native notifications
- steady-state integration tests for one live sync root pair
- conflict/stall/state tests for the first supported failure modes

If target-specific notification behavior cannot be exercised on the current host, tests should still verify the fallback path and the capability contract.

---

## Relationship To Later Stories

Story 9 is the prerequisite for later desktop subsystem work.

How later stories should consume it:

- Story 10 should treat backup as policy and scheduling over Story 9 sync runtime, not as a second filesystem engine.
- Story 11 should treat mount as a consumer of durable tree/query state and not as a replacement for sync ownership.
- Stories 6 and 6B should stage richer outward sync state, stats, and conflict events on top of Story 9's internal models rather than bypassing them.

Story 9 is therefore not optional if the epic claims SDK-shaped desktop runtime structure.

---

## Non-Goals And Explicit Deferrals

Story 9 does not attempt to:

- ship every SDK sync API in one slice
- implement backup policy or scheduling
- implement mount/FUSE behavior
- match every stall and name-conflict rule the SDK has today
- introduce a second transfer engine
- introduce platform-specific watcher implementations everywhere in the same slice
- store sync-local truth inside the engine-state SQLite tables
- infer moves or renames in the first sync landing

Those belong to later stories. Story 9 only ensures the sync subsystem exists and is real.

---

## Completion Notes

When this story is complete, the epic should be able to claim:

- Rust now has a first-class sync subsystem comparable in architectural role to `SyncConfig` plus `UnifiedSync`/`Syncs` plus `Sync`
- sync lifecycle, recovery, and scan/reconcile ownership have a stable home
- later backup and mount work can build on a real subsystem instead of reopening architecture decisions

That is the correct notion of parity for this story. It is sync-subsystem parity, not yet full desktop-sync feature parity.
