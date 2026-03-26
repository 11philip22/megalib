# Story 10A Spec: Implement Backup Subsystem Foundation / Backup-Sync Runtime

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 10A from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Its job is to establish `src/backup/` as a real subsystem home and to implement the sync-backed half of SDK backup behavior before scheduled copy lands.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_9_sync_engine_mvp.md`
- `agents/outputs/architectural_parity_story_10_scheduled_backup.md`
- `agents/outputs/architectural_parity_story_10b_scheduled_copy_controller.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- there is no `src/backup/` module yet
- there is no backup runtime boundary under `Session`
- there is no stable backup-job identity or backup-specific reporting model
- there is no sync-backed backup runtime path analogous to `SyncConfig::TYPE_BACKUP`

This story depends directly on Story 9. It cannot complete until a real sync runtime exists.

---

## Story Goal

Establish the backup subsystem foundation and implement backup sync as an SDK-shaped consumer of the sync runtime:

- `src/backup/` becomes the architectural home for backup runtime ownership
- backup sync jobs have stable backup ids analogous to `SyncConfig::mBackupId`
- backup sync jobs track explicit mirror/monitor policy state
- backup reporting metadata has a real internal model analogous to `BackupInfoSync` and `BackupMonitor`
- backup runtime persists durable job and reporting state through the session persistence layer
- backup-sync durable identity follows the SDK registration flow:
  - new backup syncs register without an id
  - the API returns a backup id
  - that backup id becomes the durable identity used by sync and backup runtime state

The outcome is not “all backup is done”. The outcome is that Rust has the correct runtime home and the sync-backed half of backup is real.

---

## Why This Story Exists

In the SDK, backup sync is not a loose flag on random transfers. It is a real sync flavor with dedicated identity and reporting:

- `SyncConfig::TYPE_BACKUP` marks backup sync as a specialized sync kind
- `mBackupId` is the stable durable identity for the backup sync
- `SyncBackupState` distinguishes mirror and monitor behavior
- `BackupInfoSync` and `BackupMonitor` layer registration, update, and heartbeat reporting above the running sync state

Primary upstream implementation anchors:

- backup sync type, durable id, backup state, and per-sync reporting storage:
  - `../sdk/include/mega/sync.h:76` `SyncConfig::Type`, including `TYPE_BACKUP`
  - `../sdk/include/mega/sync.h:131` `setBackupState(...)` / `getBackupState()`
  - `../sdk/include/mega/sync.h:168` `SyncConfig::mBackupId`
  - `../sdk/include/mega/sync.h:175` `SyncConfig::mBackupState`
  - `../sdk/include/mega/sync.h:282` `UnifiedSync::mBackupInfo`
- mirror-vs-monitor enum values:
  - `../sdk/include/mega/types.h:532` `SyncBackupState`
- backup registration lifecycle for new backup syncs:
  - `../sdk/src/megaapi_impl_sync.cpp:124` `MegaApiImpl::performRequest_syncFolder(...)`
  - `../sdk/src/megaapi_impl_sync.cpp:162` `MegaApiImpl::completeRequest_syncFolder_AddSync(...)`
  - `../sdk/src/megaclient.cpp:18082` `MegaClient::addsync(...)`
  - `../sdk/src/megaclient.cpp:18147` `MegaClient::preparebackup(...)`
- backup-id assignment and bulk-import parity case:
  - `../sdk/src/megaclient.cpp:18118` build `BackupInfoSync` before `CommandBackupPut`
  - `../sdk/src/megaclient.cpp:18139` assign returned `config.mBackupId`
  - `../sdk/src/sync.cpp:5709` bulk import builds `BackupInfoSync` before registration
  - `../sdk/src/sync.cpp:5724` bulk import `putComplete(...)`
  - `../sdk/src/sync.cpp:5762` bulk import assigns `mBackupId`
- mirror-to-monitor transition guard:
  - `../sdk/include/mega/sync.h:778` `Sync::isBackupMonitoring() const`
  - `../sdk/include/mega/sync.h:781` `Sync::setBackupMonitoring()`
  - `../sdk/src/sync.cpp:873` `Sync::isBackupMonitoring() const`
  - `../sdk/src/sync.cpp:880` `Sync::setBackupMonitoring()`
  - `../sdk/src/sync.cpp:13642` settled-initial-pass guard before switching to monitor
- backup report shape, state mapping, duplicate-snapshot suppression, and heartbeat ownership:
  - `../sdk/src/heartbeats.cpp:117` `BackupInfoSync::BackupInfoSync(const SyncConfig&, ...)`
  - `../sdk/src/heartbeats.cpp:130` `BackupInfoSync::BackupInfoSync(const UnifiedSync&, ...)`
  - `../sdk/src/heartbeats.cpp:145` `BackupInfoSync::calculatePauseActiveState(...)`
  - `../sdk/src/heartbeats.cpp:163` `BackupInfoSync::getSyncState(const UnifiedSync&, ...)`
  - `../sdk/src/heartbeats.cpp:170` `BackupInfoSync::getSyncState(SyncError, SyncRunState, ...)`
  - `../sdk/src/heartbeats.cpp:219` `BackupInfoSync::getDriveId(...)`
  - `../sdk/src/heartbeats.cpp:245` `BackupInfoSync::getSyncType(...)`
  - `../sdk/src/heartbeats.cpp:262` `BackupMonitor::BackupMonitor(...)`
  - `../sdk/src/heartbeats.cpp:267` `BackupMonitor::updateOrRegisterSync(...)`
  - `../sdk/src/heartbeats.cpp:290` `BackupInfoSync::operator==(...)`
  - `../sdk/src/heartbeats.cpp:308` `BackupMonitor::beatBackupInfo(...)`

Avoid using `../sdk/src/megaapi.cpp` wrapper forwards as the primary implementation reference for this story. The behavioral ground truth for backup-sync registration and reporting lives in `megaapi_impl_sync.cpp`, `megaclient.cpp`, `sync.cpp`, and `heartbeats.cpp`.

Rust needs the same ownership split:

- sync owns scan/reconcile execution
- backup owns backup identity, backup-specific policy state, and backup reporting metadata

If backup-sync identity or reporting is scattered across `Session`, `fs/operations/*`, or future public API adapters, the architecture will drift immediately.

---

## Scope

In scope:

- create `src/backup/` with additive internal models/runtime ownership
- define typed backup job ids and backup-sync config/state models
- define backup-sync mirror/monitor policy types
- define internal backup-sync reporting metadata with SDK-shaped fields
- persist durable backup job state and reporting metadata
- define the seam between backup runtime and Story 9 sync runtime
- define the exact state/substate mapping and report-update rules for backup-sync reporting
- route one real backup-sync path through the backup runtime once Story 9 exists
- add focused tests for backup-sync lifecycle, restart recovery, and reporting metadata

Out of scope:

- scheduled-copy controller semantics, which belong to Story 10B
- backup-local scan/reconcile logic
- public backup centre API parity
- broad public session API redesign

---

## Design Decisions

### Decision 1. `src/backup/` foundation lands here

This story owns the initial subsystem shape:

- `src/backup/mod.rs`
- `src/backup/model.rs`
- `src/backup/runtime.rs`
- `src/backup/reporting.rs`

`Session` may own a `BackupRuntime`, but backup’s architectural home remains `src/backup/`.

### Decision 2. Backup-sync identity is stable and durable

Backup sync jobs must have a stable typed identity analogous to the SDK’s `mBackupId`.

That identity must survive:

- pause/resume
- disable/re-enable
- restart recovery
- reporting updates

More concretely, Story 10A should follow the SDK’s registration semantics:

- the durable backup-sync identity is a typed wrapper around the MEGA backup handle returned by backup registration
- new backup syncs start with no backup id and are not considered fully durable/enabled until registration returns one
- Rust should not use a synthetic UUID as the durable identity of a live backup-sync job
- update, resume, pause, disable, and reporting flows all key off the same `BackupJobId`

### Decision 3. Mirror vs monitor belongs only to backup-sync policy

This story should define an explicit backup-sync policy mode such as:

```rust
pub(crate) enum BackupSyncMode {
    Mirror,
    Monitor,
}
```

The first live path starts in mirror mode and transitions to monitor mode using the same high-level rule as the SDK: once the initial mirror pass settles cleanly.

For Story 10A, “settles cleanly” should be treated as the Rust equivalent of the SDK guard:

- the job is currently a backup sync in `Mirror` mode
- the running sync instance reports no pending scan work
- the running sync instance reports no potential move reconciliation
- the running sync instance reports no remaining sync work

The runtime must not transition to `Monitor` earlier than that.

### Decision 4. Reporting metadata is owned by backup, not by sync internals

This story must define an internal report/state model with fields corresponding to the SDK’s backup reporting shape:

- backup id
- backup type
- target node
- local folder
- device id
- optional drive id for external backups
- state
- substate

The exact Rust type names may differ, but ownership belongs to `src/backup/`.

Reporting behavior should also follow the SDK shape:

- backup runtime computes a report snapshot from sync config, sync run state, transfer-pause state, device identity, and optional drive identity
- unchanged snapshots are suppressed by equality on the SDK-shaped reporting fields
- changed snapshots trigger backup registration/update state changes
- heartbeat snapshots are a separate internal reporting channel keyed by the same backup id

State/substate mapping should match `BackupInfoSync::getSyncState(...)`:

- `Pending`, `Loading`, and `Run` map to:
  - `Active` when transfers are not paused
  - `PauseUp`, `PauseDown`, or `PauseFull` when transfer-pause state applies
- `Suspend` maps to:
  - `Failed` when a sync error is present
  - `TemporaryDisabled` otherwise
- `Disable` maps to:
  - `Failed` when a sync error is present
  - `Disabled` otherwise
- `substate` should carry the current sync error or equivalent backup sub-error

### Decision 5. Backup-sync has a one-to-one binding to a sync config/runtime unit

Story 10A should follow the SDK shape where backup identity lives on the sync config itself.

Concretely:

- backup sync uses Story 9’s reserved backup-upload sync flavor
- the durable sync config for a backup-sync job must carry:
  - `backup_id`
  - backup mode/state
- one backup-sync job owns exactly one durable sync config/runtime unit
- the backup runtime owns backup-specific reporting metadata and policy decisions keyed by the same `backup_id`
- Rust should not introduce a separate many-to-many join table between backup jobs and syncs for this story

### Decision 6. Execution must go through Story 9 sync runtime contracts

Backup sync must not grow its own scanner, reconciler, watcher registration, or transfer scheduler.

This story defines the backup-owned seam that consumes Story 9. It does not reimplement Story 9.

---

## Recommended Rust Shape

The first implementation slice should aim for a minimum internal shape such as:

```rust
// src/backup/model.rs

pub(crate) struct BackupJobId(HandleLike);

pub(crate) enum BackupJobKind {
    BackupSync,
}

pub(crate) enum BackupSyncMode {
    Mirror,
    Monitor,
}

pub(crate) struct BackupSyncJobConfig {
    id: BackupJobId,
    sync_id: SyncIdLike,
    mode: BackupSyncMode,
    // local root / remote root linkage live on the backing sync config
}
```

```rust
// src/backup/reporting.rs

pub(crate) struct BackupSyncReport {
    // backup id, type, target node, local folder, device id, drive id, state, substate
}
```

```rust
// src/backup/runtime.rs

pub(crate) struct BackupRuntime {
    // durable job store + backup-sync reporting owner + sync-facing seam
}
```

---

## Affected Modules

Primary affected modules:

- new `src/backup/`
- future `src/sync/` from Story 9
- `src/session/core.rs`
- `src/session/runtime/persistence.rs`
- key/share metadata handling under `src/session/`

Modules that must not become the long-term home for backup-sync runtime:

- `src/fs/operations/*`
- `src/fs/runtime/transfer.rs`
- `src/session/actor.rs`

---

## Agent-Sized Tasks

### Task 10A.1. Add backup runtime foundation

Deliverables:

- `src/backup/` module shell
- `BackupRuntime` session ownership seam
- typed backup job/model definitions

### Task 10A.2. Add durable backup-sync state

Deliverables:

- durable backup job records
- durable backup reporting metadata
- restart recovery load/save hooks
- backup-id registration flow that persists the returned server backup id before the job is treated as enabled

### Task 10A.3. Add backup-sync reporting ownership

Deliverables:

- internal report/state models
- state update plumbing for register/update/pause/resume/disable transitions
- SDK-shaped state/substate mapping and duplicate-snapshot suppression

### Task 10A.4. Add backup-sync execution seam and tests

Deliverables:

- explicit dependency on Story 9 sync runtime contracts
- one real backup-sync path through backup runtime
- focused lifecycle and recovery tests

---

## Acceptance Criteria

Story 10A is complete when:

- `src/backup/` exists as the architectural home for backup runtime
- backup-sync jobs have stable durable backup ids returned by backup registration, not synthetic live-job ids
- backup-sync mirror/monitor policy state is modeled explicitly
- backup-sync reporting metadata exists with SDK-shaped fields
- backup-sync reporting uses explicit SDK-shaped state/substate mapping and suppresses unchanged update snapshots
- backup-sync execution is routed through the backup runtime and into Story 9 sync runtime contracts through a one-to-one backup-id keyed binding
- restart recovery restores durable backup job/reporting state
- no scheduled-copy controller behavior is smuggled into the backup-sync design

---

## Verification Requirements

Because this story will touch Rust code, completion requires:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Story-specific verification should also include:

- backup-sync lifecycle tests
- backup-sync restart-recovery tests
- mirror-to-monitor transition tests
- reporting metadata update tests
- backup-id registration/update tests

---

## Relationship To Story 10B

Story 10A is the prerequisite slice for Story 10B.

After Story 10A:

- backup has a real subsystem home
- sync-backed backup behavior is owned by backup rather than by ad hoc session code
- scheduled copy can land as a second backup-runtime branch without reshaping the foundation again
