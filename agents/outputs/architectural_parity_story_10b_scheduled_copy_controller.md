# Story 10B Spec: Implement Scheduled-Copy Controller / Retention

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 10B from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Its job is to implement the SDK-style scheduled-copy half of backup on top of the backup subsystem foundation from Story 10A.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_10_scheduled_backup.md`
- `agents/outputs/architectural_parity_story_10a_backup_sync_runtime.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`
- `agents/outputs/architectural_parity_story_7_filesystem_watcher_boundary.md`
- `agents/outputs/architectural_parity_story_8_query_index_runtime.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- there is no scheduled-copy controller under `src/backup/`
- there is no period-or-cron schedule model for backup jobs
- there is no scheduled-copy recovery metadata or retention pruning
- there is no runtime model for skipped, complete, or miscarried generations

This story depends directly on Story 10A.

---

## Story Goal

Implement scheduled copy as a dedicated backup-owned controller, matching the SDK’s architecture and semantics:

- period-or-cron schedule evaluation
- host-local wall-clock scheduling
- no overlapping runs per job
- bounded catch-up semantics via `attendPastBackups`
- timestamped child backup folders under a configured parent
- durable next-run / last-run / current-run recovery state
- retention pruning beyond `maxBackups`
- duplicate registration/update semantics keyed by `local source path + remote parent`

The outcome is not “backup sync plus schedule”. The outcome is a real scheduled-copy controller under `src/backup/`.

---

## Why This Story Exists

The SDK does not implement scheduled copy as `TYPE_BACKUP` sync config. It has a separate controller:

- `MegaScheduledCopyController`
- `setScheduledCopy(...)`
- `removeexceeding(...)`
- timestamped `_bk_` child backup folders
- explicit skipped, ongoing, and completion-state handling

Relevant upstream references, grouped by implementation concern:

- public API and request contract
  - `../sdk/include/megaapi.h:17488` `MegaApi::setScheduledCopy(...)`
  - `../sdk/src/megaapi.cpp:3720` `MegaApi::setScheduledCopy(...)`
- controller type, surface area, and controller-owned state
  - `../sdk/include/megaapi_impl.h:380` `MegaScheduledCopyController`
  - `../sdk/include/megaapi.h:8295` `MegaScheduledCopy`
- duplicate registration/update semantics keyed by `local folder + remote parent`
  - `../sdk/src/megaapi_impl.cpp:23673` `MegaApiImpl::setScheduledCopy(...)`
  - `../sdk/src/megaapi_impl.cpp:23696` existing-controller lookup
  - `../sdk/src/megaapi_impl.cpp:23710` update-in-place path
  - `../sdk/src/megaapi_impl.cpp:23732` new-controller path
- controller construction, initial retention scan, and startup state
  - `../sdk/src/megaapi_impl.cpp:31411` constructor and initial `removeexceeding(false)`
- next-run calculation, no-overlap handling, and busy postponement
  - `../sdk/src/megaapi_impl.cpp:31525` `getNextStartTime(...)`
  - `../sdk/src/megaapi_impl.cpp:31537` `getNextStartTimeDs(...)`
  - `../sdk/src/megaapi_impl.cpp:31561` `update()`
- retention pruning and previous-run `ONGOING -> MISCARRIED` cleanup
  - `../sdk/src/megaapi_impl.cpp:31619` `removeexceeding(...)`
  - `../sdk/src/megaapi_impl.cpp:31699` `getLastBackupTime()`
- backup-folder detection and scheduled-copy timestamp parsing
  - `../sdk/src/megaapi_impl.cpp:31735` `isBackup(...)`
  - `../sdk/src/megaapi_impl.cpp:31740` `getTimeOfBackup(...)`
  - `../sdk/include/mega/utils.h:60` `FORMAT_SCHEDULED_COPY`
  - `../sdk/src/utils.cpp:1981` `stringToTimestamp(...)`
- generation naming, `_bk_` timestamp formatting, and collision handling
  - `../sdk/src/megaapi_impl.cpp:31910` `epochdsToString(...)`
  - `../sdk/src/megaapi_impl.cpp:31945` `start(bool skip)`
- generation `BACKST` transitions during create/skip/complete/incomplete/abort
  - `../sdk/src/megaapi_impl.cpp:32008` `onFolderAvailable(...)`
  - `../sdk/src/megaapi_impl.cpp:32120` `checkCompletion()`
  - `../sdk/src/megaapi_impl.cpp:32183` `abortCurrent()`
- upload/tree traversal path used by the scheduled-copy controller
  - `../sdk/src/megaapi_impl.cpp:32033` folder walk and upload issuance inside `onFolderAvailable(...)`
  - `../sdk/src/megaapi_impl.cpp:32306` `onTransferFinish(...)`
- cron parsing and bounded catch-up window (`maxBackups + 10`)
  - `../sdk/src/megaapi_impl.cpp:32366` `setPeriod(...)`
  - `../sdk/src/megaapi_impl.cpp:32379` `setPeriodstring(...)`
  - `../sdk/src/megaapi_impl.cpp:32410` bounded catch-up window
  - `../sdk/src/megaapi_impl.cpp:32430` `attendPastBackups` branch

When implementing Story 10B, prefer these locations over the broader backup/sync references in the epic. Together they are the primary C++ ground truth for controller ownership, scheduling, generation lifecycle, and retention behavior.

Rust needs the same split:

- scheduled copy is backup-owned
- scheduled copy is not forced through sync config/runtime types
- scheduled copy still reuses lower node/filesystem/transfer layers instead of growing into a second steady-state engine

---

## Scope

In scope:

- define scheduled-copy job config, schedule, catch-up, and run-state models
- define scheduled-copy controller/runtime ownership under `src/backup/`
- implement period-or-cron schedule evaluation
- implement no-overlap execution semantics
- implement overdue-run handling using `attendPastBackups`
- implement timestamped child backup-folder naming and generation tracking
- implement scheduled-copy restart recovery
- implement retention pruning beyond `maxBackups`
- define duplicate-registration/update semantics and job-identity rules
- add focused tests for scheduling, catch-up, recovery, and retention

Out of scope:

- backup-sync runtime/reporting, which belongs to Story 10A
- forcing scheduled copy through Story 9 sync config/runtime types
- broad public backup centre API parity

---

## Design Decisions

### Decision 1. Scheduled copy remains separate from backup-sync runtime

Story 10B consumes the backup subsystem foundation from Story 10A, but it must not collapse scheduled copy into backup-sync job types or mirror/monitor policy.

### Decision 2. Scheduled-copy identity and duplicate registration follow the SDK

The SDK treats `(local source path, remote parent)` as the semantic uniqueness key for scheduled copy updates.

Story 10B should do the same:

- there is at most one scheduled-copy job per canonical local source path plus remote parent handle
- creating the same pair again updates the existing job in place instead of creating a second controller
- the durable Rust controller id should be a dedicated `ScheduledCopyJobId`, not a reused backup-sync id
- runtime-only transfer or folder-transfer tags are ephemeral execution ids, not durable scheduled-copy identity

### Decision 3. Schedule semantics follow the SDK

The controller must use these rules:

- schedule is either fixed period or cron expression, never both
- schedule uses host-local wall-clock semantics
- at most one run per job may be active at a time
- if a job is due while already busy, the due run is postponed rather than overlapped

### Decision 4. Catch-up semantics follow `attendPastBackups`

When downtime or delay causes missed slots:

- `SkipPastRuns` jumps directly to the next future slot
- `AttendPastRuns` resumes from the oldest bounded overdue slot
- if an older overdue slot is already obsolete because a newer slot is due, the older slot is treated as skipped rather than executed

The bound should match the SDK behavior:

- maximum catch-up window is `maxBackups + 10` scheduled slots
- older missed slots outside that window are discarded rather than executed
- this bound applies even when `AttendPastRuns` is enabled

### Decision 5. Each scheduled-copy run is a tracked generation with remote metadata

Each run materializes as a timestamped child backup folder under the configured parent.

Story 10B should distinguish controller state from generation state.

The controller may have its own runtime state such as active/running/pruning, but generation state should model the SDK’s `BACKST` lifecycle values:

```rust
pub(crate) enum ScheduledCopyGenerationState {
    Ongoing,
    Skipped,
    Complete,
    Incomplete,
    Miscarried,
}
```

Generation-state rules should follow the SDK:

- the generated remote folder name is `<local basename>_bk_<scheduled timestamp>`
- the timestamp string must use the same round-trippable scheduled-copy format for both creation and restore parsing
- if the target generation folder already exists for that scheduled timestamp, the run fails rather than inventing a different name
- remote generation folders carry a `BACKST`-equivalent custom attribute that records generation state
- local persistence may cache generation state for restart speed, but remote generation metadata is the authoritative source used by restore and retention scans
- leftover unfinished generations from earlier runs must be recognized during restore and marked as miscarried rather than treated as complete

### Decision 6. Scheduled-copy execution follows the SDK controller style

Story 10B should not instantiate a Story 9 sync job to execute scheduled copy.

The Rust analogue to `MegaScheduledCopyController` should:

- traverse the local source tree through Story 7 filesystem runtime primitives
- resolve and create remote folders through Story 8 node/query primitives
- issue uploads through Story 5 transfer runtime
- mark uploads/generations as scheduled-copy-owned for reporting and recovery
- avoid introducing a second transfer scheduler or steady-state sync engine

### Decision 7. Retention is controller-owned

Retention pruning belongs to scheduled-copy policy, not to transfer/runtime plumbing.

The controller must prune old timestamped backup children beyond `maxBackups`, preserving at least one completed backup where possible.

Retention scans should also mirror the SDK’s restore/cleanup behavior:

- unexpected `ONGOING` generations from previous runs are converted to `MISCARRIED` before pruning decisions
- completed-generation counting drives the “preserve at least one completed backup” rule
- incomplete or miscarried generations may be pruned according to age/order once the retention bound is exceeded

---

## Recommended Rust Shape

The first implementation slice should aim for a minimum shape such as:

```rust
// src/backup/model.rs

pub(crate) struct ScheduledCopyJobId(LocalIdLike);

pub(crate) enum BackupSchedule {
    Interval { every: Duration },
    Cron { expression: String },
}

pub(crate) enum CatchUpPolicy {
    SkipPastRuns,
    AttendPastRuns,
}

pub(crate) struct ScheduledCopyJobConfig {
    id: ScheduledCopyJobId,
    local_source_path: PathBufLike,
    remote_parent: NodeHandleLike,
    schedule: BackupSchedule,
    catch_up: CatchUpPolicy,
    max_backups: usize,
}
```

```rust
// src/backup/runtime.rs

pub(crate) struct ScheduledCopyController {
    // schedule evaluation, generation tracking, remote BACKST metadata, retention, recovery
}
```

Optional later growth may split retention into `src/backup/retention.rs`, but the controller/runtime home remains `src/backup/`.

---

## Affected Modules

Primary affected modules:

- backup module from Story 10A
- `src/session/core.rs`
- `src/session/runtime/persistence.rs`
- node/query layer from Story 8
- filesystem runtime from Story 7
- transfer runtime from Story 5

Modules that must not become the long-term home for scheduled-copy policy:

- `src/sync/`
- `src/fs/operations/*`
- `src/fs/runtime/transfer.rs`

---

## Agent-Sized Tasks

### Task 10B.1. Define scheduled-copy controller models

Deliverables:

- `ScheduledCopyJobId`
- `ScheduledCopyJobConfig`
- schedule and catch-up types
- scheduled-copy generation-state model
- duplicate-registration/update semantics keyed by source-path plus remote-parent

### Task 10B.2. Add schedule evaluation and execution ownership

Deliverables:

- controller/runtime type under `src/backup/`
- no-overlap execution handling
- timestamped child-folder generation ownership
- explicit lower-layer execution plan using Story 7, Story 8, and Story 5 primitives instead of Story 9 sync config/runtime

### Task 10B.3. Add recovery and retention

Deliverables:

- durable next-run / last-run / current-run recovery state
- miscarried-generation detection on restore
- remote generation-state (`BACKST`-equivalent) coordination
- `maxBackups` pruning rules

### Task 10B.4. Add scheduled-copy tests

Deliverables:

- schedule evaluation tests
- catch-up/backlog tests
- restart-recovery tests
- retention pruning tests

---

## Acceptance Criteria

Story 10B is complete when:

- scheduled copy is implemented as a dedicated backup-owned controller under `src/backup/`
- scheduled copy is not modeled as a sync config or sync run mode
- registering the same local source path plus remote parent updates the existing scheduled-copy job instead of creating a duplicate
- period-or-cron schedule evaluation is implemented
- no-overlap execution semantics are implemented
- catch-up semantics follow `attendPastBackups` with the SDK’s bounded `maxBackups + 10` catch-up window
- each run creates a timestamped child backup folder named with the SDK-style `_bk_` timestamp format and tracks explicit generation state
- generation state includes `Ongoing`, `Skipped`, `Complete`, `Incomplete`, and `Miscarried`, with remote generation metadata as the authoritative restore/retention source
- restart recovery restores controller state and marks unfinished generations appropriately
- retention prunes old backup children beyond `maxBackups`

---

## Verification Requirements

Because this story will touch Rust code, completion requires:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Story-specific verification should also include:

- interval and cron scheduling tests
- no-overlap execution tests
- catch-up policy tests
- duplicate-registration/update tests
- timestamped folder naming and collision tests
- miscarried-generation recovery tests
- retention pruning tests

---

## Relationship To Story 10A

Story 10B consumes the subsystem home and durable backup ownership established by Story 10A.

After Story 10B:

- backup sync and scheduled copy both live under `src/backup/`
- the two backup families share one subsystem without being forced into one execution model
- Story 11 can remain independent rather than inheriting unresolved backup architecture work
