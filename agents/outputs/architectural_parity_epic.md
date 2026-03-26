# megalib Architectural Parity Epic

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document is the execution plan for bringing `megalib` to architectural parity with the upstream SDK. It is intended to be split into stories, and each story is intended to be split into agent-sized implementation tasks.

Companion reports:

- `agents/outputs/architectural_parity_report.md`
- `agents/outputs/parity_report.md`

---

## Epic Goal

Bring `megalib` to architectural parity with the upstream SDK for:

- core engine ownership and runtime layering
- durable node/cache/query state
- request orchestration
- transfer scheduling and persistence
- filesystem/watch abstraction
- public event delivery
- desktop subsystems such as sync, backup, and mount/FUSE
- platform/runtime layering needed to port later SDK features cleanly
- public adapter/callback staging needed to expose later SDK features cleanly
- internal subsystem homes for future side-service families and secondary state domains

The plan must preserve public API stability unless a story explicitly introduces additive public surface.

This epic does not mean “every SDK feature is implemented immediately.”

It does mean:

- every major architectural dimension required to make the current Rust codebase structurally comparable to the C++ SDK has an owning story
- or that dimension is explicitly declared out of scope with a reason

That is the standard for calling this epic complete.

---

## Current Baseline

Current Rust architectural center:

- `src/session/actor.rs`
- `src/session/core.rs`
- `src/session/sc_poller.rs`
- `src/fs/operations/tree.rs`
- `src/fs/operations/browse.rs`
- `src/fs/operations/upload.rs`
- `src/fs/operations/download.rs`
- `src/fs/upload_state.rs`
- `src/public.rs`

Primary upstream architectural targets:

- `MegaClient`
- `NodeManager + DB + SCSN`
- `RequestDispatcher`
- `TransferQueue + TransferSlot`
- filesystem/watch abstractions
- listener/event layers
- sync, scheduled backup, and mount/FUSE subsystems

---

## Epic Principles

- One story per PR.
- Preserve existing public behavior unless a story explicitly adds public API.
- Prefer additive internal layers over large rewrites.
- Keep current actor ownership model unless a story explicitly proves a boundary change is required.
- Land enabling layers before desktop subsystems.
- Every story must name its owning modules and its dependency chain.
- Every architecture gap from the parity report must have an owning story or an explicit out-of-scope decision.

---

## Architectural Gap Coverage Matrix

This matrix exists to prevent uncovered architecture gaps from hiding inside broad story wording.

It may split a higher-level report dimension into multiple rows when the SDK has distinct runtime seams that need separate ownership or closure states.

| Dimension | Upstream SDK target | Current Rust status | Owning story |
|-----------|---------------------|---------------------|--------------|
| Core runtime ownership | `MegaClient`-centered engine under `MegaApiImpl` | Partial | Story 1 |
| Public-folder runtime separation | folder-link login/cache/auth path kept distinct from full-account runtime | Partial | Story 1 |
| Request orchestration | `RequestDispatcher` plus queue/inflight semantics | Partial | Story 2 |
| Persistence SPI | engine-owned storage boundary | Partial | Story 3 |
| Durable tree/cache coherency | `NodeManager + statecache + cachedscsn` | Partial | Story 4 |
| Production persistence backend | real on-disk DB backend (`SqliteDbAccess` / `SqliteAccountState`) | Partial | Story 4B |
| Transfer checkpoint persistence reset | dedicated transfer cache (`tctable`, `transfercacheadd`, `transfercachedel`) | Missing | Story 4B.5 |
| Production-backed tree/cache hardening | real-disk restart/refresh/AP correctness | Missing | Story 4C |
| Transfer runtime | transfer-cache plus runtime-owned transfer state | Partial | Story 5 |
| Public event subsystem | `MegaApp` event families plus request/transfer listeners and committed node observers | Partial | Story 6 |
| Public adapter/callback staging | listener/observer/callback transport depth above the event substrate | Missing | Story 6B |
| Filesystem/watch abstraction | `FileSystemAccess` / `DirNotify` style boundary | Missing | Story 7 |
| Platform/runtime layering | OS-specific runtime/module homes | Missing | Story 7B |
| Query/index substrate | DB-backed node query/search substrate | Missing | Story 8 |
| Secondary durable state domains | non-node `MegaClient` durable state families | Missing | Story 8B |
| Sync subsystem | sync engine and persisted sync state | Missing | Story 9 |
| Side-service subsystem homes | reserved distinct homes for separate upstream families such as `file_service`, gfx/media-attribute handling, and worker/executor helpers | Missing | Story 9B |
| Backup-sync runtime | backup subsystem foundation plus sync-backed backup lifecycle/reporting | Missing | Story 10A |
| Scheduled-copy controller | SDK-style scheduled copy controller with retention/recovery | Missing | Story 10B |
| Mount/FUSE subsystem | mount runtime plus durable mount-facing state | Missing | Story 11 |

These two non-architecture tracks still gate parity claims and must stay explicit:

| Gating track | Purpose | Owning story |
|--------------|---------|--------------|
| Validation harness | executable parity checks for architecture rows | Story 12 |
| Gap ledger / audit discipline | self-auditing coverage of architecture rows | Story 12B |

If a future refresh of `agents/outputs/architectural_parity_report.md` introduces a new dimension family, or the epic splits a family into a new architecture row, this matrix must be updated in the same change.

---

## Validation Findings

Overall verdict:

- Partially grounded. Most major architectural targets and matrix rows are grounded in concrete upstream SDK subsystems and files. The main corrections needed were to replace a few Rust-migration labels with the actual upstream structures, and to narrow the side-service framing so it matches the SDK's multiple separate subsystems rather than implying one unified pipeline layer.

Grounded:

- Core runtime ownership and public-folder runtime separation are grounded in `MegaClient` plus `MegaApiImpl`, with explicit folder-link auth/cache/runtime branches such as `FolderLink`, `loggedIntoFolder()`, `loggedIntoWritableFolder()`, `folderaccess()`, and folder-link-specific fetch/result handling in `../sdk/include/mega/megaclient.h`, `../sdk/src/megaclient.cpp`, and `../sdk/src/megaapi_impl.cpp`.
- Request orchestration is grounded in `RequestDispatcher` and its queue/inflight/seqtag handling in `../sdk/src/request.cpp`, with `MegaClient::reqs` and `MegaClient::mReqsLockless` declared in `../sdk/include/mega/megaclient.h`.
- Durable tree/cache coherency is grounded in `NodeManager`, `sctable`, `cachedscsn`, `SCSN`, and the SQLite-backed `statecache`/`nodes` tables in `../sdk/include/mega/megaclient.h`, `../sdk/include/mega/nodemanager.h`, `../sdk/src/nodemanager.cpp`, and `../sdk/src/db/sqlite.cpp`.
- Transfer runtime and dedicated transfer persistence are grounded in `TransferQueue`, `TransferSlot`, `tctable`, `transfercacheadd`, and `transfercachedel` in `../sdk/src/megaapi_impl.cpp`, `../sdk/src/transferslot.cpp`, and `../sdk/include/mega/megaclient.h`.
- Filesystem/watch abstraction and platform/runtime layering are grounded in `FileSystemAccess`, `DirNotify`, and platform-specific filesystem implementations in `../sdk/include/mega/filesystem.h`, `../sdk/src/filesystem.cpp`, `../sdk/src/osx/fs.cpp`, and other platform FS files.
- Query/index substrate is grounded in `NodeManager::searchNodes`, `getChildren`, fingerprint lookups, favourites queries, and SQLite query/index support over the `nodes` table in `../sdk/include/mega/nodemanager.h`, `../sdk/src/nodemanager.cpp`, and `../sdk/src/db/sqlite.cpp`.
- Secondary durable state domains are grounded in non-node cache record families such as `CACHEDUSER`, `CACHEDPCR`, `CACHEDCHAT`, `CACHEDSET`, `CACHEDSETELEMENT`, `CACHEDDBSTATE`, `CACHEDALERT`, and `statusTable` in `../sdk/include/mega/megaclient.h`.
- Sync, backup-sync, scheduled-copy backup, and mount/FUSE are all grounded in real upstream subsystems: `SyncConfig::TYPE_BACKUP`, `Syncs`, `BackupInfoSync`, `BackupMonitor`, `MegaScheduledCopyController`, and the FUSE `mount` / `mount_db` / `inode_db` / `service_context` trees in `../sdk/include/mega/sync.h`, `../sdk/src/sync.cpp`, `../sdk/src/megaapi_impl_sync.cpp`, `../sdk/src/megaapi_impl.cpp`, and `../sdk/src/fuse/`.
- The public event subsystem row is grounded in the SDK's outward event layers: `MegaApp` callback families in `../sdk/include/mega/megaapp.h`, request/transfer listener interfaces and `MegaApiImpl::fireOnRequest*` / `fireOnTransfer*` fan-out in `../sdk/include/megaapi.h` and `../sdk/src/megaapi_impl.cpp`, and committed node-observer delivery through `common::Client::addEventObserver`, `NodeEventObserver`, `ClientAdapter::updated`, and `NodeManager::notifyPurge()` in `../sdk/include/mega/common/client.h`, `../sdk/src/common/client.cpp`, `../sdk/src/common/client_adapter.cpp`, and `../sdk/src/nodemanager.cpp`.
- The public adapter/callback staging row is grounded in the same outward callback/observer layer plus cancellable callback staging in `../sdk/include/mega/common/pending_callbacks.h` and `../sdk/src/common/pending_callbacks.cpp`.

Partially grounded / speculative:

- The side-service row is only partially grounded if treated as one architecture family. Upstream instead has several separate homes such as `file_service`, gfx/media-attribute handling, and worker/executor helpers, so Story 9B should reserve distinct subsystem homes rather than a single unified side-service pipeline layer.

Unsupported:

- No outright unsupported major subsystem rows were found after the wording corrections above.

Evidence anchors consulted:

- `MegaClient`, `MegaApiImpl`, `RequestDispatcher`, `NodeManager`, `TransferQueue`, `TransferSlot`, `FileSystemAccess`, `DirNotify`, `SyncConfig`, `Syncs`, `BackupInfoSync`, `BackupMonitor`, `MegaScheduledCopyController`, and the FUSE `mount_db` / `inode_db` / `service_context` files under `../sdk/src/fuse/`.

---

## Story Backlog

### Story 1. Define the Rust core-engine target boundary

Outcome:

- establish the target internal architecture for `Session` plus request runtime plus persistence runtime plus transfer runtime plus filesystem runtime

Detailed spec:

- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`

Affected modules:

- `src/session/`
- `src/fs/`
- `src/api/`
- docs under `agents/outputs/`

Agent-sized tasks:

1. Write a short design note naming the future internal subsystems and their ownership boundaries.
2. Map current modules to future subsystem owners.
3. Document invariants that must remain true for actor ownership, SC/AP coordination, and public API stability.
4. Record explicit non-goals for the first foundation slices.

Acceptance criteria:

- later stories can reference a stable internal module ownership map
- no Rust public API changes

Dependencies:

- none

### Story 2. Introduce request-runtime abstraction under the actor

Outcome:

- actor commands stop coupling directly to raw transport calls

Detailed spec:

- `agents/outputs/architectural_parity_story_2_request_runtime.md`

Affected modules:

- `src/session/actor.rs`
- `src/session/core.rs`
- `src/api/client.rs`
- `src/session/runtime/request.rs`

Agent-sized tasks:

1. Define an internal request submission trait or service boundary.
2. Route one read path and one mutating path through the new boundary.
3. Preserve seqtag/high-watermark behavior and existing error mapping.
4. Add unit tests around ordering and retry hook points.

Acceptance criteria:

- direct `ApiClient` coupling is reduced behind one internal boundary
- existing public operations behave the same

Dependencies:

- story 1

### Story 3. Introduce persistence SPI

Outcome:

- add a first-class storage boundary for node state, alert state, transfer state, and SCSN/current-state metadata
- define the persistence contract for tree/cache and transfer state even where first live consumer wiring is deferred to later stories

Detailed spec:

- `agents/outputs/architectural_parity_story_3_persistence_spi.md`

Affected modules:

- `src/session/core.rs`
- `src/session/action_packets.rs`
- `src/fs/upload_state.rs`
- `src/session/runtime/persistence.rs`

Agent-sized tasks:

1. Define storage traits and durable data models.
2. Add a minimal backend suitable for tests and incremental wiring.
3. Wire session startup and explicit internal persistence helpers to the persistence boundary.
4. Add tests for empty-store, restore, and incompatible-store handling.

Explicit deferrals to later stories:

- cached-node, pending-node, outshare, and durable tree/SCSN coherency wiring belongs to Story 4
- transfer checkpoint model reset and generic transfer-checkpoint persistence belong to Story 4B.5
- transfer runtime consumer migration belongs to Story 5
- Story 3 may define those domains in the SPI without fully wiring them yet

Acceptance criteria:

- persistence concerns have a named internal API
- no desktop subsystem code is introduced yet

Dependencies:

- story 1

### Story 4. Build durable node-cache coherency

Outcome:

- create the Rust architectural equivalent of `NodeManager + DB + SCSN`
- make durable cached tree state, statecache-style metadata, and SC/AP-driven commits one coherent subsystem rather than separate features

Affected modules:

- `src/fs/operations/tree.rs`
- `src/fs/operations/browse.rs`
- `src/session/action_packets.rs`
- `src/session/core.rs`
- persistence backend from story 3

Agent-sized tasks:

1. Persist node tree state and restore it on session bootstrap.
2. Persist SCSN/current-state markers alongside node state.
3. Make tree refresh and action-packet application commit coherently under one persistence domain, with `scsn` driving commit boundaries.
4. Add recovery tests for restart, partial refresh, stale-state detection, and cache-vs-server divergence.

Consumes from Story 3:

- the tree snapshot and engine-metadata persistence domains defined by the Story 3 SPI

Acceptance criteria:

- cached tree state can survive restart
- SC/AP progress and node persistence stay coherent
- tree persistence behaves like one `statecache + nodes + scsn` subsystem rather than independent snapshots
- story 4 may complete against the minimal/test-oriented backend from story 3, with production-backend rollout and production-backed hardening explicitly deferred to stories 4B and 4C

Detailed spec:

- `agents/outputs/architectural_parity_story_4_tree_cache_coherency.md`

Dependencies:

- stories 1 and 3

### Story 4B. Roll out production persistence backend

Outcome:

- replace the minimal/test-oriented persistence backend with a real authenticated-session production backend
- make `PersistenceRuntime` own durable on-disk state for engine, tree/cache, and later transfer domains under stable schema and file-layout rules

Affected modules:

- `src/session/runtime/persistence.rs`
- `src/session/core.rs`
- backend/storage modules introduced for persistence implementation

Agent-sized tasks:

1. Add a real on-disk backend implementation behind `PersistenceRuntime`.
2. Define authenticated-session scope mapping, file layout, and backend lifecycle rules.
3. Wire constructor-time backend selection for authenticated sessions while preserving no-op backends for unsupported/public/test contexts.
4. Add corruption, restart, and schema-compatibility tests against real on-disk storage.

Acceptance criteria:

- authenticated sessions can use a real durable persistence backend without test-only injection
- persistence schema/version handling is explicit and enforced for production storage
- no-op and memory backends remain available for unsupported/public/test contexts

Detailed spec:

- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`

Dependencies:

- stories 1 and 3

### Story 4B.5. Replace upload-only transfer persistence with generic checkpoints

Outcome:

- replace the shipped upload-only transfer persistence contract with a generic transfer-checkpoint model
- make the production runtime own an SDK-style dedicated transfer checkpoint cache before tree/cache hardening and transfer-runtime migration continue

Affected modules:

- `src/session/runtime/persistence.rs`
- `src/session/core.rs`
- `src/fs/operations/upload.rs`
- `src/fs/upload_state.rs`

Agent-sized tasks:

1. Replace upload-only persistence APIs/data models with typed generic transfer checkpoint records.
2. Add an SDK-style dedicated transfer checkpoint cache with recycle-on-mismatch schema/version handling.
3. Remove sidecar-first resumable-upload behavior from the current runtime path and route the existing resumable upload consumer through the new checkpoint store.
4. Add malformed-record, restart, download-round-trip, and transfer-cache-recycle tests proving transfer checkpoint failures do not disturb engine/tree persistence domains.

Acceptance criteria:

- runtime persistence can represent both upload and download checkpoint records without upload-specific API shape
- the current resumable upload path no longer depends on sidecar-first durability behavior
- the production runtime owns a dedicated transfer checkpoint cache that can recycle independently without affecting engine/tree persistence

Detailed spec:

- `agents/outputs/architectural_parity_story_4b5_transfer_checkpoint_reset.md`

Dependencies:

- stories 1, 3, and 4B

### Story 4C. Reconcile tree/cache coherency with the production backend

Outcome:

- validate and fix Story 4 tree/cache behavior against the real production persistence backend
- close the gap between “coherency logic works in the seam” and “coherency behaves correctly with real durable storage”

Affected modules:

- `src/session/core.rs`
- `src/session/action_packets.rs`
- `src/session/actor.rs`
- `src/fs/operations/tree.rs`
- `src/session/runtime/persistence.rs`

Agent-sized tasks:

1. Re-run startup restore, refresh commit, and AP commit behavior against the production backend and fix any lifecycle mismatches.
2. Verify stale-cache fallback, malformed snapshot handling, and schema-upgrade failure behavior on real disk state.
3. Tighten transaction/flush boundaries so refresh and AP persistence remain one coherent domain under the production backend.
4. Add restart, corruption, and divergence coverage that specifically exercises the production backend rather than test-only backends.

Acceptance criteria:

- Story 4 behavior remains correct when backed by the production persistence backend
- durable tree/cache coherency survives real process restart and malformed/corrupt on-disk state
- the epic can truthfully claim production-backed `statecache + nodes + scsn` parity rather than seam-only parity

Detailed spec:

- `agents/outputs/architectural_parity_story_4c_production_tree_cache_hardening.md`

Dependencies:

- stories 1, 3, 4, 4B, and 4B.5

### Story 5. Separate transfer runtime from operation code

Outcome:

- move queueing, retry, concurrency policy, and durable transfer state into a dedicated transfer subsystem
- establish the Rust equivalent of transfer-cache plus runtime-owned transfer/file state rather than operation-local sidecars

Affected modules:

- `src/fs/operations/upload.rs`
- `src/fs/operations/download.rs`
- `src/fs/upload_state.rs`
- `src/progress.rs`
- `src/fs/runtime/transfer.rs`

Agent-sized tasks:

1. Extract scheduler/runtime types from upload/download operation code.
2. Move resume state behind the persistence SPI and replace operation-local durability assumptions with runtime-owned transfer persistence.
3. Define concurrency and retry policy hooks plus typed persistence identity for transfer records.
4. Add tests for cancel, resume, restart, failure recovery, and transfer-cache restore behavior.

Consumes from Story 4B.5:

- the generic transfer-checkpoint persistence domain reset before runtime migration

Acceptance criteria:

- upload/download modules become thinner orchestration layers
- transfer policy is centrally owned
- transfer durability is owned by the transfer subsystem rather than `UploadState` sidecar files

Detailed spec:

- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`

Dependencies:

- stories 1, 3, 4B, and 4B.5

### Story 6. Add public event subsystem

Outcome:

- request, transfer, node, and alert changes become a first-class public event surface

Affected modules:

- `src/session/action_packets.rs`
- `src/session/core.rs`
- `src/progress.rs`
- `src/lib.rs`
- `src/session/mod.rs`
- `src/session/runtime/events.rs`
- possibly new public event types under `src/session/`

Agent-sized tasks:

1. Define an internal event model and source adapters.
2. Bridge transfer, request, node, and alert changes into one event stream.
3. Expose a read-only public API without breaking existing callbacks.
4. Add ordering and backpressure tests.

Acceptance criteria:

- a Rust-native public event surface exists
- existing transfer progress behavior remains intact

Detailed spec:

- `agents/outputs/architectural_parity_story_6_public_event_subsystem.md`

Dependencies:

- stories 2 and 3

### Story 6B. Align public adapter and callback staging

Outcome:

- evolve the outward runtime staging so Rust has an architectural home comparable to the SDK’s adapter, listener, and observer/callback layers
- make later feature families land on a stable outward integration surface rather than directly on ad hoc actor callbacks

Affected modules:

- `src/lib.rs`
- `src/session/`
- `src/progress.rs`
- public event/runtime modules introduced by story 6

Agent-sized tasks:

1. Define the internal/public boundary between engine events and outward callback or observer delivery.
2. Separate event families and delivery semantics so later features do not pile onto one undifferentiated stream.
3. Add explicit cancellation/backpressure/runtime-staging rules where needed.
4. Add tests for callback ordering, observer isolation, and multi-family staging behavior.

Acceptance criteria:

- Rust has a clear outward adapter/callback architecture beyond a single generic event stream
- later feature families have a stable place to expose staged events without bypassing the runtime model

Detailed spec:

- `agents/outputs/architectural_parity_story_6b_public_adapter_callback_staging.md`

Dependencies:

- stories 1, 2, 3, and 6

### Story 7. Add filesystem abstraction and watcher boundary

Outcome:

- local file access becomes a reusable runtime layer for transfer, sync, backup, and mount

Affected modules:

- `src/fs/operations/upload.rs`
- `src/fs/operations/download.rs`
- `src/fs/operations/utils.rs`
- `src/fs/runtime/filesystem.rs`

Agent-sized tasks:

1. Define traits for local path handling, metadata, scanning, and watching.
2. Add the default implementation for the current supported platform set.
3. Move upload/download local file operations behind the new boundary.
4. Add tests for rename, delete, metadata change, and scan behavior.

Acceptance criteria:

- upload/download stop owning raw filesystem behavior directly
- sync-facing file primitives exist without introducing sync itself

Detailed spec:

- `agents/outputs/architectural_parity_story_7_filesystem_watcher_boundary.md`

Dependencies:

- story 1

### Story 7B. Align platform/runtime layering

Outcome:

- introduce explicit OS-aware runtime/module homes analogous to the SDK’s platform layering where later filesystem, watch, mount, and desktop work will need them
- prevent platform-sensitive behavior from accumulating in generic modules with no architectural owner

Affected modules:

- `src/fs/`
- `src/session/`
- platform-specific modules introduced under `src/` as needed

Agent-sized tasks:

1. Define the platform-sensitive runtime seams that must not remain embedded in generic code.
2. Add the minimum module/layout structure for supported platform families.
3. Move filesystem/watch and mount-facing platform decisions behind those homes.
4. Add tests or compile-gated scaffolding to prove platform capability gating is explicit.

Acceptance criteria:

- platform-sensitive runtime behavior has named module homes
- later desktop features can land into explicit OS-aware layers instead of generic catch-all modules

Detailed spec:

- `agents/outputs/architectural_parity_story_7b_platform_runtime_layering.md`

Dependencies:

- stories 1 and 7

### Story 8. Add query/index layer over cached nodes

Outcome:

- cached navigation grows into a real search/filter/page substrate

Affected modules:

- `src/fs/operations/browse.rs`
- `src/fs/node.rs`
- `src/fs/runtime/query.rs`
- node-cache/query hook seams from stories 4B and 4C as needed

Agent-sized tasks:

1. Define an internal query API for search/filter/page use cases.
2. Add an in-memory implementation on top of the current cached tree.
3. Add SDK-shaped node-backend hook seams for later query acceleration without widening the generic persistence SPI.
4. Add tests for search, filter, paging, recent-file, and version-aware query behavior.

Acceptance criteria:

- search/filter/page APIs have a clean internal substrate
- recent-file semantics are explicit and SDK-shaped
- current browse APIs continue to work

Detailed spec:

- `agents/outputs/architectural_parity_story_8_query_index_runtime.md`

Dependencies:

- stories 3, 4B, and 4C

### Story 8B. Add secondary durable state domains

Outcome:

- give non-node `MegaClient`-style durable/runtime state families explicit ownership instead of leaving them as incidental fields or one-off persistence behavior
- make later parity work for secondary state families land into known architectural homes

Affected modules:

- `src/session/core.rs`
- `src/session/runtime/persistence.rs`
- additional session/runtime modules introduced for specific state families

Agent-sized tasks:

1. Identify the secondary durable state domains the Rust architecture must own explicitly for future parity work.
2. Define internal models and persistence ownership for those families.
3. Wire the first set of those domains behind the persistence/runtime architecture without broadening into unrelated feature delivery.
4. Add restart and fallback tests for the domains brought under ownership in this story.

Acceptance criteria:

- secondary engine-state families no longer rely on incidental ownership or ad hoc persistence behavior
- future feature parity work has explicit subsystem homes for those state domains

Detailed spec:

- `agents/outputs/architectural_parity_story_8b_secondary_durable_state_domains.md`

Dependencies:

- stories 1, 3, 4B, and 4C

### Story 9. Implement sync engine MVP

Outcome:

- add a minimal but real sync runtime based on the new persistence, transfer, and filesystem layers

Affected modules:

- new sync module under `src/`
- filesystem runtime from story 7
- transfer runtime from story 5
- persistence/query layers from stories 3, 4B, 4C, and 8

Agent-sized tasks:

1. Define sync config and sync state models.
2. Implement bootstrap, scan, reconcile, and steady-state loop behavior.
3. Add conflict/error reporting and restart recovery handling.
4. Add integration tests for bootstrap sync, steady-state sync, and restart recovery.

Acceptance criteria:

- a scoped sync MVP exists behind an additive API
- sync reuses the foundational layers instead of bypassing them

Detailed spec:

- `agents/outputs/architectural_parity_story_9_sync_engine_mvp.md`

Dependencies:

- stories 3, 4B, 4C, 5, 7, 7B, and 8

### Story 9B. Define side-service subsystem homes

Outcome:

- establish explicit runtime homes for distinct non-core SDK subsystem families such as gfx/media-attribute handling, `file_service`, and worker/executor-style helpers
- make future feature porting land into reserved subsystem homes instead of distorting core engine modules

Affected modules:

- new side-service modules under `src/`, organized by subsystem family rather than as one generic pipeline bucket
- `src/session/` and `src/fs/` integration points as needed

Agent-sized tasks:

1. Define the service/runtime pattern for distinct side-service families without forcing them into one synthetic subsystem.
2. Define feature gating and lifecycle ownership for those family-specific services.
3. Add the minimum scaffolding needed so later `file_service`, media/gfx, and worker-helper style features have stable architectural homes.
4. Document which concrete feature families are still implementation-deferred after the structural homes exist.

Acceptance criteria:

- side-service families have explicit architectural homes that reflect the upstream split into separate subsystem homes
- future non-core SDK feature work can land without reshaping the core engine again

Detailed spec:

- `agents/outputs/architectural_parity_story_9b_side_service_pipeline_homes.md`

Dependencies:

- stories 1, 6B, and 7B

### Story 10A. Implement backup subsystem foundation / backup-sync runtime

Outcome:

- establish `src/backup/` as a real subsystem home and land the sync-backed half of SDK backup behavior
- backup sync jobs become sync-backed runtime units with stable backup ids, mirror/monitor policy state, and backup-specific reporting metadata

Affected modules:

- new backup module under `src/`
- sync module from story 9
- `src/session/core.rs`
- `src/session/runtime/persistence.rs`
- key/share metadata handling in `src/session/`

Agent-sized tasks:

1. Define backup runtime foundation and backup-sync job/report models.
2. Add durable backup job state and backup-sync reporting metadata ownership.
3. Add backup-sync execution plumbing against story 9 sync runtime contracts.
4. Add tests for backup-sync lifecycle, restart recovery, and reporting metadata.

Acceptance criteria:

- `src/backup/` exists as the architectural home for backup
- sync-backed backup jobs are implemented with stable backup ids and SDK-shaped reporting state
- backup-sync execution is layered on story 9 sync runtime primitives rather than on backup-local filesystem code

Detailed spec:

- `agents/outputs/architectural_parity_story_10a_backup_sync_runtime.md`

Dependencies:

- story 9
- platform/runtime-sensitive backup integrations should also follow the Story 7B layer once they exist

### Story 10B. Implement scheduled-copy controller / retention

Outcome:

- add the SDK-style scheduled-copy half of backup under `src/backup/`
- scheduled copy jobs use a dedicated backup-owned controller with period/cron scheduling, bounded catch-up semantics, timestamped child backup folders, recovery state, and retention pruning

Affected modules:

- backup module from story 10A
- `src/session/core.rs`
- `src/session/runtime/persistence.rs`
- node/query layer from story 8
- filesystem runtime from story 7
- transfer runtime from story 5

Agent-sized tasks:

1. Define scheduled-copy controller models, schedule semantics, and run-state types.
2. Add scheduled-copy execution and restart-recovery plumbing.
3. Add retention pruning and historical-generation state handling.
4. Add tests for scheduling, catch-up, recovery, and retention.

Acceptance criteria:

- scheduled copy is implemented as a dedicated backup-owned controller rather than a disguised sync config
- scheduled copy follows SDK semantics for period-or-cron scheduling, no-overlap execution, catch-up policy, timestamped child backup folders, and `maxBackups` pruning
- scheduled copy reuses lower node/filesystem/transfer layers without introducing a second steady-state sync engine

Detailed spec:

- `agents/outputs/architectural_parity_story_10b_scheduled_copy_controller.md`

Dependencies:

- story 10A
- stories 5, 7, and 8
- platform/runtime-sensitive backup integrations should also follow the Story 7B layer once they exist

### Story 11. Implement mount/FUSE subsystem

Outcome:

- mount becomes a feature-gated service built on top of the durable node/query/runtime layers

Affected modules:

- new mount module under `src/`
- query/index layer from story 8
- persistence layer from stories 3, 4B, and 4C
- filesystem runtime from story 7

Agent-sized tasks:

1. Define mount state and inode/path cache models.
2. Add service lifecycle and feature gating.
3. Implement core browse/open/read semantics on top of durable node/query state.
4. Add platform-aware test scaffolding and service lifecycle tests.

Acceptance criteria:

- mount is layered on existing foundations rather than bypassing them
- feature gating is explicit

Detailed spec:

- `agents/outputs/architectural_parity_story_11_mount_fuse_subsystem.md`

Dependencies:

- stories 4C, 7, 7B, and 8

### Story 12. Add parity validation harness

Outcome:

- architectural parity is measured continuously rather than inferred from manual inspection

Affected modules:

- `tests/`
- `examples/` if needed for integration fixtures
- docs under `agents/outputs/`

Agent-sized tasks:

1. Add Rust-vs-upstream integration scenarios for login, fetch-nodes, SC catch-up, uploads, downloads, exports, and shares.
2. Add foundation-level scenarios for persistence restore, transfer recovery, and event delivery.
3. Add sync and backup recovery scenarios after those stories land.
4. Add a small benchmark set for startup, cache restore, and large-transfer behavior.

Acceptance criteria:

- parity claims in the reports can be tied to executable checks

Detailed spec:

- `agents/outputs/architectural_parity_story_12_validation_harness.md`

Dependencies:

- starts after story 2 for core flows
- expands after stories 4B, 4B.5, 4C, 5, 6, 6B, 8B, 9, 9B, 10A, 10B, and 11

### Story 12B. Add architecture gap ledger and epic audit discipline

Outcome:

- make the epic self-auditing so uncovered architectural gaps are visible immediately rather than discovered halfway through implementation

Affected modules:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_report.md`
- validation docs under `agents/outputs/`

Agent-sized tasks:

1. Keep the architecture-gap coverage matrix current with the parity report.
2. Require each parity dimension to have an owning story or an explicit out-of-scope rationale.
3. Add a periodic refresh checklist tying epic updates to report refreshes.
4. Add validation notes showing which dimensions are fully closed, partially closed, or still open.

Acceptance criteria:

- the epic can be audited for architecture-gap coverage without reading every story in detail
- future refreshes cannot silently omit major parity dimensions

Detailed spec:

- `agents/outputs/architectural_parity_story_12b_architecture_gap_ledger.md`

Dependencies:

- starts immediately
- remains active until epic completion

---

## Execution Order

### Foundation phase

1. Story 1
2. Story 2
3. Story 3
4. Story 4
5. Story 4B
6. Story 4B.5
7. Story 4C

### Runtime-hardening phase

8. Story 5
9. Story 6
10. Story 6B
11. Story 7
12. Story 7B
13. Story 8
14. Story 8B

### Desktop-subsystem phase

15. Story 9
16. Story 9B
17. Story 10A
18. Story 10B
19. Story 11

### Validation phase

20. Story 12
21. Story 12B

Parallelism notes:

- story 4B may begin once story 3 is stable, but story 4B.5 must wait for story 4B and story 4C must wait for stories 4, 4B, and 4B.5
- stories 5 and 6 can run in parallel after stories 2, 3, 4B, and 4B.5 are stable
- story 6B can begin once story 6 has established the core event substrate
- stories 7 and 8 can run in parallel after stories 4B and 4C are stable
- story 10A must wait for story 9, and story 10B must wait for story 10A plus stories 5, 7, and 8
- stories 7B and 9B are structural follow-on stories that should begin before the corresponding feature families get large
- story 12 should begin early for core flows and expand with each completed foundation story
- story 12B should be updated whenever the parity report adds or changes a tracked architecture dimension

---

## Agent Task Template

Each story should be split into tasks of these shapes:

1. design task
   - define interfaces, invariants, migration boundaries, and test strategy
2. implementation task
   - add one internal module or boundary slice
3. wiring task
   - route one or two existing flows through the new boundary
4. verification task
   - add unit/integration coverage and update parity docs if the story changes parity status

An individual agent task should:

- own a disjoint file set where possible
- have a single measurable outcome
- avoid mixing foundational refactor and end-user feature expansion unless the story explicitly requires both

---

## Story Acceptance Rules

Every Rust-touching story must complete with:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Every story must also:

- identify whether public API changed
- update docs if public behavior changed
- avoid unrelated formatting or module churn
- record parity impact in the reports if the story materially changes parity status

---

## Recommended First Story Slice

Start with story 1 as a short architectural design slice. It is the safest place to set the module ownership map and dependency graph before agents begin landing internal subsystem work.

That first slice should produce:

- a subsystem map for request runtime, persistence runtime, transfer runtime, filesystem runtime, query/index runtime, sync, backup, and mount
- a dependency graph showing what must exist before sync, backup, and mount can start
- a list of public APIs that must remain stable through the foundation phase
