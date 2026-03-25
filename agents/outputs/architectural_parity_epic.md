# megalib Architectural Parity Epic

Validated on 2026-03-25 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

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

The plan must preserve public API stability unless a story explicitly introduces additive public surface.

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
- transfer resume/runtime consumer migration belongs to Story 5
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

Dependencies:

- stories 1 and 3

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

Consumes from Story 3:

- the transfer resume persistence domain defined by the Story 3 SPI

Acceptance criteria:

- upload/download modules become thinner orchestration layers
- transfer policy is centrally owned
- transfer durability is owned by the transfer subsystem rather than `UploadState` sidecar files

Dependencies:

- stories 1 and 3

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

Dependencies:

- stories 2 and 3

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

Dependencies:

- story 1

### Story 8. Add query/index layer over cached nodes

Outcome:

- cached navigation grows into a real search/filter/page substrate

Affected modules:

- `src/fs/operations/browse.rs`
- `src/fs/node.rs`
- `src/fs/runtime/query.rs`
- persistence/index modules from stories 3 and 4

Agent-sized tasks:

1. Define an internal query API for search/filter/page use cases.
2. Add an in-memory implementation on top of the current cached tree.
3. Add persistent-index hooks for later durable backends.
4. Add tests for search, filter, paging, and version-aware query behavior.

Acceptance criteria:

- search/filter/page APIs have a clean internal substrate
- current browse APIs continue to work

Dependencies:

- stories 3 and 4

### Story 9. Implement sync engine MVP

Outcome:

- add a minimal but real sync runtime based on the new persistence, transfer, and filesystem layers

Affected modules:

- new sync module under `src/`
- filesystem runtime from story 7
- transfer runtime from story 5
- persistence/query layers from stories 3, 4, and 8

Agent-sized tasks:

1. Define sync config and sync state models.
2. Implement bootstrap, scan, reconcile, and steady-state loop behavior.
3. Add conflict/error reporting and restart recovery handling.
4. Add integration tests for bootstrap sync, steady-state sync, and restart recovery.

Acceptance criteria:

- a scoped sync MVP exists behind an additive API
- sync reuses the foundational layers instead of bypassing them

Dependencies:

- stories 3, 4, 5, 7, and 8

### Story 10. Implement scheduled backup / scheduled copy

Outcome:

- backup becomes a policy layer on top of sync-grade runtime primitives

Affected modules:

- new backup module under `src/`
- sync module from story 9
- key/share metadata handling in `src/session/`

Agent-sized tasks:

1. Define backup job and schedule models.
2. Add schedule evaluation and execution plumbing.
3. Add retention and recovery semantics.
4. Add tests for scheduled execution, restart recovery, and metadata handling.

Acceptance criteria:

- backup is implemented without introducing a second filesystem engine

Dependencies:

- story 9

### Story 11. Implement mount/FUSE subsystem

Outcome:

- mount becomes a feature-gated service built on top of the durable node/query/runtime layers

Affected modules:

- new mount module under `src/`
- query/index layer from story 8
- persistence layer from stories 3 and 4
- filesystem runtime from story 7

Agent-sized tasks:

1. Define mount state and inode/path cache models.
2. Add service lifecycle and feature gating.
3. Implement core browse/open/read semantics on top of durable node/query state.
4. Add platform-aware test scaffolding and service lifecycle tests.

Acceptance criteria:

- mount is layered on existing foundations rather than bypassing them
- feature gating is explicit

Dependencies:

- stories 4, 7, and 8

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

Dependencies:

- starts after story 2 for core flows
- expands after stories 4, 5, 6, 9, 10, and 11

---

## Execution Order

### Foundation phase

1. Story 1
2. Story 2
3. Story 3
4. Story 4

### Runtime-hardening phase

5. Story 5
6. Story 6
7. Story 7
8. Story 8

### Desktop-subsystem phase

9. Story 9
10. Story 10
11. Story 11

### Validation phase

12. Story 12

Parallelism notes:

- stories 5 and 6 can run in parallel after stories 2 and 3 are stable
- stories 7 and 8 can run in parallel after stories 3 and 4 are stable
- story 12 should begin early for core flows and expand with each completed foundation story

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
