# Story 1 Spec: Define the Rust Core-Engine Target Boundary

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 1 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready design story. It is a documentation-first story: its purpose is to define the target internal architecture and delivery boundaries for the rest of the epic without changing Rust runtime behavior yet.

Story type:

- Documentation / design baseline

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_report.md`
- `agents/outputs/parity_report.md`

---

## Status

Completed.

Story 1 is complete as a documentation-first foundation story because it now provides:

- the target subsystem map
- current-to-target ownership mapping
- dependency direction rules
- foundation-phase invariants and non-goals
- downstream story dependencies
- an epic cross-link for later story execution
- the ownership baseline for the structural follow-on stories added after the epic was expanded

Story 1 does not produce runtime behavior changes. Its output is the ownership and dependency contract that later implementation stories must follow.

---

## Validation Findings

Overall verdict: partially grounded / partially speculative.

Grounded in the upstream MEGA C++ SDK:

- `MegaApiImpl` is explicitly the intermediate outward layer: it owns the blocking thread, request queues, transfer queues, and request/transfer/global listener registration and dispatch (`../sdk/src/megaapi_impl.cpp`, `../sdk/src/megaapi.cpp`, `../sdk/include/megaapi.h`).
- `MegaClient` is the engine core and directly owns key internal state and services including `NodeManager`, `DbAccess`, `sctable`, `SCSN`, filesystem access, transfers, syncs, gfx processing, file service, and FUSE service (`../sdk/include/mega/megaclient.h`, `../sdk/src/megaclient.cpp`).
- `NodeManager` is DB-backed for node-state/query work via `DBTableNodes`, including `getChildren`, `getRecentNodes`, `searchNodes`, and folder-link root handling (`../sdk/include/mega/nodemanager.h`, `../sdk/src/nodemanager.cpp`, `../sdk/src/megaclient.cpp`).
- Filesystem access and directory notification are foundational support layers for the SDK event loop and sync-capable platforms (`../sdk/src/megaclient.cpp`, `../sdk/include/mega/win32/megafs.h`, `../sdk/include/mega/android/androidFileSystem.h`).
- Public-folder login is a first-class mode with dedicated folder-link state and cache-resume behavior, even though it still runs through `MegaApiImpl` and `MegaClient` rather than through a wholly separate engine type (`../sdk/include/megaapi.h`, `../sdk/src/megaclient.cpp`).

Partially grounded / speculative:

- `NodeManager + DB + SCSN` are important upstream persistence/coherency anchors, but they are not the whole engine boundary by themselves; `MegaClient` also owns transfer, sync, filesystem, gfx, file-service, and FUSE concerns.
- The proposed Rust module homes in this story (`src/session/runtime/*`, `src/fs/runtime/*`, `src/platform/`, `src/services/`, and similar) are `megalib` design choices informed by upstream structure, not one-to-one upstream module names.
- The story's "public adapter", "secondary state", and "side-service pipeline" terminology is best understood as Rust-facing design vocabulary derived from upstream listener/gfx/service patterns rather than as exact named C++ subsystems.

Unsupported after the corrections below:

- no fully unsupported material claim remains; remaining forward-looking structure is now presented as design guidance rather than as direct upstream fact

---

## Story Goal

Define the target Rust internal architecture that will let `megalib` converge on the upstream SDK's core runtime layering while preserving the current Rust actor ownership model and public API stability.

This story exists to answer these questions before implementation stories begin:

- what are the internal subsystems we are building toward
- which current modules already own part of those responsibilities
- where should future internal modules live
- what invariants must remain stable while the architecture evolves
- what must be built before sync, backup, and mount/FUSE can start

---

## Why This Story Exists

The current crate already has meaningful architecture:

- `SessionHandle` is the public async facade
- `SessionActor` serializes authenticated control flow
- `Session` is the true mutable state owner
- `ScPoller` already separates the SC lane
- `tree.rs`, `browse.rs`, `key_sync.rs`, and `sharing.rs` already contain non-trivial runtime logic
- `public.rs` is a separate unauthenticated runtime shape

But the crate does not yet have named internal subsystems equivalent to the upstream architecture for:

- request orchestration
- durable node/cache/query state
- transfer scheduling and persistence
- filesystem/watch integration
- public event delivery
- public adapter/callback staging
- platform/runtime layering
- secondary durable state domains
- side-service pipeline homes

Without a stable target boundary, later stories will make local decisions that are hard to compose.

---

## Story Scope

In scope:

- define the target internal subsystem map
- define ownership boundaries between existing modules and future modules
- define rollout dependencies between stories
- define invariants and non-goals for the foundation phase
- define how later stories should split into agent-sized tasks

Out of scope:

- landing new runtime behavior
- introducing new public API
- reorganizing crate/module structure immediately
- implementing persistence, request runtime, transfer runtime, filesystem runtime, sync, backup, or mount

This story is successful if it produces a stable design contract for later stories.

---

## Architecture Principles

The following principles are binding for the foundation phase unless a later approved story explicitly revises them:

1. Preserve the actor control model.
   `SessionHandle` remains a cheap-clone async facade and authenticated mutable state remains single-owner under the actor.

2. Keep `Session` as the core engine boundary.
   We are not replacing `Session`; we are growing internal runtimes under and around it.

3. Treat `public.rs` as a separate runtime shape.
   Public-folder/public-link flows must not be forced into the authenticated actor just to fit a uniform model.

4. Prefer additive internal seams over broad rewrites.
   Stories should introduce boundaries first, then re-route existing logic incrementally.

5. Use upstream architecture as reference, not template code.
   The target is parity of runtime responsibilities, not a line-by-line clone of `MegaApiImpl` or `MegaClient`.

6. Center the upstream comparison on `MegaClient` plus its `NodeManager`/DB/`SCSN` state path.
   Those are the primary upstream engine-state anchors, not just the API adapter layer.

---

## Current Runtime Ownership

### Authenticated runtime

Current owner map:

- public authenticated facade: `src/session/actor.rs`
- authenticated mutable engine state: `src/session/core.rs`
- SC polling lane: `src/session/sc_poller.rs`
- action-packet application: `src/session/action_packets.rs`
- key and sharing state: `src/session/key_sync.rs`, `src/session/sharing.rs`, `src/crypto/key_manager.rs`
- tree bootstrap and browsing: `src/fs/operations/tree.rs`, `src/fs/operations/browse.rs`
- uploads and downloads: `src/fs/operations/upload.rs`, `src/fs/operations/download.rs`
- low-level request transport: `src/api/client.rs`
- current resumable transfer sidecar: `src/fs/upload_state.rs`

### Unauthenticated runtime

Current owner map:

- public file/folder link parsing and public-folder session runtime: `src/public.rs`

Implication:

- `megalib` already has two runtime shapes
- Story 1 must preserve that fact instead of pretending everything belongs under one actor

---

## Target Subsystem Map

The target internal architecture should converge on the following subsystem split.

| Target subsystem | Responsibility | Current owner(s) | Recommended future home |
|------------------|----------------|------------------|--------------------------|
| Public facade | stable async user-facing API for authenticated session flows | `src/session/actor.rs`, `src/lib.rs` | keep in `src/session/actor.rs` plus re-exports |
| Core engine state | authenticated mutable engine state, current-state fields, session identity, contacts, keys, runtime handles | `src/session/core.rs` | keep in `src/session/core.rs` |
| Request runtime | request submission, queueing policy, retained inflight work, seqtag integration, retry hooks | actor logic plus `src/api/client.rs` | `src/session/runtime/request.rs` |
| Persistence runtime | durable node state, SCSN/current-state state, alerts, transfer metadata, future query index backing | session state plus `src/fs/upload_state.rs` | `src/session/runtime/persistence.rs` |
| Tree coherency runtime | bootstrap/apply logic, node graph ownership, deferred-node/key coordination, cache restore/apply semantics | `src/fs/operations/tree.rs`, `src/session/action_packets.rs`, `src/fs/operations/browse.rs` | keep logic split, but owned conceptually by core engine plus persistence runtime |
| Transfer runtime | queueing, scheduling, retry policy, resume policy, worker orchestration, persistent transfer state | `src/fs/operations/upload.rs`, `src/fs/operations/download.rs`, `src/fs/upload_state.rs` | `src/fs/runtime/transfer.rs` |
| Filesystem runtime | local path handling, metadata, scanning, watch abstraction, local I/O policy | direct file I/O in `src/fs/operations/*` | `src/fs/runtime/filesystem.rs` |
| Query/index runtime | search, filter, pagination, version-aware query substrate over cached and later persistent nodes | `src/fs/operations/browse.rs` | `src/fs/runtime/query.rs` |
| Public event runtime | internal event model plus public stream/callback surface for request, transfer, node, and alert events | progress callback state plus internal SC handling | `src/session/runtime/events.rs` |
| Public adapter runtime | outward listener/callback/adaptation staging, event-family separation, bindings-facing adapter depth | `src/lib.rs`, `src/session/actor.rs`, `src/progress.rs`, future public event runtime | `src/session/runtime/adapter.rs` |
| Public-link runtime | unauthenticated public file/folder flows | `src/public.rs` | keep in `src/public.rs`, with selective reuse of shared lower layers later |
| Platform runtime layer | OS-aware module homes and capability boundaries for filesystem, watch, mount, and later desktop work | mostly missing; currently implicit in generic modules | future `src/platform/` |
| Secondary state runtime | explicit ownership for non-node durable/runtime state families that should not remain incidental `Session` fields forever | `src/session/core.rs` plus ad hoc persistence state | future `src/session/runtime/state/` |
| Side-service pipeline runtime | background worker/service homes for preview, thumbnail, metadata, and similar non-core pipelines | missing | future `src/services/` |
| Sync runtime | reconcile, watch/scan loop, persisted sync state | missing | future `src/sync/` |
| Backup runtime | scheduled backup/copy policy over sync-grade primitives | missing | future `src/backup/` |
| Mount runtime | mount/FUSE state, inode/path layer, service lifecycle | missing | future `src/mount/` |

---

## Dependency Direction Rules

The target architecture should obey these dependency directions.

### Session runtime rules

- `src/session/runtime/request.rs` may depend on `src/api/`, `src/crypto/`, `src/error.rs`, and authenticated session state.
- `src/session/runtime/persistence.rs` may depend on session-owned data models and storage helpers, but must not depend on upload/download operation modules.
- `src/session/runtime/events.rs` may depend on session state, action-packet handling, request runtime, and transfer-facing event inputs, but must not become a home for business logic currently owned by operations.
- `src/session/runtime/adapter.rs` may depend on public event/runtime types, progress-facing transport, and session-facing outward delivery hooks, but must not become a second owner of engine state or request policy.
- `src/session/runtime/state/` may depend on session-owned models and persistence/runtime seams, but secondary state domains must not be scattered back into unrelated operation files once they have a named home.

### FS runtime rules

- `src/fs/runtime/transfer.rs` may depend on `src/session/runtime/persistence.rs`, `src/fs/node.rs`, transport-neutral helpers, and transfer-local I/O abstractions.
- `src/fs/runtime/filesystem.rs` must not depend on upload/download operation modules; operations should depend on it.
- `src/fs/runtime/query.rs` may depend on node models, persisted node state, and tree coherency inputs, but must not depend on upload/download runtime details.
- `src/platform/` may be depended on by filesystem, mount, and service runtimes, but platform modules must not depend outward on operation modules or the public facade.
- `src/services/` may depend on lower runtimes such as filesystem, query, or adapter layers as needed, but side-service pipelines must not become hidden extensions of `src/session/core.rs`.

### Cross-layer rules

- `src/api/client.rs` stays transport-first and must not absorb request policy, queue ownership, or engine-level retry semantics.
- `src/fs/operations/` stays orchestration-first and must not remain the long-term home for transfer scheduling, filesystem policy, or query/index policy.
- `src/public.rs` may selectively reuse lower layers later, but it does not route through the authenticated actor and does not become a hidden second owner of authenticated engine state.
- outward callback/listener staging belongs above engine events, not inside business-logic modules that merely produce those events.
- New runtime modules should depend inward toward shared lower layers; lower layers should not depend outward on end-user operation modules.

---

## Story 1 Design Decisions

### Decision 1. `Session` remains the engine root

Why:

- current design already has a coherent single-owner mutable state boundary
- replacing it would create unnecessary risk before parity layers even exist

Consequence:

- later stories should add runtime handles and subsystem state around `Session`, not bypass it

### Decision 2. Request runtime belongs closer to `session` than `api`

Why:

- transport is only one concern
- request orchestration is semantically part of engine/runtime behavior
- seqtag ordering, current-state coordination, and retry semantics belong near the engine

Consequence:

- `src/api/client.rs` should stay transport-focused
- Story 2 should add the new request runtime at `src/session/runtime/request.rs`

### Decision 3. Persistence is an engine concern, not a transfer-only concern

Why:

- upstream parity target includes the `NodeManager`/DB/`SCSN` persistence path, not just resumable uploads
- persistence must cover nodes, SCSN/current-state, alerts, transfer metadata, and later query support

Consequence:

- Story 3 should define a broad persistence SPI at `src/session/runtime/persistence.rs`
- `src/fs/upload_state.rs` becomes one consumer of that SPI, not the architectural center

### Decision 4. Transfer runtime belongs under `fs`

Why:

- transfer execution is tightly coupled to file movement and worker policy
- transfer runtime should be reusable by sync and backup later

Consequence:

- Story 5 should create a dedicated transfer subsystem at `src/fs/runtime/transfer.rs`
- upload/download operation files should become orchestration clients of that subsystem

### Decision 5. Filesystem runtime must exist before sync or mount

Why:

- current direct local I/O is insufficient for sync, backup, and mount-grade behavior
- the upstream SDK uses filesystem access and notifications as foundational support for sync- and mount-adjacent behavior

Consequence:

- Story 7 is a prerequisite for sync MVP and mount work

### Decision 6. Public-link runtime stays separate

Why:

- `src/public.rs` already expresses a different runtime shape
- forcing it into the authenticated actor would create churn without architectural benefit

Consequence:

- future lower layers may be shared, but the runtime entrypoint remains distinct

### Decision 7. Public adapter staging is distinct from the event model

Why:

- the SDK’s outward architecture is not just “events exist”; it also has listener families, request/transfer queues, and outward dispatch layers
- later feature families need a stable outward integration surface rather than direct ad hoc callbacks from engine code

Consequence:

- Story 6 may establish the event substrate at `src/session/runtime/events.rs`
- Story 6B should establish outward adapter/callback staging at `src/session/runtime/adapter.rs`

### Decision 8. Platform-sensitive runtime behavior needs explicit homes

Why:

- the SDK’s platform layering is structurally important even when feature parity is incomplete
- later filesystem, watch, mount, and desktop work should not accumulate in generic modules with no OS-aware owner

Consequence:

- Story 7B should introduce explicit module homes under `src/platform/`

### Decision 9. Secondary durable state domains need first-class ownership

Why:

- full engine-structure parity is not only nodes and transfers
- some `MegaClient`-style durable/runtime state families should not remain incidental `Session` fields forever

Consequence:

- Story 8B should give those domains explicit homes under `src/session/runtime/state/`

### Decision 10. Side-service pipelines need reserved subsystem homes

Why:

- later SDK-adjacent side pipelines such as gfx/file-service style helpers should land into prepared architectural homes rather than distorting the core engine
- even when feature delivery is deferred, the runtime layout should anticipate that breadth

Consequence:

- Story 9B should establish service/pipeline homes under `src/services/`

---

## Invariants To Preserve

These invariants must be maintained through Stories 2 through 9B unless a later approved story explicitly revises them.

### Control-plane invariants

- authenticated mutable session state has a single owner
- public async authenticated API calls continue to flow through `SessionHandle`
- SC polling remains a distinct lane rather than being collapsed into generic request execution

### State invariants

- `Session` remains the source of truth for authenticated runtime state
- node bootstrap, deferred key handling, and share-key flows must remain coherent during refactors
- current-state and action-packet state must not become hidden incidental state in unrelated modules

### Public API invariants

- no breaking changes to existing public API during the foundation phase
- additive public event/query/sync APIs require explicit story-level approval
- docs must stay aligned with any user-visible parity change

### Module invariants

- `src/api/client.rs` stays transport-first
- `src/public.rs` stays a separate runtime entrypoint
- `src/fs/operations/` remains focused on user-facing operations, not long-term home for engine-wide policy

---

## Non-Goals For The Foundation Phase

The following are explicitly not goals of Stories 1 through 9B:

- full sync parity
- scheduled backup parity
- mount/FUSE parity
- chat or meetings parity
- full cross-platform feature parity with every upstream OS-specific subsystem
- broad module reorganization for cosmetic reasons
- replacing the actor with a waiter-thread model

These remain downstream consumers of the foundation layers.

---

## Dependency Graph

Story dependency graph:

- Story 1 enables Stories 2, 3, 6B, 7, 7B, 8B, and 9B as the ownership baseline
- Story 3 is required before durable node coherency in Story 4
- Story 4 is required before real query/index runtime in Story 8
- Story 6 is required before outward adapter/callback staging in Story 6B
- Story 7 is required before platform/runtime layering alignment in Story 7B
- Stories 3, 4B, and 4C are required before secondary durable state ownership in Story 8B
- Stories 6B and 7B are required before side-service pipeline homes in Story 9B
- Stories 3, 4, 5, 7, and 8 are all required before sync MVP in Story 9
- Story 9 is required before scheduled backup in Story 10
- Stories 4, 7, and 8 are required before mount/FUSE in Story 11

Critical architectural sequence:

1. define subsystem boundaries
2. define request and persistence seams
3. make node/cache/SCSN state durable and coherent
4. extract transfer and filesystem runtimes
5. build query/event surfaces on top
6. align outward adapter staging, platform layering, and secondary state homes
7. reserve side-service pipeline homes before broad non-core feature porting
8. then start sync, backup, mount, and later feature families

---

## Deliverables For Story 1

Story 1 should produce exactly these artifacts:

1. this detailed Story 1 spec
2. a subsystem ownership map that later stories can reference directly
3. a dependency map for later stories
4. a list of invariants and non-goals for the foundation phase

Optional but acceptable:

- a short architecture diagram in Markdown table form
- epic cross-links to this spec

Not allowed in Story 1:

- runtime behavior changes
- new public Rust APIs
- partial implementation of request, persistence, transfer, filesystem, sync, backup, or mount logic

---

## How To Consume This Story

Later stories should treat Story 1 as the ownership baseline for the foundation phase.

Use it in this order:

1. read `Target Subsystem Map` to determine where new internal code belongs
2. read `Dependency Direction Rules` before introducing imports or cross-module calls
3. read `Invariants To Preserve` before changing actor flow, session ownership, SC/AP handling, or public API shape
4. read `Non-Goals For The Foundation Phase` to avoid mixing desktop-subsystem work into foundation stories
5. read `Dependency Graph` before planning a new story or splitting agent tasks

For implementation stories:

- Story 2 must use `src/session/runtime/request.rs`
- Story 3 must use `src/session/runtime/persistence.rs`
- Story 5 must use `src/fs/runtime/transfer.rs`
- Story 6 must use `src/session/runtime/events.rs`
- Story 6B must use `src/session/runtime/adapter.rs`
- Story 7 must use `src/fs/runtime/filesystem.rs`
- Story 7B must use `src/platform/`
- Story 8 must use `src/fs/runtime/query.rs`
- Story 8B must use `src/session/runtime/state/`
- Story 9B must use `src/services/`

If a later story needs to violate this document, that should be treated as a design change and the Story 1 spec should be revised first rather than ignored locally.

---

## Agent-Sized Task Breakdown For Story 1

These are the tasks that an implementation agent can execute for Story 1.

### Task 1.1

Objective:

- define and record the target subsystem vocabulary

Write scope:

- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`

Done when:

- the subsystem table and definitions are stable enough that later stories can reference them verbatim

### Task 1.2

Objective:

- map current modules to future subsystem owners

Write scope:

- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`

Done when:

- each major current module under `src/session/`, `src/fs/`, `src/api/`, and `src/public.rs` has an explicit future owner

### Task 1.3

Objective:

- define invariants and non-goals for the foundation phase

Write scope:

- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`

Done when:

- later agents can tell what they must not break while implementing Stories 2 through 8

### Task 1.4

Objective:

- cross-link the epic to the detailed Story 1 spec

Write scope:

- `agents/outputs/architectural_parity_epic.md`

Done when:

- the epic points directly to this spec for Story 1 execution

---

## Acceptance Criteria

Story 1 is complete when:

- the target subsystem map is explicit
- current-to-target module ownership is explicit
- foundation-phase invariants are explicit
- foundation-phase non-goals are explicit
- downstream story dependencies are explicit
- the ownership map covers both the original foundation slices and the later structural-alignment slices added by the expanded epic
- the epic links to the detailed Story 1 spec
- no Rust source files changed
- no public API changed

---

## Verification

Required checks for Story 1:

- review the spec for consistency with `architectural_parity_report.md`
- review the spec for consistency with `architectural_parity_epic.md`
- confirm that only Markdown files under `agents/outputs/` changed

Rust verification commands are not required for Story 1 if it remains documentation-only.

---

## Open Questions To Resolve Before Story 2

These do not block Story 1 completion, but Story 2 and Story 3 should answer them explicitly:

1. what is the minimal event model needed before any public event API is exposed
2. what durable state must be in the first persistence backend versus deferred to later stories
3. whether query/index abstractions should be introduced before or alongside the first durable node-cache backend
4. how much platform/module scaffolding should land before platform-sensitive features start using it
5. which secondary durable state families should be first-class in Story 8B versus deferred explicitly

---

## Recommended Next Step

Do not begin Story 2 implementation until the epic and this spec are treated as the agreed ownership map for the foundation phase.

The next clean slice after Story 1 is:

- Story 2 design and implementation plan for the request-runtime abstraction under the actor
