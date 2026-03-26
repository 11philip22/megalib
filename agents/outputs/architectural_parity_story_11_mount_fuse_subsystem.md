# Story 11 Spec: Add the Mount/FUSE Subsystem

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 11 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, 4, 4B, 4C, 5, and 7, this is a code-bearing story. Its job is to introduce the mount/FUSE subsystem as a real internal architectural layer, not just a user-facing feature. The target is a feature-gated mount service that sits on top of durable node state, query/index access, filesystem/runtime boundaries, and platform hooks in a way that is structurally comparable to the upstream SDK.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_4_tree_cache_coherency.md`
- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`
- `agents/outputs/architectural_parity_story_4c_production_tree_cache_hardening.md`
- `agents/outputs/architectural_parity_story_7_filesystem_watcher_boundary.md`
- `agents/outputs/architectural_parity_story_7b_platform_runtime_layering.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- the Rust crate has no `src/mount/` tree
- there is no mount feature gate
- there is no mount service lifecycle, mount registry, inode/path cache, or mount-local durable state
- there are no platform mount hooks under `src/platform/`
- there is no public or internal FUSE-facing request/session layer in the crate
- there is effectively no current Rust mount implementation at all

This means the mount/FUSE dimension is structurally missing, not merely incomplete.

---

## Story Goal

Introduce a feature-gated mount subsystem under `src/mount/` that gives `megalib` the same kind of architectural home the upstream SDK has under `src/fuse`.

The story goal is not "implement every platform detail of the SDK mount stack." The goal is:

- create the Rust mount service layer
- define durable mount metadata and lifecycle ownership
- define mount inode/path cache ownership
- bind mount behavior to the query/index and durable node layers rather than bypassing them
- define the platform hook boundary at `src/platform/mount.rs`
- land core read-only browse/open/read semantics behind a feature gate

Done for Story 11 means:

- the architectural mount substrate exists and is layered correctly
- not that every libfuse or Windows callback is already ported

---

## Why This Story Exists

The upstream SDK treats mount/FUSE as a real subsystem, not as an afterthought on top of file browsing.

Key upstream structure:

- `Mount` owns mount-level runtime behavior and pinned inode invalidation
- `MountDB` owns durable mount metadata, enable/disable lifecycle, and startup enablement
- `ServiceContext` composes mount DB, inode DB, file cache, executor, and platform service pieces
- `InodeDB` owns the mount-facing inode identity and cloud-node mapping layer
- `FileCache` owns local cached file content contexts for mount I/O
- platform layers under `src/fuse/supported/platform/*` own session binding, dispatch, unmount, and OS-specific mount mechanics
- unsupported targets still have explicit service-context stubs rather than "missing architecture"

Grounded upstream references to implement against:

- Service-level control surface and type definitions: `../sdk/src/fuse/common/service.cpp:25`, `../sdk/include/mega/fuse/common/mount_info.h:16`, `../sdk/include/mega/fuse/common/mount_flags.h:14`, `../sdk/include/mega/fuse/common/mount_result.h:10`
- Supported/unsupported capability split: `../sdk/src/fuse/supported/platform/service.cpp:8`, `../sdk/src/fuse/unsupported/service_context.cpp:23`
- Service context composition and lifecycle: `../sdk/src/fuse/supported/platform/service_context.cpp:34`, `../sdk/src/fuse/supported/platform/service_context.cpp:52`, `../sdk/src/fuse/supported/platform/service_context.cpp:67`, `../sdk/src/fuse/supported/platform/service_context.cpp:72`, `../sdk/src/fuse/supported/platform/service_context.cpp:99`, `../sdk/src/fuse/supported/platform/service_context.cpp:147`, `../sdk/src/fuse/supported/platform/service_context.cpp:177`, `../sdk/src/fuse/supported/platform/service_context.cpp:209`
- Durable mount registry schema and startup re-enable flow: `../sdk/src/fuse/supported/common/mount_db.cpp:33`, `../sdk/src/fuse/supported/common/mount_db.cpp:98`, `../sdk/src/fuse/supported/common/mount_db.cpp:144`, `../sdk/src/fuse/supported/common/mount_db.cpp:202`, `../sdk/src/fuse/supported/common/mount_db.cpp:243`
- Mount object ownership and pinned-inode invalidation: `../sdk/src/fuse/supported/common/mount.cpp:28`, `../sdk/src/fuse/supported/common/mount.cpp:50`, `../sdk/src/fuse/supported/common/mount.cpp:70`, `../sdk/src/fuse/supported/common/mount.cpp:100`, `../sdk/src/fuse/supported/common/mount.cpp:105`, `../sdk/src/fuse/supported/common/mount.cpp:195`, `../sdk/src/fuse/supported/common/mount.cpp:239`
- Inode DB schema, synthetic inode allocation, and path traversal lookup: `../sdk/src/fuse/supported/common/inode_db.cpp:92`, `../sdk/src/fuse/supported/common/inode_db.cpp:216`, `../sdk/src/fuse/supported/common/inode_db.cpp:1654`
- File cache and file-I/O read path: `../sdk/src/fuse/supported/common/file_cache.cpp:32`, `../sdk/src/fuse/supported/common/file_cache.cpp:83`, `../sdk/src/fuse/supported/common/file_cache.cpp:106`, `../sdk/src/fuse/supported/common/file_cache.cpp:193`, `../sdk/src/fuse/supported/common/file_io_context.cpp:558`, `../sdk/src/fuse/supported/common/file_io_context.cpp:571`
- POSIX session dispatch and first-slice browse/open/read entrypoints: `../sdk/src/fuse/supported/platform/posix/session_base.cpp:68`, `../sdk/src/fuse/supported/platform/posix/session_base.cpp:195`, `../sdk/src/fuse/supported/platform/posix/session_base.cpp:258`, `../sdk/src/fuse/supported/platform/posix/session_base.cpp:275`, `../sdk/src/fuse/supported/platform/posix/libfuse/3/session.cpp:26`, `../sdk/src/fuse/supported/platform/posix/mount.cpp:139`, `../sdk/src/fuse/supported/platform/posix/mount.cpp:253`, `../sdk/src/fuse/supported/platform/posix/mount.cpp:335`, `../sdk/src/fuse/supported/platform/posix/mount.cpp:439`, `../sdk/src/fuse/supported/platform/posix/mount.cpp:466`
- Windows parity anchors for the same browse/open/read surface: `../sdk/src/fuse/supported/platform/windows/mount.cpp:133`, `../sdk/src/fuse/supported/platform/windows/mount.cpp:248`, `../sdk/src/fuse/supported/platform/windows/mount.cpp:403`, `../sdk/src/fuse/supported/platform/windows/mount.cpp:500`

These references should be treated as the primary C++ ground truth for Story 11. The rest of `../sdk/src/fuse/**` is supporting context, but the files above are the fastest path to matching the upstream ownership split and read-oriented behavior.

By contrast, the current Rust crate has:

- durable node/cache coherency
- a production persistence backend
- a planned filesystem/runtime layer
- a planned query/index layer

but no mount subsystem tying those together.

Story 11 is the slice that makes mount/FUSE a first-class architectural resident of the crate.

---

## Current State And Gap

The current gap is total:

- no mount runtime exists
- no mount state models exist
- no durable mount metadata exists
- no mount lifecycle or enable-at-startup policy exists
- no inode/path cache exists for mount-facing identity
- no platform mount session or capability surface exists

This is broader than a missing feature flag. It means later mount work would currently have no internal home and would naturally spill into generic session, fs, or platform code.

That is exactly the kind of architectural gap this epic is supposed to close.

---

## What Must Already Exist Before Story 11 Starts

Story 11 should not start until the following foundations are present:

1. Story 4C.
   Production-backed tree/cache coherency must already be reliable because mount reads must sit on durable node state rather than reconstructing cloud state ad hoc.

2. Story 7.
   The reusable filesystem/runtime boundary must exist so mount code does not invent its own local path and file behavior.

3. Story 7B.
   Platform runtime layering must already exist so mount capability gating and OS-facing session hooks land under `src/platform/mount.rs` rather than scattering `cfg(...)` logic across the new mount subsystem.

4. Story 8.
   Query/index substrate must already exist so mount browse, lookup, and child traversal use one query layer rather than re-traversing raw in-memory maps or calling network paths directly.

Practical implication:

- Story 11 depends on durable tree/query/filesystem/platform layers
- Story 11 does not need Story 9, Story 10A, or Story 10B first
- Story 11 may later need to consult sync state for local-path conflict checks if sync exists, but sync is not a prerequisite for defining the subsystem

---

## SDK Parity Target

The mount/FUSE subsystem should align with the SDK in these ways:

1. Mount is a service subsystem, not a handful of ad hoc callbacks.
2. Mount metadata and lifecycle are durably owned by a registry/database layer.
3. Inode identity and path lookup are owned by a mount-facing cache/index layer rather than improvised per request.
4. Platform session/bind/unbind mechanics are behind an OS-facing platform boundary.
5. Mount behavior consumes cloud/query/runtime state; it does not bypass the engine with direct API calls.
6. Unsupported targets still have explicit capability behavior instead of missing architecture.

Rust should stay idiomatic:

- do not clone every SDK class one-for-one
- do preserve the subsystem ownership split:
  - mount service
  - mount registry/durable state
  - inode/path cache
  - optional file cache home
  - platform mount driver/session

---

## Target Architecture

The Rust mount subsystem should converge on this split:

| Subsystem | Responsibility | Upstream analogue | Recommended Rust home |
|-----------|----------------|-------------------|------------------------|
| Mount service | top-level feature-gated service lifecycle, task orchestration, mount enable/disable entrypoints | `Service`, `ServiceContext` | `src/mount/service.rs` |
| Mount descriptor/state | mount flags, descriptor, result/status types, startup policy, read-only/persistent bits | `MountInfo`, `MountFlags`, `MountResult` | `src/mount/state.rs` |
| Mount registry | durable mount metadata, startup enablement, path/name uniqueness, add/remove/enable/disable policy | `MountDB` | `src/mount/registry.rs` |
| Mount inode/path cache | stable mount inode IDs, path-to-cloud lookup, pinned inode invalidation, child lookup | `InodeDB`, `Mount`, `MountInodeID` | `src/mount/inode.rs` |
| Mount file cache home | local cached file handles/contexts for file reads and later richer file semantics | `FileCache`, `FileInfo`, `FileIOContext` | `src/mount/file_cache.rs` |
| Platform mount driver | capability gating, bind/unbind hooks, session/context glue, unsupported-target stubs | platform `Mount`, platform `Session`, unsupported service context | `src/platform/mount.rs` |

The mount subsystem should sit on top of:

- `src/fs/runtime/query.rs`
- `src/fs/runtime/filesystem.rs`
- production persistence root/lifecycle from Stories 4B and 4C
- `src/platform/`

It must not treat `src/fs/operations/*` as its substrate.

---

## Exact Module Homes

Story 11 should reserve these homes explicitly.

### `src/mount/mod.rs`

Owns:

- internal module wiring
- feature-gated exports within the crate
- no stable public API in Story 11

### `src/mount/service.rs`

Owns:

- `MountService`
- mount service lifecycle
- enable/disable/startup restore orchestration
- internal task or executor integration
- coordination between registry, inode cache, and platform driver

### `src/mount/state.rs`

Owns:

- `MountDescriptor`
- `MountFlags`
- `MountStatus`
- `MountError` or internal result classification
- enable-at-startup and persistence bits

### `src/mount/registry.rs`

Owns:

- durable mount metadata
- mount name/path uniqueness checks
- startup re-enable policy for persistent mounts
- registry operations such as add/remove/enable/disable
- mount-local durable state store

### `src/mount/inode.rs`

Owns:

- mount inode identity
- path/component lookup against query/index results
- pinned inode invalidation bookkeeping
- parent/child resolution for mount-facing reads

### `src/mount/file_cache.rs`

Owns:

- the architectural home for file cache or file I/O contexts used by mount reads
- may start minimal or stubbed in Story 11, but the home should exist

### `src/platform/mount.rs`

Owns:

- capability detection for mount support
- unsupported-target stub implementation
- POSIX/Windows/macOS-specific bind/unbind/session hooks as later implementations deepen
- no mount business logic

This exact layout should be treated as stable once Story 11 starts, so later mount work lands into named homes instead of re-deciding the structure.

---

## Dependency Rules

These rules are binding for Story 11.

### Mount subsystem dependencies

- `src/mount/service.rs` may depend on:
  - `src/mount/state.rs`
  - `src/mount/registry.rs`
  - `src/mount/inode.rs`
  - `src/mount/file_cache.rs`
  - `src/fs/runtime/query.rs`
  - `src/fs/runtime/filesystem.rs`
  - `src/platform/mount.rs`
  - narrow engine-facing adapters or state readers from `src/session/`

- `src/mount/registry.rs` may depend on:
  - production persistence root/lifecycle helpers from Stories 4B and 4C
  - internal SQLite or storage helpers already accepted in the repo
  - `src/mount/state.rs`

- `src/mount/inode.rs` may depend on:
  - query/index results
  - durable node handles and metadata
  - internal mount state types

- `src/mount/file_cache.rs` may depend on:
  - filesystem runtime
  - mount inode identifiers and state
  - platform mount file-context helpers where needed later

### Forbidden dependencies

- mount code must not depend on `src/fs/operations/*` as a long-term substrate
- mount code must not bypass the query/index layer with direct ad hoc node-map traversal once Story 8 exists
- mount code must not call raw API/network flows for browse/open/read semantics
- `src/platform/mount.rs` must not absorb mount business logic or registry policy
- mount code must not become a second engine root independent of `Session`

### Public API rule

- Story 11 must not introduce a public mount API unless that additive surface is explicitly approved
- the default assumption for Story 11 is internal, feature-gated substrate only

---

## Design Decisions

### Decision 1. Story 11 is feature-gated from the first slice

Why:

- mount support is platform-sensitive and dependency-heavy
- unsupported platforms need explicit behavior rather than accidental build failure
- the repository constraint is to avoid public API churn unless approved

Consequence:

- the subsystem should be gated behind an internal Cargo feature such as `mount`
- unsupported platforms should compile with explicit stubs or disabled capability surfaces

### Decision 2. Mount durable state is mount-local, not a new branch of the generic persistence SPI

Why:

- the SDK keeps mount metadata in its own mount DB/service layer
- mount metadata is not just more node cache state
- overloading `src/session/runtime/persistence.rs` with mount-specific records would blur subsystem boundaries

Consequence:

- Story 11 should use the production persistence root and SQLite conventions from Stories 4B/4C
- Story 11 should keep mount metadata in `src/mount/registry.rs` or an adjacent mount-local store
- Story 11 must not redesign Story 3's generic persistence SPI just to host mount metadata
- the first Rust implementation should use one mount-local SQLite database file for the mount subsystem, with separate tables or owner modules for:
  - mount registry metadata
  - inode identity/cache metadata
- this matches the SDK shape more closely than scattering mount state across multiple unrelated stores while still staying idiomatic in Rust

### Decision 3. Read-only semantics are enough for the first parity slice

Why:

- the epic placeholder already centers Story 11 on browse/open/read semantics
- full write support in the SDK includes much broader platform and cache behavior
- the architectural gap today is the missing subsystem, not the absence of every writable callback

Consequence:

- Story 11 should focus on:
  - browse/lookup
  - open/read
  - lifecycle
  - invalidation
- rename/write/delete/create semantics are explicitly deferred
- read-only `open/read` in the MVP still requires a real mount file-cache home analogous in role to the SDK's `FileCache`
- `src/mount/file_cache.rs` must therefore be a live subsystem in Story 11, not a pure placeholder:
  - it may be minimal
  - it may be read-through only
  - but it must own mount-local cached file contexts for read semantics

### Decision 4. Inode identity must be owned by mount, not improvised from node paths

Why:

- the SDK has a real `InodeDB` and mount inode identifiers
- path-only mount behavior becomes unstable once names or parents change
- durable query and node layers already exist precisely so mount does not need to improvise

Consequence:

- Story 11 must define explicit mount inode IDs and an inode/path cache layer
- mount reads and lookups should use that cache rather than ad hoc path traversal
- for persistent mounts, inode identity should be durably restorable across mount-service restart from the mount-local database rather than being regenerated blindly every time

### Decision 5. Mount must consume the query/index layer, not raw tree internals

Why:

- Story 8 exists to become the stable query substrate over durable node state
- mount is a heavy consumer of lookup/browse semantics
- wiring mount straight to raw tree maps would bypass one of the core architecture layers this epic is building

Consequence:

- Story 11 should not start until Story 8 exists
- mount lookup and child enumeration should go through query/index interfaces

### Decision 6. Platform mount hooks belong in `src/platform/mount.rs`

Why:

- Story 7B already set the platform-runtime direction
- POSIX libfuse session glue and Windows mount glue are platform mechanics, not mount business logic
- keeping those hooks out of `src/mount/` keeps Rust layered the same way the SDK is layered

Consequence:

- `src/mount/` owns mount logic
- `src/platform/mount.rs` owns capability gating and OS-binding/session glue

### Decision 7. The first supported backend should be one real POSIX/libfuse path plus explicit unsupported stubs elsewhere

Why:

- the SDK has real supported platform implementations and also explicit unsupported service-context stubs
- trying to define a “generic mount service” with no real backend would under-prove the architecture
- landing one real backend plus explicit unsupported behavior is the cleanest Rust-idiomatic equivalent of the SDK’s platform split

Consequence:

- Story 11 should target:
  - one real POSIX/libfuse-backed driver path for the first live backend
  - explicit unsupported stubs for non-supported targets and builds without the mount feature
- unsupported targets must compile cleanly and return explicit unsupported results rather than behaving like missing architecture

### Decision 8. Startup restore should prune transient mounts, restore persistent descriptors, and attempt auto-enable after service initialization

Why:

- the SDK service context prunes transient mounts on startup and then asks `MountDB` to enable persistent mounts marked for startup
- mount lifecycle should be deterministic and independent from ad hoc user-triggered re-registration on every launch
- failed auto-enable should not destroy durable mount descriptors

Consequence:

- the mount service startup path should:
  - open the mount-local database
  - prune non-persistent or transient mounts
  - restore persistent mount descriptors into the registry
  - attempt to auto-enable only those mounts marked `persistent && enable_at_startup`
- failed auto-enable should leave the descriptor present in the registry with explicit failed or disabled status rather than removing it
- startup restore should occur only after query/runtime and platform driver initialization are ready for mount use

### Decision 9. The first internal control surface should be explicit even if no public mount API is added

Why:

- the SDK has explicit add, enable, disable, remove, get, and path/flags queries on the service context
- Story 11 needs a stable internal service surface so later additive public APIs do not pierce registry or platform internals directly
- without this, internal call sites would hard-code registry details and undermine the subsystem boundary

Consequence:

- Story 11 should define an internal service control surface with at least:
  - `add_mount(...)`
  - `enable_mount(...)`
  - `disable_mount(...)`
  - `remove_mount(...)`
  - `list_mounts(...)`
  - mount descriptor or flags lookup
- later public API work, if approved, should wrap this service surface rather than bypassing it

### Decision 10. No crate-root public mount controls in Story 11 by default

Why:

- the current repo constraint is no public API change unless approved
- Story 11 is first and foremost a subsystem-creation story
- a user-facing mount API can be added later as an additive, explicitly approved slice if needed

Consequence:

- Story 11 should be validated via internal tests, feature-gated harnesses, and service-layer integration tests
- public API surfacing is not part of the default acceptance criteria

---

## Recommended Rust Shape

The first implementation slice should aim for a small but real internal shape such as:

```rust
// src/mount/state.rs

pub(crate) struct MountDescriptor {
    pub(crate) name: String,
    pub(crate) remote_root_handle: String,
    pub(crate) local_path: std::path::PathBuf,
    pub(crate) flags: MountFlags,
}

pub(crate) struct MountFlags {
    pub(crate) enable_at_startup: bool,
    pub(crate) persistent: bool,
    pub(crate) read_only: bool,
}

pub(crate) enum MountStatus {
    Disabled,
    Enabling,
    Enabled,
    Failed,
}
```

```rust
// src/mount/service.rs

pub(crate) struct MountService {
    registry: MountRegistry,
    inode_cache: MountInodeCache,
    file_cache: MountFileCache,
    platform: Box<dyn PlatformMountDriver>,
}
```

```rust
// src/mount/inode.rs

pub(crate) struct MountInodeId(u64);

pub(crate) struct MountInodeCache {
    // handle/name/parent lookup and pin/invalidation state
}
```

```rust
// src/platform/mount.rs

pub(crate) enum MountCapability {
    Unsupported,
    Supported,
}

pub(crate) struct PlatformMountSession;

pub(crate) trait PlatformMountDriver {
    fn capability(&self) -> MountCapability;
    fn bind(&self, descriptor: &MountDescriptor) -> crate::error::Result<PlatformMountSession>;
}
```

Important implementation guidance:

- keep the service root small and explicit
- keep the registry/store and inode/path cache separate
- keep mount business logic out of the platform layer
- prefer additive internal seams rather than collapsing all mount behavior into one large file
- keep `src/mount/file_cache.rs` live in the first slice as a minimal read-through cache/context owner rather than a no-op scaffold
- use one mount-local database file with separate registry and inode ownership inside it, rather than many unrelated stores
- target one real POSIX/libfuse backend first and explicit unsupported stubs elsewhere

This is the Rust-idiomatic equivalent of introducing the SDK's mount architecture without overcommitting to every class and callback immediately.

---

## Public API And Feature-Gating Rules

These are binding for Story 11:

1. Story 11 is internal-first and feature-gated.
2. No public mount API is introduced unless explicitly approved as additive surface.
3. Unsupported targets must compile cleanly with explicit no-op or unsupported capability behavior.
4. Mount code must not be compiled accidentally on unsupported platforms without the feature gate.
5. Any later public API should be layered on top of `src/mount/service.rs`, not directly on platform or registry internals.
6. The first real backend is POSIX/libfuse; other targets remain explicit unsupported stubs until later stories deepen them.

---

## Non-Goals And Explicit Deferrals

Story 11 does not attempt to:

- achieve full libfuse or Windows callback parity in one slice
- port every platform mount implementation at once
- add broad write support, rename, create, delete, or full writable file-system semantics
- add shell integration or file explorer integration
- fully match the SDK's file cache heuristics or writeback behavior
- expose a stable end-user mount API by default
- replace the query/index or filesystem/runtime layers with mount-specific shortcuts
- implement sync
- implement backup
- redesign the production persistence backend

Those belong to later mount-deepening or public-API slices.

---

## Deliverables

Story 11 should produce these deliverables:

1. A feature-gated `src/mount/` module tree.
2. Internal mount state types and result classification.
3. A mount registry with mount-local durable metadata and startup enablement semantics.
4. A mount inode/path cache with explicit mount inode identity.
5. A live mount file cache or file-context home sufficient for read-only open/read semantics.
6. A platform mount driver boundary under `src/platform/mount.rs`.
7. Core read-only browse/open/read semantics on top of durable query/runtime state.
8. Unsupported-target or disabled-feature scaffolding that is explicit and tested.
9. Internal integration tests for mount lifecycle, registry persistence, startup auto-enable, and read-only semantics.

The story is not complete if it only adds a platform driver or only adds a mount flag without the internal subsystem structure.

---

## Implementation Tasks

### Task 11.1

Introduce the feature gate and internal mount module skeleton.

Expected outcomes:

- `src/mount/` exists
- `src/platform/mount.rs` exists
- one real POSIX/libfuse-oriented backend path exists behind the feature gate
- unsupported-target behavior is explicit
- the subsystem compiles behind a mount feature gate

Suggested verification:

- compile-checked tests or unit tests for unsupported capability behavior

### Task 11.2

Add mount descriptor/state models and the mount registry.

Expected outcomes:

- internal mount descriptors and flags exist
- registry supports add/remove/enable/disable semantics
- persistent mount definitions survive restart when marked persistent
- transient mounts are pruned on startup
- registry uses production persistence root/lifecycle without redesigning the generic persistence SPI

Suggested verification:

- tests for duplicate name/path rejection
- tests for enable-at-startup persistence
- tests for persistent vs transient mount entries

### Task 11.3

Add mount inode/path cache and read-only query-backed semantics.

Expected outcomes:

- mount inode IDs exist
- lookup, child enumeration, browse/open/read semantics use the query/index layer
- mount file cache or file-context ownership exists for read-only open/read semantics
- mount no longer depends on raw API calls or ad hoc path traversal

Suggested verification:

- tests for browse/lookup on mounted directory roots
- tests for read-only file open/read
- tests for invalidation after durable node/query changes where the mount cache must observe updated state

### Task 11.4

Add platform driver/session scaffolding and lifecycle tests.

Expected outcomes:

- platform mount driver binds and unbinds through `src/platform/mount.rs`
- one supported-platform harness or stubbed integration path exists
- unsupported targets fail predictably rather than by missing architecture

Suggested verification:

- tests for bind/unbind lifecycle
- tests for startup restore and auto-enable of persistent mounts
- tests for clean disable and cleanup

---

## Acceptance Criteria

Story 11 is complete when:

1. A feature-gated `src/mount/` subsystem exists.
2. Mount service, registry, inode/path cache, and platform driver boundaries all exist in named homes.
3. Mount durable metadata is owned by a mount-local store/registry rather than ad hoc files or generic cache-table leakage.
4. Mount uses one mount-local database file with separate registry and inode ownership rather than scattering state across generic stores.
5. Persistent mounts restore inode identity from the mount-local database rather than regenerating inode ids blindly after restart.
6. Mount browse/open/read semantics are layered on top of the durable tree and query/index layers rather than bypassing them.
7. A real read-through mount file-cache or file-context home exists for the read-only MVP.
8. Platform capability gating is explicit, POSIX/libfuse is the first supported backend, and unsupported targets are handled structurally.
9. The story can honestly claim architectural parity substrate for mount/FUSE, even if not every platform callback or writable operation is implemented.
10. Persistent mounts marked for startup are restored and auto-enabled after service initialization, while failed auto-enable leaves descriptors registered with explicit status.
11. No unapproved public API change is introduced.

Done for Story 11 does not require:

- every platform implementation
- every writable FUSE operation
- every shell integration detail

It does require the subsystem to exist in the right place with the right dependencies.

---

## Verification Requirements

Because this story will touch Rust code, completion requires:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Story-specific verification should also include:

- mount feature-gated build coverage
- unsupported-target capability coverage
- registry persistence/restart tests
- startup auto-enable tests for persistent mounts
- read-only browse/open/read integration coverage
- lifecycle tests for enable/disable/bind/unbind

If a host machine cannot exercise a real platform mount backend, the story should still include:

- explicit unsupported-target tests
- compile-checked platform-driver scaffolding
- internal lifecycle tests for the service and registry layers

---

## Relationship To Later Stories

Story 11 creates the mount subsystem as a first-class architectural resident of the crate.

How later stories should consume it:

- Story 12 should add executable parity coverage for mount lifecycle and read-only mount behavior.
- Story 12B should track mount parity as its own architecture dimension rather than burying it under desktop features.
- later additive public-API slices may expose a stable user-facing mount control surface on top of `src/mount/service.rs`.
- later mount-deepening work may add richer platform implementations, writable callbacks, file-cache behavior, and shell integration without reopening the basic subsystem shape.

How earlier stories are consumed here:

- Story 4C provides trustworthy durable node/cache state
- Story 7 provides reusable local filesystem behavior
- Story 7B provides platform mount hooks
- Story 8 provides the query substrate mount reads must consume

The correct reading is:

- Story 11 adds the mount/FUSE subsystem as architecture

Not:

- Story 11 merely adds a one-off feature entrypoint

---

## Completion Notes

When Story 11 is complete, the epic should be able to claim:

- `megalib` now has a real mount subsystem home under `src/mount/`
- mount state, lifecycle, inode identity, and platform hooks are no longer homeless
- future mount work can land into stable Rust module homes that are structurally comparable to the SDK's `src/fuse` layering

That is the correct notion of parity for this story: mount architectural parity substrate, not total platform-feature parity.
