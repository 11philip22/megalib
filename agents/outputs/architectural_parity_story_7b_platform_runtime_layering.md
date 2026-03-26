# Story 7B Spec: Align Platform Runtime Layering

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 7B from `agents/outputs/architectural_parity_epic.md` into an implementation-ready structural story. Like Story 1, this is primarily an architecture-shaping story, but unlike Story 1 it is expected to land code: its job is to introduce explicit platform runtime homes so later filesystem, watch, mount, and service work stop accumulating platform-sensitive behavior inside generic modules.

Story type:

- Implementation story / structural enablement spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`
- `agents/outputs/architectural_parity_report.md`

## Validation Findings

Verdict: structurally grounded, with upstream references tightened for the first live migrations.

Grounded against the upstream SDK:

- device-id hashing is owned by `MegaClient::getDeviceidHash()` in `../sdk/src/megaclient.cpp`, which sources raw platform identity through `fsaccess->statsid(...)`
- the platform-specific identity lookup lives on the filesystem boundary via `FileSystemAccess::statsid` in `../sdk/include/mega/filesystem.h`, with concrete implementations in `../sdk/src/posix/fs.cpp`, `../sdk/src/win32/fs.cpp`, and `../sdk/src/android/androidFileSystem.cpp`
- macOS device identity is handled in the shared POSIX filesystem implementation under the `__MACH__` branch in `../sdk/src/posix/fs.cpp`, not in `../sdk/src/osx/fs.cpp`
- database-root ownership is expressed through `DbAccess::rootPath()` and `databasePath(...)` in `../sdk/include/mega/db.h`, the SQLite implementation in `../sdk/src/db/sqlite.cpp`, and the higher-level `ClientAdapter::dbRootPath()` / `dbPath()` accessors in `../sdk/src/common/client_adapter.cpp`
- watcher/fallback layering is still a valid architectural anchor through `DirNotify` and `FileSystemAccess::newdirnotify(...)` in `../sdk/src/filesystem.cpp`, plus platform watcher implementations in `../sdk/src/posix/fs.cpp`, `../sdk/src/osx/fs.cpp`, `../sdk/src/win32/fs.cpp`, and `../sdk/src/android/androidFileSystem.cpp`

Rust-side design choices:

- `src/platform/paths.rs`, `src/platform/device.rs`, and enum-based capability seams are Rust structuring choices, not one-to-one SDK type names
- Rust-side default persistence-root discovery is not a direct SDK behavior: the public C++ SDK takes a caller-provided `basePath` and then exposes that storage root through `DbAccess::rootPath()` and `ClientAdapter::dbRootPath()`

Unsupported as originally referenced:

- `../sdk/src/posix/waiter.cpp` and `../sdk/src/common/platform/` are adjacent platform infrastructure, but they are not the primary ground-truth anchors for Story 7B's first live migrations
- `../sdk/src/osx/drivenotifyosx.cpp` is relevant for later watch work, but not for the current device-identity or persistence-root migrations

---

## Status

Not started.

Current implementation status on 2026-03-31:

- the crate has no `src/platform/` module tree yet
- platform-sensitive behavior is mostly implicit rather than structurally owned
- current OS-aware logic appears mainly in:
  - `src/session/device_id.rs`
  - `src/session/runtime/persistence.rs`
- later platform-sensitive areas such as filesystem watch, mount, and side-service runtime homes do not exist yet
- generic modules currently carry the architectural burden for behavior that the upstream SDK places under platform-specific directories

This means Rust can compile and run, but its crate structure still underspecifies where platform-sensitive runtime logic is supposed to live.

---

## Story Goal

Introduce an explicit internal platform runtime layer under `src/platform/` that gives `megalib` stable, OS-aware module homes analogous to the upstream SDK's `src/{posix,osx,win32,android}` separation.

This story is structural, not feature parity. Its purpose is to:

- make platform-sensitive behavior explicit
- stop spreading `cfg(...)` decisions through unrelated engine and filesystem code
- create the lower architectural homes that Story 7 can later deepen into as platform-sensitive behavior grows, and that Stories 9B and 11 will consume directly

The outcome is not "all platform features implemented." The outcome is "platform-sensitive runtime behavior has a defined home and dependency boundary."

---

## Why This Story Exists

The upstream SDK does not leave platform-sensitive runtime behavior buried in generic engine code. For this story, the most relevant ground-truth anchors are:

- `../sdk/include/mega/filesystem.h`
- `../sdk/src/filesystem.cpp`
- `../sdk/src/megaclient.cpp`
- `../sdk/src/posix/fs.cpp`
- `../sdk/src/osx/fs.cpp`
- `../sdk/src/win32/fs.cpp`
- `../sdk/src/android/androidFileSystem.cpp`
- `../sdk/include/mega/db.h`
- `../sdk/src/db/sqlite.cpp`
- `../sdk/src/common/client_adapter.cpp`

Watcher-specific platform files such as `../sdk/src/posix/drivenotifyposix.cpp`, `../sdk/src/osx/drivenotifyosx.cpp`, and `../sdk/src/win32/drivenotifywin.cpp` remain relevant follow-on references, but they are secondary to the first live migrations in this story.

By contrast, the Rust crate currently has a compact structure:

- `src/api/`
- `src/crypto/`
- `src/fs/`
- `src/session/`

That compact structure is fine for the current scope, but it is not enough to support later SDK-shaped work cleanly. Without an explicit platform layer:

- filesystem/watch abstractions will accumulate OS-specific branches in generic runtime code
- mount/FUSE work will have no clear home for platform capability gating
- service-style side pipelines will invent their own ad hoc platform helpers
- existing platform-aware logic such as device identity and persistence-root discovery stays stranded in unrelated modules

Story 7B fixes the architectural home problem before later platform-sensitive filesystem, mount, and service work deepens.

---

## Scope

In scope:

- introduce `src/platform/` as the architectural home for platform-sensitive runtime seams
- define explicit platform-facing module boundaries for:
  - filesystem/runtime path roots
  - watch capability and runtime hooks
  - mount capability hooks
  - service/runtime process or host hooks where needed later
- move a small amount of existing platform-sensitive logic into that layer if doing so is the minimum proof of the seam
- define compile-gated or stubbed platform capability surfaces for unsupported platforms
- add structural tests or compile-gated scaffolding so later stories can depend on the layer safely

Out of scope:

- implementing full filesystem watch support
- implementing mount/FUSE support
- implementing sync
- implementing side-service pipelines
- adding broad new public API
- mirroring every upstream platform-specific source file one-for-one
- redesigning current runtime semantics beyond moving platform-sensitive decisions to the right architectural home

This story is successful if later platform-sensitive stories have a clean home and current platform logic is no longer forced to stay in generic modules.

---

## Story 1, Story 7, Story 9B, And Story 11 Constraints

Story 7B must preserve these existing decisions:

- the platform runtime layer lives under `src/platform/`
- lower platform modules are consumed by filesystem, mount, and service runtimes; they do not depend outward on operation modules or the public facade
- `Session` remains the engine root
- `src/fs/operations/*` remain orchestration-first rather than becoming a dumping ground for platform-specific behavior
- public API stays unchanged in this story

Story 7B is a structural follow-on to Story 7 and a prerequisite for:

- later platform-specific deepening of the Story 7 filesystem/watch boundary
- Story 9B side-service pipeline homes
- Story 11 mount/FUSE subsystem

If implementation pressure suggests scattering new `cfg(...)` logic into `src/fs/operations/*` or `src/session/core.rs`, Story 1 should be treated as the source of truth and the change should be rejected.

---

## SDK Parity Target

The parity target is architectural, not feature-complete.

Rust should align with the SDK in these ways:

1. Platform-sensitive runtime code has explicit module homes instead of hiding inside generic engine files.
2. Common runtime code depends on platform seams rather than hard-coding OS branching everywhere.
3. Platform capability differences are exposed through clear compile-time module boundaries and explicit unsupported behavior.
4. Filesystem, watch, mount, and service-facing platform logic are allowed to grow in their own layer later.
5. The crate structure makes future feature porting cheaper because platform-specific work lands in familiar places.

Rust should stay idiomatic:

- do not clone the SDK's file list mechanically
- do use module-boundary `cfg(...)` selection instead of scattering `cfg(...)` throughout business logic
- prefer explicit traits, structs, and capability surfaces over ad hoc helper functions spread across unrelated modules
- prefer additive internal seams over broad module reorganizations

---

## Current Platform Gaps To Close

Story 7B is specifically targeting these current gaps:

1. There is no `src/platform/` tree at all.
2. Device identity uses platform-specific `cfg(...)` in `src/session/device_id.rs`, but there is no reusable platform layer underneath it.
3. Persistence root discovery uses platform-specific logic in `src/session/runtime/persistence.rs`, but it has no neutral architectural home.
4. Future filesystem watch and mount work have no platform-owned runtime layer to depend on.
5. The current crate structure does not communicate where OS-specific behavior belongs, so later stories would naturally regress into generic-module `cfg(...)` branches.

---

## Design Decisions

### Decision 1. Platform runtime lives under `src/platform/`

Why:

- Story 1 already fixed that as the target home
- it is the cleanest Rust equivalent of the SDK's `src/{posix,osx,win32,android}` separation
- it lets later filesystem, mount, and service stories consume one lower platform layer instead of inventing their own

Consequence:

- Story 7B must introduce `src/platform/`
- platform-sensitive logic should migrate toward that layer rather than growing inside `src/session/` or `src/fs/operations/`

### Decision 2. Use module-boundary `cfg(...)`, not consumer-spread `cfg(...)`

Why:

- the SDK uses directory-level layering for platform code
- idiomatic Rust should mirror that with module selection at the platform boundary
- scattering `cfg(...)` into generic runtime logic makes later stories harder to reason about and harder to test

Consequence:

- `src/platform/mod.rs` should select per-platform submodules
- consumers should depend on stable platform-layer functions, traits, or structs
- later generic runtime code should not need to know whether behavior came from POSIX, macOS, Windows, or Android

### Decision 3. The first live migrations should be existing platform-sensitive helpers

Why:

- Story 7B is structural; it needs a small live proof without becoming a feature story
- `src/session/device_id.rs` and persistence-root discovery in `src/session/runtime/persistence.rs` are already platform-sensitive
- moving those concerns behind `src/platform/` proves the seam while keeping scope controlled

Consequence:

- the story should migrate one or both of:
  - device identity platform helpers
  - persistence/app-data root discovery
- it does not need to implement watch or mount functionality yet

### Decision 4. Unsupported platforms should be explicit, not implicit

Why:

- the SDK has explicit unsupported or missing capability branches
- later stories need a predictable place to surface "not supported on this platform"
- hidden fallback behavior would make platform parity harder to reason about

Consequence:

- the platform layer should provide explicit unsupported stubs or capability results where a feature is not implemented
- later consumers should not infer support from missing modules

### Decision 5. Platform layering is structural and should not widen the public API

Why:

- the goal is to create runtime homes, not to expose platform APIs directly to users
- public surface churn here would create unnecessary risk and distract from the structural change

Consequence:

- Story 7B should be entirely internal
- public behavior should remain unchanged unless a small bug fix is required by the migration

### Decision 6. Rust should reserve Android and desktop homes even if implementation starts with desktop-focused scaffolding

Why:

- the SDK shape includes `android` as a first-class platform directory
- the parity goal is to make future feature additions land into a stable structure
- the current Rust crate should not hard-code a desktop-only worldview into the platform layer

Consequence:

- Story 7B should define platform module homes for:
  - POSIX
  - macOS
  - Windows
  - Android
- the first implementation slice may keep Android and some desktop capabilities as stubs if they are not consumed yet

### Decision 7. Path-root discovery should use one crate-owned platform bundle API

Why:

- the SDK exposes one root-oriented path surface through `DbAccess::rootPath()` and `ClientAdapter::dbRootPath()`, then derives named DB locations via `databasePath(...)`
- scattering separate root helpers across consumers would recreate the current problem in a new place
- idiomatic Rust should prefer one small value object over multiple unrelated free functions

Consequence:

- `src/platform/paths.rs` should expose one small crate-owned `PlatformPaths` struct
- the first consumer API should be a single function such as `platform_paths() -> PlatformPaths`
- persistence-root, app-data-root, and cache-root decisions should come from that one returned bundle rather than from multiple consumer-owned helpers

### Decision 8. Device identity should move behind a dedicated platform seam that returns the normalized internal identity input

Why:

- the SDK keeps platform-specific machine identity lookup inside platform-owned filesystem code via `FileSystemAccess::statsid(...)`, while `MegaClient::getDeviceidHash()` stays responsible for hashing and outward use
- `src/session/device_id.rs` should only remain responsible for Rust-side hashing/encoding and outward compatibility
- generic modules should not own registry, libc, or machine-id path branching directly

Consequence:

- Story 7B should introduce `src/platform/device.rs`
- that module should expose the final internal device-identity bytes or `None`
- `src/session/device_id.rs` should consume that seam and keep the current hashing behavior unchanged
- raw OS-specific details should not leak upward into session code

### Decision 9. Watch, mount, and service capability seams should be explicit enums with unsupported variants

Why:

- the SDK uses compile-time platform selection plus explicit supported or unsupported homes rather than implicit boolean guessing
- later stories need capability results that are easy to match exhaustively in Rust
- small enums are clearer and more extensible than loosely-related booleans

Consequence:

- `src/platform/watch.rs`, `src/platform/mount.rs`, and `src/platform/services.rs` should expose small enum-based capability seams
- unsupported behavior should be explicit at the platform boundary
- later stories may add richer runtime types behind those seams without reopening the structure decision

### Decision 10. Story 7B migrates current platform-sensitive helpers and capability seams only

Why:

- Story 7B exists to fix architectural layering, not to absorb Story 7 filesystem/watch implementation work
- trying to move watcher logic now would mix structural enablement with feature/runtime migration
- the current proof points already exist in device identity and persistence-root discovery

Consequence:

- Story 7B should migrate current platform-sensitive helpers and add capability seams
- Story 7 watcher/runtime logic should remain in place for now and deepen onto `src/platform/watch.rs` later
- Story 7B must not become a hidden filesystem/watch implementation refactor

---

## Recommended Rust Shape

The first implementation slice should aim for a small but real internal shape such as:

```rust
// src/platform/mod.rs

pub(crate) mod paths;
pub(crate) mod device;
pub(crate) mod watch;
pub(crate) mod mount;
pub(crate) mod services;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "android")]
mod android;
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "android")
))]
mod posix;
```

And then expose stable platform-layer seams such as:

```rust
pub(crate) struct PlatformPaths {
    pub(crate) data_root: PathBuf,
    pub(crate) cache_root: Option<PathBuf>,
    pub(crate) persistence_root: Option<PathBuf>,
}

pub(crate) enum PlatformWatchSupport {
    Unsupported,
    PollOnly,
    Native,
}

pub(crate) enum PlatformMountSupport {
    Unsupported,
    Supported,
}

pub(crate) enum PlatformServiceSupport {
    Unsupported,
    Supported,
}

pub(crate) fn platform_paths() -> PlatformPaths;
pub(crate) fn device_identity_bytes() -> Option<Vec<u8>>;
```

The first-slice contracts should follow these rules:

- `src/platform/paths.rs` owns app-data, cache, and persistence-root discovery through one crate-owned `PlatformPaths` bundle returned by one function
- `src/platform/device.rs` owns device-identity lookup and returns the normalized internal identity bytes consumed by `src/session/device_id.rs`
- `src/platform/watch.rs` owns watch capability seams and later watch runtime glue
- `src/platform/mount.rs` owns mount capability seams and later mount-facing hooks
- `src/platform/services.rs` owns service/process/runtime hooks for later side-service work
- per-platform modules provide the OS-specific implementations selected by `mod.rs`
- capability seams should be enum-based and include explicit unsupported variants
- `src/platform/android.rs` should exist in the first slice as an explicit module home even if most current behavior is stubbed

The important point is not the exact filenames. The important point is that platform-sensitive decisions have a lower layer with explicit homes.

---

## Recommended Module Layout

Story 7B should target a minimum additive structure like:

```text
src/platform/
  mod.rs
  paths.rs
  device.rs
  watch.rs
  mount.rs
  services.rs
  posix.rs
  macos.rs
  windows.rs
  android.rs
```

This layout is intentionally smaller than the upstream SDK's directory tree, but it preserves the same architectural idea:

- common platform-facing seams live in one shared layer
- per-platform code lives behind explicit OS-aware modules
- future stories extend these homes instead of inventing new top-level scatter

If implementation pressure is high, the first slice may introduce only:

- `src/platform/mod.rs`
- `src/platform/paths.rs`
- `src/platform/device.rs`
- one or more per-platform leaf modules needed to support existing migrations

But the story spec should still reserve the full layout above as the intended home for later work.

---

## First Live Consumers

The first live consumers should be deliberately small and current-code-based.

Recommended initial migrations:

1. Persistence-root discovery
   - move OS-specific root selection out of `src/session/runtime/persistence.rs`
   - make that module consume `src/platform/paths.rs`

2. Device identity platform branching
   - move OS-specific helper branching out of `src/session/device_id.rs`
   - keep public/runtime behavior unchanged

These two migrations are enough to prove:

- platform-sensitive logic can live under `src/platform/`
- generic engine/session modules can consume stable platform seams
- the story lands code, not just empty directories

Watch, mount, and service-specific consumers should be deferred to Stories 7, 9B, and 11. Story 7B should introduce their capability seams and homes, but it should not migrate existing Story 7 watcher/runtime logic into those modules yet.

---

## Affected Modules

Primary affected modules:

- new `src/platform/`
- `src/session/device_id.rs`
- `src/session/runtime/persistence.rs`

Likely follow-on consumers, but not required to migrate fully in this story:

- future `src/fs/runtime/filesystem.rs`
- future `src/mount/`
- future `src/services/`

Modules that should not become dumping grounds for platform logic:

- `src/fs/operations/*`
- `src/session/core.rs`
- `src/session/actor.rs`
- `src/lib.rs`

---

## Agent-Sized Tasks

### Task 7B.1. Introduce platform module structure

Land the minimum `src/platform/` structure and module-boundary `cfg(...)` selection.

Deliverables:

- `src/platform/mod.rs`
- reserved platform-facing common modules
- per-platform leaf module structure for supported targets and explicit unsupported behavior where needed
- `src/platform/android.rs` present as an explicit reserved module home, even if currently stubbed

### Task 7B.2. Move path-root and persistence-root platform logic

Route OS-specific persistence/app-data root discovery through the new platform layer.

Deliverables:

- one crate-owned `PlatformPaths` API under `src/platform/paths.rs`
- `src/session/runtime/persistence.rs` consuming those helpers
- no public behavior change

### Task 7B.3. Move device-identity platform branching

Route existing platform-specific device identity helpers through the new platform layer without changing behavior.

Deliverables:

- `src/platform/device.rs` plus any needed platform leaf implementations
- `src/session/device_id.rs` slimmed down to consume them

### Task 7B.4. Add capability seams for later filesystem/watch, mount, and service work

Add small internal capability surfaces or stubs so later stories do not need to reopen the platform-structure decision.

Deliverables:

- enum-based platform watch capability seam with explicit unsupported behavior
- enum-based platform mount capability seam with explicit unsupported behavior
- enum-based platform services/process capability seam with explicit unsupported behavior
- compile-gated tests or scaffolding proving the layer compiles and can be consumed

---

## Acceptance Criteria

Story 7B is complete when:

- `src/platform/` exists as the named architectural home for platform-sensitive runtime behavior
- module-boundary `cfg(...)` selection is in place for platform implementations
- persistence/app-data root logic no longer owns its own OS branching
- device identity logic no longer owns its own OS branching directly
- the crate has explicit internal homes for later watch, mount, and service platform behavior
- `src/platform/android.rs` exists as an explicit reserved platform module home
- Story 7 watcher/runtime logic has not been silently migrated into Story 7B
- public API remains unchanged
- later stories can point to `src/platform/` as the required lower layer instead of inventing new module homes

Story 7B does not require implemented watch, mount, or service features. It requires the architectural layer those stories will consume.

---

## Verification Requirements

Because this story will touch Rust code, completion requires:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Story-specific verification should also include:

- tests for persistence-root helper behavior on supported target families where practical
- tests or compile-checked scaffolding proving unsupported platform capability surfaces are explicit
- regression coverage that confirms device identity and persistence-root behavior stay unchanged after the migration

If a target-specific behavior cannot be exercised on the current host, unit tests should still verify the platform-layer API shape and the non-target fallback behavior.

---

## Relationship To Later Stories

Story 7B exists so later stories do not have to decide platform layering on the fly.

How later stories should consume it:

- Story 7 should converge local filesystem and watch implementations onto `src/platform/watch.rs` and related platform modules as platform-sensitive depth increases, rather than adding OS branching to generic filesystem runtime code.
- Story 9B should place side-service host/process/platform hooks on top of `src/platform/services.rs`.
- Story 11 should place mount capability gating and OS-facing hooks on top of `src/platform/mount.rs`.

Story 7B is therefore structural follow-on hardening. It is not optional if the goal is to make later SDK-inspired work land into stable, platform-aware runtime homes.

---

## Non-Goals And Explicit Deferrals

Story 7B does not attempt to:

- add cross-platform watch feature parity
- add mount/FUSE feature parity
- add Android-specific runtime features
- add Windows/macOS/POSIX-specific functionality beyond the minimum seam proof
- mirror upstream `waiter`, `net`, `console`, or other platform directories one-by-one
- replace existing public abstractions with a new platform-facing API

Those belong to later stories. Story 7B only ensures they will have the correct home.

---

## Completion Notes

When this story is complete, the epic should be able to claim:

- the Rust crate now has an explicit platform runtime layer comparable in architectural intent to the SDK's platform directory separation
- platform-sensitive behavior is no longer homeless in the crate structure
- later filesystem, mount, and service stories can build on a stable lower layer instead of inventing structure during implementation

That is the correct notion of parity for this story. It is structural parity, not yet platform-feature parity.
