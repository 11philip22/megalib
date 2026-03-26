# Story 7 Spec: Add a Reusable Filesystem and Watcher Boundary

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 7 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, 4, 4B, and 5, this is a code-bearing story. Its job is to stop leaving local filesystem behavior embedded in upload/download operation code and to establish one reusable internal boundary for local file access, one-directory-at-a-time scanning, and notification capability/fallback semantics.

## Validation Findings

Overall verdict: grounded.

Grounded in the current Rust tree:

- There is no `src/fs/runtime/` module tree today; `src/fs/mod.rs` still states that most filesystem behavior lives in `fs/operations/*` (`src/fs/mod.rs:1-8`).
- Upload currently owns direct local metadata, sidecar persistence, file open, seek, and chunk reads in `src/fs/operations/upload.rs` (`src/fs/operations/upload.rs:26-94`, `src/fs/operations/upload.rs:192-195`, `src/fs/operations/upload.rs:334-337`, `src/fs/operations/upload.rs:594-662`).
- Download currently owns temp-file existence checks, metadata reads, create/append/truncate policy, temp-file cleanup, and final rename in `src/fs/operations/download.rs` (`src/fs/operations/download.rs:285-345`).
- Resumable upload sidecar I/O is still direct `std::fs` work in `src/fs/upload_state.rs` (`src/fs/upload_state.rs:74-115`).
- Transfer-resume and worker-count policy still live as plain `Session` fields in `src/session/core.rs` (`src/session/core.rs:106-113`, `src/session/core.rs:753-759`, `src/session/core.rs:842-848`).

Grounded in the upstream SDK:

- `FileSystemAccess` is the reusable host-filesystem boundary. It owns `newfileaccess(bool followSymLinks)`, `newdirnotify(...)`, mutation helpers such as `renamelocal`/`unlinklocal`/`mkdirlocal`, and `directoryScan(...)` (`../sdk/include/mega/filesystem.h:678-813`).
- `Notification`, `NotificationDeque`, and `DirNotify` are real SDK types, but they are sync-coupled rather than a generic standalone watcher service. Queue state lives on `DirNotify::fsEventq` and notifications carry `ScanRequirement` plus a `LocalNode*` anchor (`../sdk/include/mega/filesystem.h:600-672`).
- The default `FileSystemAccess::newdirnotify(...)` fallback returns a plain `DirNotify(rootPath)` rather than a platform watcher, and `DirNotify::notify(...)` just queues notifications for later sync processing (`../sdk/src/filesystem.cpp:847-859`).
- Sync consumes those queued notifications later in `Sync::procscanq()`, where `Notification::scanRequirement` is interpreted into parent/self/recursive rescans (`../sdk/src/sync.cpp:3781-3925`).
- `directoryScan(...)` is an absolute-path, non-recursive, immediate-child scan primitive. The POSIX and Windows implementations both assert an absolute directory path, validate the scanned directory identity, skip `.` and `..`, and append one result per immediate child (`../sdk/src/posix/fs.cpp:1957-2175`, `../sdk/src/win32/fs.cpp:2112-2297`).
- Symlink-follow behavior is an explicit boundary choice in the SDK. `newfileaccess(...)` takes `followSymLinks`, and `directoryScan(...)` takes `followSymLinks` too (`../sdk/include/mega/filesystem.h:687-692`, `../sdk/include/mega/filesystem.h:808-813`, `../sdk/src/posix/fs.cpp:1976-1987`).
- Watch anchoring is platform-specific in the SDK rather than one universal contract:
  - macOS strips the expanded sync-root prefix before queuing a relative notification path (`../sdk/src/osx/fs.cpp:388-398`, `../sdk/src/osx/fs.cpp:435-524`)
  - Windows queues the relative filename returned by `ReadDirectoryChangesW` against the sync root watcher (`../sdk/src/win32/fs.cpp:1667-1671`, `../sdk/src/win32/fs.cpp:1769-1808`)
  - Linux associates inotify watches with `LocalNode` instances and queues a relative child name from that node/watch anchor (`../sdk/src/posix/fs.cpp:1028-1072`, `../sdk/src/posix/fs.cpp:1803-1840`, `../sdk/src/node.cpp:3604-3643`)

Corrections applied to the original draft:

- This story no longer treats a Rust `FilesystemRuntime`, `WatchSupport`, or `WatchRegistration` type as upstream facts. Those are acceptable Rust implementations, not parity facts.
- This story no longer requires every runtime entrypoint to take an absolute path. The SDK specifically asserts absolute paths for directory scanning and watched roots; current Rust public APIs still accept relative local paths for transfer destinations, so Story 7 must preserve that behavior.
- This story no longer requires per-registration watcher queue ownership or one universal root-relative notification-path contract. The SDK does not work that way across platforms.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`
- `agents/outputs/architectural_parity_story_7b_platform_runtime_layering.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-31:

- there is no `src/fs/runtime/` module tree yet
- local filesystem behavior is still spread across `src/fs/operations/upload.rs`, `src/fs/operations/download.rs`, and `src/fs/upload_state.rs`
- there is no internal scan abstraction for later sync or backup work
- there is no internal notification-capability boundary, not even an explicit disabled/unavailable shape
- platform-sensitive local filesystem behavior still has no internal owner beneath transfer code

This means local I/O works today, but the crate still lacks the reusable lower boundary that the upstream SDK exposes through `FileSystemAccess` and `DirNotify`.

---

## Story Goal

Establish `src/fs/runtime/filesystem.rs` as the reusable internal filesystem boundary for `megalib`.

That boundary must:

- live under `fs`, matching the ownership target already fixed by Story 1
- be owned once by session-owned internals and reused by transfer and later desktop subsystems
- own local metadata, open/create/remove/rename helpers, and directory scanning
- model notification capability and fallback semantics without implementing sync itself
- preserve current public upload/download behavior while turning operation modules into consumers instead of owners of host-filesystem policy

This story does not implement sync, backup, mount, or platform-specific watcher backends. It creates the lower layer those later stories can consume.

---

## Why This Story Exists

Today, local filesystem behavior is embedded directly in user-facing operation code:

- upload calls `UploadState::load(...)`, `UploadState::save(...)`, `UploadState::delete(...)`, `tokio::fs::metadata(...)`, and `tokio::fs::File::open(...)` directly (`src/fs/operations/upload.rs:26-94`, `src/fs/operations/upload.rs:192-195`, `src/fs/operations/upload.rs:334-337`, `src/fs/operations/upload.rs:594-662`)
- download calls `Path::exists()`, `std::fs::metadata(...)`, `OpenOptions`, `std::fs::remove_file(...)`, and `std::fs::rename(...)` directly (`src/fs/operations/download.rs:296-345`)
- resumable-upload sidecar persistence is direct `std::fs` work in `UploadState` (`src/fs/upload_state.rs:74-115`)

The upstream SDK has a clearer split:

- `FileSystemAccess` owns local filesystem primitives (`../sdk/include/mega/filesystem.h:678-813`)
- `directoryScan(...)` is reusable independently of watch support (`../sdk/include/mega/filesystem.h:808-813`, `../sdk/src/posix/fs.cpp:1957-2175`, `../sdk/src/win32/fs.cpp:2112-2297`)
- `DirNotify` plus `NotificationDeque` model queued scan hints for sync when notifications are available (`../sdk/include/mega/filesystem.h:600-672`, `../sdk/src/filesystem.cpp:847-859`, `../sdk/src/sync.cpp:3781-3925`)
- platform-specific implementations live behind that lower boundary rather than inside transfer code (`../sdk/src/posix/fs.cpp`, `../sdk/src/osx/fs.cpp`, `../sdk/src/win32/fs.cpp`)

Story 7 is the Rust slice that introduces the equivalent reusable lower boundary without prematurely implementing sync or platform-specific watch backends.

---

## Scope

In scope:

- introduce `src/fs/runtime/` and `src/fs/runtime/filesystem.rs`
- define a reusable internal filesystem API for:
  - local metadata access
  - read/write file opening needed by transfer consumers
  - rename/remove/create-dir style mutations needed by transfer consumers
  - one-directory-at-a-time scanning
  - notification capability and fallback semantics
- define crate-internal filesystem error mapping sufficient for transfer consumers
- add a first concrete runtime implementation for the current supported platform set
- move the first local-I/O consumers behind that runtime:
  - resumable upload source-file access
  - resumable download temp-file access
  - resumable upload sidecar file access where that path remains part of production behavior
- add focused tests for:
  - metadata access
  - rename/delete behavior
  - temp-file create/open behavior
  - directory scan behavior
  - disabled/unavailable notification capability behavior

Out of scope:

- implementing sync
- implementing backup
- implementing mount/FUSE
- adding a new public watcher API
- requiring a platform-native active watcher backend in the first Story 7 landing
- full filesystem identity / stable-ID parity work
- platform-runtime module reorganization beyond what is strictly required to create this boundary
- redesigning transfer naming policy such as `.megatmp.<handle>` or upload sidecar filenames

This is a reusable host-filesystem boundary story, not a sync or platform-backend story.

---

## Story 1, Story 5, And Story 7B Constraints

Story 7 must preserve these existing decisions:

- the filesystem runtime lives at `src/fs/runtime/filesystem.rs`
- `Session` remains the engine root
- `src/fs/operations/*` stay orchestration-first
- transfer policy remains the responsibility of Story 5, not Story 7
- platform/runtime deepening remains a follow-on concern in Story 7B
- public API stays unchanged in this story

If implementation pressure suggests moving the runtime under `session`, widening Story 7 into platform-layer redesign, or implementing sync here, Story 1 or Story 7B would need to change first.

---

## SDK Parity Target

The filesystem/watch boundary should align with the SDK in these ways:

1. Local filesystem access is owned by a reusable runtime boundary rather than embedded in transfer code.
2. Directory scanning is a first-class runtime primitive independent of watch support.
3. Notification support is modeled as capability plus fallback rather than assumed to be universally available.
4. Notification payloads carry scan intent, not sync-engine business logic.
5. Platform-specific filesystem and notification implementations can later sit behind the same boundary.
6. Later subsystems such as sync, backup, and mount can consume this layer without Story 7 implementing them now.

Rust should stay idiomatic:

- do not clone `FileSystemAccess` or `DirNotify` line-for-line
- do preserve the same ownership split between local file access, scan primitives, and notification-capability semantics

---

## Current Filesystem Gaps To Close

Story 7 is specifically targeting these current architectural gaps:

1. `upload.rs` owns direct host-file open/stat/seek/read behavior.
2. `download.rs` owns direct host-file existence, create/open, rename, and cleanup behavior.
3. `UploadState` owns direct sidecar load/save/delete filesystem behavior.
4. there is no directory scan substrate for later sync or backup work.
5. there is no explicit notification-capability boundary or fallback shape.
6. later platform-specific filesystem/watch work has no internal module owner yet because local file behavior is still spread across consumers.

---

## Design Decisions

### Decision 1. The filesystem runtime lives under `fs`, not `session`

Why:

- Story 1 already fixed that ownership target
- the layer is a reusable file-oriented substrate
- transfer, sync, backup, mount, and side-service pipelines should all consume it as a lower runtime

Consequence:

- Story 7 must introduce `src/fs/runtime/filesystem.rs`
- `Session` may own a long-lived handle to it, but the architectural home stays under `fs`

### Decision 2. Story 7 owns reusable primitives, not sync behavior

Why:

- upstream `FileSystemAccess` is a lower layer
- `DirNotify` is consumed by sync, but it is still a lower filesystem-notification seam
- widening Story 7 into reconcile logic would mix two separate story scopes

Consequence:

- Story 7 may define scan and notification-capability semantics
- Story 7 must not implement sync state machines, debounce policy, or reconcile loops

### Decision 3. Scan and notifications are separate capabilities

Why:

- the SDK always exposes scanning through `directoryScan(...)`
- notification support is optional and backend-dependent through `newdirnotify(...)`
- sync only opts into notifications when configured, and later still handles fallback/error conditions (`../sdk/src/sync.cpp:714-719`, `../sdk/src/sync.cpp:13547-13555`)

Consequence:

- Story 7 must not make notifications mandatory
- the runtime must expose a clean disabled/unavailable notification outcome
- scanning must remain available even when notification support is absent

### Decision 4. Notification payloads carry scan hints only

Why:

- upstream notifications carry `ScanRequirement` rather than reconcile actions (`../sdk/include/mega/filesystem.h:605-620`)
- sync interprets those hints later in `procscanq()` (`../sdk/src/sync.cpp:3859-3881`)

Consequence:

- Story 7 should define a scan-hint-bearing internal notification/event type
- Story 7 should not encode sync actions inside that type

### Decision 5. Story 7 must not hard-code one SDK backend detail as the Rust watcher contract

Why:

- the SDK uses different watch anchors and queue ownership shapes across backends
- macOS, Windows, and Linux do not share one universal root-relative event-path contract
- Linux also ties watch registration to `LocalNode::watch(...)` rather than to one generic root watcher object

Consequence:

- Story 7 may define internal Rust notification and registration types
- Story 7 acceptance criteria must not require per-registration queue ownership or one fixed root-relative path rule
- the Rust boundary only needs an explicit, documented internal contract that later sync can consume

### Decision 6. Transfer-specific naming policy stays with transfer consumers

Why:

- current Rust behavior for `.megatmp.<handle>` and `.megalib_upload` files is part of transfer compatibility (`src/fs/operations/download.rs:296-299`, `src/fs/upload_state.rs:72-80`)
- Story 7 is about local-I/O boundary ownership, not renaming compatibility artifacts

Consequence:

- the filesystem runtime should own generic local operations such as open/create/rename/remove
- transfer consumers may still decide temp-file and sidecar filenames in this story

---

## Minimum Boundary Requirements

The first implementation slice should satisfy these grounded requirements without freezing unnecessary internal details.

### 1. Module and ownership shape

- `src/fs/runtime/filesystem.rs` must exist.
- If `src/fs/runtime/mod.rs` is needed to house it, that module tree should be added explicitly.
- `Session`-owned internals should construct the filesystem runtime once and reuse it across upload/download paths rather than creating ad hoc operation-local filesystem helpers.

### 2. Local path and metadata semantics

- The boundary must make path handling explicit rather than leaving behavior dependent on scattered direct `std::fs` or `tokio::fs` calls.
- Directory-scan and watch-root entrypoints should require an explicit absolute directory path, matching the SDK’s `directoryScan(...)` and watched-root assumptions (`../sdk/src/posix/fs.cpp:1964-1965`, `../sdk/src/win32/fs.cpp:2119-2120`, `../sdk/src/win32/fs.cpp:1775`).
- Story 7 must preserve current public transfer behavior for relative destination/source paths where that behavior already exists; any internal normalization must remain compatibility-preserving.
- Metadata and scan operations should take an explicit symlink-follow policy, because the SDK makes that choice explicit on both file access and scanning (`../sdk/include/mega/filesystem.h:687-692`, `../sdk/include/mega/filesystem.h:808-813`).

### 3. Local file operation surface

- The boundary must cover the operations current transfer code actually needs:
  - metadata/stat
  - open for reading
  - open/create for writing with explicit create/append/truncate intent
  - rename
  - remove file
  - create directory as needed by transfer consumers
- The boundary should expose a crate-internal filesystem error type rather than leaking raw `io::Error` or deep `MegaError::Custom(String)` from low-level helpers.
- That error mapping should preserve at least the distinctions needed by current consumers and visible in the SDK’s boundary state, such as not-found, already-exists, permission, transient/unavailable, and invalid-path style cases (`../sdk/include/mega/filesystem.h:772-779`).

### 4. Directory scan semantics

- Scanning must be non-recursive and return immediate children only, matching the SDK role of `directoryScan(...)` (`../sdk/src/posix/fs.cpp:2044-2175`, `../sdk/src/win32/fs.cpp:2157-2297`).
- The boundary must not promise a result ordering contract unless the implementation explicitly defines one. Tests that need deterministic comparison should sort results.
- Scan results must preserve enough metadata for later consumers to distinguish file, directory, symlink, and other/special entries, because the SDK surfaces those distinctions in `FSNode` (`../sdk/include/mega/filesystem.h:896-966`).
- Story 7 does not need to land full FSID parity or `expectedFsid` validation everywhere, but the boundary must leave room for later sync work to add identity-aware scan behavior.

### 5. Notification capability semantics

- The boundary must model notification capability explicitly:
  - active notifications available
  - notifications disabled, unavailable, or not yet implemented
  - notifications failed and caller should fall back to scanning
- Unsupported or unavailable notification capability must be a normal internal outcome, not an automatic fatal startup condition for future consumers. That matches the SDK’s fallback `newdirnotify(...)` and `DirNotify` failure/error counters (`../sdk/src/filesystem.cpp:856-859`, `../sdk/src/filesystem.cpp:821-845`, `../sdk/src/win32/fs.cpp:1716-1727`).
- Notification events must carry scan intent equivalent to:
  - parent scan
  - self-directory scan
  - recursive scan
  because that is the stable semantic contract present in the SDK (`../sdk/include/mega/filesystem.h:605-620`).
- The Rust boundary must document how notification paths are anchored, but Story 7 does not need to impose one universal root-relative rule that the SDK itself does not have.

### 6. Consumer migration requirement

- By the end of Story 7, upload and download production paths should consume the runtime boundary for their main local-I/O behavior.
- `UploadState` may remain the owner of sidecar naming and serialized payload format, but its production-path load/save/delete I/O should be routed through the runtime boundary.

---

## Public API Preservation Rules

These are binding for Story 7:

1. `Session` upload and download methods remain the public entrypoints.
2. Existing resume behavior stays intact from the public caller’s perspective.
3. Existing progress callback behavior stays intact.
4. Story 7 must not expose a new public local watcher API.
5. Story 7 must not change temp-file or sidecar filenames as visible compatibility artifacts.

---

## Affected Modules

- `src/fs/runtime/mod.rs`
- `src/fs/runtime/filesystem.rs`
- `src/fs/mod.rs`
- `src/session/core.rs`
- `src/fs/operations/upload.rs`
- `src/fs/operations/download.rs`
- `src/fs/upload_state.rs`

Tests may live alongside those modules.

---

## Agent-Sized Tasks

### Task 7.1

Introduce the filesystem runtime module and its initial internal API shape.

Expected outcomes:

- `src/fs/runtime/filesystem.rs` exists
- session-owned internals have one reusable filesystem runtime handle
- the runtime covers metadata, file open/create, rename/remove, directory scan, and notification-capability queries/registration
- the runtime defines crate-internal filesystem error mapping and explicit write-mode intent
- disabled/unavailable notification support is explicit

Suggested verification:

- unit tests for metadata access, create/open behavior, rename, and delete using temp directories

### Task 7.2

Route upload local-I/O through the filesystem runtime.

Expected outcomes:

- `upload.rs` stops owning direct metadata/open decisions for source files
- resumable upload source-file access and seek/read setup consume runtime-owned helpers or handles
- sidecar load/save/delete paths used by resumable upload go through the same runtime boundary without changing sidecar naming or payload format
- upload behavior remains the same for public callers

Suggested verification:

- resumable upload tests still pass
- focused tests cover missing-file and metadata/open failure behavior
- focused tests cover sidecar overwrite and delete behavior through the runtime-backed helpers

### Task 7.3

Route download local temp-file behavior through the filesystem runtime.

Expected outcomes:

- `download.rs` stops owning direct local metadata/open/rename/remove calls
- temp-file resume behavior still works
- final rename and cleanup behavior remain unchanged for callers

Suggested verification:

- tests cover:
  - resume from partial temp file
  - cleanup when resume is disabled
  - final rename behavior

### Task 7.4

Add scan and notification-capability coverage.

Expected outcomes:

- a reusable directory scan API is exercised in tests
- disabled/unavailable notification capability is covered and explicit
- internal notification/event types are available for later sync work without implementing sync now
- scan tests assert the intended semantics explicitly:
  - non-recursive immediate-child results
  - symlink-policy handling
  - caller-side sorting when deterministic comparison is needed

Suggested verification:

- tests cover:
  - scan detects added/removed entries
  - scan sees metadata changes
  - scan does not recurse implicitly
  - unavailable notifications produce fallback-ready capability rather than fatal failure

---

## Acceptance Criteria

Story 7 is complete when:

1. `src/fs/runtime/filesystem.rs` exists as the architectural home for reusable local filesystem access.
2. session-owned internals reuse one filesystem runtime instance rather than constructing ad hoc operation-local helpers.
3. upload and download operation modules no longer own raw host-filesystem behavior directly for their main local-I/O paths.
4. `UploadState` sidecar file I/O in the production resumable-upload path goes through the filesystem runtime without changing public type or serialized compatibility artifacts.
5. a non-recursive directory scan substrate exists for later sync and backup work.
6. notification capability is modeled explicitly, including disabled/unavailable fallback semantics and scan-hint-bearing events suitable for later sync work.
7. the runtime boundary has explicit symlink-policy, write-mode, and structured filesystem-error contracts.
8. current public upload/download behavior remains intact.
9. no sync, backup, or mount implementation is introduced in this story.

---

## Verification Requirements

Story 7 should end with:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Focused coverage should include:

- metadata for existing and missing paths
- file open/create behavior for transfer consumers
- rename/delete behavior
- temp-file resume path handling
- sidecar overwrite/load/delete behavior
- directory scan add/remove/change behavior
- directory scan non-recursive behavior
- disabled/unavailable notification capability behavior

Prefer temp-directory tests over mocks where practical, because this story is about host-filesystem behavior and boundary ownership.

---

## Story Relationship To Later Work

Story 7 is a prerequisite for later stories, but it does not implement them:

- Story 5 consumes the filesystem runtime as the transfer runtime becomes thinner and more reusable
- Story 7B deepens platform/runtime layering and platform-specific watcher implementations
- Story 9 uses scan and notification primitives for sync
- Story 10 uses the same primitives for scheduled backup/copy behavior
- Story 11 uses the same boundary as part of mount-facing local filesystem integration
- Story 9B may later consume the boundary for side-service pipelines that touch local files

The correct architectural reading is:

- Story 7 creates a reusable `FileSystemAccess`-like lower layer plus a Rust notification-capability boundary informed by the SDK’s sync-coupled `DirNotify` model
- later stories are consumers of that substrate

It should not be read as:

- Story 7 partially implementing sync or mount ahead of schedule

---

## Recommended First Implementation Slice

If this story is executed as one small slice first, the highest-value first landing is:

1. add `src/fs/runtime/mod.rs` and `src/fs/runtime/filesystem.rs`
2. migrate `download_to_file(...)` to use the runtime for temp-file metadata/open/rename/remove
3. migrate resumable upload source-file metadata/open setup and sidecar I/O to the runtime
4. add temp-dir tests for rename/delete/scan and disabled notification capability

That is enough to make the boundary real without dragging in sync or platform-layout redesign prematurely.
