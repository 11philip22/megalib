# Story 5 Spec: Separate Transfer Runtime From Operation Code

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 5 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, 4, and 4B, this is a code-bearing story. Its job is to turn the current upload/download hot paths into orchestration clients of a real transfer runtime rather than leaving transfer policy, checkpointing, and worker behavior embedded in operation modules.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`
- `agents/outputs/architectural_parity_story_4b5_transfer_checkpoint_reset.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-31:

- uploads and downloads work today through `src/fs/operations/upload.rs` and `src/fs/operations/download.rs`
- concurrency policy is still mostly the `Session.workers` field plus per-operation branching
- cancellation still flows through `report_progress(...)` checks in operation code
- resumable upload still revolves around `UploadState` sidecar files, with mirrored persistence runtime support added in Story 3
- download resume is still file-size and HTTP-range based without a dedicated transfer runtime state model
- production persistence backend now exists from Story 4B, but transfer behavior still does not have a first-class runtime owner

This means transfer behavior is functional but still architecturally thin compared with the SDK.

---

## Validation Findings

Overall verdict: grounded.

Grounded:

- `TransferSlot` is the upstream active-transfer runtime surface: it owns connection counts, request sizing, temp-URL use, retries, progress reporting, and CloudRAID-related execution behavior (`../sdk/include/mega/transferslot.h:74`, `../sdk/src/transferslot.cpp:606`).
- Durable resumable state in the SDK lives in the transfer DB cache through persisted `Transfer` and `File` records, with `TransferDbCommitter` providing the transaction boundary used by queue, file-cache, and progress updates (`../sdk/include/mega/db.h:289`, `../sdk/src/megaclient.cpp:13831`, `../sdk/src/megaclient.cpp:15369`).
- Cached downloads resume by matching the source node handle in `Transfer::downloadFileHandle`, then validating persisted local temp-file state; the final target path comes from the cached file record while `Transfer::localfilename` carries the temp path (`../sdk/include/mega/transfer.h:144`, `../sdk/src/megaclient.cpp:18853`, `../sdk/src/file.cpp:72`, `../sdk/src/megaapi_impl.cpp:6632`).
- Cached transfer state is refreshed on committed progress boundaries, not just on cancel: upload chunk success/completion and download write completion all call back into `transfercacheadd(...)` (`../sdk/src/transferslot.cpp:813`, `../sdk/src/transferslot.cpp:903`, `../sdk/src/transferslot.cpp:1072`, `../sdk/src/transferslot.cpp:1131`).
- Core queued-transfer ordering, reprioritization, and paused-state handling live in `TransferList`, while `MegaApiImpl::TransferQueue` is a separate API-layer queue of `MegaTransferPrivate` objects (`../sdk/src/transfer.cpp:2778`, `../sdk/include/megaapi_impl.h:3200`, `../sdk/src/megaapi_impl.cpp:29132`).
- The SDK’s authoritative durable transfer state is a transfer-cache family, not a single transfer record: `enabletransferresumption()` loads both cached `Transfer` and cached `File` rows, `transfercacheadd(...)` and `filecacheadd(...)` persist them under the same DB table/key, and `TransferDbCommitter` is the shared transaction boundary for those updates (`../sdk/src/megaclient.cpp:13831`, `../sdk/src/megaclient.cpp:13851`, `../sdk/src/megaclient.cpp:15369`, `../sdk/src/file.cpp:72`, `../sdk/src/transfer.cpp:178`).

Unsupported:

- No material claim remains unsupported in the corrected story text.

---

## Story Goal

Establish a dedicated transfer runtime at `src/fs/runtime/transfer.rs` that owns:

- transfer policy
- worker/concurrency policy
- temp URL and transfer-session lifecycle decisions
- runtime checkpoint and durable transfer state
- cancel/resume/restart semantics

The story must preserve the existing public API surface while making upload/download modules thinner orchestration layers.

This story does not need to clone the SDK’s exact transfer classes. It does need to create the Rust equivalent of:

- core queued-transfer ownership plus an API-visible queue surface
- transfer-slot-style execution policy
- transfer-cache ownership spanning persisted transfer state and companion file state

---

## Why This Story Exists

Today, Rust transfer behavior is implemented mostly inside user-facing operation code:

- `src/fs/operations/upload.rs` owns resumable upload state loading/saving, chunk scheduling, progress cancellation, and upload preflight
- `src/fs/operations/download.rs` owns sequential-vs-parallel policy, chunk partitioning, resume offset logic, and progress cancellation
- `src/fs/upload_state.rs` is still the visible durable artifact for resumable upload, even though Story 3 already mirrored it behind the persistence SPI
- `Session` still stores transfer knobs such as `workers` and `resume_enabled` directly in `src/session/core.rs`

Upstream transfer architecture is broader and more layered:

- core queued-transfer ordering and reprioritization live in `TransferList`, while `MegaApiImpl::TransferQueue` is a separate API-layer transfer queue
- `TransferSlot` owns connection count, request sizing, temp URL use, retries, RAID setup/recovery, and chunk progress behavior
- transfer and file cache records live in the transfer DB cache rather than in operation-local sidecars
- `TransferDbCommitter` gives transfer runtime one durable transaction boundary for queue and file-state updates

Relevant upstream references:

- `../sdk/src/megaapi_impl.cpp:29132`
- `../sdk/include/megaapi_impl.h:3200`
- `../sdk/include/mega/transferslot.h:74`
- `../sdk/src/transferslot.cpp:106`
- `../sdk/include/mega/transfer.h:97`
- `../sdk/src/transfer.cpp:178`
- `../sdk/src/transfer.cpp:682`
- `../sdk/src/megaclient.cpp:15369`
- `../sdk/src/megaclient.cpp:13831`
- `../sdk/src/megaclient.cpp:18853`
- `../sdk/src/megaapi_impl.cpp:6632`

Story 5 is the slice that turns the current Rust transfer path from “working operations” into “runtime-owned transfer architecture.”

---

## Scope

In scope:

- introduce `src/fs/runtime/transfer.rs`
- define a transfer runtime API for upload/download orchestration
- move transfer policy and checkpoint ownership out of upload/download operation files
- move `workers` / resume policy ownership behind the transfer runtime while preserving the current public `Session` knobs
- define typed durable transfer identity and runtime-owned checkpoint behavior
- route one real upload path and one real download path through the new runtime seam
- add focused tests for:
  - upload resume
  - download resume
  - cancel handling
  - restart/recovery behavior
  - runtime-owned persistence behavior

Out of scope:

- full SDK-equivalent queued-transfer / `TransferList` parity in one slice
- CloudRAID implementation
- multi-transfer global scheduler fairness across the whole crate
- preview/media side pipelines
- public event redesign beyond preserving current progress callbacks
- filesystem/watch redesign
- sync-specific transfer semantics
- breaking or removing the public `UploadState` API in this story

This is a transfer-runtime ownership story, not the final word on every advanced transfer feature in the SDK.

---

## Story 1, Story 3, Story 4B, And Story 4B.5 Constraints

Story 5 must preserve these existing decisions:

- transfer runtime lives at `src/fs/runtime/transfer.rs`
- `Session` remains the engine root
- `src/fs/operations/*` stay orchestration-first
- persistence runtime remains at `src/session/runtime/persistence.rs`
- production transfer durability must build on the Story 3 SPI and Story 4B backend, not bypass them
- Story 4B.5 owns the transfer-checkpoint contract reset away from upload-only persistence and sidecar-first resumable behavior
- public API stays unchanged in this story

If implementation pressure suggests moving transfer runtime under `session` or bypassing the persistence SPI, Story 1 or Story 3 must be revised first.

---

## SDK Parity Target

The transfer runtime should align with the SDK in these ways:

1. Transfer policy is owned by a runtime subsystem, not by user-facing operation helpers.
2. Queue and execution concerns are separate from raw HTTP helpers.
3. Durable transfer state belongs to runtime-owned persistence, not operation-local files.
4. Resume and restart semantics are based on runtime checkpoints and transfer identity.
5. Concurrency policy and request sizing are runtime policy, not incidental local branching.
6. The runtime has a stable place to grow later features such as slot policy, queue mutations, or richer durable file records.

Rust should stay idiomatic:

- it does not need a line-by-line `TransferList` / `TransferQueue` / `TransferSlot` clone
- it does need equivalent ownership boundaries

---

## Current Transfer Gaps To Close

Story 5 is specifically targeting these current architectural gaps:

1. `upload.rs` still owns resumable upload state policy and persistence decisions.
2. `download.rs` still owns sequential-vs-parallel branching and chunk execution policy.
3. transfer knobs live as plain fields on `Session` rather than behind a transfer runtime/config owner.
4. download resume has no runtime-owned durable transfer model.
5. mirrored persistence runtime support exists, but the sidecar file is still the architectural center instead of the runtime.
6. there is no internal runtime seam where later queue/slot/cache behavior can land cleanly.

---

## Design Decisions

### Decision 1. The transfer runtime lives under `fs`, not `session`

Why:

- Story 1 already fixed that ownership
- transfer execution is tightly coupled to file movement and transfer-local worker policy
- sync and backup should later consume transfer runtime as a lower file-oriented subsystem

Consequence:

- Story 5 must introduce `src/fs/runtime/transfer.rs`
- `Session` may own or route to a transfer runtime handle, but the runtime’s architectural home stays under `fs`

### Decision 2. Public `Session` knobs stay stable, but delegate inward

Why:

- `set_workers`, `workers`, `set_resume`, `is_resume_enabled`, and progress callback behavior are already public
- the story goal is ownership change, not public API churn

Consequence:

- public setters/getters remain on `Session`
- internally they should read/write transfer runtime config rather than raw loose fields over time

### Decision 3. `UploadState` is no longer the architectural center

Why:

- `UploadState` is currently the public type and sidecar format for resumable upload
- removing it now would be unnecessary surface churn
- but runtime-owned persistence must become authoritative architecturally

Consequence:

- Story 5 may continue to use `UploadState` as an initial checkpoint payload or compatibility type
- the transfer runtime must own the policy and persistence contract around it
- operation-local sidecar assumptions must stop being the architectural source of truth

### Decision 4. Transfer identity must be typed and runtime-owned

Why:

- Story 3 already introduced `TransferPersistenceKey`
- future download and richer transfer runtime persistence will need more than upload-only fingerprints
- stringly-typed transfer identity will not scale into queue and restart semantics

Consequence:

- Story 5 should extend or wrap transfer persistence identity so upload and download runtime records have explicit kinds
- operation files should not invent their own persistence keys

### Decision 5. One upload path and one download path are enough for the first seam

Why:

- this story is about runtime ownership, not migrating every transfer variant immediately
- proving one real upload path and one real download path is enough to make the seam live

Consequence:

- Story 5 should migrate:
  - resumable file upload
  - local-path download with resume support

### Decision 6. Runtime policy should cover config, checkpoint, and execution seams separately

Why:

- the SDK separates queue/cache/slot behavior across different responsibilities
- one monolithic “transfer helper” would reproduce today’s problem under a new file name

Consequence:

- Story 5 should name at least these internal concepts:
  - transfer config
  - transfer checkpoint / durable record
  - transfer runtime execution entrypoints

These do not all need separate files in Story 5, but they must not be conceptually collapsed.

### Decision 7. Story 5 should consume one generic typed transfer-checkpoint SPI, not add another transfer-specific shape

Why:

- the SDK persists cached transfer and file records rather than upload-only sidecar state
- download resume in the SDK is first-class cached transfer behavior, not just file-length probing
- Story 4B.5 exists specifically to correct the upload-only SPI before runtime migration proceeds

Consequence:

- Story 5 should build on one typed generic transfer-checkpoint record API for load/save/clear operations
- new runtime call sites should target generic checkpoint ownership directly rather than adding another transitional persistence shape
- Story 5 must not reopen backend-schema design or reintroduce upload-only persistence APIs

### Decision 8. Download identity follows the SDK’s source-node anchoring, with path metadata stored alongside transfer state

Why:

- upstream resumes cached downloads by the cloud source identity, not by local file length alone
- the SDK persists transfer-owned state and file-owned local-path state separately:
  - `Transfer` serializes source-node-anchored transfer state, temp URLs, and transfer-local temp-path state
  - cached `File` state serializes the local target path used to reconstruct restart intent
- Rust’s current public surface is `download_to_file(node, path)`, so destination-specific temp-file state must be explicit

Consequence:

- a runtime-owned download checkpoint must include the source node handle as the authoritative remote identity
- the Rust runtime should treat source node handle as the primary transfer identity, with target path and runtime temp path retained as checkpoint metadata or companion file-state
- the checkpoint payload should retain runtime temp path and enough metadata to validate restart compatibility cleanly
- a resumed download must reject mismatched source node identity, incompatible file metadata, or incoherent temp-file state by clearing that checkpoint and restarting cleanly

### Decision 9. Runtime persistence is authoritative; Story 5 must not reintroduce sidecar-driven durability

Why:

- the SDK’s authoritative durable state is the transfer DB cache (`Transfer` plus cached `File` records), not dual durable sources
- dual-authority sidecar and runtime behavior leaves restart semantics ambiguous
- Story 4B.5 exists specifically to remove sidecar-first resumable-upload persistence from the production contract
- Story 5 must keep `UploadState` public without keeping sidecar files architecturally central

Consequence:

- Story 5 should assume runtime-owned transfer checkpoints are already the only authoritative durable source in production paths
- Story 5 must not rely on sidecar reads, sidecar imports, or sidecar mirroring for correctness
- if tests or temporary scaffolding still touch sidecar files during transition, that behavior is not part of the architectural contract and must not become runtime policy

### Decision 10. Checkpoints update on committed progress boundaries, not only on cancel

Why:

- the SDK refreshes cached transfer records after committed upload/download progress, not merely at cancellation time
- restart correctness depends on persisting only bytes that are known committed locally or remotely

Consequence:

- upload checkpoints should be saved after each successful committed upload chunk boundary
- download checkpoints should be saved after each chunk is durably written and contiguous progress advances
- cancel and transient failure should leave the last committed checkpoint intact for restart
- malformed or incompatible checkpoint records should be treated as cache misses and cleaned up rather than poisoning the runtime
- if a download temp URL expires, the runtime should reacquire fresh temp URL(s) and continue from committed bytes
- if an upload temp URL expires or becomes invalid, the runtime may keep the transfer identity but must restart the upload from zero unless later work proves safe server-side continuation

### Decision 11. The first live seam is explicit and intentionally narrow

Why:

- the story goal is to establish real runtime ownership without reopening every transfer helper in one slice
- the current Rust public surface includes both resumable local-path flows and stateless writer/stream helpers

Consequence:

- Story 5 must migrate `upload_resumable_to_node` / `upload_resumable`
- Story 5 must migrate `download_to_file`
- `download()` / `download_with_offset()` and non-resumable upload helpers may remain stateless helpers in this story
- when those helpers still use transfer worker or request policy, they should route through runtime planning/config helpers rather than new ad hoc branching

### Decision 12. The first slice establishes one session-owned transfer runtime without full queue-fairness parity

Why:

- the SDK has broader queue behavior through `TransferList` in the core, `TransferQueue` in the API layer, cached file records, and `TransferSlot` execution policy
- Story 5 still needs to stay a small slice rather than a full queue-scheduler port
- what matters architecturally is that one runtime owns config, checkpoint state, and execution entrypoints

Consequence:

- Story 5 must establish one session-owned transfer runtime that centrally owns:
  - config
  - checkpoint persistence
  - runtime planning and execution entrypoints
- full SDK-style global queue fairness, reprioritization breadth, and queue mutation depth remain deferred
- the first implementation must not pretend operation-local sequencing is still acceptable once the runtime exists

### Decision 13. Transfer runtime owns progress delivery and cancel interpretation

Why:

- in the SDK, progress accounting and cached-transfer updates are driven from `TransferSlot` and the transfer/API adapter boundary rather than from ad hoc per-operation branches
- Rust currently preserves a synchronous `ProgressCallback -> bool` compatibility surface, but that should be treated as an outward control hook over runtime-owned progress delivery

Consequence:

- the transfer runtime should own progress callback invocation and interpretation of a `false` return as a cancellation request
- operation code should report transfer facts and committed progress boundaries to the runtime rather than deciding cancellation policy itself
- Story 5 must preserve current public callback behavior while moving ownership of that behavior inward

---

## Recommended Rust Shape

The first implementation slice should aim for a small but real internal shape such as:

```rust
// src/fs/runtime/transfer.rs

pub(crate) struct TransferRuntime {
    config: TransferConfig,
}

pub(crate) struct TransferConfig {
    pub(crate) workers: usize,
    pub(crate) resume_enabled: bool,
}

pub(crate) enum TransferIdentity {
    Upload {
        source_fingerprint: String,
        local_path: std::path::PathBuf,
    },
    Download {
        source_node_handle: String,
    },
}

pub(crate) struct DownloadCheckpoint {
    pub(crate) target_path: std::path::PathBuf,
    pub(crate) temp_path: std::path::PathBuf,
}

pub(crate) enum TransferCheckpointPayload {
    Upload(UploadCheckpoint),
    Download(DownloadCheckpoint),
}

pub(crate) struct TransferCheckpointRecord {
    pub(crate) identity: TransferIdentity,
    pub(crate) committed_bytes: u64,
    pub(crate) temp_urls: Vec<String>,
    pub(crate) payload: TransferCheckpointPayload,
}
```

And runtime-facing entrypoints along the lines of:

- `load_checkpoint(...)`
- `save_checkpoint(...)`
- `clear_checkpoint(...)`
- `plan_download_to_path(...)`
- `plan_upload(...)`

The exact API names may differ, but the story should preserve the distinction between:

- runtime config
- durable checkpoint ownership
- transfer execution planning

That is the Rust-idiomatic equivalent of introducing queue/slot/cache ownership without over-designing Story 5.

---

## Public API Preservation Rules

These are binding for Story 5:

1. `Session` upload/download methods remain the public entrypoints.
2. `Session::set_workers()` and `Session::set_resume()` remain available and keep current behavior.
3. existing transfer progress callback behavior remains intact.
4. `UploadState` remains available as a public type in this story.
5. Story 5 must not introduce a new public transfer scheduler API unless explicitly approved later.

---

## Durable State Rules

These are binding for Story 5:

1. runtime-owned transfer persistence must go through `src/session/runtime/persistence.rs`
2. Story 5 should consume one generic typed transfer-checkpoint SPI/backend rather than redesigning persistence shape again
3. operation files must not own transfer-identity or persistence-key construction long-term
4. upload checkpoints should remain keyed by runtime-owned source identity rather than by ad hoc operation-local strings
5. download checkpoints must use source node handle as the primary transfer identity, with target path and runtime temp path stored in checkpoint metadata or companion file-state
6. Story 5 must not depend on sidecar files for resumable-upload correctness
7. download resume must gain a runtime-owned checkpoint story rather than remaining only “existing file length plus range request”
8. persisted transfer checkpoints must update on committed progress boundaries, not only on cancel
9. malformed or incompatible persisted transfer records must fall back cleanly rather than poisoning the runtime
10. transfer runtime owns progress callback invocation and cancel interpretation; operations should only surface committed progress facts and transfer errors into that runtime

---

## Affected Modules

- `src/fs/operations/upload.rs`
- `src/fs/operations/download.rs`
- `src/fs/upload_state.rs`
- `src/fs/mod.rs`
- `src/progress.rs`
- `src/session/core.rs`
- `src/session/runtime/persistence.rs`
- `src/fs/runtime/transfer.rs`

Tests may live alongside the above modules.

---

## Agent-Sized Tasks

### Task 5.1

Introduce the transfer runtime module and transfer config owner.

Expected outcomes:

- `src/fs/runtime/transfer.rs` exists
- transfer config is named and no longer conceptually lives as loose `Session` fields
- `Session` public knobs route through the runtime/config owner without public API changes
- the first slice establishes one session-owned transfer runtime without claiming full SDK queue-fairness parity

Suggested ownership:

- `src/fs/runtime/transfer.rs`
- `src/session/core.rs`
- `src/fs/mod.rs`

### Task 5.2

Move upload checkpoint ownership behind the transfer runtime.

Expected outcomes:

- resumable upload persistence is runtime-owned
- `UploadState` may remain as compatibility payload, but operation code no longer owns persistence policy
- sidecar files are no longer part of the resumable-upload runtime contract

Suggested ownership:

- `src/fs/runtime/transfer.rs`
- `src/fs/operations/upload.rs`
- `src/fs/upload_state.rs`
- `src/session/runtime/persistence.rs`

### Task 5.3

Introduce download checkpoint/planning ownership behind the transfer runtime.

Expected outcomes:

- local-path download resume logic goes through runtime-owned planning/checkpoint rules
- sequential-vs-parallel policy is no longer embedded directly in `download.rs`
- runtime now owns both an upload and a download consumer path
- download checkpoint identity is explicitly source-node anchored and path-aware
- the persistence SPI/backend can represent download restart state without overloading `UploadState`
- runtime-owned download identity uses source node handle as the primary transfer key, while target path and temp path remain checkpoint metadata or companion file-state

Suggested ownership:

- `src/fs/runtime/transfer.rs`
- `src/fs/operations/download.rs`
- `src/session/runtime/persistence.rs`

### Task 5.4

Add focused regression coverage and close the story.

Expected outcomes:

- tests cover:
  - upload resume through runtime-owned checkpointing
  - download resume through runtime-owned planning/checkpointing
  - cancel handling without regression
  - restart/recovery behavior through the persistence runtime
  - malformed checkpoint fallback
  - absence of sidecar dependence in production resumable-upload paths
  - download temp-URL refresh after restart without losing committed bytes

Suggested ownership:

- tests alongside `upload.rs`, `download.rs`, `transfer.rs`, and `persistence.rs`

---

## Acceptance Criteria

Story 5 is complete when:

1. `src/fs/runtime/transfer.rs` exists and owns transfer runtime concepts explicitly.
2. upload and download operations have become thinner orchestration clients of that runtime.
3. transfer config and worker/resume policy are centrally owned rather than scattered in operation logic.
4. durable transfer state is owned by the runtime through the persistence SPI rather than by operation-local sidecar assumptions.
5. the persistence layer can represent both upload and download runtime checkpoints without forcing download state through `UploadState`.
6. upload sidecar files are not part of the resumable-upload runtime contract.
7. one real resumable upload path and one real local-path download path are proven through the runtime seam.
8. current public transfer API and progress callback behavior remain stable.
9. transfer runtime owns progress/cancel plumbing rather than leaving callback interpretation embedded in operation-local branches.
10. the first slice establishes central runtime/config/checkpoint/execution ownership without requiring full SDK queue-fairness parity in the same change.

---

## Verification Requirements

Because this is a Rust source-code story, every implementation slice must end with:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

At least one slice in the story should include focused transfer-runtime resume/restart tests instead of relying only on broad crate coverage.

---

## Story Relationship To Later Work

Story 5 is a prerequisite runtime story, not an endpoint.

Later stories should consume it like this:

- Story 6 may emit transfer-family public events from the runtime rather than directly from operation code
- Story 7 may provide the filesystem abstraction the runtime should use instead of direct local file I/O
- Story 9 sync should reuse transfer runtime rather than implementing a second transfer engine
- Story 10 backup should reuse the same runtime policy and checkpoint ownership

Story 5 should not be forced to solve sync, backup, CloudRAID, or public event parity on its own.
