# Story 4B.5 Spec: Replace Upload-Only Transfer Persistence With Generic Checkpoints

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 4B.5 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 3, 4B, and 4C, this is a code-bearing story. Its job is to correct the shipped transfer-persistence shape before later hardening and transfer-runtime work continue: the current upload-only transfer persistence contract is too narrow for SDK-style transfer-cache ownership and should be replaced now rather than compensated for later.

Story type:

- Implementation story / persistence-contract reset

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`
- `agents/outputs/architectural_parity_story_4c_production_tree_cache_hardening.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- Story 4B is complete as the production SQLite backend rollout
- `PersistenceRuntime` still exposes upload-only transfer APIs in `src/session/runtime/persistence.rs:406` and `src/session/runtime/persistence.rs:480`:
  - `load_upload_state(...)`
  - `save_upload_state(...)`
  - `clear_upload_state(...)`
- `TransferPersistenceKey` still only supports `TransferPersistenceKind::Upload` in `src/session/runtime/persistence.rs:83`
- the production schema still persists transfer state in `upload_state(kind, local_fingerprint, json)` in `src/session/runtime/persistence.rs:286`
- `Session` still constructs upload persistence identity from `UploadState::state_file_path(source_path)` in `src/session/core.rs:396`
- the resumable upload path still reads the local sidecar first and only falls back to the persistence runtime mirror in `src/fs/operations/upload.rs:26` and `src/fs/operations/upload.rs:293`
- download resume still has no durable runtime checkpoint model; `download_to_file(...)` has no matching persistence path in the current tree (`src/fs/operations/download.rs:285`, `src/session/runtime/persistence.rs:406`)

This means the backend is real, but the transfer persistence contract is still architecturally wrong for the SDK-aligned runtime that later stories need.

## Validation Findings

Overall verdict: Grounded.

- Grounded current-state evidence: `megalib` currently persists only upload state, keys it with `TransferPersistenceKind::Upload`, stores it in the `upload_state` table, derives the key from `UploadState::state_file_path(...)`, and loads the sidecar before the runtime mirror (`src/session/runtime/persistence.rs:83`, `src/session/runtime/persistence.rs:286`, `src/session/core.rs:396`, `src/fs/operations/upload.rs:26`, `src/fs/operations/upload.rs:293`).
- Grounded upstream evidence: the SDK keeps transfer resumption in a dedicated `transfers_*` cache opened with `DB_OPEN_FLAG_RECYCLE | DB_OPEN_FLAG_TRANSACTED`; that cache stores both cached `Transfer` rows and cached `File` rows; resume starts from cached file rows via `MegaApiImpl::file_resume(...)` and then matches cached transfers; cached transfer state is serialized through `Transfer::serialize(...)`, refreshed on committed upload/download progress, and unreadable cached transfer rows are deleted as record-local cache failures (`../sdk/src/megaclient.cpp:15391`, `../sdk/include/mega/db.h:315`, `../sdk/src/megaclient.cpp:13831`, `../sdk/src/megaclient.cpp:13851`, `../sdk/src/megaclient.cpp:15536`, `../sdk/src/megaapi_impl.cpp:13661`, `../sdk/src/transfer.cpp:178`, `../sdk/src/transferslot.cpp:903`, `../sdk/src/transferslot.cpp:1072`, `../sdk/src/megaclient.cpp:15434`).
- Grounded matching semantics: upload and download resume are both fingerprint-bucketed because `Transfer` derives from `FileFingerprint`; upload resume then prefers exact `localfilename`, while download resume uses `downloadFileHandle` to disambiguate same-fingerprint candidates (`../sdk/include/mega/transfer.h:97`, `../sdk/include/mega/transfer.h:115`, `../sdk/include/mega/transfer.h:145`, `../sdk/src/megaclient.cpp:18853`).
- Grounded story consequence: Story 4B.5 should reset the Rust persistence contract before Story 5 because the current Rust implementation lacks any download checkpoint backend and does not model the upstream transfer-cache family. The generic Rust checkpoint store described below is therefore a deliberate story design derived from these constraints, not a claim that the C++ SDK already uses the exact same schema.

---

## Story Goal

Replace the shipped upload-only transfer persistence contract with a generic internal transfer-checkpoint model and an SDK-style dedicated transfer checkpoint cache so later stories do not have to redesign persistence mid-flight.

This story must leave the system with these properties:

- engine/tree persistence from Stories 3, 4, and 4B remains intact because transfer checkpoints move into their own SDK-style cache store
- transfer persistence is no longer shaped around `UploadState`-specific APIs
- transfer checkpoint schema/version handling follows the SDK’s cache semantics and may recycle the transfer checkpoint store wholesale
- the current resumable upload path no longer depends on sidecar-first durability behavior
- Story 4C can harden tree/cache behavior without also reopening transfer-cache design
- Story 5 can build a transfer runtime on top of a generic checkpoint store instead of an upload-only store

This story is still an internal persistence story. It must not break public API or widen into the full transfer-runtime migration.

---

## Why This Story Exists

Story 3 intentionally shipped a narrow first transfer model:

- `TransferPersistenceKey` exists
- `UploadState` is the persisted transfer payload
- the SPI and backend expose upload-only methods

Story 4B then made that shape real on disk:

- the production backend now has a real SQLite file
- the transfer domain is persisted in an `upload_state` table
- malformed rows are treated as recoverable cache misses

That was a reasonable first cut, but it is no longer the right base for the next stories.

The SDK does not treat transfer persistence as “upload state plus maybe something else later”:

- the SDK persists a cached transfer family centered on `Transfer` rows plus companion cached `File` rows used during resume
- transfer resumption lives in a dedicated `transfers_*` DB/cache opened with recycle semantics
- cached transfer records persist local temp path, progress, temp URLs, crypto/progress fields, and download-specific remote identity
- uploads and downloads both belong to the same cached-transfer family
- transfer cache updates happen on committed transfer progress, not only on cancellation

Relevant upstream references:

- `../sdk/include/mega/transfer.h:97`
- `../sdk/src/transfer.cpp:178`
- `../sdk/src/transfer.cpp:682`
- `../sdk/src/transferslot.cpp:903`
- `../sdk/src/transferslot.cpp:1072`
- `../sdk/src/megaclient.cpp:13831`
- `../sdk/src/megaclient.cpp:15367`
- `../sdk/src/megaclient.cpp:18853`
- `../sdk/src/megaclient.cpp:15536`
- `../sdk/src/megaapi_impl.cpp:13661`
- `../sdk/include/mega/db.h:315`

The current Rust shape diverges from that architecture in specific ways:

- transfer persistence is upload-only at the API boundary
- upload identity is derived from the sidecar file path rather than a runtime-owned transfer identity
- sidecar files still drive resumable upload behavior in the live path
- download resume has no durable record model to build on

If this is left for Story 5 to “work around,” Story 5 would have to simultaneously:

- redesign the persistence SPI
- redesign the production schema
- remove sidecar-first behavior
- add runtime ownership and consumer migration

That is too much for one slice and would reopen Story 4B after Story 4C starts depending on it.

Story 4B.5 exists to make the persistence foundation honest before later work continues.

---

## Scope

In scope:

- replace upload-only transfer persistence APIs with generic internal transfer-checkpoint APIs
- replace the upload-only persistence data model with typed generic checkpoint records
- move transfer checkpoints into a dedicated SDK-style transfer SQLite cache managed by `PersistenceRuntime`
- make transfer checkpoint schema/version handling recycle that dedicated transfer cache on mismatch, like the SDK
- remove sidecar-first resumable-upload behavior from the current runtime path
- route the existing resumable upload consumer through the new generic checkpoint store
- define and persist download checkpoint identity and payload shape at the backend level, even if download consumer migration remains for Story 5
- add focused tests for:
  - checkpoint round-trip in memory and SQLite transfer-cache backends
  - malformed checkpoint row fallback
  - transfer-cache schema/version mismatch recycle behavior
  - engine/tree persistence remaining untouched when the transfer cache recycles
  - resumable upload behavior no longer depending on sidecar-first lookup
  - download checkpoint round-trip support in the dedicated transfer cache

Out of scope:

- full transfer runtime extraction into `src/fs/runtime/transfer.rs`
- migrating `download_to_file(...)` through runtime-owned checkpoints
- queue scheduling, slot policy, or retry/runtime orchestration work
- redesigning Story 4 tree/cache coherency semantics
- changing the production backend technology chosen in Story 4B
- public transfer scheduler APIs
- public API removal of `UploadState`
- cross-transfer queue restore or automatic queued-transfer replay on session startup

This is a persistence reset story, not the full transfer-runtime story.

---

## Story 1, Story 3, Story 4, And Story 4B Constraints

Story 4B.5 must preserve these existing decisions:

- `Session` remains the engine root
- persistence runtime stays at `src/session/runtime/persistence.rs`
- Stories 4 and 4C remain the semantic owners of tree/cache restore, refresh replacement, and AP-batch commit rules
- Story 4B remains the owner of production backend technology and constructor-time backend installation
- no-op and memory backends remain available for unsupported/public/test contexts
- public API remains stable

Story 4B.5 is explicitly allowed to revise these earlier implementation details:

- the upload-only transfer persistence API shape shipped in Story 3/4B
- the `upload_state`-specific production table as the long-term transfer-store shape
- the transfer backend layout for this domain, including moving transfer checkpoints into a dedicated SDK-style transfer cache DB
- sidecar-first resumable-upload lookup as an implementation behavior

Story 4B.5 must not reopen:

- engine-state durable model shape
- tree snapshot durable model shape
- Story 4 restore/refresh/AP commit boundaries
- the backend choice made in Story 4B

---

## Grounded SDK Constraints And Story Design Target

The inspected upstream code establishes these parity constraints:

1. Transfer resumption lives in a dedicated `transfers_*` cache DB that is opened with recycle and transaction semantics.
2. That transfer cache stores both cached `Transfer` rows and cached `File` rows.
3. A cached `Transfer` carries file-fingerprint identity, representative local path, progress, temp URLs, crypto state, and optional `downloadFileHandle`.
4. Resume starts from cached file rows via `file_resume(...)` and then matches cached transfers by fingerprint bucket plus exact-path or `downloadFileHandle` disambiguation.
5. Transfer-cache durability is refreshed on committed progress, malformed cached transfer rows are dropped locally, and transfer-cache schema mismatches may recycle the whole cache.

Story 4B.5 adopts the following Rust design to satisfy those constraints without claiming literal schema parity:

1. Replace the upload-only SPI with one typed transfer-checkpoint persistence family owned by `src/session/runtime/persistence.rs`.
2. Move transfer checkpoints into a dedicated transfer cache DB so engine/tree persistence remains separate.
3. Preserve the SDK's matching inputs in the Rust model: upload checkpoints must carry fingerprint plus representative local path, and download checkpoints must carry fingerprint plus source-node disambiguation data and transfer-owned temp-path state.
4. Rust may encode upload/download payloads as enums and typed structs rather than one monolithic serialized `Transfer`; if companion file-resume data is folded into checkpoint metadata, that is an explicit Rust design choice rather than a claim about the upstream schema.
5. Sidecar files leave the hot path because this story makes runtime-owned transfer persistence the authoritative resumable store.

---

## Binding Decisions

The following implementation choices are fixed for Story 4B.5.

### Decision 1. Replace upload-only SPI methods instead of layering new work around them

Why:

- an upload-only persistence API bakes the wrong architectural center into every later consumer
- Story 5 should not need to carry compatibility wrappers as its primary design

Consequence:

- `PersistenceBackend` and `PersistenceRuntime` should expose generic transfer-checkpoint methods instead of upload-only methods
- upload-specific helpers may remain only as very small local adapters if needed during the slice, but the persistence contract itself should no longer be upload-shaped

### Decision 2. Use an SDK-style dedicated transfer cache with recycle-on-mismatch semantics

Why:

- the SDK keeps transfer resumption in its own `transfers_*` DB/cache
- that cache is opened with recycle semantics because transfer persistence is cache-like, not authoritative account state
- the user explicitly wants SDK behavior here, not a Rust-specific migration layer

Consequence:

- `PersistenceRuntime` should manage transfer checkpoints through a dedicated transfer SQLite store distinct from engine/tree persistence
- transfer-cache schema/version mismatch may recycle that dedicated transfer cache wholesale
- Story 4B.5 does not need to preserve the old `upload_state` table or migrate its contents
- engine/tree persistence remains intact because it stays outside the transfer cache store

### Decision 3. Upload identity follows the SDK’s file fingerprint model, with representative local path retained

Why:

- upstream `Transfer` derives from `FileFingerprint`
- cached uploads are selected by fingerprint family first and exact `localfilename` match second
- sidecar-path identity is not SDK behavior

Consequence:

- upload checkpoint identity must use a Rust equivalent of the SDK file fingerprint
- the representative local source path must be persisted alongside that fingerprint so exact-path matches can be preferred
- `Session` must stop deriving upload persistence identity from `UploadState::state_file_path(...)`

### Decision 4. Download checkpoint identity follows the SDK’s fingerprint-bucket-plus-source-node matching, with temp path stored in transfer state

Why:

- cached downloads are resumed from a fingerprint bucket and then matched by `downloadFileHandle`
- the SDK transfer record serializes the transfer-owned temp path in `localfilename`
- the final target path is important, but the inspected SDK path uses it as transfer state, not as the primary cached-transfer disambiguator

Consequence:

- download checkpoint identity must at minimum retain the fingerprint bucket, source node handle, and any other data needed to disambiguate same-fingerprint candidates
- the checkpoint record must persist the transfer-owned temp path
- if Rust needs to retain final target path for `download_to_file(...)`, that path should live in checkpoint payload or companion metadata rather than replace the source-handle disambiguation data

### Decision 5. Sidecar files are removed from the runtime contract in this story

Why:

- the user explicitly does not care about legacy compatibility here
- one authoritative durable source is simpler and is closer to the SDK-managed DB cache model
- sidecar-first behavior is the current architectural bug, not a feature worth preserving

Consequence:

- the current resumable upload path should stop reading sidecar files before consulting runtime persistence
- new transfer-checkpoint persistence should not mirror to sidecar files
- the public `UploadState` type may remain, but `.megalib_upload` files stop being part of the production resumable-upload contract
- pre-existing `.megalib_upload` files are ignored by the runtime; Story 4B.5 does not need import or cleanup behavior for them

### Decision 6. Story 4B.5 must implement real backend support for download checkpoint records

Why:

- the SDK caches both upload and download transfer records
- type-only download placeholders would leave Story 5 reopening backend questions the story is supposed to settle now

Consequence:

- memory and SQLite backends must both round-trip download checkpoint records in this story
- malformed-row fallback coverage should include download records as well as upload records
- Story 5 may defer download-consumer migration, but not download checkpoint backend reality

### Decision 7. The current upload consumer must adopt SDK-style checkpoint write and reset rules

Why:

- the SDK refreshes cached transfer state on committed progress, not only on cancel
- upload temp-URL expiry in the SDK resets upload progress/chunk MAC/token state to zero rather than pretending continuation is safe

Consequence:

- the current resumable upload path must save a checkpoint when transfer state becomes resumable and after each committed upload chunk boundary
- successful upload completion must clear the checkpoint
- cancel or transient failure must preserve the last committed checkpoint
- expired or invalid upload temp URLs must reset upload progress/chunk-MAC/upload-token state to zero before resuming
- the backend model introduced here must also be able to represent the SDK’s download rule: keep committed bytes and reacquire temp URLs when a download temp URL expires

### Decision 8. Story 4B.5 defines the checkpoint store; Story 5 consumes it

Why:

- this story is about fixing the persistence base
- Story 5 is about runtime ownership and operation thinning

Consequence:

- Story 4B.5 must make the generic checkpoint store real and use it for the current resumable upload path
- Story 5 may then build runtime-owned upload/download planning and checkpoint rules on top of that store without reopening schema or SPI shape

---

## Recommended Rust Shape

Story 4B.5 should aim for a small but real internal model along these lines:

```rust
pub(crate) enum TransferCheckpointKind {
    Upload,
    Download,
}

pub(crate) enum TransferCheckpointKey {
    Upload {
        source_fingerprint: String,
        local_path: std::path::PathBuf,
    },
    Download {
        source_fingerprint: String,
        source_node_handle: String,
    },
}

pub(crate) struct TransferCheckpointRecord {
    pub(crate) key: TransferCheckpointKey,
    pub(crate) committed_bytes: u64,
    pub(crate) temp_urls: Vec<String>,
    pub(crate) payload: TransferCheckpointPayload,
}

pub(crate) enum TransferCheckpointPayload {
    Upload(PersistedUploadCheckpoint),
    Download(PersistedDownloadCheckpoint),
}
```

And persistence entrypoints along the lines of:

- `load_transfer_checkpoint(...)`
- `save_transfer_checkpoint(...)`
- `clear_transfer_checkpoint(...)`

Optional later extension:

- `list_transfer_checkpoints(...)`

That iterator/list shape is not required to complete Story 4B.5 unless implementation naturally needs it, but the new record model must not block it.

Recommended upload payload contents:

- file crypto/resume material equivalent to what current resumable upload needs
- upload URL(s) or temp URL state
- chunk MAC/progress state
- file metadata needed to validate a resumed upload safely

Recommended download payload contents:

- transfer-owned temp path
- final target path if required by Rust `download_to_file(...)` restart reconstruction
- temp file metadata needed for restart validation
- any download-specific remote metadata later runtime code needs to validate restart

The exact field names may differ, but the persistence contract should preserve the distinction between:

- checkpoint identity
- committed progress
- temp URL state
- kind-specific payload

---

## Durable State Rules

These are binding for Story 4B.5:

1. Transfer checkpoint persistence must continue living under `src/session/runtime/persistence.rs`.
2. The persistence contract must no longer be upload-only.
3. Upload and download checkpoints must share one typed persistence family.
4. Transfer checkpoints must live in a dedicated transfer cache DB, not in engine/tree persistence tables.
5. Transfer-cache schema/version mismatch may recycle the transfer cache without affecting engine/tree persistence.
6. Transfer checkpoint row corruption must be handled as a record-local cache miss.
7. Runtime persistence becomes the only authoritative resumable-upload store in production paths touched by this story.
8. Sidecar files must not remain on the hot path for resumable upload after this story and are ignored if present.
9. Public `UploadState` availability does not justify keeping upload-only persistence APIs.
10. Transfer checkpoint durability rules must encode SDK-style upload reset semantics and download temp-URL refresh semantics.

---

## Current Implementation Gaps This Story Closes

Story 4B.5 is specifically targeting these current problems:

1. `PersistenceBackend` is upload-only for transfer state.
2. `TransferPersistenceKind` cannot express downloads.
3. transfer state still lives in an upload-specific table inside the engine/tree persistence backend instead of a dedicated transfer cache.
4. `Session` constructs transfer identity from the sidecar-file path.
5. resumable upload still treats sidecar files as the primary durable source.
6. later stories would otherwise need to combine persistence redesign with runtime migration.

---

## Affected Modules

Primary write scope:

- `src/session/runtime/persistence.rs`
- `src/session/core.rs`
- `src/fs/operations/upload.rs`

Recommended secondary scope:

- `src/fs/upload_state.rs`
- tests in touched modules

Read-only coordination context:

- `src/fs/operations/download.rs`
- `src/session/auth.rs`
- `agents/outputs/architectural_parity_story_4c_production_tree_cache_hardening.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`

---

## Agent-Sized Tasks

### Task 4B.5.1

Define the generic transfer-checkpoint models and persistence APIs.

Expected outcomes:

- upload-only persistence methods are replaced by generic transfer-checkpoint methods
- transfer checkpoint key and payload types exist
- the contract can represent both upload and download checkpoints without upload-specific API shape

Suggested ownership:

- `src/session/runtime/persistence.rs`

### Task 4B.5.2

Add the dedicated transfer cache backend/schema for the generic checkpoint store.

Expected outcomes:

- SQLite backend persists generic transfer checkpoints in a dedicated transfer cache DB
- transfer-cache schema/version handling is explicit and recycle-on-mismatch
- engine/tree persistence remains untouched because it does not share this transfer cache DB

Suggested ownership:

- `src/session/runtime/persistence.rs`

### Task 4B.5.3

Remove sidecar-first resumable-upload behavior and route the current resumable upload consumer through the checkpoint store.

Expected outcomes:

- resumable upload no longer loads from sidecar first
- resumable upload persistence uses the generic checkpoint store
- no sidecar mirroring remains in the production resumable path touched by this story
- upload checkpoint writes follow SDK-style committed-progress cadence and reset rules

Suggested ownership:

- `src/fs/operations/upload.rs`
- `src/session/core.rs`
- `src/session/runtime/persistence.rs`

### Task 4B.5.4

Add focused regression coverage and close the story.

Expected outcomes:

- tests prove malformed checkpoint rows are record-local failures
- tests prove transfer-cache schema/version mismatch recycles transfer state without disturbing engine/tree persistence
- tests prove resumable upload no longer depends on sidecar-first behavior
- tests prove memory and SQLite backends both round-trip generic upload and download checkpoints

Suggested ownership:

- tests alongside `persistence.rs`, `core.rs`, and `upload.rs`

---

## Acceptance Criteria

Story 4B.5 is complete when:

1. `PersistenceRuntime` and `PersistenceBackend` no longer expose upload-only transfer persistence as the primary internal contract.
2. the production runtime persists transfer checkpoints in a dedicated SDK-style transfer cache store that may recycle on schema mismatch.
3. the transfer cache can persist generic checkpoint records for both upload and download kinds.
4. engine/tree persistence remains unaffected by transfer-cache reset or recycle behavior.
5. the current resumable upload path no longer depends on sidecar-first durability behavior and ignores `.megalib_upload` files.
6. upload checkpoint identity is fingerprint-based and no longer derived from sidecar paths.
7. malformed transfer checkpoint rows fall back cleanly without poisoning engine/tree restore behavior.
8. Story 4C and Story 5 can build on the transfer checkpoint store without reopening persistence contract shape.

---

## Verification Requirements

Because this is a Rust source-code story, every implementation slice must end with:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

At least one slice in the story should include focused real-disk tests showing that transfer-cache schema/version mismatch recycles only the dedicated transfer cache and does not disturb engine/tree persistence files.

---

## Story Relationship To Later Work

Story 4B.5 is the transfer-persistence reset story.

Later stories should consume it like this:

- Story 4C may assume the production backend’s transfer domain is no longer upload-only and will not need redesign during tree/cache hardening
- Story 5 should assume an SDK-style dedicated transfer checkpoint store already exists and should focus on runtime ownership plus consumer migration
- later sync/backup/mount stories may assume transfer persistence is a typed internal checkpoint domain rather than an upload-sidecar holdover

Story 4B.5 should not be forced to solve:

- transfer queue fairness
- runtime scheduler extraction
- download consumer migration
- public transfer event design
- sync or backup behavior
