# Story 4B Spec: Roll Out Production Persistence Backend

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 4B from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, and 4, this is a code-bearing story. Its job is to replace the current minimal/test-oriented persistence backend with a real authenticated-session on-disk backend without reopening the Story 3 SPI or the Story 4 coherency contract.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_story_4_tree_cache_coherency.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Completed.

Current implementation status on 2026-03-26:

- `PersistenceRuntime` exists at `src/session/runtime/persistence.rs`
- `NoopPersistenceBackend` and `MemoryPersistenceBackend` exist and are covered by tests
- `SqlitePersistenceBackend` now exists behind `PersistenceBackend`
- backend schema constants, schema-init helpers, and per-scope DB-path resolution now exist in code
- focused real-disk backend tests now cover create/init, reopen round-trip, scope isolation, and backend-schema mismatch rejection
- authenticated session creation and saved-session load paths now install the production runtime at construction time
- Story 3 and Story 4 still preserve no-op or in-memory backends for unsupported/public/test contexts
- unsupported backend schema now recycles the on-disk DB to a fresh empty backend instead of poisoning startup
- malformed engine/upload rows now behave like recoverable cache misses instead of backend-fatal errors
- real-disk session-level tests now cover disk-backed tree/cache restore, upload-state round-trip, and scope isolation through the `Session` helpers

This story closes that rollout gap.

Current task status:

- Task 4B.1 is complete in code
- Task 4B.2 is complete in code
- Task 4B.3 is complete in code
- Task 4B.4 is complete in code

---

## Story Goal

Add a real production persistence backend behind `PersistenceRuntime` so authenticated sessions can use durable on-disk storage for:

- engine metadata
- tree/cache snapshots
- transfer resume records

The story must preserve the existing Story 3 SPI and Story 4 coherency rules. It should make the backend real, versioned, scope-aware, and testable on disk without widening into query/index, sync, or transfer-runtime redesign.

---

## Why This Story Exists

Today, the architecture has a persistence seam but not production durability:

- Story 3 introduced `PersistenceRuntime`, durable models, and test backends
- Story 4 made tree/cache coherency real through that seam
- production sessions still run with `PersistenceRuntime::disabled()`

That leaves the epic in an awkward state:

- the architecture can prove restore/commit behavior in tests
- the shipped runtime still has no real backend for authenticated sessions

Upstream does not have that gap:

- `MegaApiImpl` constructs `MegaDbAccess` before `MegaClient` is created
- `MegaClient` owns `dbaccess`, `sctable`, `statusTable`, and `tctable`
- `opensctable()` opens the versioned state DB early and starts a transaction shared by `"statecache"` and `"nodes"`
- `fetchnodes()` / `fetchsc()` consume the cache only after DB setup succeeds and `cachedscsn` is known

Relevant upstream references:

- `../sdk/src/megaapi_impl.cpp:7015`
- `../sdk/include/mega/megaclient.h:2014`
- `../sdk/include/mega/megaclient.h:2017`
- `../sdk/include/mega/megaclient.h:2033`
- `../sdk/include/mega/db.h:320`
- `../sdk/include/mega/db/sqlite.h:217`
- `../sdk/src/megaclient.cpp:12233`
- `../sdk/src/megaclient.cpp:15869`

Story 4B is the story that gives Rust the same architectural property:

- a real backend exists at construction time
- it has durable file/schema rules
- later stories can rely on it without test-only injection

---

## Scope

In scope:

- add a real authenticated-session on-disk backend behind `PersistenceRuntime`
- define backend file layout and scope-to-path mapping
- define backend schema/version handling for production storage
- wire constructor-time backend selection for authenticated sessions and session-load paths
- keep no-op and memory backends for unsupported/public/test contexts
- add focused tests for:
  - first-run create
  - restart reopen
  - per-scope isolation
  - unsupported schema handling
  - malformed/corrupt on-disk content

Out of scope:

- redesigning the Story 3 persistence trait
- reworking Story 4 tree/cache semantics
- normalizing the persisted engine/tree model into SDK-style `statecache` and `nodes` tables in this story
- migrating transfer orchestration to the new backend
- public query/index APIs
- sync/backup/mount work

This is a production-backend rollout story, not the Story 4 parity-fix story. Story 4C will validate and repair coherency behavior against the real backend after 4B lands.

---

## Story 1, 3, And 4 Constraints

Story 4B must preserve these existing decisions:

- persistence runtime lives at `src/session/runtime/persistence.rs`
- `Session` remains the engine root
- `Session` owns `PersistenceRuntime` at construction time
- `PersistedEngineState`, `PersistedTreeState`, `TransferPersistenceKey`, and `UploadState` remain the durable model contract from Story 3
- Story 4 restore/commit boundaries remain authoritative:
  - startup restore
  - successful `refresh()`
  - successful AP batch with durable tree/share changes
- no public API may be broken

If implementation pressure suggests changing the Story 3 trait shape or the Story 4 coherency contract, those stories must be revised explicitly first.

---

## Current-State Preservation Rules

These invariants are binding for Story 4B:

1. Backend rollout must not silently redesign the persistence contract.
   Story 4B adds a real backend under the existing `PersistenceRuntime` API. It must not turn this slice into a second SPI story.

2. Production backend ownership is constructor-time, not late mutation.
   The backend must be installed when an authenticated `Session` is constructed or loaded, not by later ambient mutation.

3. Unsupported/public/test contexts retain explicit non-production behavior.
   Public-link runtime, unsupported contexts, and tests may still use no-op or memory backends. Story 4B only changes authenticated-session production behavior.

4. Disk schema compatibility is explicit.
   Production storage must have a named backend schema version independent of payload schema versions.

5. On-disk corruption handling must be explicit.
   Backend-open failures, incompatible backend schema, and malformed stored payloads must not be conflated.

---

## SDK Alignment And Rust-Practice Decisions

### Decision 1. Use SQLite as the production backend technology

Why:

- upstream parity is clearly SQLite-backed through `SqliteDbAccess`
- Story 4B needs transactional on-disk durability, versioning, and corruption handling
- a small synchronous SQLite layer is a better fit than an ORM or async wrapper for this internal runtime boundary

Consequence:

- Story 4B should introduce a small internal SQLite-backed backend, preferably via a lightweight synchronous crate such as `rusqlite`
- Story 4B should avoid ORM layers and avoid adding a second async runtime abstraction
- the backend implementation should stay internal to `src/session/runtime/persistence.rs` or a tightly scoped sibling module

### Decision 2. Preserve the Story 3 model contract and store it as backend rows, not re-normalized tables yet

Why:

- Story 3 already fixed the durable model contract
- Story 4 already relies on that model for coherency behavior
- rewriting the model into SDK-style normalized `statecache`/`nodes` tables would mix backend rollout with a second data-model migration

Consequence:

- Story 4B should persist the existing durable shapes as SQLite rows
- a simple first production schema is sufficient:
  - metadata table for backend schema/version
  - engine-state table holding the serialized `PersistedEngineState`
  - upload-state table keyed by `TransferPersistenceKey`
- Story 4C may later tighten or restructure how those rows are used, but 4B should not widen into that work

### Decision 3. Use one backend DB file per authenticated persistence scope

Why:

- upstream uses account-scoped DB names derived from authenticated session/folder identity
- Story 3 already fixed the Rust scope identity as `PersistenceScope { account_handle }`
- account-scoped files keep isolation and cleanup simple

Consequence:

- Story 4B should create one DB file per authenticated account scope
- the filename should be derived from `PersistenceScope.account_handle`, using a filesystem-safe encoding if needed
- public-link and unauthenticated contexts should continue using `PersistenceRuntime::disabled()`

### Decision 4. Open SQLite connections on demand per operation in the first slice

Why:

- `PersistenceBackend` is `Send + Sync`, while a shared SQLite connection would require extra synchronization
- current persistence call frequency is low and already aligned with startup / refresh / AP batch boundaries
- opening on demand keeps the backend implementation small and avoids long-lived shared connection complexity in the first slice

Consequence:

- the production backend should own a root path and derive a per-scope DB path
- each persistence method may open a connection, ensure schema, run one transaction, and close it
- if performance later requires pooled or cached connections, that can be a follow-up optimization without changing the public contract

### Decision 5. Separate backend schema version from payload schema version

Why:

- `ENGINE_STATE_SCHEMA_VERSION` already version-controls the serialized engine payload
- SQLite table/layout versioning is a different concern from payload compatibility
- conflating both would make future backend migrations harder

Consequence:

- Story 4B should define a backend schema version constant separate from `ENGINE_STATE_SCHEMA_VERSION`
- opening a DB should verify backend schema first
- payload validation should still happen through the existing `PersistedEngineState::validate_schema_version()` path

### Decision 6. Handle unsupported backend schema by recycling the DB, not by silently disabling persistence

Why:

- upstream adjusts legacy DB versions and recycles incompatible DB files rather than pretending persistence never existed
- silently downgrading to disabled persistence would make durability disappear without an explicit signal
- hard-failing every startup on stale cache state is worse than dropping incompatible cache state and recreating it

Consequence:

- if the backend file exists but has an unsupported backend schema, Story 4B should move it aside or recreate it cleanly
- the new DB should start empty and valid
- this should be logged or surfaced internally, but it should not require public API changes

### Decision 7. Distinguish backend-open failures from malformed cached payloads

Why:

- a path/permission/SQLite-open failure means the backend itself is unavailable
- a malformed engine-state row means the backend is available but the cache contents are unusable
- Story 4 and Story 4C already rely on safe fallback behavior for malformed cached state

Consequence:

- backend-open and commit I/O failures should return an internal error and stop pretending the backend is healthy
- malformed or incompatible cached payload rows should be treated as empty/unusable persisted state, allowing Story 4 restore logic to fall back cleanly

### Decision 8. Prefer an OS-appropriate default storage root over hidden current-directory storage

Why:

- the SDK defaults to a caller-provided base path or current working directory, but Rust SDK users generally expect application-state files to live under an OS-appropriate state/config location
- hidden `cwd`-based state would be fragile in tests, examples, and server processes

Consequence:

- Story 4B should define an internal root-path helper using standard OS state directories
- no new public API is required if the internal default is stable and deterministic
- if implementation friction makes explicit override necessary, any new API must be additive and minimal

Recommended default root strategy:

- macOS: `~/Library/Application Support/megalib`
- Windows: `%LOCALAPPDATA%\\megalib`
- Unix: `$XDG_STATE_HOME/megalib` or `$HOME/.local/state/megalib`

This is intentionally more Rust-idiomatic than the SDK’s default `cwd` fallback while preserving the SDK’s constructor-time root-owned model.

---

## Proposed Backend Shape

Preferred internal shape:

```rust
// src/session/runtime/persistence.rs or a sibling internal module

pub(crate) struct SqlitePersistenceBackend {
    root: PathBuf,
}

impl SqlitePersistenceBackend {
    pub(crate) fn new(root: PathBuf) -> Self;
    fn db_path(&self, scope: &PersistenceScope) -> PathBuf;
    fn open_connection(&self, scope: &PersistenceScope) -> Result<Connection>;
    fn ensure_schema(&self, conn: &Connection) -> Result<()>;
}
```

The production backend should continue implementing the existing trait:

```rust
pub(crate) trait PersistenceBackend: Send + Sync {
    fn load_engine_state(&self, scope: &PersistenceScope) -> Result<Option<PersistedEngineState>>;
    fn save_engine_state(&self, scope: &PersistenceScope, state: &PersistedEngineState) -> Result<()>;
    fn clear_engine_state(&self, scope: &PersistenceScope) -> Result<()>;

    fn load_upload_state(&self, scope: &PersistenceScope, key: &TransferPersistenceKey) -> Result<Option<UploadState>>;
    fn save_upload_state(&self, scope: &PersistenceScope, key: &TransferPersistenceKey, state: &UploadState) -> Result<()>;
    fn clear_upload_state(&self, scope: &PersistenceScope, key: &TransferPersistenceKey) -> Result<()>;
}
```

Preferred first DB layout:

- `meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`
- `engine_state(slot INTEGER PRIMARY KEY CHECK(slot = 0), json TEXT NOT NULL)`
- `upload_state(kind TEXT NOT NULL, local_fingerprint TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY(kind, local_fingerprint))`

Notes:

- one DB file per scope means the scope itself does not need to be a row key
- JSON storage is acceptable in Story 4B because the durable model contract is already defined and tested
- `engine_state` may be a singleton row keyed by `slot = 0`

---

## Production Wiring Plan

Story 4B should install the backend at the same architectural points where upstream installs DB ownership:

1. authenticated login path
   - after user identity is known
   - before returning `Session`

2. saved-session load path
   - before `restore_tree_cache_state()` runs
   - so startup restore uses the real production backend

3. unsupported/public/test paths
   - remain on no-op or memory backends

Recommended Rust implementation direction:

- add an internal helper that builds the production `PersistenceRuntime` from a resolved root path once `user_handle` is known
- apply it in `login_internal(...)`, `login_with_session(...)`, and the session-load path
- keep `with_persistence_for_tests(...)` for tests

Story 4B should not force the actor to own backend construction. The backend remains `Session`-owned runtime state.

---

## Error Handling Rules

These rules are binding for Story 4B:

1. Backend-open failures are explicit errors.
   If the backend root cannot be created or the SQLite DB cannot be opened, Story 4B should return a structured internal error rather than silently pretending production persistence is active.

2. Unsupported backend schema triggers recycle/recreate.
   The old DB may be renamed aside or replaced, then a new empty DB should be initialized.

3. Malformed cached payloads are recoverable cache failures.
   Invalid engine/upload JSON rows should behave like missing cached state for restore purposes, not like a total backend-open failure.

4. Library code must continue following repository error-handling policy.
   No `unwrap()` in library code, no loss of structure to ad hoc stringly public errors, and no public leakage of backend-specific error types unless a later story explicitly introduces a public error surface.

---

## Verification Plan

Story 4B is not complete until all of these are covered with real on-disk tests:

- create a new backend in an empty temp directory
- save engine state, reopen process/runtime, and load it again
- save upload state, reopen, and load it again
- keep two account scopes isolated in separate DB files
- detect unsupported backend schema and recycle/recreate cleanly
- treat malformed stored engine/upload rows as recoverable cache misses
- preserve no-op behavior for unsupported/public/test contexts

If Rust source changes, Story 4B must end with:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

---

## Agent-Sized Tasks

### Task 4B.1. Add SQLite production backend

Deliver:

- internal SQLite backend implementation behind `PersistenceBackend`
- backend schema constants and schema-init helpers
- per-scope DB-path resolution

Suggested file ownership:

- `src/session/runtime/persistence.rs`
- new sibling internal storage/backend module if needed

### Task 4B.2. Wire authenticated sessions to the production backend

Deliver:

- constructor-time installation of the production backend for authenticated sessions
- shared internal root-path resolution helper
- preserved no-op behavior for unsupported/public contexts

Suggested file ownership:

- `src/session/core.rs`
- `src/session/auth.rs`

### Task 4B.3. Add backend lifecycle and schema handling

Deliver:

- create/open/recycle logic
- backend schema validation
- malformed-row fallback behavior

Suggested file ownership:

- `src/session/runtime/persistence.rs`

### Task 4B.4. Add real-disk verification coverage

Deliver:

- temp-directory integration-style tests for create/reopen/isolation/schema/corruption behavior

Suggested file ownership:

- `src/session/runtime/persistence.rs`
- narrowly scoped backend tests module if split out

---

## Acceptance Criteria

Story 4B is complete when:

- authenticated sessions install a real on-disk `PersistenceRuntime` backend without test-only injection
- backend storage root and per-scope DB-path behavior are explicit and deterministic
- production storage has a distinct backend schema version and initialization path
- no-op and memory backends remain available for unsupported/public/test contexts
- real-disk tests prove create, reopen, isolation, and schema/corruption handling
- Story 4 logic can now be exercised against a real backend without changing the Story 3 SPI

Story 4B does not, by itself, certify full production-backed tree/cache parity. That is the job of Story 4C.

---

## How Later Stories Consume This Story

- Story 4C assumes a real production backend exists and uses it to revalidate startup restore, refresh commits, and AP commits under real disk behavior
- Story 5 assumes transfer-runtime work can move from sidecar-only semantics onto a real persistence backend
- Story 8 assumes durable query/index hooks can target a real storage root rather than a test-only seam
- Story 12 can start running parity scenarios against real restart behavior instead of only in-memory fakes
