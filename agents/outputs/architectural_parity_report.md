# megalib Architectural Parity Report: C++ SDK vs Rust Port

Validated on 2026-03-12 against the Rust graph `project` and the upstream C++ graph `sdk`.

This report complements `agents/outputs/parity_report.md`. The parity report is about user-visible capability; this report is about runtime shape and the architectural foundations required for durable parity.

Graph size signal:

- Rust graph (`project`): 1083 units
- C++ graph (`sdk`): 12829 units

That is not a feature count, but it does match the architecture gap: the Rust port already covers the core cloud-drive path, while the C++ SDK still carries many more runtime layers and background subsystems.

---

## Evidence Anchors

### Rust port

- Public async facade and actor boundary: `src/session/actor.rs:91`, `src/session/actor.rs:2026`
- Session state owner: `src/session/core.rs:26`
- SC polling lane: `src/session/sc_poller.rs:57`
- Direct API client and batch helper: `src/api/client.rs:25`, `src/api/client.rs:475`
- Transfer progress surface: `src/progress.rs:21`, `src/session/actor.rs:1950`
- Upload resume sidecar: `src/fs/upload_state.rs:19`
- Cached-tree browsing helpers: `src/fs/operations/browse.rs:32`
- Internal-only user alert accumulation and AP no-op for account-update parity: `src/session/actor.rs:2650`, `src/session/action_packets.rs:250`

### Upstream C++ SDK

- `MegaApiImpl` listener APIs and queue fields: `../sdk/include/megaapi_impl.h:3699`, `../sdk/include/megaapi_impl.h:4839`
- Request dispatch runtime: `../sdk/src/request.cpp:394`
- Transfer slot engine and Cloud RAID hooks: `../sdk/src/transferslot.cpp:106`, `../sdk/src/transferslot.cpp:1556`, `../sdk/src/transferslot.cpp:1726`
- DB/search interfaces: `../sdk/include/mega/db.h:79`, `../sdk/include/mega/db.h:140`
- Sync request queueing: `../sdk/src/megaapi_impl_sync.cpp:75`
- FUSE mount and mount DB: `../sdk/src/fuse/supported/common/mount.cpp:1`, `../sdk/src/fuse/supported/common/mount_db.cpp:130`

---

## Executive Summary

- `megalib` already has a coherent runtime for the core cloud-drive path: `SessionHandle` drives a single `SessionActor`, `Session` owns in-memory auth and node state, `ScPoller` handles long-poll SC work, and upload/download flows support parallel workers plus cancellation/progress callbacks.
- The C++ SDK is materially broader. `MegaApiImpl` owns request, SC, and transfer queues; `RequestDispatcher` batches and retries idempotent command batches; `TransferSlot` adapts connections and handles Cloud RAID; `MegaDbAccess` and `DBTableNodes` back durable node/search state; sync and FUSE sit on top of filesystem abstractions and mount databases.
- The main parity blocker is not a few missing endpoints. It is the absence in Rust of:
  - durable SDK-local state
  - first-class request orchestration
  - transfer-slot-style scheduling/runtime policy
  - filesystem/watch abstractions
  - public event/listener surfaces
- Some Rust pieces are already good foundations and should be preserved: the single-owner actor model, SC/AP catch-up separation, SDK-compatible session blobs, resumable transfer mechanics, and `^!keys` persistence. They are useful building blocks, but they are not yet substitutes for the broader C++ runtime layers.

---

## Rust Architecture As It Exists Today

### Control plane

`SessionHandle` is the public API boundary. It forwards commands over a channel to a single `SessionActor`, which spawns and coordinates the background runtime in `src/session/actor.rs`.

This gives Rust a clear ownership model:

- one command lane
- one state owner
- one SC poller lane feeding events back into the actor

That is a strong fit for Rust, and it already avoids a lot of shared-state complexity.

### State owner

`Session` is the real state container. It keeps:

- auth state and keys
- cached nodes in `Vec<Node>`
- contact/share maps
- SC sequence state and current-state flags
- cached user alerts
- transfer knobs such as worker count and progress callback

Important nuance: most of this is in-memory state. The crate does not yet have a durable node/search/cache database comparable to the C++ SDK.

### Request path

Requests are mostly issued directly through `ApiClient::request` and `ApiClient::request_batch`. The actor provides serialization and seqtag waiter logic, but there is no separate internal subsystem equivalent to `RequestDispatcher` plus `requestQueue` and `scRequestQueue`.

That means Rust already has:

- ordered command handling through the actor
- direct batch submission helpers
- SC state synchronization between actor and poller

But Rust does not yet have:

- centralized request batching policy
- batch-separate rules
- retained inflight batch state for idempotent retry
- a request queue that is a first-class architectural layer

### SC and action packets

This is one of the stronger areas in the port.

`ScPoller` is a dedicated worker that receives state updates, long-polls the SC lane, polls SC50 user alerts, and sends batches back into the actor. `Session` also tracks `current_seqtag`, `state_current`, and `action_packets_current`, and the actor maintains seqtag waiters.

Architecturally, this is real progress toward SDK-style current-state behavior. The gap is breadth, not absence.

### Transfer path

Transfers live in the upload/download operation modules rather than in a separate scheduler subsystem. The Rust crate already supports:

- configurable worker count
- parallel chunk upload/download
- resumable uploads via `UploadState`
- transfer progress/cancel callbacks via `ProgressCallback`

This is good functionality, but it is still much thinner than the C++ transfer runtime because policy and execution are still embedded inside the operations rather than isolated in queue/slot/runtime objects.

### Persistence

Rust has real persistence in a few narrow areas:

- session blobs and folder-session blobs
- resumable upload sidecar state files
- `^!keys` persistence, including an opaque backups blob

That is useful parity groundwork, but it is not a durable SDK-local data layer. There is still no equivalent to C++ node cache tables, transfer DB state, or indexed search storage.

### Public observability

The only clear public runtime callback surface today is transfer progress (`TransferProgress` and `ProgressCallback` plus `SessionHandle::watch_status`).

Internally the actor accumulates SC50 user alerts, but there is no public alert/listener API, and some action-packet parity hooks are explicitly left as no-ops in `src/session/action_packets.rs`.

---

## C++ Architecture That Rust Is Still Missing

### 1. Request orchestration as a subsystem

The C++ SDK does not treat API calls as only direct method invocations. `MegaApiImpl` owns `requestQueue`, `scRequestQueue`, and `transferQueue`, while `RequestDispatcher` is responsible for:

- batching commands
- separating commands that must not share a batch
- tracking inflight request JSON and idempotence state
- retrying failed inflight batches
- continuing chunked response processing

This is a deeper runtime contract than Rust's current actor plus direct `ApiClient` calls.

### 2. Durable local state and indexed node access

The C++ SDK has a real database abstraction layer:

- `MegaDbAccess` inherits `SqliteDbAccess`
- `DbTable` and `DBTableNodes` define transactional storage
- `DBTableNodes` includes `getChildren`, `searchNodes`, and `createIndexes`

That matters because the upstream SDK architecture assumes:

- durable node/cache state
- restart continuity
- indexed queries
- storage-backed search and paging

Rust currently offers cached traversal helpers over an in-memory node list. That is useful, but it is not the same architectural layer.

### 3. Transfer-slot runtime

`TransferSlot` is not just a worker. It manages:

- dynamic connection counts
- request sizing
- retry/backoff behavior
- temporary URL handling
- progress delivery to the app
- Cloud RAID initialization and recovery

Rust has working transfer mechanics, but it does not yet separate transfer policy into equivalent runtime objects.

### 4. Filesystem integration

The upstream SDK has broad filesystem and desktop-service architecture:

- sync entrypoints queue request work through `MegaApiImpl`
- FUSE mount code has its own mount DB and file-cache related logic
- the broader SDK contains filesystem abstractions used by sync and mount code

Rust currently performs direct file operations inside upload/download helpers. There is no standalone filesystem/watch layer that sync, backup, or FUSE could be built on.

### 5. Listener ecosystems

`MegaApiImpl` exposes add/remove methods for:

- `MegaListener`
- `MegaRequestListener`
- `MegaTransferListener`
- `MegaScheduledCopyListener`
- `MegaGlobalListener`

The concrete listener interfaces in `megaapi.cpp` cover request, transfer, node, alert, backup, mount, and global events. Rust does not yet expose a comparable public observability surface.

---

## Layer-By-Layer Architectural Parity

| Layer | C++ SDK | Rust port | Assessment |
|------|---------|-----------|------------|
| Public facade | `MegaApiImpl` fronts a queue/listener-heavy runtime | `SessionHandle` fronts an async actor runtime | Partial. Rust has a clean facade, but the contract behind it is much smaller. |
| Core state owner | `MegaClient` and related managers own nodes, transfers, sync state, alerts, DB/search integration | `Session` owns keys, cached nodes, shares, SC state, alerts, transfer knobs | Partial. Rust has the right ownership shape for current scope, but not the same subsystem breadth. |
| Request execution | `requestQueue`, `scRequestQueue`, `RequestDispatcher`, waiter notification | Actor serialization, direct `ApiClient::request` and `request_batch`, seqtag waiters | Weak-to-partial. The actor gives ordering, but not equivalent dispatcher behavior. |
| SC/AP processing | Integrated current-state runtime plus SC request queue | Dedicated `ScPoller` plus actor-side state tracking and seqtag waiters | Good but thinner. This is one of Rust's better architectural areas. |
| Transfer engine | `transferQueue`, `TransferSlot`, adaptive connections, Cloud RAID, durable transfer state | Upload/download ops with worker parallelism, resumable upload sidecars, progress callbacks | Partial. Good mechanics exist, but not the full runtime model. |
| Durable state / search | SQLite-backed DB abstractions, node tables, indexed children/search queries | In-memory `Vec<Node>` plus session blobs and upload sidecars | Weak. This is the most important architectural gap. |
| Filesystem / desktop integration | Sync, FUSE, mount DB, file cache, filesystem abstractions | Direct local file I/O only | Missing. A major prerequisite layer is absent. |
| Public event surface | Multiple listener families and many event categories | Transfer progress callback only; alerts remain internal | Weak. Good enough for simple embedding, not for SDK-style app integration. |
| Large background services | Sync, scheduled backup, FUSE / virtual drive | Missing; only an opaque backups blob exists in `^!keys` | Missing. Metadata exists, runtime does not. |

---

## Strong Foundations Already Present In Rust

### 1. Single-owner actor model

`SessionHandle` to `SessionActor` to `Session` is a defensible Rust-native runtime shape. It should remain the control boundary even if more internal queues are introduced later.

### 2. SC worker split and current-state tracking

The dedicated `ScPoller` plus actor-side seqtag/current-state handling is already meaningful architecture, not just a temporary workaround.

### 3. SDK-compatible blob handling

Session blobs and folder-session blobs are the right kind of compatibility investment. They allow session interchange and preserve alignment with upstream session semantics without forcing a full port of the C++ persistence stack up front.

### 4. Resumable transfer groundwork

`UploadState` sidecars and worker-based chunking are useful primitives. They are not enough for full transfer-engine parity, but they are a reasonable base for a future scheduler layer.

### 5. `^!keys` domain parity work

`Session` and `KeyManager` already carry authring, manual-verification, warnings, and backups data. That is useful parity work, but it should not be confused with sync or scheduled-backup runtime parity.

---

## Main Architectural Gaps To Solve First

1. Add a durable local data layer for nodes, transfer state, alerts, and query/index support.
2. Introduce a first-class internal request scheduling layer around actor to API submission.
3. Separate transfer scheduling policy from upload/download operation code.
4. Expose a public event model for request, transfer, node, and alert state.
5. Add a filesystem abstraction and watcher layer before any sync or FUSE work.

If these layers are skipped, later ports will either stall or hard-code new subsystems onto the current thin runtime.

---

## Recommended Port Sequencing

### Architecture-first sequence

1. Persistent node, transfer, and alert store
2. Internal request queue and dispatcher layer
3. Transfer runtime hardening and durable queueing
4. Public event surface
5. Filesystem abstraction and watcher interfaces
6. Search and indexed query APIs
7. Sync, scheduled backup, and FUSE

### Mixed product plus architecture sequence

1. Public event surface
2. 2FA APIs
3. Contact-request APIs
4. Cached-tree search APIs
5. Durable local store
6. Transfer runtime hardening
7. Filesystem abstraction
8. Sync, scheduled backup, and FUSE

The mixed path can ship user-visible features sooner, but it still needs to converge back to persistence and runtime hardening before the large desktop subsystems.

---

## Small-Slice Backlog

1. Introduce an internal request-submission abstraction so actor commands stop calling `ApiClient` directly.
2. Define a persistence trait for cached nodes and transfer state, even if the first backend is intentionally minimal.
3. Split transfer scheduling policy out of `upload.rs` and `download.rs`.
4. Expose a read-only Rust event stream for transfer, request, node, and alert changes before cloning the full C++ listener taxonomy.
5. Add a search/query interface over cached nodes with an implementation that can later switch from in-memory traversal to indexed storage.
6. Add a filesystem abstraction trait layer before any sync-specific code.
7. Clarify in docs that `set_backups_blob` is metadata persistence, not scheduled-backup support.

---

## Recommendation

The cleanest path to real architectural parity is still:

1. keep the Rust actor model
2. add the missing internal layers under it
3. only then port the large desktop subsystems

That approach preserves the strengths of the current Rust design while still converging on the parts of the C++ SDK that actually matter for long-lived, desktop-grade behavior.

This report is intentionally architecture-focused. It is grounded in the current Rust and C++ code graphs and does not try to enumerate every upstream endpoint.
