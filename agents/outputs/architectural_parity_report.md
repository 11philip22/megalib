# megalib Architectural Parity Report: C++ SDK vs Rust Port

Validated on 2026-03-25 against the Rust graph `project`, the upstream C++ graph `sdk`, the current `megalib` tree, and the sibling upstream SDK at `../sdk`.

This report complements `agents/outputs/parity_report.md`. The parity report is about user-visible capability. This report is about runtime shape, subsystem boundaries, and the internal layers required for durable parity.

Directional graph-size signal:

- Rust graph (`project`): 1083 units
- C++ graph (`sdk`): 12829 units

That is not a feature count. It is, however, consistent with the architecture gap: `megalib` already covers the core cloud-drive path, while the upstream SDK still contains many more runtime layers, persistence boundaries, background services, and desktop-facing subsystems.

---

## Refresh Delta For This Validation

Compared with the older architecture framing, this validation makes four things more explicit:

- the upstream comparison must center `MegaClient`, not only `MegaApiImpl`
- `NodeManager + DB + SCSN` is one coherency target, not three unrelated details
- some Rust layers are already architecturally meaningful but still thin, while others are structurally absent
- this report is hand-maintained and should name its concrete evidence inputs and evidence limits

---

## Scope And Method

This report is intentionally architecture-first:

- It compares runtime layers, not just endpoint coverage.
- It treats the upstream C++ design as `MegaApiImpl` plus `MegaClient` plus the persistence, transfer, filesystem, sync, and event subsystems under them.
- It treats the current Rust design as what is actually in the crate today, not what could be built on top of the actor later.

The most important consequence is this:

- comparing Rust only against `MegaApiImpl` is too shallow
- comparing Rust only against public API method lists is also too shallow

The real parity question is whether Rust already has equivalents for:

1. request ingress and orchestration
2. current-state and SC/AP coherency
3. persistent node and transfer state
4. transfer scheduling policy
5. filesystem/watch abstractions
6. public callback and event delivery
7. desktop subsystems such as sync and mount

---

## Report Inputs And Known Evidence Limits

This report was refreshed from these concrete inputs:

- Rust code graph artifact: `agents/project.acb`
- Upstream C++ graph artifact: `agents/sdk.acb`
- live Rust tree in this repository under `src/`
- sibling upstream SDK tree at `../sdk`
- companion capability report at `agents/outputs/parity_report.md`

Known limits for this report:

- it appears to be hand-maintained rather than generated from a repeatable report script
- `AGENTS.md` points to `agents/outputs/pol_discover/`, but that directory is not present in this workspace today
- some conclusions are therefore analyst synthesis over code and graph evidence rather than output from a dedicated discovery bundle

---

## Evidence Anchors

### Rust port

- Crate/module topology: `src/lib.rs:89`, `src/session/mod.rs:1`, `src/fs/mod.rs:1`
- Public async facade and actor boundary: `src/session/actor.rs:91`
- Session state owner and SDK-style current-state flags: `src/session/core.rs:26`, `src/session/core.rs:69`, `src/session/core.rs:83`, `src/session/core.rs:92`
- Tree bootstrap, share-key ingestion, deferred-node drain, and state-current recompute: `src/fs/operations/tree.rs:34`, `src/fs/operations/tree.rs:57`, `src/fs/operations/tree.rs:106`, `src/fs/operations/tree.rs:169`, `src/fs/operations/tree.rs:178`
- Cached browsing helpers over in-memory nodes: `src/fs/operations/browse.rs:32`, `src/fs/operations/browse.rs:125`
- SC polling lane and SC50 alert catch-up: `src/session/sc_poller.rs:15`, `src/session/sc_poller.rs:57`, `src/session/sc_poller.rs:185`, `src/session/sc_poller.rs:226`
- Direct request and batch transport: `src/api/client.rs:85`, `src/api/client.rs:475`
- Share-key and `^!keys` lifecycle: `src/session/key_sync.rs:1`, `src/session/key_sync.rs:121`, `src/session/key_sync.rs:193`, `src/session/sharing.rs:37`
- Transfer resume sidecar and operation-local transfer logic: `src/fs/upload_state.rs:19`, `src/fs/operations/upload.rs:901`, `src/fs/operations/download.rs:120`, `src/fs/operations/download.rs:168`
- Public-folder runtime outside the session actor: `src/public.rs:456`, `src/public.rs:492`, `src/public.rs:515`
- Public event surface and current no-op upgrade hook: `src/session/core.rs:518`, `src/session/action_packets.rs:246`

### Upstream C++ SDK

- `MegaApiImpl` queue ownership: `../sdk/include/megaapi_impl.h:4839`
- `MegaApiImpl` runtime pump: `../sdk/src/megaapi_impl.cpp:8008`
- Request batching and inflight retry semantics: `../sdk/src/request.cpp:394`
- `MegaClient` state, DB tables, `NodeManager`, and `cachedscsn`: `../sdk/include/mega/megaclient.h:2016`, `../sdk/include/mega/megaclient.h:2020`, `../sdk/include/mega/megaclient.h:2033`, `../sdk/include/mega/megaclient.h:2058`
- `NodeManager` persistence/coherency contract: `../sdk/include/mega/nodemanager.h:272`
- DB-backed node query/search interfaces: `../sdk/include/mega/db.h:140`, `../sdk/include/mega/db.h:158`, `../sdk/include/mega/db.h:220`
- Transfer slot runtime and adaptive connection sizing: `../sdk/src/transferslot.cpp:106`, `../sdk/src/transferslot.cpp:169`, `../sdk/src/transferslot.cpp:191`
- Sync request queueing entrypoint: `../sdk/src/megaapi_impl_sync.cpp:75`
- Mount DB enable/check path: `../sdk/src/fuse/supported/common/mount_db.cpp:98`, `../sdk/src/fuse/supported/common/mount_db.cpp:144`
- Mount runtime object: `../sdk/src/fuse/supported/common/mount.cpp:70`
- Higher-level event observer and cancellable callback layers: `../sdk/include/mega/common/client.h:34`, `../sdk/include/mega/common/pending_callbacks.h:69`

---

## Executive Summary

- `megalib` already has a coherent Rust-native runtime for the core cloud-drive path. `SessionHandle` fronts a single actor, `Session` owns state, `ScPoller` handles the SC lane, and uploads/downloads already support parallel work plus cancellation/progress callbacks.
- The upstream SDK is materially broader and more layered. `MegaApiImpl` is only the threaded adapter. `MegaClient` is the architectural center of gravity, and it is backed by `NodeManager`, DB tables, request dispatchers, transfer slots, filesystem abstractions, sync state, and multiple callback/event layers.
- The main parity blocker is still architectural, not just endpoint count. Rust does not yet have first-class equivalents for:
  - persistent node/cache/query state
  - request orchestration as a subsystem
  - transfer-slot-style scheduling and persistence
  - filesystem/watch abstractions
  - public multi-family event delivery
  - desktop subsystems such as sync and mount
- Some current Rust foundations are worth preserving:
  - single-owner actor control plane
  - explicit SC poller split
  - SDK-aware current-state tracking
  - meaningful `^!keys` and share-key lifecycle work
  - resumable transfer sidecars
  - separate public-folder runtime

The clean parity path is still:

1. keep the Rust actor model
2. add the missing internal layers under it
3. port large desktop subsystems only after those layers exist

---

## Architecture Map At A Glance

| Layer | Upstream C++ center | Rust center today | Assessment |
|------|----------------------|-------------------|------------|
| Public facade | `MegaApiImpl` plus listener APIs and cross-thread queues | `SessionHandle` and actor commands | Partial. Rust has a clean facade, but it fronts a much thinner runtime. |
| Core engine | `MegaClient` | `Session` | Partial. Rust has a real state owner, but not the same subsystem breadth. |
| Node/tree runtime | `NodeManager` plus DB tables and cache restore | in-memory `Vec<Node>` plus bootstrap/apply logic in `tree.rs` | Weak-to-partial. Rust has useful mechanics, not the same storage and coherency model. |
| Request orchestration | `RequestDispatcher` plus request/sc queues | actor serialization plus direct `ApiClient::request` calls | Weak. Ordering exists, but queueing/idempotent retry policy is not a first-class layer. |
| SC/AP coherency | `MegaClient` current-state runtime and `cachedscsn` persistence | `ScPoller`, seqtag waiters, `state_current`, `action_packets_current` | Good but thinner. One of Rust's stronger areas. |
| Transfer engine | `TransferQueue` plus `TransferSlot` plus transfer cache | upload/download modules plus `UploadState` | Partial. Good mechanics exist, but not the upstream runtime model. |
| Share-key/key state | authrings and key flows inside client/session architecture | `key_sync.rs`, `sharing.rs`, `KeyManager` | Partial and improving. Stronger than the old report made explicit. |
| Public folder path | integrated public-link support plus broader runtime | standalone `public.rs` subsystem | Partial. Real functionality exists, but it is intentionally separate from the actor. |
| Durable state/querying | SQLite-backed node/search/state/transfer tables | session blobs, `^!keys`, upload sidecars only | Weak. This remains the most important gap. |
| Filesystem/watch layer | `FileSystemAccess`, `DirNotify`, scan services, mount DB | direct local file I/O only | Missing. Major prerequisite layer absent. |
| Public events/callbacks | `MegaApp`, listener families, observer/callback helpers | transfer progress callback only | Weak. Internal alert accumulation exists, public event delivery does not. |
| Desktop services | sync, scheduled backup, FUSE/mount | missing | Missing. Large subsystem gap. |

---

## Parity Dimensions To Track Explicitly

The architecture map above is the compact view. For future refreshes, these are the dimension families that should stay explicit so the report does not collapse back into a generic “features missing” narrative.

The epic and the gap ledger may split one family into multiple audit rows when the SDK has distinct runtime seams that deserve separate ownership and closure states. That is expected for cases such as persistence SPI versus production backend rollout, or public adapter depth versus public event delivery.

| Dimension | Upstream reference shape | Rust reference shape today | Why this dimension matters |
|-----------|--------------------------|----------------------------|----------------------------|
| Core runtime ownership | `MegaClient` breadth under `MegaApiImpl` | `Session` under `SessionHandle` and the actor | This is the real engine boundary, not just the public facade. |
| Public-folder runtime separation | folder-link login/cache/auth state via `folderaccess`, `loggedIntoFolder`, folder-session restore, and folder-auth URI shaping | `open_folder()` runtime in `src/public.rs`, separate from the authenticated actor/session runtime | SDK parity cannot assume a single authenticated runtime shape; folder-link access is a real second runtime path upstream and in Rust. |
| Tree coherency | `NodeManager + DBTableNodes + cachedscsn + statecache` | in-memory nodes plus bootstrap/apply logic | Durable tree parity depends on treating cache, DB, and SC/AP coherency as one target. |
| SC/AP lifecycle | fetchnodes, catch-up, current-state transitions, persisted SCSN | `ScPoller`, seqtag waiters, `state_current`, `action_packets_current` | This is one of Rust's stronger areas and should not be understated. |
| Transfer engine depth | `TransferQueue`, `TransferSlot`, async I/O, CloudRAID, transfer cache | upload/download operation logic plus `UploadState` | Working transfers are not the same as upstream transfer-runtime parity. |
| Filesystem abstraction | `FileSystemAccess`, notifications, local path semantics | direct local file I/O only | This is a prerequisite layer for sync, better transfer fidelity, and mount. |
| Sync subsystem | sync config, backup modes, scan strategy, persisted sync state | missing | Sync is a first-class engine upstream, not an add-on. |
| Desktop services | file service, mount/FUSE, mount DBs | missing | These widen the architectural target beyond cloud-drive primitives. |
| Media and side pipelines | gfx/preview/metadata extraction workers and options | missing | Upstream runtime breadth includes non-core pipelines with their own runtime constraints. |
| Platform layering | feature-gated `src/{posix,osx,win32,android}` plus build options | largely absent in crate structure today | Platform surface affects what “architectural parity” should mean in scope discussions. |
| Public adapter depth | `MegaApiImpl`, listeners, newer observer/callback layers, bindings-facing surface | compact async facade plus progress callback | Public parity is partly about transport and callback/runtime staging, not only method names. |

---

## Rust Architecture As It Exists Today

### 1. Public surface and control boundary

The crate surface is still compact: `src/lib.rs` re-exports the main public modules, and `SessionHandle` is the core authenticated facade.

Architecturally, the key boundary is:

- `SessionHandle` receives public async calls
- actor commands serialize those calls
- a single `SessionActor` owns the mutable runtime
- `Session` remains the true state container

That is a strong Rust-native ownership model. It should be preserved.

The report should also make explicit that not all public functionality enters through the actor. `open_folder()` in `src/public.rs` is its own unauthenticated runtime for public folders. That matters because parity work cannot assume there is exactly one runtime shape in the crate.

### 2. Session state is richer than a token holder

`Session` is not just auth state. It owns:

- session and key material
- cached nodes
- pending undecryptable nodes
- outgoing and pending shares
- contacts
- `KeyManager` and `^!keys` state
- SC sequence, current-state, and alert fields
- transfer knobs and progress callback state

This is important because the Rust crate already moved beyond a stateless request wrapper. The current report was right about that, but it underplayed how much of the SDK-style state vocabulary already exists in `src/session/core.rs`.

### 3. Tree bootstrap is a real subsystem, not just `fetch_nodes()`

The bootstrap/runtime path in `src/fs/operations/tree.rs` is more substantial than the old report made obvious. `refresh()` currently does all of the following:

- initializes keys before fetch
- issues the `f` command
- resets and seeds SC/AP state
- parses share keys from `ok`
- ingests outgoing shares
- parses public links
- preloads own-folder share keys
- stashes deferred nodes until keys are available
- builds node paths
- stores the new cached tree
- drains deferred nodes
- recomputes `state_current` / `action_packets_current`

That is meaningful architecture. It is still in-memory and still thinner than upstream, but it is not a trivial helper.

### 4. Cached browsing is intentionally tree-local

The browsing model in `src/fs/operations/browse.rs` is a direct expression of the current architecture:

- lookups happen over `self.nodes`
- traversal is cached-tree based
- path queries are compatibility helpers layered over the cached tree

This is exactly why parity is only partial:

- the tree exists
- the ergonomics are decent
- but there is no DB-backed query layer, paging layer, or search/index subsystem behind it

### 5. Request path is still transport-first

`ApiClient::request()` and `request_batch()` are the operative request layer today. The actor provides serialization and seqtag waiter plumbing, but the actual API submission model is still mostly:

- command arrives at actor
- actor or helper calls `ApiClient`
- local helper code interprets the response

That is enough for functionality, but it is not the same as the upstream staged pipeline:

- public API ingress
- retained request queue
- batch shaping
- inflight idempotent retry
- client-loop execution

The missing architecture is not just “more batching.” It is the lack of a first-class request-orchestration subsystem.

### 6. SC/AP handling is one of the better parity areas

Rust already has a dedicated `ScPoller` with its own control/event channel. Combined with `Session` fields such as `scsn`, `state_current`, `action_packets_current`, `current_seqtag`, and `alerts_catchup_pending`, this is real architecture rather than a temporary workaround.

The important nuance is:

- current-state tracking exists
- seqtag/high-watermark coordination exists
- user alerts are fetched and accumulated internally

What is missing is breadth and persistence:

- no durable SC/AP backing store
- no public alert/event API
- some upgrade/account-update parity hooks still no-op

### 7. `^!keys` and share-key lifecycle work is now substantial

The old report mentioned `^!keys` as groundwork, but the current tree shows it has become a genuine subsystem:

- `key_sync.rs` handles pending promotions and contact-key fetches
- `sharing.rs` persists local share-key state around sharing flows
- `KeyManager` is treated as the session's single source of truth for authrings, warnings, backups, and share-key state

This does not close the larger persistence gap, but it does mean the Rust port already mirrors a non-trivial part of the upstream session/key architecture.

### 8. Transfers work, but policy is embedded in operations

Rust already supports:

- resumable uploads through `UploadState`
- sequential and parallel download paths
- configurable worker counts
- transfer progress callbacks
- cancellation via callback return value

The architectural limitation is where this logic lives:

- upload behavior remains centered in `upload.rs`
- download behavior remains centered in `download.rs`
- resume state is a sidecar file, not part of a transfer-runtime/persistence layer

So the crate has good mechanics, but not yet a transfer engine in the upstream sense.

### 9. Public observability remains intentionally narrow

The public event surface is still basically transfer progress:

- `watch_status()` installs a single progress callback
- internal user alerts are accumulated, but not exposed as a public API
- `handle_actionpacket_upgrade()` still explicitly no-ops on SDK account-update/user-alert behavior

This is an architectural gap, not just a missing convenience method. The upstream SDK has multiple listener families and newer callback/observer layers. Rust does not yet expose an equivalent public event model.

---

## Upstream C++ Architecture That Matters For Parity

### 1. `MegaApiImpl` is the threaded adapter, not the whole architecture

The upstream runtime is often described as “the MegaApiImpl design,” but that is only partly true.

`MegaApiImpl` matters because it owns:

- public API ingress
- request, SC, and transfer queues
- listener sets
- the main threaded runtime loop

Its `loop()` function makes the staging explicit:

1. wait and collect work
2. send pending transfers
3. send pending requests
4. send pending SC requests
5. run `client->exec()`

This is much more structured than direct per-call transport usage.

### 2. `MegaClient` is the architectural center of gravity

The bigger upstream fact is that `MegaClient` owns the core engine state:

- DB tables
- `NodeManager`
- cached `scsn`
- fetchnodes/current-state fields
- request dispatchers
- transfer state
- sync state
- auth/key flows

That is why comparing Rust only against `MegaApiImpl` understates the gap. The real missing parity is against the layers sitting behind the adapter.

### 3. `NodeManager + DB + SCSN` is one coherency subsystem

This is one of the most important upstream architectural facts.

`NodeManager` is not just a container. Its own docs state that:

- nodes can be loaded from the `nodes` DB table on demand
- `statecache` and `nodes` live in the same DB domain
- commits are driven by action-packet sequence numbers (`scsn`)

That means the upstream SDK assumes:

- durable node state
- lazy materialization
- shared transaction boundaries between cache and state
- SC/AP-driven persistence coherency

Rust does not have an equivalent subsystem yet.

### 4. Request dispatch is a core contract

`RequestDispatcher` is more than a batching helper. It:

- splits commands across requests
- isolates batch-separate commands
- retains inflight request JSON
- supports exact retry of failed inflight work
- tracks whether commands are still logically inflight
- handles chunked response processing

Rust currently has transport helpers and actor ordering, but not this retained request contract.

### 5. Transfer architecture is scheduler/slot/cache based

Upstream transfers are not “HTTP helpers plus callbacks.” They are built around:

- `TransferQueue`
- `TransferSlot`
- connection-count policy
- request sizing policy
- temp URL handling
- persistent transfer state
- resume and failure handling
- RAID initialization and recovery

That is why transfer parity remains only partial even though uploads and downloads already work in Rust.

### 6. Filesystem and sync are foundational, not optional helpers

The upstream filesystem layer includes:

- `FileSystemAccess`
- notification/watch abstractions
- filesystem identity/fingerprint handling
- async file I/O support
- scan services

Sync then builds on top of that as its own engine, with its own state model and threading constraints. FUSE/mount code adds another layer on top, backed by mount databases and file-cache/inode state.

Rust currently has none of those foundational layers, which is why sync and mount parity are still far away.

### 7. Upstream event delivery exists at more than one layer

The classic listener families are only part of the story. Upstream also contains:

- `MegaApp` style callbacks
- cancellable callback wrappers with `API_EINCOMPLETE` semantics
- higher-level observer/event queue paths used by newer common/FUSE-facing code

So “listener parity” is not just about cloning event names. It is about staged delivery, cancellation semantics, and thread-safe event transport.

---

## The Architectural Gaps That Matter Most

Before looking at each gap in detail, it helps to separate layers that already exist in thinner form from layers that are still structurally absent:

| Gap family | Rust status today | Why it belongs in this bucket |
|------------|-------------------|-------------------------------|
| Request orchestration | Present but thin | The actor gives ordering, but there is no retained request-runtime/scheduler layer. |
| Transfer engine | Present but thin | Upload/download mechanics exist, but slot policy, queue ownership, and transfer persistence do not. |
| Public event delivery | Present but thin | Internal alert accumulation and transfer progress exist, but there is no broad public event subsystem. |
| Tree runtime and querying | Present but thin | Cached nodes and browse helpers exist, but not durable/indexed node state. |
| Durable local state | Structurally missing | There is no `NodeManager + DB + SCSN` equivalent yet. |
| Filesystem/watch abstraction | Structurally missing | No `FileSystemAccess` or watcher layer exists under the runtime. |
| Sync/backup/mount | Structurally missing | These desktop subsystems are absent and remain blocked on lower layers. |
| File-service/media/platform layers | Structurally missing | The Rust crate does not yet mirror these broader upstream runtime slices. |

### 1. Durable local state and query/index support

This is still the biggest gap.

Rust has:

- session blobs
- folder-session blobs
- `^!keys` persistence
- upload resume sidecars

Rust does not have:

- durable node cache
- persistent alert state
- transfer DB state
- indexed search/query support
- SC/AP-backed persistence transactions

Without this layer, later parity work either stalls or gets hard-coded onto in-memory state.

### 2. First-class request orchestration

The actor currently guarantees a useful amount of ordering. It does not provide an internal request scheduler equivalent to:

- request queue ownership
- batch-shaping policy
- retained inflight batches
- idempotent retry of exact inflight work
- a dedicated request-runtime boundary under the public facade

### 3. Transfer policy separation

Transfer logic currently works, but policy is embedded in operations. Upstream parity needs a layer that can own:

- scheduling policy
- queueing and resume policy
- adaptive concurrency
- richer failure/retry behavior
- persistence boundaries

### 4. Public event model

Rust needs a proper public event surface for:

- request lifecycle
- transfer lifecycle
- node/tree updates
- alert/account updates

That surface does not need to clone the full C++ taxonomy on day one, but it must become a first-class subsystem rather than internal state plus a single transfer callback.

### 5. Filesystem/watch abstraction

This is the architecture prerequisite for:

- sync
- scheduled backup
- FUSE/mount
- more faithful desktop transfer behavior

Until this exists, those large desktop subsystems should be treated as structurally blocked.

---

## Areas Where The Old Report Was Too Flat

The previous version was directionally correct, but an enhanced report should make these points explicit:

### 1. Tree bootstrap deserves its own emphasis

`tree.rs` is not just “fetch nodes.” It is the current Rust bootstrap and state-current assembly point.

### 2. `^!keys` and sharing work are stronger than a footnote

The share-key lifecycle already spans `key_sync.rs`, `sharing.rs`, and `KeyManager`. That is meaningful architecture.

### 3. Public-folder support is a separate runtime

`public.rs` is not part of the authenticated actor flow. The report should call out that there are already two runtime shapes in the crate.

### 4. The C++ comparison should center `MegaClient`, not only `MegaApiImpl`

`MegaApiImpl` is the adapter. `MegaClient` plus `NodeManager` plus DB tables plus transfer/sync/filesystem subsystems are the real architectural reference.

### 5. `NodeManager + DB + SCSN` should be treated as one parity target

Those pieces are not separable in upstream architecture, so the Rust backlog should not treat them as unrelated nice-to-haves.

---

## Recommended Port Sequencing

### Architecture-first sequence

1. Define a persistence boundary for nodes, alerts, and transfer state.
2. Introduce an internal request-submission/scheduling layer under the actor.
3. Split transfer scheduling policy out of operation modules.
4. Expose a public event stream or equivalent Rust-native event model.
5. Add a filesystem abstraction and watcher interface.
6. Add indexed query/search support over cached nodes.
7. Port sync, scheduled backup, and mount/FUSE layers.

### Mixed product plus architecture sequence

1. Public event surface
2. Search/query APIs over the cached tree
3. 2FA and contact-request APIs
4. Durable local state
5. Transfer runtime hardening
6. Filesystem/watch abstraction
7. Sync, scheduled backup, and mount/FUSE

The mixed path can ship visible features sooner, but it still has to converge back to persistence and runtime hardening before the large desktop subsystems become realistic.

---

## Small-Slice Backlog

1. Introduce an internal request-submission trait or service so actor commands stop calling `ApiClient` directly.
2. Define a persistence trait for node cache, alerts, and transfer state, even if the first backend is intentionally minimal.
3. Carve transfer policy out of `upload.rs` and `download.rs` into an internal scheduler boundary.
4. Expose a read-only event stream for transfer, request, node, and alert changes before attempting listener-family parity.
5. Add a query/search abstraction over cached nodes so the current in-memory traversal model has a clean upgrade path to indexed storage.
6. Add a filesystem abstraction trait layer before any sync-specific code lands.
7. Clarify in docs that backup-related `^!keys` persistence is metadata parity, not scheduled-backup runtime parity.

---

## Report Maintenance Notes

This report appears to be hand-maintained rather than generated. To keep it useful, future refreshes should update:

1. the validation date
2. the graph-size counts
3. the Rust evidence anchors
4. the upstream evidence anchors
5. a short note about what changed since the previous validation

The most likely places to drift next are:

- Rust tree bootstrap and current-state handling
- key/share lifecycle behavior
- public event surface
- any future persistence layer introduction

---

## Recommendation

The clearest path to real architectural parity remains:

1. keep the Rust actor model
2. treat `Session` plus a future request layer plus a future persistence layer as the Rust equivalent of the upstream core engine boundary
3. make `NodeManager + DB + SCSN` the reference target for durable tree parity
4. make transfer scheduling/persistence a subsystem rather than helper logic
5. only then pursue sync, scheduled backup, and mount/FUSE parity

That preserves the strengths of the current Rust design while converging on the upstream layers that actually matter for long-lived SDK behavior.
