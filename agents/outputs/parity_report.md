# megalib Parity Report: C++ SDK vs Rust Port

Validated on 2026-03-25 against the Rust graph `project`, the upstream C++ graph `sdk`, the current Rust tree, and the upstream C++ SDK in `../sdk`.

This report replaces the older version, which was stale in a few important ways. In particular, Rust already has node-first folder/move/rename/remove/export APIs, and the public-folder download parity bug called out earlier was fixed in `0.11.0`.

Companion report: `agents/outputs/architectural_parity_report.md`.

Directional size signal from the code graphs:

- Rust graph (`project`): 1083 units
- C++ graph (`sdk`): 12829 units

That number is not a feature count, but it does match the architectural reality: the Rust port covers the core cloud-drive path well, while the C++ SDK still contains many more subsystems and runtime layers.

---

## Refresh Delta For This Validation

Compared with the older parity framing, this validation makes four things more explicit:

- parity should be tracked by capability families, not only by a flat list of missing methods
- the Rust port already covers the main cloud-drive path well enough that remaining gaps should be separated into partial parity versus truly missing subsystems
- the capability report should stay aligned with `architectural_parity_report.md`, while remaining user-facing rather than runtime-first
- this report is hand-maintained and should name its concrete inputs and evidence limits

---

## Scope And Method

This report is intentionally capability-first:

- it evaluates what an SDK consumer can actually do today
- it groups parity by stable capability families rather than by raw symbol count
- it uses architecture only where runtime shape directly explains why a capability family is still partial or missing

The most important consequence is this:

- comparing Rust only against public method names is too shallow
- comparing Rust only against runtime architecture is also too shallow

The real parity question is whether Rust already supports the capability families that most application and SDK consumers expect:

1. authenticated cloud-drive workflows
2. public-link and public-folder workflows
3. sharing and contacts
4. account, identity, and security flows
5. transfer lifecycle and observability
6. search, traversal, and history/versioning
7. desktop subsystems such as sync, backup, and mount

---

## Report Inputs And Known Evidence Limits

This report was refreshed from these concrete inputs:

- Rust code graph artifact: `agents/project.acb`
- Upstream C++ graph artifact: `agents/sdk.acb`
- live Rust tree in this repository under `src/`
- sibling upstream SDK tree at `../sdk`
- companion architecture report at `agents/outputs/architectural_parity_report.md`

Known limits for this report:

- it appears to be hand-maintained rather than generated from a repeatable report script
- `AGENTS.md` points to `agents/outputs/pol_discover/`, but that directory is not present in this workspace today
- some conclusions are therefore analyst synthesis over code and graph evidence rather than output from a dedicated discovery bundle

---

## Executive Summary

| Question | Answer |
|----------|--------|
| Can a user do the main cloud-drive workflows in both SDKs? | **Mostly yes.** Login, session restore, fetch nodes, browse, upload, download, export links, folder sharing, public file access, and public folder browsing all exist in Rust. |
| Is megalib at full parity? | **No.** The biggest missing pieces are sync/FUSE/backup subsystems, 2FA, contact-request flows, search/filter APIs, versioning/rubbish-bin APIs, and the broader listener/notification surface. |
| Is the remaining gap mostly feature count, or architecture too? | **Both.** Several end-user features are missing, but there is also a real architectural gap: C++ has request/transfer queues, waiter-driven background processing, persistent DB/cache layers, and richer listener models that Rust does not yet mirror. |
| Are the old TODOs (`gzip login body`, `flag for tls`) the main parity blockers? | **No.** They are minor compared with the missing subsystems and runtime behavior differences. |

---

## Capability Families To Track Explicitly

This report is capability-first, but it should still track parity across stable capability families rather than a changing list of individual methods:

| Capability family | Upstream C++ breadth | Rust breadth today | Why this family should stay explicit |
|-------------------|----------------------|--------------------|--------------------------------------|
| Auth and session lifecycle | login variants, session restore, account lifecycle, 2FA | login, proxy login, session blobs, registration, password change | This is the entry path for almost every client and a visible SDK contract. |
| Cloud-drive tree operations | fetch nodes, browse, stat, create/move/rename/remove/export, richer move semantics | strong coverage of the main authenticated tree path | This is the Rust port's strongest user-facing area and should not be understated. |
| Transfer surface | uploads/downloads, progress, persistence, richer scheduling/runtime knobs | strong end-user transfer support, thinner runtime depth | Users care about whether transfers work; applications care about how much control exists. |
| Public links and folders | public file/folder access integrated with broader runtime | public file download and public folder browsing in separate runtime | This is already usable in Rust and deserves its own parity line item. |
| Account basics and security | account details, profile/attributes, password-reset and 2FA flows | account basics, quota, password change, authring/manual-verification controls | A large part of the remaining application-facing parity gap is here rather than in desktop subsystems. |
| Share/contact inventory and collaboration | contacts, shares, contact requests, sharing ecosystem | contact listing, inshare/outshare/pending-outshare views, folder sharing | Rust already has meaningful collaboration coverage, but the lifecycle/request surface is still incomplete. |
| Search, versioning, and history | search filters, folder info, versions, rubbish-bin management | cached traversal only, no full search/versioning/rubbish-bin surface | These gaps matter even when desktop subsystems are out of scope. |
| Events and notifications | listeners, request/transfer/global callbacks, user alerts, banners | transfer progress callback plus internal SC handling | This is a major application integration gap, not just a convenience feature. |
| Desktop services | sync, backup, FUSE/mount, file-service layers | missing | These are major parity categories and should remain clearly separated from cloud-drive APIs. |
| Product-adjacent and platform-facing surface | chat, meetings, push settings, surveys, bindings-facing adapter breadth | mostly missing | These exist upstream, but parity value depends on the intended Rust product scope. |

---

## Current Functional Parity

### Strong parity today

| Area | Rust status | Notes |
|------|-------------|-------|
| Auth and session restore | **Good** | `SessionHandle::login`, proxy login, session blob dump/load, folder-session blob support |
| Node tree fetch and cached browsing | **Good** | `fetch_nodes`, cached node lookups, root/children/descendants, handle-based access |
| Remote file and folder operations | **Good** | First-class create/move/rename/remove/export APIs exist in Rust; `move_node` still has narrower semantics than C++ `moveNode` |
| Uploads | **Good** | Path- and node-based upload APIs, resumable file uploads, async-reader uploads |
| Downloads | **Good** | Authenticated downloads, resumable downloads, public file download |
| Public file and folder access | **Good** | `parse_mega_link`, `download_public_file`, `parse_folder_link`, and browsable `open_folder()` sessions with `list`/`stat`/`download` |
| Registration | **Good** | Register + verify flow is implemented |
| Account basics | **Good** | Basic identity info and storage quota are implemented |
| Share-key and authring handling | **Good** | `^!keys`, authring, manual verification flag, pending key promotion, SC-driven key maintenance |

### Partial parity

| Area | Rust has | Still missing vs C++ |
|------|----------|----------------------|
| Share/contact inventory and folder sharing | Contact listing, inshare/outshare/pending-outshare/root-share views, folder sharing | Richer share inspection APIs and some higher-level contact/share lifecycle ergonomics remain thinner than C++ |
| Contact-request lifecycle | Folder sharing and contact inventory provide adjacent collaboration primitives | Invite/reply/remove contact flows, contact-request objects/lists, and request-state APIs are still missing |
| Node mutation semantics | First-class `create_folder_in` and `move_node` APIs | C++ still has richer behavior: duplicate-folder prechecks, `moveNode(..., newName)` overload, stronger move preconditions, and copy-delete fallback when direct move is not allowed |
| Account basics and security surface | Basic account info, quota, password change, manual verification/authring-related controls | Full account-details surface, avatar/profile helpers, password-reset flows, 2FA, misc flags, payment/subscription info |
| Events and notifications | Internal SC worker, action-packet processing, transfer progress callback | Public user-alert API, typed request/global/transfer listeners, banner/notification management |
| Deletion/history semantics | Node removal works | Keep-versions delete, remove-all-versions, rubbish-bin cleanup/autopurge, version inspection |
| Search/filter/page/query surface | Cached-tree traversal, child lookup by name/type, descendants, and path-style browse helpers | Search filters, pagination, indexed search, folder-info APIs, and version-aware query surfaces |
| Media attributes | Optional preview feature and file-attribute handling | Broader SDK media/gfx surface and provider integration |
| Persistence | Session blobs, upload resume state files | Persistent node cache, transfer DB, user-alert persistence, DB-backed search/index state |

### Missing major feature areas

| Feature area | C++ status | Rust status | Priority for full parity |
|--------------|------------|-------------|--------------------------|
| Sync engine | Present | Missing | **Very high** |
| FUSE / virtual drive | Present | Missing | **Very high** |
| Scheduled backup / scheduled copy | Present | Missing | **High** |
| 2FA / TOTP flows | Present | Missing | **High** |
| Contact-request flows | Present | Missing | **High** |
| Search/filter/page APIs | Present | Missing | **High** |
| Versioning and rubbish-bin APIs | Present | Missing | **High** |
| User alerts / notification management | Present | Missing or internal-only | **Medium-high** |
| Local transfer server / session transfer URL | Present | Missing | **Medium** |
| Platform/bindings-facing and product-adjacent APIs | Present | Largely missing | **Scope-dependent** |
| Chat / meetings / scheduled meetings | Present | Missing | **Depends on scope** |
| Push notifications / surveys / AB-test utilities | Present | Missing | **Low unless product-required** |

---

## Architectural Parity

This section stays capability-first: it calls out architecture only where the runtime gap directly blocks user-visible parity. For the fuller runtime-first analysis, see `agents/outputs/architectural_parity_report.md`.

### 1. Request dispatch and batching

| C++ SDK | megalib | Parity impact |
|---------|---------|---------------|
| `RequestDispatcher` batches commands, splits batch-separate commands, retries inflight requests, and tracks seqtag/idempotence behavior as part of the core runtime. | Rust has `ApiClient::request` and `request_batch`, plus actor-side seqtag waiters for mutating operations, but no general request-dispatch layer or queue/batching policy shared across the SDK. | **Medium-high.** Rust can perform the operations, but it does not yet mirror the SDK's request-shaping and queueing behavior. This matters for rate limits, background ordering, and “SDK-feel” under load. |

What this means in practice:

- The C++ SDK treats API commands as queueable work.
- Rust mostly issues requests directly from the session actor or helper flows.
- The Rust actor preserves ordering for many operations, but it is not equivalent to the C++ dispatcher model.

### 2. Runtime topology: waiter + queues vs actor + poller

| C++ SDK | megalib | Parity impact |
|---------|---------|---------------|
| `MegaApiImpl` maintains `requestQueue`, `scRequestQueue`, and `transferQueue`, and the broader SDK runtime is built around waiter-driven background processing and listener notification. | Rust uses one session actor plus a dedicated `ScPoller` task. That is a reasonable design, but it is much thinner than the C++ runtime. | **Medium.** Good enough for core API use, but not yet the same operational model for long-running desktop-grade clients. |

### 3. Transfer scheduler and transfer engine

| C++ SDK | megalib | Parity impact |
|---------|---------|---------------|
| `TransferSlot` manages dynamic connection counts, request sizing, timeout/backoff behavior, queue limits, and Cloud RAID handling/recovery. The core also maintains transfer queues and DB-backed transfer state. | Rust supports parallel chunk workers, resumable uploads, resumable downloads, and progress callbacks, but it does not have the same slot scheduler, Cloud RAID machinery, or durable transfer queue model. | **High.** This is one of the biggest non-feature parity gaps because it affects performance tuning, large-transfer robustness, and desktop-client behavior. |

### 4. Persistence and caching

| C++ SDK | megalib | Parity impact |
|---------|---------|---------------|
| C++ ships with DB abstractions (`db.h`, sqlite integration), transfer persistence, user-alert persistence, and search/cache infrastructure. | Rust currently keeps the node tree in memory, persists session blobs, and stores resumable-upload state files, but has no equivalent persistent node/transfer/user-alert database layer. | **High.** This blocks true desktop parity and makes future sync/search/FUSE work much harder. |

### 5. Listener and notification surface

| C++ SDK | megalib | Parity impact |
|---------|---------|---------------|
| C++ exposes `MegaListener`, `MegaRequestListener`, `MegaTransferListener`, `MegaGlobalListener`, scheduled-copy listeners, user-alert accessors, and many app callbacks. | Rust exposes a transfer progress callback and internal SC handling, but no public listener ecosystem comparable to the C++ SDK. | **Medium-high.** Embedded apps can use Rust today, but not with the same event model or observability hooks. |

### 6. Filesystem integration layer

| C++ SDK | megalib | Parity impact |
|---------|---------|---------------|
| C++ has deep filesystem abstractions, OS notifications, sync-facing FS logic, FUSE mount state, and file-cache helpers. | Rust directly performs file operations for uploads/downloads and does not yet have a cross-platform FS integration layer. | **Very high.** This is a prerequisite for sync, virtual drive, and several desktop-oriented services. |

### 7. Search and indexed querying

| C++ SDK | megalib | Parity impact |
|---------|---------|---------------|
| C++ supports search filters, paging, folder-info queries, version queries, and richer indexed node access. | Rust currently offers cached-tree traversal and path-prefix style browsing, but not true SDK-level search/filter/page APIs. | **High** for application parity, even though the underlying node tree exists. |

---

## What Is Left To Do For Full Parity

### Highest-value user-facing ports

These would close obvious SDK feature gaps without first reproducing the entire C++ runtime:

1. **2FA APIs**
   Add the C++-style multi-factor check/enable/disable/login/change-password flows.
2. **Contact-request APIs**
   Add invite, reply, accept/deny/ignore, remove-contact, and request-list access.
3. **Search/filter/page APIs**
   Add user-facing search over the cached tree, then align with C++ filter/page semantics.
4. **Versioning and rubbish-bin APIs**
   Add get-versions, remove-versions, keep-versions delete behavior, and rubbish-bin cleanup.
5. **Public notification/listener surface**
   Expose a proper Rust event model instead of only internal SC handling and transfer progress.

### Highest-value architectural ports

These are not as flashy, but they are the main blockers for “real SDK parity” rather than “core API parity”:

1. **Persistent cache/DB layer**
   Node cache, transfer persistence, alert persistence, and searchable local state.
2. **Request scheduling model**
   A proper request queue/dispatcher model instead of mostly direct request issuance.
3. **Richer transfer scheduler**
   Centralized queueing, better concurrency policy, and any Cloud RAID parity work that matters for MEGA transfers.
4. **Filesystem abstraction layer**
   Cross-platform local FS/watch abstractions needed by sync, FUSE, and backup features.

### Major subsystems after the foundations are in place

1. **Sync engine**
2. **Scheduled backup / scheduled copy**
3. **FUSE / virtual drive**

These are large slices, not follow-up tickets. They depend on persistence, transfer scheduling, and filesystem integration.

### Probably optional unless product scope requires them

These exist in the C++ SDK, but may not be worth chasing if the Rust crate is intended to stay focused on storage/cloud-drive use cases:

1. Chat and meeting APIs
2. Local FTP/HTTP transfer server helpers
3. Push-notification settings, banners, surveys, AB-test utilities

---

## Verification Gap

Even after this report update, one major gap remains in the project itself:

- There is no formal Rust-vs-C++ behavior test suite for core flows.
- There are no meaningful comparative performance benchmarks.

That means feature-parity status is easier to validate than behavior-parity or performance-parity status. Once the next batch of ports lands, adding cross-SDK integration checks for login, fetch-nodes, uploads, downloads, exports, shares, and SC catch-up behavior would pay off quickly.

---

## Minor TODOs Still Present

These are still valid, but they are not the main parity story:

- `gzip login body`
- `flag for tls`

They should be treated as cleanup items, not major parity milestones.

---

## Recommended Prioritization

If the goal is **application/API parity first**, port in this order:

1. 2FA
2. Contact requests
3. Search/filter/page APIs
4. Versioning + rubbish-bin APIs
5. Public listener/user-alert surface

If the goal is **desktop/runtime parity first**, port in this order:

1. Persistent cache/DB layer
2. Request/transfer queue architecture
3. Filesystem abstraction layer
4. Sync engine
5. Scheduled backup
6. FUSE

If the goal is **strict “everything in the C++ SDK” parity**, the work after that still includes chat, meetings, notification settings, transfer-server helpers, and other product-adjacent APIs.

---

## Evidence Basis

Rust areas reviewed:

- `src/session/actor.rs`
- `src/session/sc_poller.rs`
- `src/session/core.rs`
- `src/api/client.rs`
- `src/http.rs`
- `src/fs/operations/*.rs`
- `src/public.rs`

C++ areas reviewed:

- `../sdk/src/request.cpp`
- `../sdk/src/megaclient.cpp`
- `../sdk/src/transferslot.cpp`
- `../sdk/include/megaapi_impl.h`
- `../sdk/include/mega/megaapp.h`
- `../sdk/include/mega/db.h`

This report is intentionally focused on practical parity planning, not exhaustive symbol-by-symbol inventory.
