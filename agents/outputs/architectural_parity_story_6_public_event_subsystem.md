# Story 6 Spec: Add Public Event Subsystem

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 6 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, 4, 4B, and 5, this is a code-bearing story. Its job is to establish a real internal event runtime plus additive, read-only public event observability for authenticated sessions. It must stay intentionally narrower than Story 6B, which will later own listener-family separation, adapter staging, and callback/observer depth.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_2_request_runtime.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-31:

- `src/progress.rs` defines `TransferProgress` plus `ProgressCallback`, and that is still the only public event-like surface in the crate.
- `src/session/core.rs` stores one synchronous progress callback and uses `report_progress(...)` to both notify the caller and decide whether a transfer should be cancelled.
- `src/session/actor.rs` exposes `SessionHandle::watch_status(...)`, but there is no general public event entrypoint for requests, tree changes, or alerts.
- `src/session/runtime/request.rs` now exists from Story 2, but request submission is still silent from an observability perspective.
- `src/session/action_packets.rs` mutates node/share state and `src/session/actor.rs` consumes `ScPollerEvent::AlertsBatch`, but those changes only update internal session state.
- `handle_actionpacket_upgrade(...)` in `src/session/action_packets.rs` still no-ops even though the SDK treats related packets as outward account/user-alert signals.
- `src/lib.rs` re-exports transfer progress types, but no public session event types or subscription handle exist.

This means the Rust crate now has multiple internal event producers, but still lacks a first-class event subsystem.

---

## Story Goal

Establish a dedicated event runtime at `src/session/runtime/events.rs` that:

- collects request, transfer, node, and alert/account event inputs
- publishes additive, read-only public event observability for authenticated sessions
- preserves the existing synchronous progress callback behavior
- becomes the substrate later used by Story 6B for richer listener-family and callback staging

This story does not need to clone the SDK’s full callback taxonomy. It does need to make event production a named subsystem rather than leaving observability as a mixture of:

- transfer-only callbacks
- internal state mutation
- silent request/runtime transitions

---

## Why This Story Exists

Today, `megalib` has observability fragments, not an event architecture:

- transfer progress is surfaced through `Session::report_progress(...)` and `SessionHandle::watch_status(...)`
- request lifecycle transitions are internal to request helpers and actor command flows
- node/tree changes are visible only indirectly through refreshed session state
- alert/account update paths are persisted internally, but not surfaced as first-class runtime outputs

The upstream SDK is architecturally broader:

- `MegaApp` in `../sdk/include/mega/megaapp.h` defines many outward callback families such as `nodes_updated`, `sequencetag_update`, `useralerts_updated`, and `account_updated`
- `MegaRequestListener`, `MegaTransferListener`, and `MegaListener` in `../sdk/include/megaapi.h` define request and transfer lifecycle callbacks, with concrete fan-out in `../sdk/src/megaapi_impl.cpp`
- `common::Client` in `../sdk/include/mega/common/client.h` has a node-event observer concept on top of the client via `addEventObserver(...)` / `removeEventObserver(...)`

That upstream shape matters for parity, but Story 6 should not attempt to port all of it at once. The correct first slice is:

- create the Rust event substrate
- surface the upstream-grounded request, transfer, node, user-alert, and account notification families through additive public observability
- keep richer outward callback/observer staging for Story 6B

This matches the parity report’s recommendation that Rust first expose a public event stream for request, transfer, node, and alert changes before attempting listener-family parity.

---

## Validation Findings

Overall verdict: fully grounded, once Story 6 is scoped to the specific upstream event families and committed notification seams it is meant to mirror.

Grounded in upstream:

- `MegaApp` defines outward callback families including `nodes_updated(...)`, `sequencetag_update(...)`, `useralerts_updated(...)`, `account_updated()`, and transfer callbacks such as `transfer_added(...)`, `transfer_update(...)`, `transfer_failed(...)`, and `transfer_complete(...)` in `../sdk/include/mega/megaapp.h`.
- `MegaRequestListener`, `MegaTransferListener`, and `MegaListener` define start/update/temporary-error/finish lifecycles in `../sdk/include/megaapi.h`, and `MegaApiImpl::fireOnRequestStart(...)`, `fireOnRequestUpdate(...)`, `fireOnRequestTemporaryError(...)`, `fireOnRequestFinish(...)`, `fireOnTransferStart(...)`, `fireOnTransferUpdate(...)`, `fireOnTransferTemporaryError(...)`, and `fireOnTransferFinish(...)` are the concrete outward fan-out paths in `../sdk/src/megaapi_impl.cpp`.
- `common::Client` owns a node-only observer surface in `../sdk/include/mega/common/client.h`, with `NodeEventObserver` / `NodeEventQueue` in `../sdk/include/mega/common/node_event_observer.h` and `../sdk/include/mega/common/node_event_queue.h`, and typed node events `ADDED`, `MODIFIED`, `MOVED`, `PERMISSIONS`, and `REMOVED` in `../sdk/include/mega/common/node_event_type.h`.
- `NodeManager::notifyPurge()` forwards committed node changes to both `mClient.app->nodes_updated(...)` and `mClient.mClientAdapter.updated(...)` in `../sdk/src/nodemanager.cpp`, and `ClientAdapter::updated(...)` fans those node events out to observers in `../sdk/src/common/client_adapter.cpp`.
- `UserAlerts::purgescalerts()` emits `mc.app->useralerts_updated(...)` after alert accumulation, `MegaClient::notifypurge()` flushes committed notification batches, and upgrade/account-change handling calls `app->account_updated()` after state changes in `../sdk/src/useralerts.cpp` and `../sdk/src/megaclient.cpp`.
- `MegaClient` also emits `app->sequencetag_update(...)` when SC processing reaches a new sequence-tag boundary in `../sdk/src/megaclient.cpp`, which confirms that the SDK treats outward event publication as a first-class runtime concern rather than ad hoc callback side effects.

Grounding constraints for this story:

- `common::Client` is not a unified observer API for requests, transfers, alerts, or account updates; it is specifically a node-event observer layer.
- `PendingCallbacks` is real upstream evidence for the later adapter-layer story, but Story 6 stays fully grounded by leaving callback cancellation and detachment semantics to Story 6B instead of folding them into the event-substrate claim.
- The first Rust public API only needs to be additive and read-only. Whether it initially appears as one generic receiver or thin family-aware wrappers is a repo-local API-shape choice, not the parity target itself.
- If a Rust implementation needs a coarse reload/invalidation marker for refresh paths that do not expose precise deltas, that marker is a Rust representation choice informed by upstream null-list/full-refresh callbacks, not the grounding basis of the story.

---

## Scope

In scope:

- introduce `src/session/runtime/events.rs`
- define one internal event model that can represent:
  - request lifecycle changes
  - transfer progress/change notifications
  - node/tree mutation notifications
  - alert/account-update notifications
- add additive public event observability for authenticated sessions
- preserve `ProgressCallback` and `watch_status(...)`
- bridge the current event sources into the event runtime
- add ordering and backpressure tests for the new runtime

Out of scope:

- multiple public listener families
- callback cancellation contexts comparable to `PendingCallbacks`
- observer registration architecture comparable to the SDK’s full adapter layers
- bindings-facing adapter depth
- public-link runtime events from `src/public.rs`
- a one-to-one port of every `MegaApp` callback family
- transfer-runtime redesign beyond consuming existing transfer progress/change inputs

Story 6 is the event substrate story. Story 6B is the outward adapter/callback staging story.

---

## Story 1, Story 2, And Story 3 Constraints

Story 6 must preserve these existing decisions:

- the internal event runtime lives at `src/session/runtime/events.rs`
- `Session` remains the engine root
- request runtime remains at `src/session/runtime/request.rs`
- persistence/runtime state ownership remains in `Session` plus lower runtimes; the event runtime only observes and republishes
- public API changes in this story must be additive
- the existing synchronous transfer progress callback must remain intact

If implementation pressure suggests turning the event runtime into a second owner of actor logic, request policy, or transfer policy, Story 1 must be revised first.

---

## SDK Parity Target

Story 6 should align with the upstream SDK in these ways:

1. Engine changes have named event families rather than being observable only through direct callback side effects.
2. Event production is separated from outward adapter and callback staging.
3. Node/tree, alert/account, request, and transfer transitions become first-class runtime outputs.
4. Event publication follows committed state transitions rather than speculative intermediate mutation.

In concrete upstream terms, the strongest grounded analogues are:

- request lifecycle should look like the SDK request-listener model: start, optional update/temporary-error, finish, keyed by request kind plus opaque request identity rather than raw API JSON
- transfer lifecycle should look like the SDK transfer-listener model: start, update, temporary-error, finish, while cancellation remains outside the event stream
- node changes should follow the SDK/common observer taxonomy of committed typed node changes; if Rust cannot enumerate precise deltas for a refresh path, any coarse invalidation marker is a repo-local representation detail rather than the parity target
- user alerts and account updates should remain separate families, matching `useralerts_updated(...)` versus `account_updated()`
- `PendingCallbacks`-style cancellation contexts remain deferred to Story 6B because the grounded upstream evidence places them in the later adapter/callback layer rather than in the engine event substrate

Story 6 should not attempt these SDK-parity goals yet:

- full `MegaApp` callback-family coverage
- `PendingCallbacks`-style cancellation semantics
- full observer/listener-family layering
- bindings-specific adapter behavior

Those belong to Story 6B.

---

## Current Rust Gaps

The current codebase is still missing these event-subsystem pieces:

- a unified internal event model
- a session-owned event runtime
- a public read-only event subscription API
- request event emission from Story 2 request runtime helpers
- node/tree event emission from refresh and action-packet application boundaries
- alert/account event emission from SC alert batches and upgrade/action packets
- explicit lag/backpressure behavior for slow consumers

The current `watch_status(...)` path is valuable, but it is not a general event subsystem.

---

## Design Decisions

The decisions below combine the grounded parity target with repo-local API constraints. When a point is Rust-owned rather than directly validated upstream, that is called out explicitly.

### Decision 1. `Session` owns the event runtime

Why:

- current mutable engine state is already centered on `Session`
- request, transfer, tree, and alert sources already converge there or in adjacent modules
- event runtime must observe engine transitions, not become a new global owner

Consequence:

- `Session` should hold an `EventRuntime` handle
- actor code, request helpers, and transfer paths should publish into that runtime
- `src/session/runtime/events.rs` must not become a second engine or policy owner

### Decision 2. Story 6 introduces the smallest additive public event entrypoint that covers the grounded families

Why:

- the crate currently has no general public event surface at all
- the story needs one additive way to expose the grounded request/transfer/node/alert/account families
- it gives later stories a stable substrate without forcing Story 6B transport depth too early

Consequence:

- this story should add an additive public entrypoint such as `SessionHandle::subscribe_events(...)`
- the exact first-slice outward shape may be one generic receiver or a thin wrapper over crate-owned family types, but it must stay read-only
- Story 6 must not also introduce multiple listener-registration APIs with independent lifecycle rules
- request and transfer events published through that surface should still retain family-specific identities and lifecycle semantics

### Decision 3. Public event types must be crate-owned and runtime-agnostic

Why:

- exposing raw Tokio channel types would hard-wire the public API to one internal implementation choice
- Story 6 needs additive public surface, but it should remain flexible for Story 6B and later changes
- Rust-idiomatic SDK design favors a crate-owned receiver wrapper and crate-owned error types

Consequence:

- public API should expose a wrapper such as `SessionEventReceiver`
- public receive errors should be crate-owned, for example `SessionEventRecvError`
- public event families should use crate-owned opaque ids such as `SessionRequestId` and `SessionTransferId` instead of exposing raw API payloads or runtime internals
- do not expose `tokio::sync::broadcast::Receiver` directly in the public API

### Decision 4. Existing transfer progress callback remains authoritative for cancellation

Why:

- `report_progress(...)` currently returns `bool` and transfer code depends on that synchronous decision
- the new event surface in Story 6 is read-only and must not become a hidden control plane

Consequence:

- `watch_status(...)` and `ProgressCallback` remain supported
- transfer event emission must be observational only
- `TransferEvent` should follow an SDK-shaped lifecycle such as started/progress/temporary-error/finished
- `report_progress(...)` should preserve today’s callback semantics even if it also emits a best-effort public event

### Decision 5. Event emission happens after relevant state mutation, not before

Why:

- public observers should see committed runtime transitions, not speculative or partially applied state
- this matches SDK-style expectations where outward notifications follow meaningful engine updates

Consequence:

- request lifecycle events should be emitted after request outcome handling and any seqtag/session state updates relevant to that logical request
- node/tree events should be emitted after refresh or action-packet application succeeds, using typed change kinds where precise deltas are already known from committed state and a coarse reload/invalidation marker only when precision is not actually available
- alert and account events should be emitted after their respective internal states are updated

### Decision 6. Public event fan-out must not stall the session runtime

Why:

- engine, actor, request, and transfer paths cannot wait on arbitrary observers
- slow consumers are a normal case and should degrade explicitly instead of stalling the runtime
- this is a Rust runtime requirement for `megalib` stability, not a stronger contract than the C++ listener docs promise

Consequence:

- the internal runtime may use a bounded fan-out mechanism such as `tokio::sync::broadcast`
- `SessionEventReceiver` should expose owned events and explicit crate-owned receive errors such as `Lagged { dropped: u64 }` and `Closed`
- each call to `subscribe_events(...)` should create an independent live-only receiver
- each receiver must observe the session publish order across all event families
- “no subscribers” and “receiver dropped” are not runtime errors

### Decision 7. Story 6 ends at the generic event surface

Why:

- the SDK’s listener/callback architecture is broader than what is needed for the first Rust event slice
- trying to solve adapter families, cancellation contexts, and event-family staging here would merge Story 6 and Story 6B

Consequence:

- Story 6 should only define the internal event model and the first additive public event entrypoint
- Story 6B will later layer family-specific outward delivery and adapter semantics over that substrate

---

## Recommended Rust Shape

The grounded parity target above does not force one exact Rust API shape. One minimal repo-local mapping that fits the current codebase and keeps Story 6B open is:

### Internal runtime home

- `src/session/runtime/events.rs`

Recommended internal types:

- `pub(crate) struct EventRuntime`
- `pub(crate) enum InternalEvent`
- lightweight internal publish helpers such as:
  - `publish_request(...)`
  - `publish_transfer(...)`
  - `publish_node(...)`
  - `publish_alert(...)`
  - `publish_account(...)`

`EventRuntime` should be session-owned and should not expose raw channel types outside the session/runtime layer.

### Public event home

- `src/session/events.rs`

Recommended public types:

- `pub struct SessionRequestId`
- `pub enum SessionRequestKind`
- `pub struct SessionTransferId`
- `pub enum SessionEvent`
- `pub enum RequestEvent`
- `pub enum TransferEvent`
- `pub enum NodeEvent`
- `pub enum AlertEvent`
- `pub enum AccountEvent`
- `pub struct SessionEventReceiver`
- `pub enum SessionEventRecvError`

Recommended public entrypoint:

- additive `SessionHandle::subscribe_events(&self) -> Result<SessionEventReceiver>`

Recommended public export path:

- `src/session/mod.rs` re-exports the public event types
- `src/lib.rs` re-exports the public event types for crate-level discoverability

### Public event families

The public event model should stay lightweight and clone-friendly.

One workable first-slice shape:

- `SessionEvent::Request(RequestEvent)`
- `SessionEvent::Transfer(TransferEvent)`
- `SessionEvent::Node(NodeEvent)`
- `SessionEvent::Alert(AlertEvent)`
- `SessionEvent::Account(AccountEvent)`

If Story 6 uses a generic outward event enum, the first-slice family semantics should be:

- `RequestEvent`
  - SDK-shaped logical-request lifecycle: `Started`, optional `Updated`, optional `TemporaryError`, `Finished`
  - every event carries crate-owned `request_id` plus crate-owned `kind`, analogous to SDK request tag/type
  - `request_id` is session-local and observational; it is not a stable persistence identifier
  - one logical session operation produces one request lifecycle sequence even if it submits a batch internally
  - do not expose raw request JSON, `serde_json::Value`, or mutable session references
- `TransferEvent`
  - SDK-shaped transfer lifecycle: `Started`, `Progress`, optional `TemporaryError`, `Finished`
  - every event carries a session-local opaque `transfer_id`
  - `transfer_id` is for correlating events on the live receiver; it is not a cross-restart resume key
  - `Progress` reuses `TransferProgress` rather than inventing a second progress model
  - terminal outcome should be observational only; cancellation authority stays with the existing callback path
- `NodeEvent`
  - follow the SDK/common node-observer taxonomy rather than a vague invalidation event
  - direct node-delta variants should be equivalent to `Added`, `Modified`, `Moved`, `PermissionsChanged`, and `Removed`
  - if refresh or coalesced reload paths cannot provide precise committed deltas, the public API may also expose a coarse reload/invalidation marker instead of fabricating false precision
  - refresh and action-packet application are the important first sources
- `AlertEvent`
  - user-alert updates only
  - may carry owned alert summaries for new/updated alerts or another coarse refresh marker analogous to the SDK’s null-list path
  - avoid committing the public API to raw persisted alert JSON as the first design
- `AccountEvent`
  - separate family for account-plan / upgrade / downgrade updates analogous to `account_updated()`
  - payloads should stay coarse, for example `Updated` or similarly stable account-change markers

The public event API should prefer stable, coarse metadata over large internal state clones. In particular:

- do not emit full `Vec<Node>` snapshots as events
- do not expose internal session references
- do not expose raw Tokio or channel internals

### Backpressure shape

If the first Rust surface is receiver-based, a minimal contract is:

- `SessionEventReceiver` should expose an owned-event receive method such as `recv(&mut self) -> Result<SessionEvent, SessionEventRecvError>`
- subscription is live-only, not replaying historical events
- each receiver has bounded buffering
- lag becomes an explicit receive error (`Lagged { dropped: u64 }`), not silent loss
- runtime shutdown or event-runtime teardown becomes an explicit `Closed` receive error
- each receiver preserves the session publish order across all families
- event publication remains best-effort and non-blocking

This is the closest Rust-idiomatic equivalent of the SDK’s “engine produces signals; outward delivery layers decide how to stage them later.”

---

## Exact Behavioral Rules

Story 6 should follow these behavioral rules. Family coverage and committed publication boundaries are the parity-critical parts; receiver mechanics are Rust-owned API discipline.

### Rule 1. The public event surface is additive and read-only

- it must not replace `watch_status(...)`
- it must not become a control plane for cancellation or request sequencing
- it must not mutate engine state from receiver-side code

### Rule 2. Transfer progress compatibility stays intact

- `ProgressCallback` remains supported
- `watch_status(...)` and `clear_status(...)` remain public APIs
- transfer event publication should not change the current transfer-cancel decision path

### Rule 3. Request events should be bridged from the request-runtime seam

Story 6 request events should follow the SDK request-listener shape, but use Rust-owned ids and kinds instead of SDK object pointers.

Required first-slice request coverage:

- `src/session/runtime/request.rs`
- session-side helpers that apply seqtag/session state
- authenticated-session refresh / fetch-nodes paths, because the SDK’s request-update semantics are currently meaningful there first

Request rules:

- emit one request lifecycle per logical session operation, not one public event per raw command inside a request batch
- use crate-owned request kind metadata analogous to SDK `MegaRequest::TYPE_*`, not raw JSON payloads
- if a public authenticated-session path must emit request events in Story 6, it should route through the session-owned request seam instead of instrumenting `ApiClient` directly

### Rule 4. Node events should be emitted from committed tree-change boundaries

The first node-event sources should be:

- successful full refresh / fetch-nodes application
- successful action-packet batch application that changed durable tree/share state

Node rules:

- when precise per-node deltas are available, classify them using SDK-style node change kinds (`Added`, `Modified`, `Moved`, `PermissionsChanged`, `Removed`)
- when a refresh/reload path intentionally replaces or coalesces the tree, expose that as a coarse reload/invalidation event rather than fabricating false per-node precision
- do not expose speculative or partially applied mutations

### Rule 5. Alert and account events are separate families

The first alert-event sources should be:

- `ScPollerEvent::AlertsBatch` handling in `src/session/actor.rs`

The first account-event sources should be:

- upgrade/account-related action-packet handling in `src/session/action_packets.rs`

Rules:

- `AlertEvent` covers user-alert changes only
- `AccountEvent` covers coarse account-plan / upgrade / downgrade changes only
- `handle_actionpacket_upgrade(...)` should stop being a permanent no-op once Story 6 lands

### Rule 6. Public receivers do not see historical state replay by default

Public event subscriptions are for future changes only. Existing query methods remain the way to inspect current state.

Additional receiver rules:

- each `subscribe_events(...)` call returns an independent receiver cursor
- receivers observe session publish order across mixed event families
- the public API does not require receiver cloning; callers that need another cursor should subscribe again

### Rule 7. Event emission failure is not a fatal runtime error

- no subscribers: acceptable
- dropped receiver: acceptable
- lagged receiver: surfaced to that receiver, not escalated into engine failure
- runtime shutdown: surfaced as `Closed` to receivers, not escalated into engine failure

---

## Public API Preservation Rules

Story 6 must preserve the existing public API surface except for additive event APIs.

Required preservation rules:

- keep `ProgressCallback` unchanged
- keep `TransferProgress` unchanged
- keep `SessionHandle::watch_status(...)`
- keep `Session::watch_status(...)` / `clear_status(...)`
- do not remove or rename any existing public session methods

Allowed additive public APIs:

- public event enums and receiver wrapper
- one or more additive session event entrypoints, provided they share one coherent runtime model
- crate-level re-exports for the new public event types

Disallowed in this story:

- replacing `watch_status(...)`
- exposing raw Tokio receiver types publicly
- binding the public API to listener-family semantics that belong to Story 6B

---

## Affected Modules

Primary implementation targets:

- `src/session/runtime/events.rs`
- `src/session/events.rs`
- `src/session/core.rs`
- `src/session/actor.rs`
- `src/session/action_packets.rs`
- `src/session/runtime/request.rs`
- `src/progress.rs`
- `src/session/mod.rs`
- `src/lib.rs`

Likely source-to-event bridges in the first slice:

- request submission paths in `src/session/runtime/request.rs` and session-side wrappers
- fetch-nodes / refresh request path in `src/fs/operations/tree.rs`
- transfer lifecycle paths in `src/session/core.rs` and transfer operations, including the existing progress path in `src/session/core.rs::report_progress(...)`
- tree refresh/application path in `src/fs/operations/tree.rs`
- action-packet batch application path in `src/session/action_packets.rs` plus actor SC handling
- alert-batch handling in `src/session/actor.rs`

---

## Agent-Sized Tasks

### Task 6.1. Introduce the internal event runtime and public event types

Land:

- `src/session/runtime/events.rs`
- `src/session/events.rs`
- session-owned runtime handle initialization
- public event enums and receiver wrapper
- crate-owned opaque request / transfer identifiers
- separate `AlertEvent` and `AccountEvent` families

Do not yet attempt listener-family staging.

### Task 6.2. Bridge request and transfer sources into the runtime

Bridge:

- request-runtime logical request lifecycle
- fetch-nodes / refresh request lifecycle updates
- transfer lifecycle events that are already observable in the current runtime: started, progress, temporary-error where available, and finished

Preserve current progress callback behavior exactly.

### Task 6.3. Bridge node/tree and alert/account sources into the runtime

Bridge:

- successful refresh/tree replacement as a coarse reload/invalidation node event
- successful action-packet batch application as typed node events when precise deltas are available, otherwise a coarse reload/invalidation node event
- alert batches as `AlertEvent`
- account/upgrade-related action packets as `AccountEvent`

Keep the public event payloads lightweight and coarse-grained.

### Task 6.4. Expose the public subscription API and add ordering/backpressure tests

Add:

- additive subscription method on `SessionHandle`
- public docs and crate re-exports
- tests for:
  - ordering across mixed source families in session publish order
  - lag/backpressure behavior
  - compatibility with existing progress callback semantics
  - live-only, no-replay subscription behavior
  - `Lagged` and `Closed` receiver behavior
  - node coarse reload/invalidation behavior

---

## Acceptance Criteria

Story 6 is complete when all of the following are true:

1. `src/session/runtime/events.rs` exists and is owned by `Session`.
2. The crate exposes additive, read-only public event observability for authenticated sessions.
3. Request lifecycle, transfer lifecycle, typed node changes plus any necessary coarse reload/invalidation notifications, user-alert updates, and account updates are all bridged into the event runtime with crate-owned public types.
4. Existing transfer progress callback behavior still works without semantic regression.
5. Slow subscribers cannot block request, actor, or transfer execution, and each receiver preserves session publish order.
6. Public event types do not expose raw Tokio internals or raw API JSON payloads.
7. Public receivers surface explicit `Lagged` and `Closed` conditions.
8. Story 6B remains clearly deferred; this story does not also attempt full listener-family or adapter parity.

---

## Verification Requirements

When Story 6 code is implemented, the slice must end with:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Focused coverage should include:

- transfer progress callback compatibility while events are also enabled
- request event emission from the Story 2 request seam plus fetch-nodes / refresh update coverage
- refresh/action-packet node event classification and coarse reload/invalidation behavior
- separate alert-event and account-event emission
- lag/backpressure behavior
- subscription close behavior
- mixed-family ordering on one receiver

---

## Relationship To Story 6B And Later Stories

Story 6 is the event substrate.

Story 6B will later build on this story by adding:

- event-family separation beyond the first Story 6 event entrypoint
- outward callback/listener/observer staging
- cancellation/backpressure/runtime-staging rules at the adapter layer
- bindings-facing outward architecture

Later stories should consume Story 6 like this:

- Story 5 may enrich transfer event production once transfer runtime becomes first-class
- Story 8 and later can use the public event surface without inventing new ad hoc callbacks
- Story 6B must build above `src/session/runtime/events.rs`, not bypass it

The key architectural rule is simple:

- Story 6 makes engine events first-class
- Story 6B decides how those engine events should be staged outward
