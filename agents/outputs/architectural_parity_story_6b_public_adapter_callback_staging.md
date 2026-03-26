# Story 6B Spec: Align Public Adapter And Callback Staging

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 6B from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2 through 5, this is a code-bearing story. Its job is to add the outward adapter and callback/observer staging layer that should sit above the event model introduced by Story 6, so later feature families do not bolt themselves directly onto ad hoc actor callbacks.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_report.md`
- `agents/outputs/architectural_parity_story_6_public_event_subsystem.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- the current outward transfer callback surface is still essentially `watch_status()` in `src/session/actor.rs`
- `Session` still owns one mutable `progress_callback` slot in `src/session/core.rs`
- internal alert accumulation exists, but it is not a public runtime surface
- Story 6 is expected to create the internal event model and one minimal read-only public event API
- Rust still lacks a distinct outward adapter/callback staging layer comparable to the SDK’s `MegaApp` plus observer/cancellable-callback depth

That means event production and outward delivery are still too tightly collapsed.

## Validation Findings

Overall verdict: grounded, once the story is scoped to the specific upstream callback, observer, and cancellable-callback layers it is meant to mirror.

Grounded upstream:

- `MegaApp` is a broad callback surface with distinct families, including `nodes_updated`, `sequencetag_update`, `useralerts_updated`, and `account_updated`; see `../sdk/include/mega/megaapp.h`.
- `mega::common::Client` owns explicit `NodeEventObserver` registration via `mEventObservers` and `addEventObserver()`/`removeEventObserver()`; `ClientAdapter::updated()` fans node changes out to those observers; see `../sdk/include/mega/common/client.h`, `../sdk/src/common/client.cpp`, and `../sdk/src/common/client_adapter.cpp`.
- `PendingCallbacks` wraps callbacks in tracked contexts, removes the context before normal delivery, and cancels outstanding callbacks with `API_EINCOMPLETE`-style completion on teardown; see `../sdk/include/mega/common/pending_callbacks.h` and `../sdk/src/common/pending_callbacks.cpp`.
- `MegaApiImpl` provides the concrete outward callback staging for `nodes_updated`, `sequencetag_update`, `useralerts_updated`, and `account_updated`; see `../sdk/src/megaapi_impl.cpp`.
- For node updates specifically, upstream reports to `MegaApp` outside the `NodeManager` lock and then notifies the client adapter observer path; see `../sdk/src/nodemanager.cpp`.

Grounding constraints for this story:

- The observer layer in `mega/common/client.h` is specifically a node-event observer mechanism, not a generic observer bus for every `MegaApp` family. Story 6B stays grounded by treating node observers as one family-specific outward staging path, not as proof of a universal observer substrate.
- I did not find an upstream bounded backlog or explicit lag-signaling policy. Story 6B therefore treats any bounded non-blocking backpressure rule as a Rust delivery policy layered on top of the grounded adapter boundary, not as the parity target itself.

---

## Story Goal

Add a public adapter/callback staging layer at `src/session/runtime/adapter.rs` so the crate has a stable outward runtime home for:

- callback wrapping
- observer/subscriber staging above Story 6's generic event substrate
- event-family separation
- callback lifecycle semantics plus Rust-owned non-blocking delivery policy

This story must build on Story 6. It must not reinvent the underlying event model. Its job is to separate “events exist” from “events are delivered outward through a stable adapter surface.”

---

## Why This Story Exists

The SDK’s outward runtime shape is broader than a raw callback slot:

- `MegaApp` is the classic callback surface with many families of notifications
- `Client` in `mega/common/client.h` plus `ClientAdapter::updated()` own a node-event observer layer above raw engine state
- `PendingCallbacks` adds cancellable wrapper semantics and explicit callback lifecycle handling

Relevant upstream references:

- `../sdk/include/mega/megaapp.h:45`
- `../sdk/include/mega/common/client.h:34`
- `../sdk/include/mega/common/pending_callbacks.h:60`
- `../sdk/src/common/client_adapter.cpp:1246`
- `../sdk/src/nodemanager.cpp:1560`

Current Rust architecture is much thinner:

- `watch_status()` installs one transfer progress callback
- that callback is stored directly on `Session`
- later outward feature families would currently have no stable architectural home except “add another callback somewhere”

Story 6 is the first step that should define the underlying event model. Story 6B is the second step that gives those events a proper outward staging architecture.

Without Story 6B, later features are likely to drift into:

- one-off actor callbacks
- direct public API plumbing from internal producers
- mixed event-family semantics with no consistent callback-lifecycle or delivery-policy story

---

## Scope

In scope:

- introduce `src/session/runtime/adapter.rs`
- define the boundary between internal event production and outward callback/observer delivery
- define event-family grouping for outward delivery
- define how existing progress callback behavior maps onto the new adapter layer
- define callback lifecycle and Rust-side delivery-policy rules for outward delivery
- add focused tests for callback ordering, observer isolation, and family separation

Out of scope:

- inventing the internal event taxonomy from scratch
- replacing Story 6’s unified event model
- full listener-family parity with every `MegaApp` callback
- file-service, sync, or mount-specific observer systems
- changing the public API in breaking ways

This is an outward runtime-staging story, not a second event-model story.

---

## Story 1 And Story 6 Constraints

Story 6B must preserve these existing decisions:

- public adapter staging lives at `src/session/runtime/adapter.rs`
- `Session` remains the engine root
- Story 6 owns the internal/public event model substrate
- Story 6B layers on top of that substrate rather than bypassing it
- `watch_status()` and existing transfer progress behavior must remain compatible
- public API changes, if any, must be additive

If implementation pressure suggests merging adapter staging back into `src/session/runtime/events.rs`, Story 1 should be revised first rather than ignored.

---

## SDK Parity Target

The outward staging layer should align with the SDK in these ways:

1. Event production and outward delivery are not the same subsystem.
2. There is an explicit place for callback delivery semantics, plus a node-event observer layer, above raw engine events.
3. Callback lifecycle can later support cancellation or late-delivery handling without rewriting the engine.
4. Different outward event families can later diverge in semantics without changing internal event producers.

Rust should stay idiomatic:

- do not clone the full `MegaApp` taxonomy immediately
- do not expose raw queue/runtime internals in the public API
- do keep a clean boundary between event runtime and outward adapter logic

---

## Design Decisions

### Decision 1. Story 6B builds on Story 6 instead of replacing it

Why:

- Story 6 should create the underlying internal event substrate
- Story 6B exists because the SDK’s architecture also has an outward staging layer above that substrate

Consequence:

- `src/session/runtime/adapter.rs` may depend on event types or event-runtime outputs
- `src/session/runtime/events.rs` must not absorb the whole adapter/callback problem

### Decision 2. Existing progress callback behavior must become one consumer of the adapter layer

Why:

- `watch_status()` is already public
- removing or bypassing it would create unnecessary churn

Consequence:

- Story 6B should preserve `watch_status()` as a compatibility API
- internally, progress callback delivery should be understood as one outward adapter family rather than a privileged special case

### Decision 3. Story 6B owns family separation, not full feature-family breadth

Why:

- the SDK has many outward callback families
- Rust does not need all of them at once, but it does need a place to separate them cleanly

Consequence:

- Story 6B should define family boundaries such as:
  - transfer
  - request
  - node/tree
  - alert/account
- those family boundaries should surface through explicit family-aware outward wrappers, not only through one undifferentiated public stream
- it should not promise immediate implementation of every future family

### Decision 4. Outward delivery must not block the actor

Why:

- current Rust architecture depends on single-owner actor progress
- the SDK’s callback and observer systems also stage delivery away from raw engine mutation

Consequence:

- Story 6B should require a non-blocking outward delivery strategy
- lagging or cancelled consumers must not stall the core engine

### Decision 5. Callback cancellation semantics belong here, not in Story 6

Why:

- `PendingCallbacks`-style wrapper behavior is an outward lifecycle concern
- Story 6 should stay focused on event production and a minimal read-only surface

Consequence:

- Story 6B should define how cancellation, detachment, or late-delivery behavior is represented for outward callbacks/observers
- callback-style staged deliveries should follow the SDK pattern from `PendingCallbacks`:
  - cancellation removes the pending callback context
  - any callback that is still pending resolves once with a crate-owned cancellation/incomplete result analogous to `API_EINCOMPLETE`
  - after cancellation or detachment, no further deliveries occur for that callback registration
- stream-style family receivers may detach by drop without synthetic final events, but they must not silently keep pending callback work alive

### Decision 6. Story 6B should prefer explicit family-aware outward wrappers over one generic adapter stream

Why:

- `MegaApp` exposes distinct callback families such as `nodes_updated`, `sequencetag_update`, `useralerts_updated`, and `account_updated`
- `Client` adds explicit node-event observer registration rather than one untyped callback sink
- Rust already has Story 6’s generic event substrate; Story 6B exists to add outward family staging above it

Consequence:

- Story 6B should keep Story 6’s generic event stream intact as the substrate
- Story 6B should add family-aware outward wrappers or registrations on top of that substrate rather than treating the generic stream as the final public adapter API
- future families should add explicit outward homes instead of multiplexing everything through a single tagged stream forever

### Decision 7. Outward delivery must be non-blocking, and any bounded lag policy is Rust-owned rather than a parity claim

Why:

- the actor must not block on observers
- upstream stages some delivery work away from raw mutation paths, such as reporting node updates outside the `NodeManager` lock and routing wrapped callbacks through `PendingCallbacks`/`ClientAdapter`
- upstream does not show an explicit bounded lag-signaling policy here, so any Rust lag contract must be justified as a local runtime rule rather than as a direct C++ analogue

Consequence:

- family-stream delivery should use a non-blocking fan-out strategy; if Rust chooses bounded queues, lag signaling should be explicit
- lagging stream consumers must observe a crate-owned lag condition and resynchronize from current state if needed
- callback-style adapters must not accumulate unbounded pending deliveries; if the adapter cannot deliver them, cancellation/incomplete semantics should win over silent backlog growth

### Decision 8. `watch_status()` becomes a transfer-family compatibility facade owned by the adapter runtime

Why:

- current `watch_status()` is the only outward callback surface Rust already has
- it must remain behaviorally compatible
- leaving it as a bypass around the adapter layer would preserve the architecture gap this story is meant to close

Consequence:

- `watch_status()` should remain available as a compatibility API
- internally it should register through the transfer-family path in `src/session/runtime/adapter.rs`
- transfer progress should not bypass the adapter runtime once Story 6B lands

---

## Recommended Rust Shape

The first implementation slice should aim for a shape like:

```rust
// src/session/runtime/adapter.rs

pub(crate) struct PublicAdapterRuntime {
    // outward callback/observer staging
}

pub(crate) enum OutboundEventFamily {
    Transfer,
    Request,
    Node,
    Alert,
}
```

And additive public-facing wrappers such as:

- the generic public event subscription type introduced by Story 6
- family-aware outward wrappers or registrations such as transfer/request/node/alert subscriptions
- compatibility plumbing for `watch_status()` as the transfer-family callback facade
- crate-owned cancellation/lag result types rather than leaked channel internals

The exact API names may differ, but the architecture should preserve the split:

- `events.rs` produces events
- `adapter.rs` stages them outward

---

## Public API Preservation Rules

These are binding for Story 6B:

1. `watch_status()` remains available and behaviorally compatible.
2. additive public API is allowed only where needed to support explicit outward event-family separation.
3. Story 6B must not remove or break the Story 6 public event surface.
4. no internal queue or synchronization type should leak as the public API surface directly if a small wrapper type can avoid it.
5. family-aware outward wrappers should be crate-owned adapter types or registrations, not raw channel types.

---

## Delivery Rules

These are binding for Story 6B:

Items 3 and 5 are Rust runtime rules layered on top of the grounded adapter boundary. The validated upstream parity is the staging split and callback-cancellation depth, not a specific backlog contract.

1. outward delivery happens after internal state mutation, not before
2. per-consumer order should be preserved within one family stream
3. lagging or detached consumers must not block the actor
4. callback-style cancellation must resolve pending deliveries with a crate-owned cancellation/incomplete result rather than silently dropping them
5. stream-style lag must be explicit and bounded rather than hidden behind unbounded queues
6. `watch_status()` must route through the transfer-family adapter path, not bypass it
7. family separation must be explicit enough that later feature families do not overload one undifferentiated stream

---

## Affected Modules

- `src/lib.rs`
- `src/session/mod.rs`
- `src/session/actor.rs`
- `src/session/core.rs`
- `src/progress.rs`
- `src/session/runtime/events.rs`
- `src/session/runtime/adapter.rs`
- possibly new public event/adapter types under `src/session/`

Tests may live alongside the above modules.

---

## Agent-Sized Tasks

### Task 6B.1

Define the adapter/runtime boundary and family model.

Expected outcomes:

- `src/session/runtime/adapter.rs` exists
- family separation is explicit
- Story 6 event runtime remains the producer-side owner
- family-aware outward wrappers or registrations are defined above the Story 6 generic event substrate

### Task 6B.2

Bridge existing transfer progress callback behavior through the adapter layer.

Expected outcomes:

- `watch_status()` remains supported
- transfer progress is delivered through the transfer-family adapter path rather than by special-case direct plumbing

### Task 6B.3

Define cancellation semantics and Rust-side delivery-policy rules for outward delivery.

Expected outcomes:

- lagging consumers do not block the actor
- callback-style cancellation resolves pending deliveries with a crate-owned cancellation/incomplete result
- stream-style lag and detachment behavior are explicit

### Task 6B.4

Add focused tests and close the story.

Expected outcomes:

- tests cover ordering, isolation, family separation, lag signaling, and callback cancellation behavior
- Story 6B can be treated as the stable outward adapter baseline for later stories

---

## Acceptance Criteria

Story 6B is complete when:

1. Rust has an explicit outward adapter/callback staging layer above the event model.
2. `watch_status()` remains intact but is no longer the only architectural outward-delivery concept.
3. event-family separation is explicit enough for later feature families to add staged delivery without bypassing the runtime model.
4. family-aware outward wrappers or registrations exist above the Story 6 generic event substrate.
5. callback-style cancellation and any Rust-owned stream lag/backpressure behavior are defined and tested.
6. later features can build on the outward adapter layer instead of adding ad hoc actor callbacks.

---

## Verification Requirements

Because this is a Rust source-code story, every implementation slice must end with:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

At least one slice in the story should include focused tests for callback ordering and lagging-consumer behavior.

---

## Story Relationship To Later Work

Story 6B is the outward-staging follow-on to Story 6.

Later stories should consume it like this:

- Story 9 and Story 10 may expose sync/backup events through the adapter layer rather than inventing direct callback paths
- Story 11 mount/FUSE-facing events should build on the same outward staging principles
- later feature families can add richer outward delivery semantics without reopening the core event runtime
