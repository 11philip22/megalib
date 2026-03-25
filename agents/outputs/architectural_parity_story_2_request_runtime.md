# Story 2 Spec: Introduce Request Runtime Abstraction Under the Actor

Validated on 2026-03-25 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 2 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Unlike Story 1, this is a code-bearing story: it should introduce a real internal request-runtime boundary while keeping scope small enough for one PR.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Planned.

Story 2 is not complete until the request-runtime boundary exists in code, at least one read path and one mutating path use it, and the Story 2 acceptance criteria below pass.

---

## Story Goal

Introduce an internal request-runtime abstraction at `src/session/runtime/request.rs` so authenticated actor flows stop coupling directly to raw `ApiClient` request calls.

This story should create the first real architectural seam between:

- public async actor commands
- engine/runtime request policy
- low-level transport in `src/api/client.rs`

The seam must preserve current seqtag handling, current-state coordination, and error behavior.

---

## Why This Story Exists

Today, the actor owns ordering, but the request path is still transport-first:

- authenticated flows ultimately issue `api.request(...)` or `api.request_batch(...)`
- mutating operations then separately track seqtags and waiter behavior
- request semantics are spread across actor code, session helpers, and operation modules

Representative current hotspots:

- direct request batching in `src/session/core.rs`
- direct mutating requests in `src/fs/operations/dir_ops.rs`, `src/fs/operations/export.rs`, and `src/fs/operations/upload.rs`
- direct share-related requests in `src/session/sharing.rs`
- actor-owned seqtag waiter bookkeeping in `src/session/actor.rs`

Upstream parity target:

- the C++ SDK has a dedicated `RequestDispatcher`
- request batching, inflight retention, and retry semantics are runtime concerns rather than incidental transport usage

Story 2 does not try to replicate the full upstream dispatcher. It creates the first internal seam that later stories can extend.

---

## Scope

In scope:

- introduce `src/session/runtime/request.rs`
- define a minimal request-runtime API for authenticated actor-owned flows
- route one read path and one mutating path through the new boundary
- preserve seqtag and current-state behavior
- add targeted tests around the new boundary

Out of scope:

- full request queue ownership equivalent to upstream `RequestDispatcher`
- inflight request replay across restarts
- general retry scheduler policy
- persistence of request state
- migrating every direct request call site in the crate
- unauthenticated `src/public.rs` flows
- registration and pre-auth helper flows outside the authenticated actor

This is a seam-introduction story, not a full request-runtime parity story.

---

## Story 1 Constraints This Story Must Follow

Story 2 must follow the Story 1 baseline exactly:

- request runtime lives at `src/session/runtime/request.rs`
- `Session` remains the engine root
- `src/api/client.rs` remains transport-first
- actor ownership of authenticated mutable state remains single-owner
- `src/public.rs` remains outside the authenticated actor

If implementation pressure suggests violating any of these, Story 1 must be revised first.

---

## Current-State Preservation Rules

These are the invariants Story 2 must preserve:

1. The actor still owns seqtag waiter registration and resolution.
   Story 2 may centralize request submission, but `seqtag_waiters`, `current_seqtag`, and actor-side high-watermark logic must keep working the same way.

2. The actor still owns state-current transitions.
   `state_current` and `action_packets_current` remain coordinated by the existing session/actor logic.

3. Transport remains in `src/api/client.rs`.
   Story 2 may call into transport through a new internal boundary, but it must not move HTTP or raw JSON transport concerns into actor code.

4. Public API behavior stays stable.
   `SessionHandle` methods, return types, and error behavior must remain compatible.

---

## Design Decisions

### Decision 1. The request runtime is owned by `Session`

Implementation direction:

- add a `RequestRuntime` type in `src/session/runtime/request.rs`
- store it as session-owned runtime state rather than as a free-floating helper

Reason:

- request policy is engine behavior, not transport behavior
- later persistence and event stories will need engine-owned request metadata

### Decision 2. Seqtag waiters stay in the actor for Story 2

Implementation direction:

- `RequestRuntime` parses seqtag from the response and returns it in `RequestOutcome`
- actor remains responsible for waiter registration and high-watermark resolution

Reason:

- this keeps Story 2 small
- it avoids mixing request seam introduction with event or statecurrent redesign

Additional boundary rule:

- `RequestRuntime` may perform wire-format parsing for seqtag extraction
- `RequestRuntime` must not mutate `Session.current_seqtag`, `Session.current_seqtag_seen`, or actor waiter state

### Decision 3. Story 2 proves the seam with one read path and one mutating path

Recommended migration targets:

- read path: quota
- mutating path: create folder / mkdir

Reason:

- quota is simple and non-mutating
- mkdir exercises seqtag extraction and waiter handling
- both are meaningful without dragging in tree bootstrap, upload state, or share complexity

### Decision 4. Out-of-actor request flows remain unchanged in Story 2

Flows explicitly deferred:

- `src/public.rs`
- registration and auth helpers outside the authenticated actor
- larger transfer and share-specific request choreography

Reason:

- Story 2 should introduce the seam under the authenticated actor first

---

## Target Module Shape

Target file:

- `src/session/runtime/request.rs`

Recommended initial contents:

- `RequestRuntime`
- `RequestClass`
- `RequestEnvelope`
- `RequestOutcome`
- a private seqtag extraction helper local to request runtime
- a narrow error-preserving submission API over `ApiClient`

Suggested exact minimal API shape:

```rust
use serde_json::Value;

use crate::api::ApiClient;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestClass {
    ReadOnly,
    Mutating,
}

#[derive(Debug)]
pub(crate) enum RequestEnvelope {
    Single {
        class: RequestClass,
        payload: Value,
    },
    Batch {
        class: RequestClass,
        payloads: Vec<Value>,
    },
}

#[derive(Debug)]
pub(crate) struct RequestOutcome {
    pub(crate) response: Value,
    pub(crate) seqtag: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct RequestRuntime;

impl RequestRuntime {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) async fn submit(
        &mut self,
        api: &mut ApiClient,
        envelope: RequestEnvelope,
    ) -> Result<RequestOutcome>;

    pub(crate) async fn submit_single(
        &mut self,
        api: &mut ApiClient,
        class: RequestClass,
        payload: Value,
    ) -> Result<RequestOutcome>;

    pub(crate) async fn submit_batch(
        &mut self,
        api: &mut ApiClient,
        class: RequestClass,
        payloads: Vec<Value>,
    ) -> Result<RequestOutcome>;
}

impl RequestEnvelope {
    pub(crate) fn read(payload: Value) -> Self;
    pub(crate) fn mutating(payload: Value) -> Self;
    pub(crate) fn read_batch(payloads: Vec<Value>) -> Self;
    pub(crate) fn mutating_batch(payloads: Vec<Value>) -> Self;
}
```

Session integration for the first slice:

- `Session` should own `request_runtime: RequestRuntime`
- `Session::new_internal()` should initialize it with `RequestRuntime::new()`

Convenience wrapper rule:

- `submit(...)` remains the single underlying seam
- `submit_single(...)` and `submit_batch(...)` should be thin wrappers that construct `RequestEnvelope` and delegate to `submit(...)`
- migrated call sites in Story 2 should prefer the convenience wrappers for readability

Empty-batch rule:

- `submit_batch(...)` should normalize an empty batch to `RequestOutcome { response: Value::Array(vec![]), seqtag: None }`
- Story 2 should preserve current `ApiClient::request_batch(...)` behavior rather than introducing a new error case for empty batches

Seqtag handling rule for the first slice:

- `submit()` should extract seqtag internally and populate `RequestOutcome.seqtag`
- `submit()` should not update session state
- actor/session code should continue deciding whether and how returned seqtags update `current_seqtag`, `current_seqtag_seen`, and waiter registration

Recommended helper placement:

- define `fn extract_seqtag(response: &Value) -> Option<String>` as a private helper inside `src/session/runtime/request.rs`
- `submit()` should call that helper after transport submission succeeds
- the helper should stay transport/response-format focused and must not depend on `Session`

Migration rule for existing helper logic:

- Story 2 may duplicate the current seqtag parsing logic from `src/session/action_packets.rs` into `request.rs` for the first slice if that keeps scope smaller
- Story 2 should not widen scope by trying to fully centralize every seqtag concern into one shared utility module
- after Story 2 lands, a later cleanup slice may consolidate duplicated response-format parsing if it is still justified

Recommended non-goals for the initial module:

- no global queue scheduler yet
- no persistence coupling yet
- no public event stream yet
- no migration of all existing request call sites

---

## Proposed Internal Boundary

The boundary should look like this conceptually:

1. actor or session-owned logic builds a request description
2. `RequestRuntime` submits it through `ApiClient`
3. `RequestRuntime` returns a response plus any seqtag metadata
4. actor continues existing waiter/high-watermark handling for mutating calls

The important shift is:

- actor code stops deciding how raw request submission is performed
- actor code keeps deciding what to do with the semantic result

Story 2 ownership split:

- `RequestRuntime` submits transport work and returns `RequestOutcome`
- `RequestRuntime` owns seqtag parsing from response wire format
- actor/session code remains responsible for assigning `current_seqtag`, clearing `current_seqtag_seen`, and registering/resolving seqtag waiters
- convenience wrappers may improve call-site readability, but they must not introduce separate request semantics

Practical implementation note:

- for Story 2, response-format parsing can move into `request.rs` even if `src/session/action_packets.rs` still keeps its own helper for AP-side logic
- avoid a speculative shared helper module unless the first implementation actually needs one

That gives later stories a place to add:

- retry policy
- inflight tracking
- batching policy
- event emission
- persistence hooks

without reworking every command handler again.

---

## Initial Migration Slice

Story 2 should land in these phases.

### Phase 1. Introduce the module and boundary

Deliverables:

- add `src/session/runtime/request.rs`
- add the `RequestRuntime` type and minimal outcome types
- add `request_runtime: RequestRuntime` to `Session`
- wire it into session-owned state

Done when:

- the crate has a named internal request-runtime boundary and no public API changed

### Phase 2. Migrate one read path

Recommended target:

- quota flow

Done when:

- the quota request no longer issues raw transport calls directly from its current path
- behavior and returned values are unchanged

### Phase 3. Migrate one mutating path

Recommended target:

- create folder / mkdir flow

Done when:

- the mutating path uses the request runtime
- seqtag extraction and actor waiter resolution still behave as before

### Phase 4. Add focused tests

Minimum coverage:

- request-runtime read submission
- request-runtime mutating submission returning seqtag
- no regression in actor-side waiter and current-state behavior for the migrated mutating path

---

## Affected Modules

Primary write scope:

- `src/session/runtime/request.rs`
- `src/session/core.rs`
- `src/session/actor.rs`
- `src/api/client.rs`
- one read-path module
- one mutating-path module

Expected initial migration targets:

- `src/fs/operations/quota.rs`
- `src/fs/operations/dir_ops.rs`

Secondary read-only verification context:

- `src/session/action_packets.rs`
- `src/session/sc_poller.rs`

---

## Acceptance Criteria

Story 2 is complete when:

- `src/session/runtime/request.rs` exists
- `Session` owns `request_runtime: RequestRuntime`
- authenticated actor-owned request submission has a named internal boundary
- one read path uses the boundary
- one mutating path uses the boundary
- migrated mutating flow still integrates with existing seqtag waiter handling
- no public Rust API changed
- no unauthenticated/public-link flows were unintentionally rerouted
- targeted tests cover the new seam and migrated behavior

---

## Verification Plan

Required checks for Story 2:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Additional targeted validation:

- verify the migrated mutating path still advances seqtag/high-watermark behavior correctly
- verify the migrated read path has identical success and error behavior
- review diff for any new direct `ApiClient` coupling added to actor-owned flows

---

## Agent-Sized Task Breakdown

### Task 2.1

Objective:

- add the request-runtime module and minimal internal API

Write scope:

- `src/session/runtime/request.rs`
- `src/session/mod.rs`
- `src/session/core.rs`

Done when:

- the request-runtime type exists and can submit transport work internally

### Task 2.2

Objective:

- migrate one read path through the new boundary

Recommended write scope:

- `src/fs/operations/quota.rs`
- `src/session/runtime/request.rs`
- `src/session/core.rs`

Done when:

- the selected read path no longer performs raw submission the old way

### Task 2.3

Objective:

- migrate one mutating path through the new boundary

Recommended write scope:

- `src/fs/operations/dir_ops.rs`
- `src/session/runtime/request.rs`
- `src/session/actor.rs`
- `src/session/core.rs`

Done when:

- the selected mutating path uses request runtime and still works with existing seqtag waiter handling

### Task 2.4

Objective:

- add focused tests for the seam and migrated paths

Write scope:

- touched module test blocks

Done when:

- tests protect the initial seam from regression

---

## Risks

Main risks:

- moving too much seqtag logic into Story 2 and accidentally widening scope
- creating a nominal `RequestRuntime` that is just a thin wrapper with no real seam value
- mixing public-link or pre-auth flows into the first authenticated request-runtime slice
- changing error mapping or current-state behavior while trying to centralize submission
- dropping batch support from the API shape and forcing a second seam redesign when batch callers migrate later

Risk control:

- keep seqtag waiter ownership in the actor
- migrate only quota and mkdir in the first slice
- do not touch `src/public.rs`
- do not expand into persistence or event emission yet
- keep batch support in `RequestEnvelope`, but defer batch caller migration in the first implementation slice
- normalize empty batch input rather than inventing stricter batch semantics in Story 2
- keep seqtag extraction helper local to `request.rs` in the first slice to avoid turning Story 2 into a cross-module utility refactor

---

## Open Questions

These do not block the Story 2 spec, but implementation should answer them explicitly in code review:

1. should `RequestRuntime` hold future queue/retry state immediately, or start stateless and become stateful in later stories
2. should batch submission live in the same initial type or behind a second helper inside `request.rs`
3. whether response-to-seqtag extraction belongs fully inside request runtime or remains split with existing session helpers for the first slice

---

## Recommended Next Step

Treat this document as the coding contract for Story 2.

The next implementation slice should be:

- Task 2.1 plus Task 2.2 in one PR if the seam stays small
- otherwise Task 2.1 first, then Task 2.2 and Task 2.3 as the next slice
