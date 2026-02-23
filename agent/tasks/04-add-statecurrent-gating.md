# Task 04 - Add `statecurrent`-Style Gating

## Goal
Prevent startup catch-up from triggering unnecessary key network work before state is current.

## SDK Reference Behavior
SDK skips pending-key fetch triggered by AP `pk` until state is current.
- SDK sets `statecurrent = true` when initial AP catch-up batch is done (`!insca_notlast`) and node state is ready.
- SDK applies seqtag high-watermark gating to `actionpacketsCurrent`, not to `statecurrent`.

## Problem
During new-session catch-up, megalib can run key work too early, increasing startup noise and delaying operations.

## Required Changes
1. Add a `state_current` flag to megalib session runtime state.
2. Initialization:
   - `false` after login/session restore.
   - `false` after refresh/fetchnodes reset.
3. Add explicit readiness inputs for `state_current` (do not use only `ir == false`):
   - `nodes_state_ready`: true after refresh/fetchnodes result has been parsed/applied locally.
   - `sc_batch_catchup_done`: true when current SC/AP catch-up batch is fully drained (`ir`/`insca_notlast` equivalent complete for current batch).
4. Transition to `true` only when both readiness inputs are true:
   - `state_current = nodes_state_ready && sc_batch_catchup_done`
5. Add a separate `action_packets_current` style flag for SDK parity:
   - gate this flag with seqtag high-watermark catch-up (`scTagNotCaughtUp` equivalent).
   - do not block `state_current` on seqtag high-watermark.
6. Gate key work:
   - defer/skip AP-triggered pending-key fetch until `state_current == true`.
7. On the transition edge `state_current: false -> true`, apply SDK-style account gating first:
   - run startup key reconciliation only for full-account sessions.
   - run startup key reconciliation only when key manager is upgraded/ready (generation > 0 equivalent).
   - when not upgraded, follow upgrade/init path semantics instead of forcing pending-key reconciliation.
8. If gated-in (full-account + upgraded), run one startup key reconciliation pass even if no AP `pk` was deferred:
   - SDK intent reference: when becoming current, it proactively triggers contact key fetch + pending key processing.
   - megalib equivalent should trigger:
     - contact key refresh path (or current best equivalent)
     - one pending-key fetch/promotion pass
9. On security-upgrade completion (generation transition `0 -> >0`) while session is full-account:
   - explicitly trigger one post-upgrade reconciliation pass equivalent to SDK:
     - contact key refresh (`fetchContactsKeys` equivalent)
     - pending-key fetch/promotion (`sc_pk` equivalent)
   - do not require a new AP `pk` signal for this post-upgrade pass.
10. Once transitioning to `true`, also run deferred reconciliation if any key work was queued during catch-up.

## Suggested File Touchpoints
- `megalib/src/session/core.rs`
- `megalib/src/session/actor.rs`
- `megalib/src/session/action_packets.rs`
- `megalib/src/fs/operations/tree.rs` (refresh state reset)

## Out of Scope
- Debounce persist details (Task 05).

## Acceptance Criteria
1. During startup catch-up, AP `pk` does not immediately trigger pending-key network fetch.
2. `state_current` does not flip true from SC `ir` alone when node state is not yet ready.
3. `state_current` can flip true before seqtag high-watermark catch-up completes (SDK parity).
4. `action_packets_current` remains false while seqtag high-watermark catch-up is pending.
5. On `state_current=false -> true`, startup key reconciliation runs only when session is full-account and key manager is upgraded.
6. On `state_current=false -> true`, non-upgraded sessions follow upgrade/init path semantics (no forced pending-key reconciliation).
7. If gated-in, startup key reconciliation runs once even when no `pk` AP was observed.
8. After upgrade completion (`generation 0 -> >0`), one explicit contact-key + pending-key reconciliation pass runs even without new `pk` AP.
9. Once `state_current` flips true, deferred key work executes exactly once per deferred burst.
10. Normal mid-session `pk` behavior still works.

## Validation
1. Add logs:
   - `state_current=false -> true`
   - deferred key-work queued/executed counts
2. Validate startup sequence with MITM capture.
   - include a case where previous seqtag/high-watermark is ahead, and verify:
     - `state_current` can become true when batch catch-up is done and node state is ready.
     - `action_packets_current` remains false until high-watermark catch-up is satisfied.
3. Validate security-upgrade flow:
   - when generation becomes > 0, verify one explicit contact-key + pending-key reconciliation pass runs without waiting for new AP `pk`.
4. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- Keep this gate narrowly scoped to AP-triggered key jobs. Do not block explicit user-triggered calls.
