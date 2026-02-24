# Task 03 - Implement SDK-Style `pk` Trigger

## Goal
Match SDK behavior: pending-key retrieval should be triggered by AP `a:"pk"` events and queued asynchronously.

## SDK Reference Behavior
- `sc_pk()` queues `CommandPendingKeys`.
- It does not run full heavy key sync inline.

## Problem
Current megalib key handling can run broad key sync on many AP changes, causing unnecessary `pk`/`uga`/`upv` bursts.

## Required Changes
1. Detect explicit AP `a:"pk"` signals during AP parsing.
2. Apply SDK-style upgraded-account guard before scheduling:
   - only schedule pending-key fetch when account key manager is upgraded/ready (SDK equivalent: `mKeyManager.generation() > 0`).
   - if not upgraded, ignore `pk` trigger.
3. Emit a focused deferred job:
   - `KeyWork::PendingKeysFetch`
4. Keep SDK-like queueing semantics:
   - enqueue pending-key fetch work through the normal command lane (non-blocking AP path).
   - do not run pending-key network flow inline in AP dispatch.
5. Optional coalescing is allowed only if behavior-equivalent:
   - it must not suppress required pending-key fetch/deletion cycles that SDK would perform.
   - default behavior should mirror SDK trigger semantics first.

## Suggested File Touchpoints
- `megalib/src/session/action_packets.rs`
- `megalib/src/session/actor.rs` (or key-work coordinator)
- `megalib/src/session/key_sync.rs` (`fetch_pending_keys`, promotion path)

## Out of Scope
- Startup/catch-up gating (Task 04).
- Debounce persist strategy (Task 05).

## Acceptance Criteria
1. AP `pk` generates pending-key work request.
2. AP `pk` does not schedule pending-key fetch when account is not upgraded.
3. AP path remains non-blocking; pending-key work is executed asynchronously via command lane.
4. No regressions for pending-share promotions after pending keys arrive.

## Validation
1. Add counters:
   - `ap_pk_seen`
   - `pending_keys_fetch_queued`
   - `pending_keys_fetch_started`
2. Use MITM capture/replay or integration path to verify AP `pk` triggers queued async pending-key work without inline blocking.
3. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- Keep failure handling best-effort: temporary fetch errors should not poison future `pk` triggers.
