# Task 02 - Make Action Packet Handling Non-Blocking

## Goal
Ensure AP dispatch never performs heavy network/persist work inline.

## Problem
`dispatch_action_packets()` currently can call key-sync logic that performs network and persistence in the same processing path.

Key hot path today:
- `megalib/src/session/action_packets.rs` (`dispatch_action_packets`, call to `handle_actionpacket_keys`)
- `megalib/src/session/key_sync.rs` (`handle_actionpacket_keys`, `sync_keys_attribute`, `promote_pending_shares`, `persist_keys_with_retry`)

## Required Changes
1. Refactor AP dispatch to split into two phases:
   - Phase A: parse/apply local node/contact changes only.
   - Phase B: emit deferred key-work signals (no network here).
2. Replace direct inline key-sync calls with a deferred work queue event, for example:
   - `KeyWork::FromActionPacket { share_changed, changed_handles, stale_key_attrs, saw_pk }`
3. Ensure AP processing remains idempotent if batches are retried.
4. Keep seqtag observation behavior intact.
5. Do not break AP/command response ordering semantics:
   - deferred key-work scheduling must not delay or reorder seqtag progression hooks used to advance related command responses.

## Suggested File Touchpoints
- `megalib/src/session/action_packets.rs`
- `megalib/src/session/actor.rs` (or key-work scheduler module)
- `megalib/src/session/key_sync.rs` (entrypoint for deferred work execution)

## Out of Scope
- Detailed `pk` semantics and gating (Task 03/04).
- Debounce/coalesce persist strategy (Task 05).

## Acceptance Criteria
1. AP dispatch path does not directly call key network APIs.
2. AP dispatch path does not directly call `persist_keys_with_retry`.
3. Key-related work still happens eventually through deferred queue.
4. Existing node/contact AP behavior is unchanged.
5. Seqtag-driven command response progression semantics are unchanged.

## Validation
1. Add instrumentation:
   - AP parse/apply duration
   - deferred job enqueue count
2. Verify no long blocking awaits inside AP dispatch path.
3. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- Preserve ordering guarantees relevant to seqtags.
- If needed, add a bounded key-work queue with drop/coalesce rules to avoid unbounded growth.
