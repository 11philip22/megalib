# Task 07 - Align SC Timeout Policy With SDK Intent

## Goal
Use dedicated SC timeout policy that matches SDK intent while keeping command lane non-blocking.

## Problem
Timeout value tuning alone does not fix stalls, but SC should still have its own channel policy and retry behavior.

## Required Changes
1. Keep SC transport on dedicated request kind and dedicated worker (from Task 01).
2. Set explicit SC timeout policy separate from API JSON and transfers.
3. Separate SC long-poll policy from user-alert catch-up policy:
   - SC long-poll (`wsc`/SC channel equivalent): use dedicated long timeout policy (`SCREQUESTTIMEOUT` intent, ~40s).
   - user-alert catch-up request (`sc?c=50` equivalent): do not force long-poll timeout semantics; keep distinct "no long-poll timeout" behavior.
   - keep timeout semantics distinct, but align retry/backoff coupling with SDK SC channel behavior.
4. Align retry/backoff coupling with SDK:
   - SC long-poll and user-alert catch-up participate in the same SC channel backoff flow (SDK-style shared `btsc` intent).
   - avoid introducing independent retry loops that can drift relative to SDK cadence.
5. Match SDK intent:
   - long-poll timeout appropriate for SC channel (SDK reference constant: `SCREQUESTTIMEOUT = 400 ds`, about 40 seconds)
   - robust reconnect/backoff on transient failures
6. Ensure timeout/backoff handling in SC worker does not block command processing.

## Suggested File Touchpoints
- `megalib/src/http.rs` (`RequestKind::ScPoll` policy)
- `megalib/src/api/client.rs` (`poll_sc`, `poll_user_alerts`)
- `megalib/src/session/sc_poller.rs` (from Task 01)

## Out of Scope
- Architectural split itself if not already done (Task 01 prerequisite).

## Acceptance Criteria
1. SC timeout policy is defined independently from command API calls.
2. User-alert catch-up request policy is explicitly separate from SC long-poll policy.
3. SC/user-alert retry backoff coupling follows one shared SC-channel backoff flow (SDK parity intent).
4. SC timeout/retry does not add latency to command queue.
5. SC reconnect behavior remains stable under transient network failures.

## Validation
1. Simulate slow/no SC response and verify command responsiveness.
2. Simulate user-alert catch-up request and verify it does not inherit SC long-poll timeout semantics.
3. Simulate user-alert catch-up request failures and verify shared SC-channel backoff behavior is applied.
4. Confirm expected backoff logs from SC worker only.
5. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- Treat this as a policy hardening task after architecture split, not as the primary stall fix.
