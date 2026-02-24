# Task 05 - Debounce and Coalesce `upv` Persists

## Goal
Reduce repeated `upv` writes caused by bursty AP/key events.

## Problem
Multiple key-affecting events in short succession can call `persist_keys_with_retry()` repeatedly, producing avoidable `upv` bursts.

## Required Changes
1. Add a key-persist scheduler state in runtime:
   - `keys_persist_dirty`
   - `keys_persist_inflight`
   - optional `keys_persist_deadline` only if a timed mode is enabled
2. Replace immediate persist calls from AP/key workflows with coalesced scheduling:
   - mark dirty
   - schedule a single flush at the next safe scheduler turn (event-burst coalescing by default)
3. Flush rules:
   - if inflight, keep dirty and run one additional flush after completion.
   - if shutdown requested, force immediate flush or explicitly document skipped flush behavior.
4. Keep downgrade/error handling semantics from `persist_keys_with_retry()` unchanged.
5. Do not require fixed wall-clock delay for correctness. If a timed debounce is added, gate it behind explicit config/feature flag.

## Suggested File Touchpoints
- `megalib/src/session/key_sync.rs`
- `megalib/src/session/actor.rs` (or scheduler module)
- `megalib/src/session/core.rs` (runtime state fields if needed)

## Out of Scope
- Choosing which operations are key-related (Tasks 02-04 already define signals).

## Acceptance Criteria
1. Burst AP/key events produce coalesced persists (not one persist per event).
2. Persist never runs concurrently more than once.
3. Final state remains correct after burst (no dropped updates).

## Validation
1. Add counters:
   - `persist_requested`
   - `persist_started`
   - `persist_coalesced`
2. Verify reduced `upv` request count in MITM capture near upload start.
3. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- Keep debounce implementation simple and deterministic first; avoid timer complexity that can stall shutdown.
