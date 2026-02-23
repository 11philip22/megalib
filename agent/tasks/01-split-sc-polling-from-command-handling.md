# Task 01 - Split SC Polling From Command Handling

## Goal
Make uploads/downloads and other user commands independent from SC long-poll waits.

## Problem
`SessionActor::run` currently multiplexes command handling and SC polling in one loop. A long SC wait can delay command processing.

Key hot path today:
- `megalib/src/session/actor.rs` (`run`, SC timeout branch around the `poll_action_packets_once_with_seqtags()` call)

## SDK Alignment Note
SDK behavior goal to match: SC handling should not stall command progress.
- SDK implementation shape is a single core loop with separate request queues (`sendPendingRequests` and `sendPendingScRequest`), not a separate SC thread.
- This task intentionally uses a dedicated SC worker in megalib as an implementation choice for the same responsiveness outcome.
- If strict structural parity is later required, replace the dedicated worker with an equivalent non-blocking SC state machine in the main loop.

## Required Changes
1. Introduce a dedicated SC worker task (`ScPoller`) that owns SC network polling cadence.
2. Keep command handling in `SessionActor` and receive SC events via channel.
3. Move SC transport/backoff state to poller:
   - `sn`
   - `wsc_url`
   - catch-up mode flag
   - delay/backoff timer
4. Define a message type from poller to actor, for example:
   - `ScBatch { packets, seqtags, next_sn, next_wsc_url, ir, source }`
5. In actor loop, replace timer-driven SC poll branch with:
   - `cmd_rx.recv()` for commands
   - `sc_event_rx.recv()` for SC/AP events
6. Preserve SDK-style AP/command response coupling:
   - when SC/AP batch reaches end-of-object/end-of-batch, run a seqtag advancement step equivalent in intent to SDK `sc_checkSequenceTag`.
   - ensure command responses associated with the latest AP seqtag are not starved behind polling refactor boundaries.
7. On shutdown:
   - stop actor cleanly
   - signal poller stop
   - await poller task join

## Suggested File Touchpoints
- `megalib/src/session/actor.rs`
- new file: `megalib/src/session/sc_poller.rs` (or equivalent module)
- `megalib/src/session/mod.rs`

## Out of Scope
- Changing key-sync behavior (covered by Task 02+).
- Changing upload preflight rules (Task 06).

## Acceptance Criteria
1. A command can be accepted/started while SC long-poll is in flight.
2. No command path directly awaits SC long-poll transport calls.
3. SC backoff and reconnect behavior remains functional.
4. Seqtag-associated command response progression semantics are preserved (SDK parity intent).
5. Shutdown does not leak poller tasks.

## Validation
1. Add debug logs/timestamps to show interleaving:
   - command receipt
   - SC poll start/end
2. Confirm command latency is not bounded by SC timeout.
3. Confirm AP end-of-batch processing still advances seqtag-related command response handling.
4. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- Keep behavior-preserving defaults first. Do not change action packet semantics in this task.
- Avoid introducing lock contention between actor and poller. Prefer message passing over shared mutable state.
- Document clearly in code comments that this is behavioral parity with SDK, not structural parity.
