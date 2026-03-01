# Task 06 - Keep Upload Hot Path SDK-Parity Minimal

## Goal
Match SDK behavior: do not run key-attribute preflight from upload entrypoints before requesting upload URL (`a:"u"`).

## SDK Reference
- Upload URL request is direct (`CommandPutFile` sends `a:"u"` with size/target); no `^!keys` bootstrap in this step.
  - `sdk/src/commands.cpp` (`CommandPutFile::CommandPutFile`)
- Share/CR handling is attached at putnodes (`a:"p"`) time via `ShareNodeKeys`.
  - `sdk/src/commands.cpp` (`CommandPutNodes`, `snk.get(...)`)
  - `sdk/src/sharenodekeys.cpp`
- Key sync (`pk` / pending keys) is handled by SC/action-packet flow, not upload preflight.
  - `sdk/src/megaclient.cpp` (`sc_pk`)

## Problem
Any synchronous `ensure_keys_attribute()` on upload entrypoints adds pre-upload latency and diverges from SDK flow.

## Required Changes
1. Remove upload-time key preflight from all upload entrypoints:
   - `upload`
   - `upload_resumable`
   - `upload_from_bytes`
   - `upload_from_reader`
2. Do not call `ensure_keys_attribute()` from upload hot path, including shared-parent uploads.
3. Keep upload pre-`a:"u"` checks limited to target validation/access only (SDK-style intent).
4. Keep CR/share behavior in upload finalization (`a:"p"`) path:
   - reuse available share context
   - include CR when share key/context exists
   - preserve seqtag/finalization behavior
5. Keep key initialization in lifecycle/share-management flows instead:
   - login/bootstrap/refresh
   - explicit share/export operations (`ensure_share_keys_ready`)

## Suggested File Touchpoints
- `megalib/src/fs/operations/upload.rs`
- optional: upload finalization helper path if needed for clearer CR behavior

## Out of Scope
- Rewriting finalize upload protocol shape.
- Reworking SC/action-packet architecture (covered by other tasks).

## Acceptance Criteria
1. No upload entrypoint performs `ensure_keys_attribute()` before `a:"u"`.
2. Plain uploads and shared uploads both avoid key-bootstrap work on the pre-`a:"u"` hot path.
3. Shared uploads still keep correct CR/share behavior at `a:"p"` finalize stage.
4. No regression for upload finalization and seqtag wait behavior.

## Validation
1. Add/adjust debug trace to show SDK-style upload preflight policy (no key bootstrap on upload path).
2. MITM compare before/after:
   - no upload-triggered `^!keys`/`upv`/`*keyring` bootstrap burst immediately before `a:"u"`.
3. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- Prefer strict SDK parity over conditional upload preflight logic.
- If a future shared-edge case appears, fix it in finalize/share logic, not by reintroducing hot-path key bootstrap.
