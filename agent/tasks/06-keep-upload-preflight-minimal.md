# Task 06 - Keep Upload Preflight Minimal

## Goal
Avoid running heavy key-attribute preflight for uploads that do not require share-key/CR handling.

## Problem
`upload()` currently always calls `ensure_keys_attribute()` before requesting upload URL. This can add avoidable pre-upload delay for plain uploads.

Current call site:
- `megalib/src/fs/operations/upload.rs` (`upload`, unconditional `ensure_keys_attribute`)

## Required Changes
1. Make upload preflight conditional across all upload entrypoints:
   - `upload`
   - `upload_resumable`
   - `upload_from_bytes`
   - `upload_from_reader`
2. Centralize decision logic in one helper (for example `requires_share_preflight(parent)`), so all entrypoints follow the same rule.
3. For plain uploads (for example parent in own `/Root` and no share context), skip key-attribute preflight.
4. Only perform key/share preflight when needed:
   - parent has share context
   - CR mapping will be required
   - other explicit secure-share conditions
5. Preserve existing behavior for shared-folder uploads:
   - CR generation
   - key persistence path

## Suggested File Touchpoints
- `megalib/src/fs/operations/upload.rs`
- possibly `megalib/src/session/sharing.rs` helper usage for share-context detection

## Out of Scope
- Rewriting finalize upload protocol shape.

## Acceptance Criteria
1. Plain uploads do not invoke key-attribute preflight on hot path for any upload entrypoint.
2. Shared uploads still produce correct CR/share behavior for all entrypoints.
3. No regression for upload finalization and seqtag wait behavior.

## Validation
1. Add debug trace for decision branch:
   - `upload_preflight=skip` vs `upload_preflight=share-required`
2. Compare MITM sequence before/after:
   - fewer pre-`a:u` key requests for plain uploads.
3. Run:
   - `cargo build`
   - `cargo test --lib`

## Notes for Agent
- This task should improve plain upload latency without changing shared-folder correctness guarantees.
