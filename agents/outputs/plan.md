# Plan: Close Rust/C++ Parity Gaps for SC Catch-up, SC Failure Semantics, Share-Key Verification, and
Pending-Keys ACK

## Summary

Implement strict behavioral parity with the C++ SDK for the four identified gaps:

1. Use /sc/wsc for SC catch-up polling (not /sc).
2. Add C++-style SC failure handling branches (terminal stop states, API_ETOOMANY reload/reset behavior, and
    richer classification vs generic backoff).
3. Enforce C++-equivalent default verification gate for share-key promotion (SEEN baseline, VERIFIED when
    manual verification is enabled).
4. Send immediate pending-keys delete ACK (pk with d=lastcompleted) after successful processing/persist,
    instead of waiting for next cycle.

Chosen defaults (from your answers):

- Parity target: Strict parity
- Verification gate: Match C++ default
- PK deletion timing: Immediate post-commit

## Scope and Files

Primary Rust files to modify:

- /Users/woldp001/Documents/Devel/mega/megalib/src/api/client.rs
- /Users/woldp001/Documents/Devel/mega/megalib/src/session/sc_poller.rs
- /Users/woldp001/Documents/Devel/mega/megalib/src/session/actor.rs
- /Users/woldp001/Documents/Devel/mega/megalib/src/session/core.rs
- /Users/woldp001/Documents/Devel/mega/megalib/src/session/key_sync.rs
- /Users/woldp001/Documents/Devel/mega/megalib/src/session/action_packets.rs
- Tests in existing module test files adjacent to the above (unit + integration style where currently used).

No workspace/module reorganization. No public crate API break unless explicitly required.

## Implementation Design

### 1. SC catch-up endpoint parity (/sc/wsc)

### Goal

Match C++ catch-up routing semantics:

- Catch-up polls go to /sc/wsc.
- Normal long-poll uses returned w URL or /wsc.

### Changes

1. In ApiClient::poll_sc:

- Replace current use_sc branch that picks SC_URL with explicit catch-up URL constant:
    - add SC_WSC_URL = "https://g.api.mega.co.nz/sc/wsc".
- Branching:
    - poll_catchup=true => base SC_WSC_URL
    - otherwise => wsc_base.unwrap_or(WSC_URL)

2. Keep existing sn, sid, and response parsing contract unchanged.

### Acceptance

- When sc_catchup true, request URL starts with /sc/wsc.
- When false, it uses w if present; otherwise /wsc.

———

### 2. SC failure semantics parity (beyond generic backoff)

### Goal

Mirror C++ control decisions in Rust polling pipeline:

- Distinguish terminal SC errors vs retryable transient failures.
- Trigger reload/reset on API_ETOOMANY.
- Stop SC channel on session-invalid or fatal security-like failures.

### Changes

1. Introduce SC poll outcome classification in ApiClient::poll_sc and/or ScPoller layer:

- Retryable: API_EAGAIN, API_ERATELIMIT, transport/network transient.
- Reload-required: API_ETOOMANY.
- Terminal-stop: API_ESID (and any configured fatal equivalents).
- Unexpected API errors: treat as terminal-stop (strict parity bias).

2. Add poller control/event surface:

- Extend ScPollerEvent with explicit failure event variants (e.g. ScFatalStop, ScReloadRequired,
ScTransientFailure).
- Do not silently absorb all failures into backoff.

3. Actor handling:

- On ScReloadRequired => trigger session refresh/reset path equivalent to “reload local state” behavior.
- On ScFatalStop => clear/disable SC polling state until re-auth/refresh.
- On retryable failures => retain exponential backoff behavior.

4. Preserve existing backoff mechanics for transient failures, but gate them behind classification.
5. Add explicit logging fields for category/reason to ease parity debugging.

### Acceptance

- API_ETOOMANY no longer just backs off; it triggers explicit reload path.
- API_ESID (or mapped terminal errors) transitions poller/session to stopped SC state.
- Retryable failures still back off.

———

### 3. Share-key promotion verification gate parity

### Goal

Match C++ default policy:

- Without manual verification: require Ed25519 authring >= SEEN.
- With manual verification: require verified credentials (strict).
- Avoid promoting keys when verification preconditions fail.

### Changes

1. In key_sync.rs promotion flow:

- Replace current default gate logic (strict mainly when manual_verification true) with a two-level policy:
    - manual_verification=false:
        - require Ed25519 authring state at least Seen for recipient.
    - manual_verification=true:
        - require verified state for required rings/identity (existing strict checks retained, aligned
        consistently).
- Keep CV warning behavior aligned: set warning when blocked by verification policy.

2. Ensure helper(s) for authring threshold checks are centralized (avoid duplicated conditional logic in
    outshare/inshare paths).

### Acceptance

- Unverified/unknown contacts are blocked by default unless minimum C++-equivalent trust level is met.
- Manual verification mode remains stricter than default mode.

———

### 4. Immediate pending-keys delete ACK (pk with d)

### Goal

Match C++ post-processing behavior:

- After successfully processing pending keys and persisting resulting key-manager changes, immediately send
pk with d=lastcompleted to delete processed server-side entries.

### Changes

1. In fetch_pending_keys handling path (promote_pending_shares_internal):

- Track fetched lastcompleted token for current batch.
- If batch produced state changes and persist/commit succeeds:
    - immediately send delete ACK request {"a":"pk","d":"<token>"}.
- If persist fails:
    - do not ACK delete; keep token for retry safety.

2. Add dedicated helper:

- ack_pending_keys_processed(last_completed: &str) -> Result<()>
- Best-effort retry policy consistent with existing deferred work queue (strict parity still allows non-
fatal logging if delete fails after local success).

3. Integrate with deferred key work queue:

- If immediate ACK fails, enqueue targeted retry work item (or retain token for next cycle) so deletion
eventually occurs.

### Acceptance

- Successful local processing + persist triggers immediate delete ACK in same logical cycle.
- Failures do not lose token nor incorrectly acknowledge uncommitted state.

## Public API / Interface Impact

Expected external/public API changes: None (internal behavior only).

Internal interface additions likely:

- New SC poll failure/event enums in session polling internals.
- New helper for pending-keys delete ACK.

If any public type signatures must change, they will be minimized and documented explicitly in code
comments/changelog notes.

## Test Plan

### Unit Tests

1. SC URL selection

- poll_sc chooses /sc/wsc in catch-up mode.
- poll_sc chooses w URL or /wsc in normal mode.

2. SC failure classification

- Map API codes to expected categories:
    - -3/-4 retryable
    - API_ETOOMANY reload-required
    - API_ESID terminal-stop

3. Verification gating

- Default mode blocks recipients below SEEN.
- Manual mode requires verified status and sets CV warning when blocked.
- Positive path promotes when trust criteria satisfied.

4. Pending-keys ACK flow

- On successful processing+persist, ACK is sent immediately with d.
- If persist fails, ACK is not sent.
- If ACK fails, retry path retains recoverability.

### Integration/Behavioral Tests

1. End-to-end SC catch-up cycle:

- refresh() sets catch-up flags; first poll uses /sc/wsc; state transitions to current after ir drain.

2. AP a:"pk" handling:

- queued fetch only when generation > 0 and state_current.
- immediate delete ACK after successful promotion/persist.

3. Regression tests around existing seqtag/state_current transitions to ensure no behavior regressions.

### Verification Commands (per AGENTS.md)

Because Rust sources are modified, run:

1. cargo fmt --all
2. cargo clippy --all-targets --all-features -- -D warnings
3. cargo test --all

## Risks and Mitigations

- Risk: Overly aggressive terminal-stop mapping could stall polling.
    - Mitigation: strict code-to-code parity table from C++ error branches and explicit tests per code.
- Risk: Immediate pk d ACK race with persist/version conflicts.
    - Mitigation: send ACK only after successful persist; queue retry on ACK failure.
- Risk: Verification gate tightening may delay some legacy promotions.
    - Mitigation: CV warning path and explicit logs for blocked promotions.

## Assumptions

1. Rust should prioritize C++ parity over preserving current Rust behavior where they differ.
2. No public API behavior contract guarantees current looser verification semantics.
3. Existing session actor/deferred queue is the right place for retry orchestration (no new subsystem
    needed).
4. API_ETOOMANY handling in Rust should trigger refresh/reload equivalent to C++ fetchnodes reset behavior,
    implemented via existing Rust refresh path rather than duplicating C++ internals 1:1.