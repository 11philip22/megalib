# Error Handling Policy (megalib)

Scope: library and API-layer error design in `src/`.

## MUST
1. Return crate-level `Result<T>` (`MegaError`) from fallible public library APIs.
Evidence: `src/error.rs` (`pub type Result<T> = ...`), `src/lib.rs` re-export, `src/api/client.rs`.
How to verify: `rg -n "pub .*-> .*Result<" src`.

2. Keep core error taxonomy centralized in `MegaError` and derived via `thiserror::Error`.
Evidence: `src/error.rs`.
How to verify: `rg -n "thiserror::Error|derive\\(Error" src/error.rs`.

3. Use `#[from]` conversions for upstream parsing/transport errors where direct propagation is intended.
Evidence: `src/error.rs` (`reqwest::Error`, `serde_json::Error`, `base64::DecodeError`).
How to verify: `rg -n "#\\[from\\]" src/error.rs`.

4. Error messages SHOULD be treated as unstable and may change without notice; documentation and examples SHOULD demonstrate matching on variants/codes instead of strings.

    **Evidence:**
    - Variant/code-based handling exists (`ApiErrorCode`, `MegaError::ApiError`).

    **How to verify:**
    - Ensure docs/examples do not show `if err.to_string().contains(...)` patterns.

5. Treat malformed/unexpected API payload shapes as `MegaError::InvalidResponse`.
Evidence: `src/api/client.rs`.
How to verify: `rg -n "InvalidResponse" src/api/client.rs`.

6. Keep EAGAIN retry handling with bounded exponential backoff and return `MegaError::ServerBusy` when exhausted.
Evidence: `src/api/client.rs` (`ApiErrorCode::Again`, `delay_ms`, `max_attempts`, `ServerBusy`).
How to verify: `rg -n "Again|ServerBusy|delay_ms|max_attempts" src/api/client.rs`.

7. Apply request-specific timeout/redirect policy via `RequestKind` + `RequestPolicy`.
Evidence: `src/http.rs`.
How to verify: `rg -n "enum RequestKind|struct RequestPolicy|timeout|max_redirects" src/http.rs`.

8. Missing required runtime state (e.g., session ID, SC sequence) MUST return a stable, structured error shape.

    - Do not require callers to match on error strings.
    - `MegaError::Custom(String)` MAY be used only as a temporary/internal placeholder; recurring or user-actionable cases MUST be promoted to a dedicated `MegaError` variant.

    **Evidence:**
    - Current missing-state paths use `MegaError::Custom` messages (`src/api/client.rs`: “Missing SC sequence number”, “Session ID not set”).

    **How to verify:**
    - If a missing-state error is referenced in docs, examples, or caller handling, introduce a dedicated variant and update call sites.

9. Keep deterministic error-code mapping covered by unit tests.
Evidence: `src/api/error.rs` tests.
How to verify: `cargo test api::error`.

10. Errors MUST be machine-actionable via structured variants/codes; users MUST NOT be expected to parse error message strings.

    - Public error messages are for humans (debugging), not control flow.
    - Any behavior that callers may need to branch on MUST be represented as:
        - a dedicated `MegaError` variant, and/or
        - a typed error code (e.g., `ApiErrorCode`), and/or
        - structured fields on the error variant.

    **Evidence:**
    - Typed API mapping exists via `ApiErrorCode` and `MegaError::ApiError { code, message }` (`src/api/error.rs`, `src/api/client.rs`).

    **How to verify:**
    - Review new errors: if caller branching is implied, require a variant/code instead of relying on message text.

11. Library code MUST NOT implement control flow by parsing error strings (e.g., `to_string().contains(...)`) outside of tests/examples.

    **How to verify:**
    - `rg -n "to_string\\(\\)\\.contains\\(|contains\\(.*MegaError" src`

12. Errors SHOULD preserve a causal chain (“sub-errors”) using `source`/`#[source]` so debugging can inspect the full chain.

    - When mapping an upstream error into `MegaError`, prefer storing it as a source (e.g., `#[from]` or `#[source]`) rather than discarding it.
    - Avoid converting upstream errors into plain strings when the underlying error type can be preserved.

    **Evidence:**
    - Existing `#[from]` usage in `src/error.rs` preserves sources (`reqwest::Error`, `serde_json::Error`, etc.).

    **How to verify:**
    - Ensure new `MegaError` variants carrying upstream failures include a `source` error.
    - Spot-check: `rg -n "\\#\\[source\\]|source:|\\#\\[from\\]" src/error.rs src`

13. When errors cross subsystem boundaries (HTTP ↔ API ↔ session), errors SHOULD capture enough context to debug without reproducing.

    - Prefer adding structured context fields (e.g., `RequestKind`, endpoint/operation name, retry attempt) to error variants.
    - If backtraces are enabled in this crate, boundary errors SHOULD capture a `std::backtrace::Backtrace`.

    **Evidence:**
    - Request classification already exists (`RequestKind`, `RequestPolicy`) in `src/http.rs`.

    **How to verify:**
    - Review boundary `map_err`/`?` sites: ensure context is added (fields or `.context(...)`-equivalent).
    - If using backtraces: ensure `Backtrace` is stored on boundary variants and printed in debug logs.

## SHOULD
1. Prefer dedicated `MegaError` variants when a `Custom(String)` condition becomes recurring/domain-significant.
Evidence: `src/error.rs` includes both dedicated variants and `Custom(String)`.
How to verify: `rg -n "Custom\\(|enum MegaError" src/error.rs src`.

2. Preserve structured tracing around API/network errors to aid production debugging.
Evidence: `src/api/client.rs` uses `tracing::{info_span, trace}` around request failure paths.
How to verify: `rg -n "info_span|trace!" src/api/client.rs`.

3. Convert lower-level errors at subsystem boundaries instead of exposing transport-specific details directly.
Evidence: `src/http.rs` and `src/api/client.rs` map to `MegaError` variants before returning.
How to verify: `rg -n "map_err\\(|return Err\\(MegaError" src/http.rs src/api/client.rs`.

## MAY
1. Use `request_with_allowed(..., allowed_errors)` style when callers intentionally treat specific API codes as non-fatal.
Evidence: `src/api/client.rs`.
How to verify: `rg -n "request_with_allowed|allowed_errors" src/api/client.rs`.

2. Introduce new explicit variants for currently overloaded cases (for example proxy configuration/build errors now mapped to `CryptoError`).
Evidence: `src/http.rs` (`Invalid proxy` and `Failed to build client` map to `MegaError::CryptoError`).
How to verify: `rg -n "Invalid proxy|Failed to build client|CryptoError" src/http.rs src/error.rs`.

## TODO / Unknowns
- No CI policy was found enforcing error-message style or forbidden error patterns.
- No documented retry policy outside code comments was found; operational SLO/backoff constraints should be documented if required.
