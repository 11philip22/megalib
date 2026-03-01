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

4. Map MEGA numeric API codes through `ApiErrorCode` and return `MegaError::ApiError { code, message }`.
Evidence: `src/api/error.rs`, `src/api/client.rs`.
How to verify: `rg -n "ApiErrorCode|MegaError::ApiError" src/api/error.rs src/api/client.rs`.

5. Treat malformed/unexpected API payload shapes as `MegaError::InvalidResponse`.
Evidence: `src/api/client.rs`.
How to verify: `rg -n "InvalidResponse" src/api/client.rs`.

6. Keep EAGAIN retry handling with bounded exponential backoff and return `MegaError::ServerBusy` when exhausted.
Evidence: `src/api/client.rs` (`ApiErrorCode::Again`, `delay_ms`, `max_attempts`, `ServerBusy`).
How to verify: `rg -n "Again|ServerBusy|delay_ms|max_attempts" src/api/client.rs`.

7. Apply request-specific timeout/redirect policy via `RequestKind` + `RequestPolicy`.
Evidence: `src/http.rs`.
How to verify: `rg -n "enum RequestKind|struct RequestPolicy|timeout|max_redirects" src/http.rs`.

8. For missing required runtime state (for example session ID or SC sequence), return explicit error messages (currently via `MegaError::Custom`).
Evidence: `src/api/client.rs` (`Missing SC sequence number`, `Session ID not set`).
How to verify: `rg -n "Missing SC sequence number|Session ID not set|MegaError::Custom" src/api/client.rs`.

9. Keep deterministic error-code mapping covered by unit tests.
Evidence: `src/api/error.rs` tests.
How to verify: `cargo test api::error`.

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
