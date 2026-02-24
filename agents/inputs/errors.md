# Error Model

## Public Error Type
The crate exposes `MegaError` and a `Result<T>` alias for SDK operations.

Evidence:
- `src/error.rs::MegaError`
- `src/error.rs::Result`
- `src/lib.rs::MegaError`

## Variants And Payloads
| Variant | When it occurs | Payload |
| --- | --- | --- |
| `HttpError` | HTTP response has a non-success status code. | `u16` status code. |
| `RequestError` | `reqwest` request/response error. | `reqwest::Error` (via `#[from]`). |
| `JsonError` | JSON parse/serialize error. | `serde_json::Error` (via `#[from]`). |
| `ServerBusy` | API returned EAGAIN repeatedly and retries were exhausted. | None. |
| `InvalidResponse` | Response shape missing expected fields. | None. |
| `ApiError` | MEGA API returned negative error code. | `code: i32`, `message: String`. |
| `CryptoError` | Crypto operation failed. | `String` message. |
| `InvalidChallenge` | Registration challenge verification failed. | None. |
| `Base64Error` | Base64 decoding failed. | `base64::DecodeError` (via `#[from]`). |
| `DowngradeDetected` | ^!keys attribute appears downgraded. | None. |
| `InvalidState` | Registration state string is malformed. | `String` message. |
| `Custom` | Explicit custom error strings. | `String` message. |

Evidence:
- `src/error.rs::MegaError`
- `src/api/client.rs::ApiClient`
- `src/session/registration.rs::RegistrationState`
- `src/crypto/key_manager.rs::KeyManager`

## HTTP Error Representation
HTTP failures are represented by `MegaError::HttpError(u16)`; no response body snippet or request-id is stored in the variant. `HttpClient::post` also emits `MegaError::Custom("Too many redirects")` when redirect limits are exceeded.

Evidence:
- `src/error.rs::MegaError`
- `src/http.rs::HttpClient`

## Error Sources And Conversions
- `RequestError`, `JsonError`, and `Base64Error` preserve their source types via `#[from]`.
- API numeric error codes are mapped to `MegaError::ApiError` with a human-readable message.

Evidence:
- `src/error.rs::MegaError`
- `src/api/client.rs::ApiClient`

## Guarantees And Non-Guarantees
No explicit “no panic” guarantee exists in code. `HttpClient::new` uses `expect` on client construction, which can panic if the reqwest client fails to build.

Evidence:
- `src/http.rs::HttpClient`
