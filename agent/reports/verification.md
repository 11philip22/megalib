# Verification Report

## Summary
| File | Status | Notes |
| --- | --- | --- |
| `agent/inputs/readme.md` | FAIL | Multiple policy/discrepancy claims lack evidence in `src/` or `README.md`. |
| `agent/inputs/architecture.md` | PASS | All major claims map to `src/` evidence. |
| `agent/inputs/public_api.md` | FAIL | Version discrepancy claim lacks evidence for current version from allowed sources. |
| `agent/inputs/errors.md` | PASS | Claims align with `src/error.rs`, `src/http.rs`, and `src/api/client.rs`. |
| `agent/inputs/api.md` | PASS | Claims align with `src/` evidence. |
| `agent/inputs/testing.md` | FAIL | Several claims rely on repo layout or Cargo metadata not in allowed evidence. |
| `agent/inputs/decisions.md` | FAIL | Dependency-feature claim lacks allowed evidence. |

## `agent/inputs/readme.md`
| Claim | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Docs describe SDK as implemented in code; code is source of truth; discrepancies must be noted. | UNVERIFIED | MISSING | Policy statement not evidenced in `src/` or `README.md`. |
| Public API changes require updating `public_api.md`. | UNVERIFIED | MISSING | Policy statement not evidenced in `src/` or `README.md`. |
| Error behavior changes require updating `errors.md`. | UNVERIFIED | MISSING | Policy statement not evidenced in `src/` or `README.md`. |
| Preferred workflow: small, focused PRs and update docs with behavior changes. | UNVERIFIED | MISSING | Policy statement not evidenced in `src/` or `README.md`. |
| README installation snippet uses `megalib = "0.1.0"`. | VERIFIED | `README.md > Installation` |  |
| Current crate version is `0.6.0`. | UNVERIFIED | MISSING | Requires Cargo metadata; not available in allowed evidence sources. |
| README features include “Text/Video/Image streaming support”. | VERIFIED | `README.md > Features` |  |
| `Session::upload_from_reader` exists. | VERIFIED | `src/fs/operations/upload.rs::upload_from_reader` |  |
| `Session::download` and `Session::download_to_file` exist. | VERIFIED | `src/fs/operations/download.rs::download` |  |
| README streaming support line does not map to a named API; closest streaming APIs are upload/download functions. | UNVERIFIED | MISSING | Interpretive claim not directly evidenced. |

## `agent/inputs/architecture.md`
| Claim | Status | Evidence | Notes |
| --- | --- | --- | --- |
| SDK is async Rust built on `reqwest`. | VERIFIED | `src/http.rs::HttpClient`, `src/session/session.rs::login` |  |
| `Session` owns auth state, `ApiClient`, and cached filesystem nodes. | VERIFIED | `src/session/session.rs::Session` |  |
| Public-link workflows live in `public.rs`. | VERIFIED | `src/public.rs::PublicFile` |  |
| Crypto helpers live under `crypto`. | VERIFIED | `src/crypto/mod.rs::aes` |  |
| `src/lib.rs` defines public modules and re-exports common types. | VERIFIED | `src/lib.rs::session` |  |
| `src/api/client.rs` provides API client with retry/backoff for EAGAIN. | VERIFIED | `src/api/client.rs::ApiClient` |  |
| `src/http.rs` wraps `reqwest::Client` and handles redirects. | VERIFIED | `src/http.rs::HttpClient` |  |
| `src/fs/operations/*` implements `Session` methods for FS operations. | VERIFIED | `src/fs/operations/browse.rs::list` |  |
| `src/session/*` implements login, session caching, registration, key management. | VERIFIED | `src/session/session.rs::login`, `src/session/registration.rs::register`, `src/session/keys.rs::fetch_contact_public_keys` |  |
| `src/preview.rs` generates thumbnails (non-WASM). | VERIFIED | `src/preview.rs::generate_thumbnail` |  |
| Authenticated request flow uses `ApiClient::request` and `HttpClient::post`; negative codes map to `MegaError::ApiError` with EAGAIN backoff. | VERIFIED | `src/api/client.rs::ApiClient`, `src/error.rs::MegaError` |  |
| Public-link flow parses links, uses unauthenticated `ApiClient`, downloads with AES-CTR decryption. | VERIFIED | `src/public.rs::parse_mega_link`, `src/public.rs::download_public_file_data` |  |
| `Session::refresh` fetches node tree and builds paths; `list`/`stat` use cached nodes. | VERIFIED | `src/fs/operations/tree.rs::refresh`, `src/fs/operations/browse.rs::list` |  |
| Mutations/transfers call `ApiClient` and update cache as needed. | VERIFIED | `src/fs/operations/dir_ops.rs::mkdir`, `src/fs/operations/upload.rs::upload` |  |
| Login decrypts keys/session id using crypto helpers; ^!keys uses `KeyManager`; previews toggled via `enable_previews`. | VERIFIED | `src/session/session.rs::login`, `src/crypto/auth.rs::decrypt_session_id`, `src/session/session.rs::enable_previews` |  |
| Proxy support and preview generation are non-WASM; WASM uses custom sleep for backoff. | VERIFIED | `src/http.rs::HttpClient`, `src/lib.rs::preview`, `src/api/client.rs::sleep` |  |

## `agent/inputs/public_api.md`
| Claim | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Top-level public modules include `api`, `base64`, `crypto`, `error`, `fs`, `http`, `preview`, `progress`, `public`, `session`. | VERIFIED | `src/lib.rs::api` |  |
| Top-level re-exports include `MegaError`, `Result`, `Node`, `NodeType`, `Quota`, `ProgressCallback`, `TransferProgress`, `make_progress_bar`, `PublicFile`, `PublicFolder`, `download_public_file`, `get_public_file_info`, `open_folder`, `parse_folder_link`, `parse_mega_link`, `RegistrationState`, `Session`, `register`, `verify_registration`. | VERIFIED | `src/lib.rs::MegaError` |  |
| Primary entry points are `Session`, `public` module helpers, `ApiClient`, and `HttpClient`. | VERIFIED | `src/session/session.rs::Session`, `src/public.rs::get_public_file_info`, `src/api/client.rs::ApiClient`, `src/http.rs::HttpClient` |  |
| Session auth/lifecycle methods include `login`, `login_with_proxy`, `session_id`, `save`, `load`, `load_with_proxy`. | VERIFIED | `src/session/session.rs::login`, `src/session/session.rs::login_with_proxy`, `src/session/session.rs::session_id`, `src/session/session.rs::save`, `src/session/session.rs::load_with_proxy` |  |
| Session FS cache/browse methods include `refresh`, `nodes`, `list`, `stat`, `get_node_by_handle`, `node_has_ancestor`, `list_contacts`. | VERIFIED | `src/fs/operations/tree.rs::refresh`, `src/session/session.rs::nodes`, `src/fs/operations/browse.rs::list_contacts` |  |
| Session FS mutations include `mkdir`, `mv`, `rename`, `rm`. | VERIFIED | `src/fs/operations/dir_ops.rs::mkdir` |  |
| Transfers/links include downloads, uploads, and exports as listed. | VERIFIED | `src/fs/operations/download.rs::download`, `src/fs/operations/upload.rs::upload`, `src/fs/operations/export.rs::export` |  |
| Transfer configuration includes `set_resume`, `is_resume_enabled`, `set_workers`, `workers`, `watch_status`, `clear_status`, `enable_previews`, `previews_enabled`. | VERIFIED | `src/session/session.rs::set_resume`, `src/session/session.rs::set_workers`, `src/session/session.rs::watch_status`, `src/session/session.rs::enable_previews` |  |
| Account/attributes include `change_password`, `get_user_attribute_raw`, `set_private_attribute`. | VERIFIED | `src/session/session.rs::change_password`, `src/session/session.rs::get_user_attribute_raw`, `src/session/session.rs::set_private_attribute` |  |
| Keys/authrings/share management methods listed are public. | VERIFIED | `src/session/session.rs::load_keys_attribute`, `src/session/keys.rs::fetch_contact_public_keys`, `src/session/session.rs::get_public_key`, `src/session/session.rs::share_folder` |  |
| `fs` public types include `Node`, `NodeType`, `Quota`, `UploadState`. | VERIFIED | `src/fs/node.rs::Node`, `src/fs/upload_state.rs::UploadState` |  |
| `public` module functions/types include `PublicFile`, `PublicFolder`, and link/download helpers. | VERIFIED | `src/public.rs::PublicFile`, `src/public.rs::parse_mega_link` |  |
| `progress` module exposes `TransferProgress`, `ProgressCallback`, and `make_progress_bar`. | VERIFIED | `src/progress.rs::TransferProgress`, `src/progress.rs::make_progress_bar` |  |
| `preview` module exposes thumbnail helpers on non-WASM. | VERIFIED | `src/preview.rs::generate_thumbnail` |  |
| `base64` module exposes `base64url_encode`/`base64url_decode`. | VERIFIED | `src/base64.rs::base64url_encode`, `src/base64.rs::base64url_decode` |  |
| `crypto` module exposes KeyManager/Keyring/AuthRing/AuthState/Warn/RSA/KDF/AES helpers. | VERIFIED | `src/crypto/key_manager.rs::KeyManager`, `src/crypto/authring.rs::AuthRing`, `src/crypto/rsa.rs::MegaRsaKey`, `src/crypto/auth.rs::derive_key_v2`, `src/crypto/aes.rs::aes128_ecb_encrypt_block` |  |
| README installation snippet uses `0.1.0` and current version is `0.6.0` (discrepancy). | UNVERIFIED | `README.md > Installation` | Current version requires Cargo evidence not allowed in this report. |

## `agent/inputs/errors.md`
| Claim | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Public error type is `MegaError` with `Result<T>` alias. | VERIFIED | `src/error.rs::MegaError`, `src/error.rs::Result` |  |
| Error variants and payloads match the table. | VERIFIED | `src/error.rs::MegaError` |  |
| `ServerBusy` corresponds to repeated EAGAIN retries. | VERIFIED | `src/api/client.rs::ApiClient` |  |
| HTTP errors are `MegaError::HttpError(u16)` without body/request-id; too many redirects yields `MegaError::Custom("Too many redirects")`. | VERIFIED | `src/error.rs::MegaError`, `src/http.rs::HttpClient` |  |
| Source errors preserved via `#[from]` for reqwest/serde/base64. | VERIFIED | `src/error.rs::MegaError` |  |
| No explicit “no panic” guarantee; `HttpClient::new` can panic on builder failure. | VERIFIED | `src/http.rs::HttpClient` |  |

## `agent/inputs/api.md`
| Claim | Status | Evidence | Notes |
| --- | --- | --- | --- |
| SDK centers on `Session` for auth and `public` for unauthenticated links; low-level `ApiClient`/`HttpClient` available. | VERIFIED | `src/session/session.rs::Session`, `src/public.rs::get_public_file_info`, `src/api/client.rs::ApiClient`, `src/http.rs::HttpClient` |  |
| `Session` manages auth state, cached nodes, transfers, and account ops. | VERIFIED | `src/session/session.rs::Session`, `src/session/session.rs::change_password` |  |
| `ApiClient` handles MEGA JSON API with EAGAIN backoff. | VERIFIED | `src/api/client.rs::ApiClient` |  |
| `HttpClient` performs JSON POSTs and manual redirects. | VERIFIED | `src/http.rs::HttpClient` |  |
| Registration flow uses `register`/`verify_registration` with serialized `RegistrationState`. | VERIFIED | `src/session/registration.rs::register`, `src/session/registration.rs::RegistrationState` |  |
| Filesystem cache and browse operations listed are public and operate on cached nodes. | VERIFIED | `src/fs/operations/tree.rs::refresh`, `src/fs/operations/browse.rs::list` |  |
| Mutations (`mkdir`, `mv`, `rename`, `rm`) and `quota` are public. | VERIFIED | `src/fs/operations/dir_ops.rs::mkdir`, `src/fs/operations/quota.rs::quota` |  |
| Transfers and export operations listed are public. | VERIFIED | `src/fs/operations/download.rs::download`, `src/fs/operations/upload.rs::upload`, `src/fs/operations/export.rs::export` |  |
| Transfer config/progress methods listed are public. | VERIFIED | `src/session/session.rs::set_resume`, `src/session/session.rs::set_workers`, `src/session/session.rs::watch_status`, `src/session/session.rs::enable_previews` |  |
| Public-link operations (`parse_mega_link`, `parse_folder_link`, `get_public_file_info`, `download_public_file`, `open_folder`) are public. | VERIFIED | `src/public.rs::parse_mega_link`, `src/public.rs::open_folder` |  |
| HTTP behavior: base URL, `sid` query param, JSON POST, EAGAIN retry, manual redirects. | VERIFIED | `src/api/client.rs::API_URL`, `src/api/client.rs::ApiClient`, `src/http.rs::HttpClient` |  |

## `agent/inputs/testing.md`
| Claim | Status | Evidence | Notes |
| --- | --- | --- | --- |
| Tests are embedded in source modules under `#[cfg(test)]`. | VERIFIED | `src/http.rs::tests`, `src/public.rs::tests` |  |
| No `tests/` integration test directory exists. | UNVERIFIED | MISSING | Repo layout evidence not allowed under current evidence rules. |
| `tokio-test` is the only dev-dependency. | UNVERIFIED | MISSING | Requires Cargo metadata not allowed in this report. |
| No HTTP mocking crate is present in dev-dependencies; tests do not use mock servers. | UNVERIFIED | MISSING | Requires Cargo metadata and full test audit. |
| Prefer deterministic inputs and avoid live network calls. | UNVERIFIED | MISSING | Policy statement not evidenced in `src/` or `README.md`. |
| Favor small unit tests colocated with modules. | UNVERIFIED | MISSING | Policy statement not evidenced in `src/` or `README.md`. |
| Use `no_run` for networked doc examples. | UNVERIFIED | MISSING | Guidance statement; not directly evidenced. |

## `agent/inputs/decisions.md`
| Claim | Status | Evidence | Notes |
| --- | --- | --- | --- |
| HTTP client is `reqwest` with `rustls-tls` and `socks` features, default features disabled. | UNVERIFIED | MISSING | Requires Cargo metadata not allowed in this report. |
| Requests are JSON POSTs with manual redirect handling in `HttpClient`. | VERIFIED | `src/http.rs::HttpClient` |  |
| Public error model uses `thiserror`. | VERIFIED | `src/error.rs::MegaError` |  |
| API responses parsed into `serde_json::Value` at API layer. | VERIFIED | `src/api/client.rs::request` |  |
| `Session` owns auth state, `ApiClient`, and cached node list. | VERIFIED | `src/session/session.rs::Session` |  |
| `Session::save`/`load` persist session state to disk. | VERIFIED | `src/session/session.rs::save` |  |
| SDK retries EAGAIN responses with exponential backoff. | VERIFIED | `src/api/client.rs::ApiClient` |  |
| Crypto stack uses AES/RSA/PBKDF2/keyring/authring/^!keys; base64 URL-safe variant. | VERIFIED | `src/crypto/mod.rs::aes`, `src/crypto/auth.rs::derive_key_v2`, `src/crypto/keyring.rs::Keyring`, `src/crypto/authring.rs::AuthRing`, `src/crypto/key_manager.rs::KeyManager`, `src/base64.rs::base64url_encode` |  |
| Public links are handled without requiring a session. | VERIFIED | `src/public.rs::get_public_file_info` |  |
| Preview generation available on native targets with `image` and optional `ffmpegthumbnailer`. | VERIFIED | `src/preview.rs::generate_thumbnail`, `src/preview.rs::generate_video_thumbnail` |  |
| Platform gating: proxy/preview are non-WASM; WASM uses custom sleep. | VERIFIED | `src/http.rs::HttpClient`, `src/lib.rs::preview`, `src/api/client.rs::sleep` |  |

## Top 15 Mismatches (By Severity)
1. HIGH: `decisions.md` claim about `reqwest` feature flags and default features is unverified (requires Cargo evidence).
2. HIGH: `readme.md` claim that current crate version is `0.6.0` is unverified under evidence rules.
3. HIGH: `public_api.md` discrepancy claim about current version is unverified under evidence rules.
4. MEDIUM: `readme.md` policy rules (public API/errors update requirements) are unverified.
5. MEDIUM: `readme.md` preferred workflow guidance is unverified.
6. MEDIUM: `readme.md` claim that README streaming feature line does not map to a named API is unverified.
7. MEDIUM: `testing.md` claim that no `tests/` directory exists is unverified.
8. MEDIUM: `testing.md` claim that `tokio-test` is the only dev-dependency is unverified.
9. MEDIUM: `testing.md` claim that no HTTP mocking crate is present is unverified.
10. LOW: `testing.md` guidance on deterministic inputs is unverified.
11. LOW: `testing.md` guidance on colocated unit tests is unverified.
12. LOW: `testing.md` guidance on `no_run` for networked doc examples is unverified.
13. LOW: `readme.md` claim that docs must be updated from repo evidence only is unverified.
14. LOW: `readme.md` claim that code is source of truth and discrepancies must be noted is unverified.
15. LOW: `readme.md` claim that docs index is authoritative is unverified (file listing not evidenced).

## Minimal Doc Edits Needed To Reach PASS
- `agent/inputs/readme.md`:
  - Mark policy statements as “Unknown” with TODOs referencing missing evidence, or remove them.
  - Split discrepancy statements into verifiable parts; remove or TODO the current-version claim unless evidence is added in allowed sources.
  - Remove or TODO the interpretive “streaming support does not map” statement.
- `agent/inputs/public_api.md`:
  - Replace version-discrepancy claim with verifiable README-only statement or mark the current-version part as TODO/Unknown.
- `agent/inputs/testing.md`:
  - Remove or TODO claims that depend on Cargo metadata or repo layout (dev-dependencies, mock crates, no `tests/` dir).
  - Keep only claims directly evidenced by `src/` tests or README.
- `agent/inputs/decisions.md`:
  - Remove or TODO the `reqwest` feature-flag claim unless allowed evidence is added.

