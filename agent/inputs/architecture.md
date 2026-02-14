# Architecture

## Overview
This crate is an async Rust SDK for MEGA, built on `reqwest` and structured around a `Session` that owns auth state, a low-level `ApiClient`, and a cached filesystem tree. Public-link workflows live in `public.rs`, and cryptographic helpers live under `crypto`.

Evidence:
- `src/lib.rs::session`
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`
- `src/public.rs::PublicFile`
- `src/crypto/mod.rs::aes`

## Module Layout
- `src/lib.rs` defines public modules and re-exports commonly used types and functions.
- `src/public.rs` implements public-link parsing, metadata lookup, and download for files/folders without authentication.
- `src/api/client.rs` provides the MEGA JSON API client with retry/backoff for EAGAIN.
- `src/http.rs` wraps `reqwest::Client` and performs JSON POSTs with manual redirect handling.
- `src/fs/operations/*` implements filesystem operations as `impl Session` methods.
- `src/session/*` implements login, session caching, registration, and key management helpers.
- `src/crypto/*` implements MEGA-specific auth, AES/RSA, keyring, and ^!keys handling.
- `src/preview.rs` generates thumbnails for uploads.
- `src/progress.rs` defines transfer progress reporting and callbacks.

Evidence:
- `src/lib.rs::public`
- `src/public.rs::open_folder`
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`
- `src/fs/operations/mod.rs::browse`
- `src/session/mod.rs::Session`
- `src/crypto/mod.rs::key_manager`
- `src/preview.rs::generate_thumbnail`
- `src/progress.rs::TransferProgress`

## Authenticated Request Flow
1. Create a `Session` via `Session::login` (or `Session::load`).
2. `Session` holds an `ApiClient` with `session_id` set after login.
3. `Session` methods call `ApiClient::request`, which builds a JSON command array and URL with `id` and optional `sid` query params.
4. `ApiClient` calls `HttpClient::post` to send the JSON POST using `reqwest`.
5. Responses are parsed as `serde_json::Value`; negative MEGA codes map to `MegaError::ApiError` and `EAGAIN` triggers backoff retries.

Evidence:
- `src/session/session.rs::login`
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`
- `src/error.rs::MegaError`

## Public-Link Flow (No Login)
1. Public helpers parse the link (`parse_mega_link` / `parse_folder_link`).
2. Public file metadata is fetched via `ApiClient::new()` without a session id.
3. File data is downloaded via `reqwest` and decrypted using AES-CTR with keys derived from the link.

Evidence:
- `src/public.rs::parse_mega_link`
- `src/public.rs::get_public_file_info`
- `src/public.rs::download_public_file_data`

## Filesystem Cache And Operations
- `Session::refresh` fetches the node tree (`a: "f"`), decrypts nodes, and builds paths.
- `list`, `stat`, and `get_node_by_handle` operate on the cached node list and paths.
- Mutations (`mkdir`, `mv`, `rename`, `rm`) and transfers call back into `ApiClient` and update cache as needed.

Evidence:
- `src/fs/operations/tree.rs::refresh`
- `src/fs/operations/browse.rs::list`
- `src/fs/operations/dir_ops.rs::mkdir`
- `src/fs/operations/download.rs::download`
- `src/fs/operations/upload.rs::upload`

## Crypto And Session Integration
- Login derives password keys, decrypts the master key and RSA key, and decrypts the session id using crypto helpers.
- ^!keys support is handled via `KeyManager`, with authrings and share keys integrated into `Session`.
- Preview/thumbnail generation is optional and enabled per session via `enable_previews`.

Evidence:
- `src/session/session.rs::login`
- `src/crypto/auth.rs::decrypt_session_id`
- `src/crypto/key_manager.rs::KeyManager`
- `src/session/session.rs::enable_previews`
- `src/preview.rs::generate_thumbnail`
