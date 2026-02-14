# Design Decisions (Evidence-Backed)

## HTTP Client And TLS
- Chosen HTTP client: `reqwest` with `rustls-tls` and `socks` features, default features disabled.
- Requests are JSON POSTs with manual redirect handling in `HttpClient`.

Evidence:
- `Cargo.toml::dependencies`
- `src/http.rs::HttpClient`

## Error Handling
- Public error model is a `thiserror`-based enum (`MegaError`).

Evidence:
- `Cargo.toml::dependencies`
- `src/error.rs::MegaError`

## JSON Model
- API responses are parsed into `serde_json::Value` rather than typed structs at the API layer.

Evidence:
- `src/api/client.rs::request`

## Session Model And Caching
- `Session` owns auth state, a low-level `ApiClient`, and a cached node list.
- `Session::save`/`load` persist session state to disk.

Evidence:
- `src/session/session.rs::Session`
- `src/session/session.rs::save`

## Retry Policy
- The SDK retries MEGA `EAGAIN` responses with exponential backoff in `ApiClient::request`.

Evidence:
- `src/api/client.rs::ApiClient`

## Crypto Stack
- MEGA-specific crypto is implemented in `crypto` modules (AES, RSA, PBKDF2, keyring, authring, ^!keys key manager).
- Base64 encoding uses MEGA’s URL-safe variant in `base64`.

Evidence:
- `src/crypto/mod.rs::aes`
- `src/crypto/auth.rs::derive_key_v2`
- `src/crypto/key_manager.rs::KeyManager`
- `src/crypto/keyring.rs::Keyring`
- `src/crypto/authring.rs::AuthRing`
- `src/base64.rs::base64url_encode`

## Public Links Without Auth
- Public link parsing and downloads are implemented in `public` without requiring a session.

Evidence:
- `src/public.rs::get_public_file_info`

## Preview/Thumbnail Generation
- Preview generation uses the `image` crate plus optional `ffmpegthumbnailer` for video thumbnails.

Evidence:
- `src/preview.rs::generate_thumbnail`
- `Cargo.toml::dependencies`
