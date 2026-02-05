# Rust SDK Map (Stable Index)

## Top-Level Modules (src/lib.rs)
- `api`: MEGA JSON API client (`ApiClient`).
- `base64`: MEGA URL-safe base64 helpers.
- `crypto`: AES/RSA/KDF/Authring/Keyring/KeyManager primitives.
- `error`: `MegaError` + `Result<T>`.
- `fs`: Node model and filesystem operations.
- `http`: Low-level HTTP client wrapper.
- `preview` (non-WASM): Thumbnail generation helpers.
- `progress`: Transfer progress types + callbacks.
- `public`: Public link parsing + anonymous download/folder browsing.
- `session`: Authenticated session, registration, key management.

## Core Types And Where They Live
- `Session`: `src/session/session.rs`.
- `ApiClient`: `src/api/client.rs`.
- `HttpClient`: `src/http.rs`.
- `Node`, `NodeType`, `Quota`: `src/fs/node.rs`.
- `UploadState`: `src/fs/upload_state.rs`.
- `PublicFile`, `PublicFolder`: `src/public.rs`.
- `RegistrationState`: `src/session/registration.rs`.
- `KeyManager`: `src/crypto/key_manager.rs`.
- `Keyring`: `src/crypto/keyring.rs`.
- `AuthRing`, `AuthState`: `src/crypto/authring.rs`.
- `MegaRsaKey`: `src/crypto/rsa.rs`.
- `TransferProgress`, `ProgressCallback`: `src/progress.rs`.
- `MegaError`: `src/error.rs`.

## Public API Entry Points (User-Facing)
- Authentication/session: `Session::login`, `Session::login_with_proxy`, `Session::load`, `Session::save`.
- Filesystem cache/browse: `Session::refresh`, `Session::list`, `Session::stat`, `Session::get_node_by_handle`.
- Filesystem mutations: `Session::mkdir`, `Session::mv`, `Session::rename`, `Session::rm`.
- Transfers: `Session::upload`, `Session::upload_resumable`, `Session::upload_from_bytes`, `Session::upload_from_reader`, `Session::download`, `Session::download_with_offset`, `Session::download_to_file`.
- Public links: `parse_mega_link`, `get_public_file_info`, `download_public_file`, `open_folder`.
- Account/keys: `Session::change_password`, `Session::get_user_attribute_raw`, `Session::set_private_attribute`, `Session::share_folder`.

## MEGA API Command Map (Observed)
- `us0`: pre-login variant detection. (`Session::login_internal`)
- `us`: login (email or anon handle). (`Session::login_internal`, `register`, `verify_registration`)
- `ug`: user info. (`Session::login_internal`, `Session::load_internal`)
- `f`: fetch nodes (tree). (`Session::refresh`)
- `g`: get download URL. (`Session::download_with_offset`, `get_public_file_info`, `PublicFolder::download`)
- `u`: get upload URL. (`upload`, `upload_resumable`, `upload_from_reader`)
- `ufa`: upload attribute URL. (`upload_node_attribute`)
- `p`: create nodes / finalize uploads / mkdir. (`mkdir`, `finalize_upload`)
- `a`: set attributes (rename). (`rename`)
- `m`: move node. (`mv`)
- `d`: delete node. (`rm`)
- `l`: export/get public link. (`export`, `export_many`)
- `s2`: share / export folder. (`share_folder`, `export`)
- `up`: account updates (password, name, signup finalize). (`change_password`, `register`, `verify_registration`)
- `uc`: request signup link. (`register`)
- `ud`: verify signup link. (`verify_registration`)
- `uk`: fetch public keys. (`get_public_key`, `fetch_contact_public_keys`)
- `pk`: pending keys feed / promotion. (`fetch_pending_keys`, `send_pending_key_promotion`)
- `uga`: get user attribute. (`get_user_attribute_raw` via `ApiClient::get_user_attribute`)
- `upv`: set private attribute. (`set_private_attribute`)
- `uq`: quota. (`quota`)
- `sc`: action packets. (`poll_sc`)

## Key Flows (High-Level)
- Auth login: `Session::login_internal` (prelogin -> login -> decrypt keys -> set `sid`).
- Registration: `register` -> `verify_registration` with serialized `RegistrationState`.
- Tree refresh: `Session::refresh` decrypts nodes and rebuilds paths.
- Upload: `upload_resumable`/`upload_internal` chunk + MAC + finalize node.
- Download: `download_with_offset` -> AES-CTR decrypt to writer.
- Public links: `get_public_file_info` + `download_public_file_data`; `open_folder` for folder trees.
- Key management: `load_keys_attribute` / `sync_keys_attribute` / `persist_keys_with_retry`.

## Notes / Unknowns
- Request signing beyond `compute_handle_auth` and CR mappings: UNKNOWN.
- Additional API commands used outside listed modules: UNKNOWN.
