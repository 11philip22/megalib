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
- Sharing/export: `Session::share_folder`, `Session::export`, `Session::export_many`.
- Account/keys: `Session::change_password`, `Session::get_user_attribute_raw`, `Session::set_private_attribute`.

## Nodes & Filesystem Model
- `Session::refresh` parses `f` + `ok`, decrypts node keys/attrs, and builds paths. (`src/fs/operations/tree.rs`)
- Node keys: master key for `key_handle == user_handle`, otherwise share key; attr decrypt uses AES-CBC (zero IV) and requires `MEGA` prefix; file attr key = XOR halves of 32-byte file key. (`src/fs/operations/tree.rs`)
- Paths are computed with recursion depth cap 100 and cached on each node. (`src/fs/operations/tree.rs`)
- Mutations: `mkdir` encrypts attrs + node key; `rename` re-encrypts attrs using node key; `mv` requires destination container. (`src/fs/operations/dir_ops.rs`)

## Sharing / Export (Authenticated)
- `Session::share_folder` uses `s2` with `ok` (RSA-encrypted share key), `ha` (handle auth), and CR mapping for descendants. (`src/session/session.rs`)
- `Session::export` for folders uses `s2` then `l`; share key is the folder link key and is stored in `share_keys` + ^!keys when available. (`src/fs/operations/export.rs`)
- `Session::export` for files uses `l` directly; link key is the node key. (`src/fs/operations/export.rs`)
- `find_share_for_handle` walks ancestors and checks in-memory share keys then ^!keys. (`src/session/session.rs`)
- Uploading into exported/shared folders: `finalize_upload` looks up share key via `find_share_for_handle` and emits CR mapping so new nodes remain decryptable by existing links. (`src/fs/operations/upload.rs`, `src/session/session.rs`)

## Public Links (Anonymous)
- `parse_mega_link` and `parse_folder_link` support new and legacy URL formats. (`src/public.rs`)
- File links use 32-byte keys; folder links use 16-byte keys; public folder fetch is a direct POST to `cs?id=<rand>&n=<handle>`. (`src/public.rs`)
- Public folder nodes may have empty `k`; in that case the folder key is reused for decryption. (`src/public.rs`)

## Crypto Notes
- AES: ECB/CBC require 16-byte block alignment; CBC uses zero IV; CTR uses nonce (bytes 16..24 of node key) + big-endian counter from offset. (`src/crypto/aes.rs`)
- KDFs: v2 uses PBKDF2-SHA512 (100k iterations); legacy KDF runs 65,536 AES rounds over UTF-16 packed password; username hash uses 16k AES rounds. (`src/crypto/auth.rs`, `src/crypto/keys.rs`)
- RSA: RSA-2048 with exponent e=3; RSA encrypt/decrypt treat inputs as big-endian integers; private key encoding is AES-ECB over MPI blocks. (`src/crypto/rsa.rs`, `src/crypto/auth.rs`)
- `*keyring`: encSetting + IV + ciphertext; supports AES-GCM/CCM variants; default write uses AES-GCM (12-byte IV, 16-byte tag). (`src/crypto/keyring.rs`)

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
- Auth login: `Session::login_internal` (prelogin -> login -> decrypt keys -> set `sid` -> `ug` -> `load_keys_attribute` -> promote pending shares).
- Registration: `register` -> `verify_registration` with serialized `RegistrationState`.
- Tree refresh: `Session::refresh` decrypts nodes and rebuilds paths.
- Upload: `upload_resumable`/`upload_internal` chunk + MAC + finalize node.
- Download: `download_with_offset` -> AES-CTR decrypt to writer.
- Public links: `get_public_file_info` + `download_public_file_data`; `open_folder` for folder trees.
- Key management: `load_keys_attribute` / `sync_keys_attribute` / `persist_keys_with_retry`.
- Exported folder updates: export caches share key; upload finalization uses `build_cr_for_nodes` so new nodes stay decryptable by existing public links. (`src/fs/operations/export.rs`, `src/fs/operations/upload.rs`)
- Background key import sequence: login -> `ug` -> `load_keys_attribute` -> `promote_pending_shares` -> persist if needed; action packets -> `poll_sc` -> `handle_actionpacket_keys` -> `sync_keys_attribute`/promotion. (`src/session/session.rs`, `src/session/keys.rs`)

## Notes / Unknowns
- Request signing beyond `compute_handle_auth` and CR mappings: UNKNOWN.
- Additional API commands used outside listed modules: UNKNOWN.
