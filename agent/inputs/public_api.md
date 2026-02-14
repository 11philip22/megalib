# Public API

## Top-Level Exports (`megalib::*`)
- Modules: `api`, `base64`, `crypto`, `error`, `fs`, `http`, `preview`, `progress`, `public`, `session`.
- Re-exports: `MegaError`, `Result`, `Node`, `NodeType`, `Quota`, `ProgressCallback`, `TransferProgress`, `make_progress_bar`, `PublicFile`, `PublicFolder`, `download_public_file`, `get_public_file_info`, `open_folder`, `parse_folder_link`, `parse_mega_link`, `RegistrationState`, `Session`, `register`, `verify_registration`.

Evidence:
- `src/lib.rs::api`
- `src/lib.rs::MegaError`
- `src/lib.rs::PublicFile`
- `src/lib.rs::Session`

## Primary Entry Points
- `Session` for authenticated operations and filesystem access.
- `public` module functions (`parse_mega_link`, `get_public_file_info`, `download_public_file`, `open_folder`) for unauthenticated public links.
- `api::ApiClient` and `http::HttpClient` for low-level access.

Evidence:
- `src/session/session.rs::Session`
- `src/public.rs::get_public_file_info`
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`

## Session API Groups

### Authentication And Lifecycle
- `login`, `login_with_proxy`, `session_id`, `save`, `load`, `load_with_proxy`.

Evidence:
- `src/session/session.rs::login`
- `src/session/session.rs::load`

### Filesystem Cache And Browse
- `refresh`, `nodes`, `list`, `stat`, `get_node_by_handle`, `node_has_ancestor`, `list_contacts`.

Evidence:
- `src/fs/operations/tree.rs::refresh`
- `src/fs/operations/browse.rs::list`

### Filesystem Mutations
- `mkdir`, `mv`, `rename`, `rm`.

Evidence:
- `src/fs/operations/dir_ops.rs::mkdir`

### Transfers And Links
- Downloads: `download`, `download_with_offset`, `download_to_file`.
- Uploads: `upload`, `upload_resumable`, `upload_from_bytes`, `upload_from_reader`, `upload_node_attribute`.
- Public links: `export`, `export_many`.

Evidence:
- `src/fs/operations/download.rs::download`
- `src/fs/operations/upload.rs::upload`
- `src/fs/operations/export.rs::export`

### Transfer Configuration And Progress
- `set_resume`, `is_resume_enabled`, `set_workers`, `workers`, `watch_status`, `clear_status`, `enable_previews`, `previews_enabled`.

Evidence:
- `src/session/session.rs::set_resume`
- `src/session/session.rs::set_workers`
- `src/session/session.rs::watch_status`
- `src/session/session.rs::enable_previews`

### Account And Attributes
- `change_password`, `get_user_attribute_raw`, `set_private_attribute`.

Evidence:
- `src/session/session.rs::change_password`
- `src/session/session.rs::get_user_attribute_raw`

### Keys, Authrings, And Share Management
- `load_keys_attribute`, `ensure_keys_attribute`, `persist_keys_attribute`, `keys_downgrade_detected`.
- `set_authring_ed25519`, `set_authring_cu25519`, `authring_state`.
- `set_warnings`, `set_contact_verification_warning`, `contact_verification_warning`, `set_manual_verification`, `set_backups_blob`.
- `fetch_contact_public_keys`, `fetch_pending_keys`, `send_pending_key_promotion`, `promote_pending_shares`, `get_public_key`, `share_folder`.

Evidence:
- `src/session/session.rs::load_keys_attribute`
- `src/session/session.rs::set_authring_ed25519`
- `src/session/keys.rs::fetch_contact_public_keys`
- `src/session/keys.rs::fetch_pending_keys`
- `src/session/session.rs::get_public_key`
- `src/session/session.rs::share_folder`

## Public Modules And Types

### `fs`
- Types: `Node`, `NodeType`, `Quota`, `UploadState`.

Evidence:
- `src/fs/node.rs::Node`
- `src/fs/upload_state.rs::UploadState`

### `public`
- Types: `PublicFile`, `PublicFolder`.
- Functions: `parse_mega_link`, `parse_folder_link`, `get_public_file_info`, `download_public_file`, `download_public_file_data`, `open_folder`.

Evidence:
- `src/public.rs::PublicFile`
- `src/public.rs::parse_mega_link`

### `progress`
- Types: `TransferProgress`, `ProgressCallback`.
- Functions: `make_progress_bar`.

Evidence:
- `src/progress.rs::TransferProgress`
- `src/progress.rs::make_progress_bar`

### `preview`
- Functions: `generate_thumbnail`, `generate_image_thumbnail`, `generate_video_thumbnail`, `is_image`, `is_video`, `has_ffmpegthumbnailer`.

Evidence:
- `src/preview.rs::generate_thumbnail`

### `base64`
- Functions: `base64url_encode`, `base64url_decode`.

Evidence:
- `src/base64.rs::base64url_encode`

### `crypto`
- Key management: `KeyManager`, `Keyring`, `AuthRing`, `AuthState`, `Warnings`.
- RSA: `MegaRsaKey`.
- Auth/KDF: `derive_key_v2`, `make_password_key`, `make_username_hash`.
- AES helpers and MAC helpers (re-exported from `crypto::aes`).

Evidence:
- `src/crypto/key_manager.rs::KeyManager`
- `src/crypto/keyring.rs::Keyring`
- `src/crypto/authring.rs::AuthRing`
- `src/crypto/rsa.rs::MegaRsaKey`
- `src/crypto/auth.rs::derive_key_v2`
- `src/crypto/keys.rs::make_password_key`
- `src/crypto/aes.rs::aes128_ecb_encrypt_block`

## Discrepancies With Root README
- The README installation snippet references version `0.1.0`; current crate version is `0.6.0`.

Evidence:
- `README.md > Installation`
- `Cargo.toml::package`
