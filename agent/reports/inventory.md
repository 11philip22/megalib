**Public Exports**

| Item | Kind | Visibility source | Evidence |
| --- | --- | --- | --- |
| `api` | mod | lib.rs | `src/lib.rs::api` |
| `base64` | mod | lib.rs | `src/lib.rs::base64` |
| `crypto` | mod | lib.rs | `src/lib.rs::crypto` |
| `error` | mod | lib.rs | `src/lib.rs::error` |
| `fs` | mod | lib.rs | `src/lib.rs::fs` |
| `http` | mod | lib.rs | `src/lib.rs::http` |
| `preview` | mod | lib.rs | `src/lib.rs::preview` |
| `progress` | mod | lib.rs | `src/lib.rs::progress` |
| `public` | mod | lib.rs | `src/lib.rs::public` |
| `session` | mod | lib.rs | `src/lib.rs::session` |
| `MegaError` | re-export (enum) | lib.rs | `src/lib.rs::MegaError` |
| `Result` | re-export (type alias) | lib.rs | `src/lib.rs::Result` |
| `Node` | re-export (struct) | lib.rs | `src/lib.rs::Node` |
| `NodeType` | re-export (enum) | lib.rs | `src/lib.rs::NodeType` |
| `Quota` | re-export (struct) | lib.rs | `src/lib.rs::Quota` |
| `ProgressCallback` | re-export (type alias) | lib.rs | `src/lib.rs::ProgressCallback` |
| `TransferProgress` | re-export (struct) | lib.rs | `src/lib.rs::TransferProgress` |
| `make_progress_bar` | re-export (fn) | lib.rs | `src/lib.rs::make_progress_bar` |
| `PublicFile` | re-export (struct) | lib.rs | `src/lib.rs::PublicFile` |
| `PublicFolder` | re-export (struct) | lib.rs | `src/lib.rs::PublicFolder` |
| `download_public_file` | re-export (fn) | lib.rs | `src/lib.rs::download_public_file` |
| `get_public_file_info` | re-export (fn) | lib.rs | `src/lib.rs::get_public_file_info` |
| `open_folder` | re-export (fn) | lib.rs | `src/lib.rs::open_folder` |
| `parse_folder_link` | re-export (fn) | lib.rs | `src/lib.rs::parse_folder_link` |
| `parse_mega_link` | re-export (fn) | lib.rs | `src/lib.rs::parse_mega_link` |
| `RegistrationState` | re-export (struct) | lib.rs | `src/lib.rs::RegistrationState` |
| `Session` | re-export (struct) | lib.rs | `src/lib.rs::Session` |
| `register` | re-export (fn) | lib.rs | `src/lib.rs::register` |
| `verify_registration` | re-export (fn) | lib.rs | `src/lib.rs::verify_registration` |
| `download_public_file_data` | fn | public.rs | `src/public.rs::download_public_file_data` |

**Core Types**

| Type name | Purpose | Main methods (grouped) | Evidence |
| --- | --- | --- | --- |
| `Session` | Authenticated MEGA session with filesystem, transfers, and account ops. | Auth: `login`, `login_with_proxy`. FS: `refresh`, `list`, `stat`, `mkdir`, `mv`, `rename`, `rm`. Transfers: `upload`, `upload_resumable`, `download`, `download_to_file`, `export`, `export_many`. Cache: `save`, `load`, `load_with_proxy`. | `src/session/session.rs::login`, `src/fs/operations/tree.rs::refresh`, `src/fs/operations/browse.rs::list`, `src/fs/operations/dir_ops.rs::mkdir`, `src/fs/operations/upload.rs::upload`, `src/fs/operations/download.rs::download`, `src/fs/operations/export.rs::export`, `src/session/session.rs::save` |
| `ApiClient` | Low-level MEGA API client for JSON requests and session scoping. | `new`, `with_proxy`, `set_session_id`, `request`, `request_batch`, `poll_sc`, `get_user_attribute`, `set_private_attribute`. | `src/api/client.rs::ApiClient` |
| `HttpClient` | HTTP wrapper for API POSTs with timeouts and redirect handling. | `new`, `with_proxy`, `post`. | `src/http.rs::HttpClient` |
| `RegistrationState` | Registration state saved between `register` and `verify_registration`. | `serialize`, `deserialize`. | `src/session/registration.rs::RegistrationState` |
| `PublicFile` | Public file metadata and link helpers. | `get_key`, `get_link`. | `src/public.rs::PublicFile` |
| `PublicFolder` | Browse and download public folders without login. | `nodes`, `list`, `stat`, `download`. | `src/public.rs::PublicFolder` |
| `Node` | Filesystem node with metadata and helper accessors. | `is_file`, `is_folder`, `is_contact`, `path`, `get_key`, `get_link`, `is_exported`, `is_writable`. | `src/fs/node.rs::Node` |
| `NodeType` | Enum for MEGA node kinds and conversions. | `from_i64`, `is_container`. | `src/fs/node.rs::NodeType` |
| `Quota` | Storage quota summary. | `free`, `usage_percent`. | `src/fs/node.rs::Quota` |
| `UploadState` | Persisted state for resumable uploads. | `new`, `state_file_path`, `save`, `load`, `delete`, `is_likely_valid`, `add_chunk_mac`. | `src/fs/upload_state.rs::UploadState` |
| `TransferProgress` | Transfer progress info for callbacks. | `new`, `percent`, `is_complete`. | `src/progress.rs::TransferProgress` |
| `ProgressCallback` | Callback type for transfer progress. | Type alias for `FnMut(&TransferProgress) -> bool`. | `src/progress.rs::ProgressCallback` |
| `MegaError` | SDK error type. | Variants in `MegaError` enum. | `src/error.rs::MegaError` |
| `ContactPublicKeys` | Contact public keys + verification flag. | Struct fields for `ed25519`, `cu25519`, `verified`, `user_handle`. | `src/session/keys.rs::ContactPublicKeys` |
| `KeyManager` | ^!keys container management and share-key tracking. | `new`, `is_ready`, `encode_container`, `decode_container`, share-key helpers. | `src/crypto/key_manager.rs::KeyManager` |
| `Keyring` | *keyring attribute decrypt/encrypt and generation. | `from_encrypted`, `to_encrypted`, `generate`. | `src/crypto/keyring.rs::Keyring` |
| `AuthRing` | Contact fingerprint trust state map. | `update`, `get_state`, `serialize_ltlv`, `deserialize_ltlv`. | `src/crypto/authring.rs::AuthRing` |
| `MegaRsaKey` | MEGA RSA keypair operations. | `generate`, `encode_public_key`, `encode_private_key`, `decrypt`, `encrypt`. | `src/crypto/rsa.rs::MegaRsaKey` |

**FS Operations (src/fs/operations/*)**

| Operation module | Public entry points (functions/structs) | Inputs/Outputs (type names only) | Evidence |
| --- | --- | --- | --- |
| `browse` | `Session::list`, `Session::list_contacts`, `Session::stat`, `Session::get_node_by_handle`, `Session::node_has_ancestor` | `(&str, bool) -> Result<Vec<&Node>>; () -> Vec<&Node>; (&str) -> Option<&Node>; (&str) -> Option<&Node>; (&Node, &Node) -> bool` | `src/fs/operations/browse.rs::list` |
| `dir_ops` | `Session::mkdir`, `Session::rm`, `Session::mv`, `Session::rename` | `(&str) -> Result<Node>; (&str) -> Result<()>; (&str, &str) -> Result<()>; (&str, &str) -> Result<()>` | `src/fs/operations/dir_ops.rs::mkdir` |
| `download` | `Session::download`, `Session::download_with_offset`, `Session::download_to_file` | `(&Node, Write) -> Result<()>; (&Node, Write, u64) -> Result<()>; (&Node, Path) -> Result<()>` | `src/fs/operations/download.rs::download` |
| `upload` | `Session::upload_node_attribute`, `Session::upload`, `Session::upload_resumable`, `Session::upload_from_bytes`, `Session::upload_from_reader` | `(&[u8], &str, &[u8;16]) -> Result<String>; (Path, &str) -> Result<Node>; (Path, &str) -> Result<Node>; (&[u8], &str, &str) -> Result<Node>; (AsyncRead+AsyncSeek+Unpin+Send, &str, u64, &str) -> Result<Node>` | `src/fs/operations/upload.rs::upload_node_attribute` |
| `quota` | `Session::quota` | `() -> Result<Quota>` | `src/fs/operations/quota.rs::quota` |
| `tree` | `Session::refresh` | `() -> Result<()>` | `src/fs/operations/tree.rs::refresh` |
| `export` | `Session::export`, `Session::export_many` | `(&str) -> Result<String>; (&[&str]) -> Result<Vec<(String, String)>>` | `src/fs/operations/export.rs::export` |
| `utils` | No public entry points (internal helpers only). | N/A | `src/fs/operations/utils.rs::normalize_path` |

**Crypto (src/crypto/*)**

| Module | Public entry points | What it is used for | Evidence |
| --- | --- | --- | --- |
| `aes` | `aes128_ecb_encrypt_block`, `aes128_ecb_decrypt_block`, `aes128_ecb_encrypt`, `aes128_ecb_decrypt`, `aes128_cbc_encrypt`, `aes128_cbc_decrypt`, `aes128_ctr_encrypt`, `aes128_ctr_decrypt`, `chunk_mac_calculate`, `meta_mac_calculate` | AES-128 primitives for key/attribute encryption and file chunk crypto. | `src/crypto/aes.rs::aes128_ecb_encrypt_block` |
| `auth` | `derive_key_v2`, `encrypt_key`, `decrypt_key`, `decrypt_private_key`, `parse_raw_private_key`, `decrypt_session_id` | Authentication and key derivation helpers. | `src/crypto/auth.rs::derive_key_v2` |
| `authring` | `AuthRing`, `AuthEntry`, `AuthState`, `normalize_handle` | Per-contact key fingerprint storage and trust state. | `src/crypto/authring.rs::AuthRing` |
| `key_manager` | `KeyManager`, `ShareKeyEntry`, `PendingOutEntry`, `PendingInEntry`, `PendingUid`, `Warnings`, `SHAREKEY_FLAG_TRUSTED`, `SHAREKEY_FLAG_IN_USE` | ^!keys container encoding/decoding and share-key tracking. | `src/crypto/key_manager.rs::KeyManager` |
| `keyring` | `Keyring` | *keyring attribute decrypt/encrypt and keypair generation. | `src/crypto/keyring.rs::Keyring` |
| `keys` | `make_password_key`, `make_username_hash`, `pack_node_key` | MEGA-specific KDF and node-key packing. | `src/crypto/keys.rs::make_password_key` |
| `random` | `make_random_key` | Random key generation helper. | `src/crypto/random.rs::make_random_key` |
| `rsa` | `MegaRsaKey`, `read_mpi` | RSA-2048 key operations and MPI parsing. | `src/crypto/rsa.rs::MegaRsaKey` |

**Error Model**

| Error variant / category | When it occurs | Contains | Evidence |
| --- | --- | --- | --- |
| `HttpError` | HTTP request failed with a status code. | `u16` status code. | `src/error.rs::MegaError` |
| `RequestError` | Underlying HTTP request error from `reqwest`. | `reqwest::Error`. | `src/error.rs::MegaError` |
| `JsonError` | JSON parsing/serialization error. | `serde_json::Error`. | `src/error.rs::MegaError` |
| `ServerBusy` | API returns EAGAIN repeatedly and retries are exhausted. | No extra fields. | `src/error.rs::MegaError`, `src/api/client.rs::ApiClient` |
| `InvalidResponse` | Response shape is missing/invalid for expected API fields. | No extra fields. | `src/error.rs::MegaError` |
| `ApiError` | MEGA API returned a negative error code. | `code: i32`, `message: String`. | `src/error.rs::MegaError` |
| `CryptoError` | Cryptographic operation failed. | `String` message. | `src/error.rs::MegaError` |
| `InvalidChallenge` | Registration challenge verification failed. | No extra fields. | `src/error.rs::MegaError` |
| `Base64Error` | Base64 decoding failure. | `base64::DecodeError`. | `src/error.rs::MegaError` |
| `DowngradeDetected` | ^!keys attribute appears downgraded. | No extra fields. | `src/error.rs::MegaError` |
| `InvalidState` | Registration state string is malformed. | `String` message. | `src/error.rs::MegaError` |
| `Custom` | Custom error message paths. | `String` message. | `src/error.rs::MegaError` |

**HTTP Behavior**

| Aspect | Current behavior | Evidence |
| --- | --- | --- |
| Base URL | API requests use `https://g.api.mega.co.nz/cs`. | `src/api/client.rs::API_URL` |
| Auth | Adds `sid` query parameter when `session_id` is set on `ApiClient`. | `src/api/client.rs::ApiClient` |
| Headers | API POST sets `Content-Type: application/json`. | `src/http.rs::HttpClient` |
| Timeouts | `HttpClient` builder sets 60s timeout; API requests are wrapped in a 20s `tokio::time::timeout`. | `src/http.rs::HttpClient`, `src/api/client.rs::ApiClient` |
| Retries | `ApiClient::request` retries with exponential backoff on `EAGAIN` until max attempts. | `src/api/client.rs::ApiClient` |
| TLS | `reqwest` is built with `rustls-tls` feature. | `Cargo.toml::reqwest` |
| Redirects | `HttpClient::post` disables automatic redirects and follows up to 10 manually; non-redirect errors become `HttpError`. | `src/http.rs::HttpClient` |
