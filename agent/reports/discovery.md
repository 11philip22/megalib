**Public Surface Entry Points**
- `src/lib.rs` exposes public module `api`. Evidence: `src/lib.rs::api`.
- `src/lib.rs` exposes public module `base64`. Evidence: `src/lib.rs::base64`.
- `src/lib.rs` exposes public module `crypto`. Evidence: `src/lib.rs::crypto`.
- `src/lib.rs` exposes public module `error`. Evidence: `src/lib.rs::error`.
- `src/lib.rs` exposes public module `fs`. Evidence: `src/lib.rs::fs`.
- `src/lib.rs` exposes public module `http`. Evidence: `src/lib.rs::http`.
- `src/lib.rs` exposes public module `preview` (cfg-gated in source). Evidence: `src/lib.rs::preview`.
- `src/lib.rs` exposes public module `progress`. Evidence: `src/lib.rs::progress`.
- `src/lib.rs` exposes public module `public`. Evidence: `src/lib.rs::public`.
- `src/lib.rs` exposes public module `session`. Evidence: `src/lib.rs::session`.
- `src/lib.rs` re-exports `MegaError` and `Result`. Evidence: `src/lib.rs::MegaError`.
- `src/lib.rs` re-exports `Node`, `NodeType`, and `Quota`. Evidence: `src/lib.rs::Node`.
- `src/lib.rs` re-exports `ProgressCallback`, `TransferProgress`, and `make_progress_bar`. Evidence: `src/lib.rs::ProgressCallback`.
- `src/lib.rs` re-exports `PublicFile`, `PublicFolder`, `download_public_file`, `get_public_file_info`, `open_folder`, `parse_folder_link`, and `parse_mega_link`. Evidence: `src/lib.rs::PublicFile`.
- `src/lib.rs` re-exports `RegistrationState`, `Session`, `register`, and `verify_registration`. Evidence: `src/lib.rs::RegistrationState`.
- `src/public.rs` exposes `PublicFile` with public accessors `get_key` and `get_link`. Evidence: `src/public.rs::PublicFile`.
- `src/public.rs` exposes `PublicFolder` with public APIs `nodes`, `list`, `stat`, and `download`. Evidence: `src/public.rs::PublicFolder`.
- `src/public.rs` exposes public link helpers `parse_mega_link`, `get_public_file_info`, `download_public_file`, `download_public_file_data`, `parse_folder_link`, and `open_folder`. Evidence: `src/public.rs::parse_mega_link`.
Evidence:
- `src/lib.rs::api`
- `src/lib.rs::base64`
- `src/lib.rs::crypto`
- `src/lib.rs::error`
- `src/lib.rs::fs`
- `src/lib.rs::http`
- `src/lib.rs::preview`
- `src/lib.rs::progress`
- `src/lib.rs::public`
- `src/lib.rs::session`
- `src/lib.rs::MegaError`
- `src/lib.rs::Node`
- `src/lib.rs::ProgressCallback`
- `src/lib.rs::PublicFile`
- `src/lib.rs::RegistrationState`
- `src/public.rs::PublicFile`
- `src/public.rs::PublicFolder`
- `src/public.rs::parse_mega_link`

**Client & HTTP Stack**
- The primary API client type is `ApiClient`. Evidence: `src/api/client.rs::ApiClient`.
- `ApiClient::request` and `request_with_allowed` build JSON requests and call into the HTTP layer for execution, with retry/backoff on `EAGAIN` and `ServerBusy` on exhaustion. Evidence: `src/api/client.rs::ApiClient`.
- The HTTP layer is `HttpClient`, which wraps `reqwest::Client` and exposes `post` for JSON requests with manual redirect handling and non-2xx status as `MegaError::HttpError`. Evidence: `src/http.rs::HttpClient`.
- Authentication is applied by setting a session id via `ApiClient::set_session_id`, and `Session::login` decrypts `csid` then sets it on the API client for subsequent requests. Evidence: `src/api/client.rs::ApiClient`, `src/session/session.rs::Session`.
- Public link operations instantiate `ApiClient::new()` without session credentials. Evidence: `src/public.rs::get_public_file_info`.
Evidence:
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`
- `src/session/session.rs::Session`
- `src/public.rs::get_public_file_info`

**Error Model**
- The public error type is `MegaError`, and the public `Result<T>` alias uses it. Evidence: `src/error.rs::MegaError`.
- `MegaError` includes variants for HTTP status, request/JSON/base64 errors, API errors, crypto errors, invalid response, invalid challenge, downgrade detection, invalid state, server busy, and custom messages. Evidence: `src/error.rs::MegaError`.
- `HttpClient::post` maps non-success HTTP responses to `MegaError::HttpError` and emits a `MegaError::Custom("Too many redirects")` on excessive redirects. Evidence: `src/http.rs::HttpClient`.
- `ApiClient::request` maps negative API codes into `MegaError::ApiError` and uses `MegaError::ServerBusy` when `EAGAIN` retries exceed the limit. Evidence: `src/api/client.rs::ApiClient`.
- `MegaError` uses `#[from]` conversions for `reqwest::Error`, `serde_json::Error`, and `base64::DecodeError`. Evidence: `src/error.rs::MegaError`.
Evidence:
- `src/error.rs::MegaError`
- `src/http.rs::HttpClient`
- `src/api/client.rs::ApiClient`

**Modules By Domain**
- API domain centers on `ApiClient` and `ApiErrorCode`, including `request`, `request_batch`, `poll_sc`, `get_user_attribute`, and `set_private_attribute`. Evidence: `src/api/client.rs::ApiClient`, `src/api/client.rs::ApiErrorCode`.
- Filesystem domain core types are `Node`, `NodeType`, and `Quota`. Evidence: `src/fs/node.rs::Node`.
- Filesystem tree refresh is `Session::refresh`, which fetches and parses nodes into a cached tree. Evidence: `src/fs/operations/tree.rs::refresh`.
- Filesystem browsing includes `Session::list`, `list_contacts`, `stat`, `get_node_by_handle`, and `node_has_ancestor`. Evidence: `src/fs/operations/browse.rs::list`, `src/fs/operations/browse.rs::list_contacts`.
- Filesystem mutation includes `Session::mkdir`, `rm`, `mv`, and `rename`. Evidence: `src/fs/operations/dir_ops.rs::mkdir`.
- File transfers include `Session::download`, `download_with_offset`, and `download_to_file`, plus uploads via `upload`, `upload_resumable`, `upload_from_bytes`, `upload_from_reader`, and `upload_node_attribute`. Evidence: `src/fs/operations/download.rs::download`, `src/fs/operations/upload.rs::upload`.
- Public link export includes `Session::export` and `export_many`. Evidence: `src/fs/operations/export.rs::export`.
- Quota fetching is `Session::quota`. Evidence: `src/fs/operations/quota.rs::quota`.
- Session domain includes `Session::login` and `Session::login_with_proxy` for authentication. Evidence: `src/session/session.rs::login`.
- Registration flow is implemented by `RegistrationState`, `register`, and `verify_registration`. Evidence: `src/session/registration.rs::RegistrationState`.
- Session storage uses `Session::save`, `Session::load`, and `Session::load_with_proxy`. Evidence: `src/session/session.rs::save`.
- Session key/contact utilities include `ContactPublicKeys` and `Session::fetch_contact_public_keys`. Evidence: `src/session/keys.rs::ContactPublicKeys`.
- Crypto authring types are `AuthRing` and `AuthState` for per-contact trust. Evidence: `src/crypto/authring.rs::AuthRing`.
- Crypto key management uses `KeyManager` for ^!keys containers and share key tracking. Evidence: `src/crypto/key_manager.rs::KeyManager`.
- Crypto keyring handling is represented by `Keyring` with `from_encrypted`/`to_encrypted`/`generate`. Evidence: `src/crypto/keyring.rs::Keyring`.
- Crypto AES helpers include `aes128_ecb_encrypt_block` and `aes128_cbc_decrypt` for key and attribute operations. Evidence: `src/crypto/aes.rs::aes128_ecb_encrypt_block`.
- Crypto RSA type `MegaRsaKey` supports key generation and RSA operations. Evidence: `src/crypto/rsa.rs::MegaRsaKey`.
Evidence:
- `src/api/client.rs::ApiClient`
- `src/api/client.rs::ApiErrorCode`
- `src/fs/node.rs::Node`
- `src/fs/operations/tree.rs::refresh`
- `src/fs/operations/browse.rs::list`
- `src/fs/operations/browse.rs::list_contacts`
- `src/fs/operations/dir_ops.rs::mkdir`
- `src/fs/operations/download.rs::download`
- `src/fs/operations/upload.rs::upload`
- `src/fs/operations/export.rs::export`
- `src/fs/operations/quota.rs::quota`
- `src/session/session.rs::login`
- `src/session/registration.rs::RegistrationState`
- `src/session/session.rs::save`
- `src/session/keys.rs::ContactPublicKeys`
- `src/crypto/authring.rs::AuthRing`
- `src/crypto/key_manager.rs::KeyManager`
- `src/crypto/keyring.rs::Keyring`
- `src/crypto/aes.rs::aes128_ecb_encrypt_block`
- `src/crypto/rsa.rs::MegaRsaKey`

**Feature Flags / Configuration**
- The `preview` module is gated to non-WASM targets via `#[cfg(not(target_arch = "wasm32"))]`. Evidence: `src/lib.rs::preview`.
- Proxy support is gated to non-WASM targets for `HttpClient::with_proxy`, `ApiClient::with_proxy`, and `Session::login_with_proxy`. Evidence: `src/http.rs::HttpClient`, `src/api/client.rs::ApiClient`, `src/session/session.rs::login_with_proxy`.
- The API client uses a WASM-specific `sleep` implementation behind `cfg(target_arch = "wasm32")`. Evidence: `src/api/client.rs::sleep`.
- Native-only file APIs such as `upload` and `download_to_file` are gated with `cfg(not(target_arch = "wasm32"))`. Evidence: `src/fs/operations/upload.rs::upload`.
Evidence:
- `src/lib.rs::preview`
- `src/http.rs::HttpClient`
- `src/api/client.rs::ApiClient`
- `src/session/session.rs::login_with_proxy`
- `src/api/client.rs::sleep`
- `src/fs/operations/upload.rs::upload`
- `src/fs/operations/download.rs::download_to_file`

**Usage Patterns From Docs/Examples**
- Login pattern from README uses `Session::login` and prints the session email. Evidence: `README.md > Login (Standard)`.
```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::login("user@example.com", "password").await?;
    println!("Logged in as: {}", session.email);
    Ok(())
}
```
- Session caching pattern from README uses `Session::load` and `Session::save` for persistence. Evidence: `README.md > Session Caching`.
```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load from file if exists
    let mut session = match Session::load("session.json").await? {
        Some(s) => s,
        None => {
            // Fallback to login
            let s = Session::login("user@example.com", "password").await?;
            s.save("session.json")?;
            s
        }
    };
    
    // Validate session
    session.refresh().await?;
    Ok(())
}
```
- Filesystem listing pattern from README uses `Session::refresh`, `list`, and `stat`. Evidence: `README.md > List Files and Get Info`.
```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    // List root directory
    let nodes = session.list("/", false)?;
    for node in nodes {
        println!("- {} ({} bytes)", node.name, node.size);
    }
    
    // Get info for a specific file
    if let Some(node) = session.stat("/Root/Documents/Report.pdf") {
        println!("Found file: {}", node.name);
    }

    Ok(())
}
```
Evidence:
- `README.md > Login (Standard)`
- `README.md > Session Caching`
- `README.md > List Files and Get Info`
