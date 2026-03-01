<p align="center">
  <img src="assets/hero-banner.png" alt="hero pane" width="980">
</p>

<p align="center">
  <a href="https://crates.io/crates/megalib"><img src="https://img.shields.io/badge/crates.io-megalib-F59E0B?style=for-the-badge&logo=rust&logoColor=white" alt="Crates.io"></a>
  <a href="https://docs.rs/megalib"><img src="https://img.shields.io/badge/docs.rs-megalib-3B82F6?style=for-the-badge&logo=readthedocs&logoColor=white" alt="Documentation"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-8B5CF6?style=for-the-badge" alt="MIT License"></a>
  <a href="https://github.com/11philip22/megalib/pulls"><img src="https://img.shields.io/badge/PRs-Welcome-22C55E?style=for-the-badge" alt="PRs Welcome"></a>
</p>

<p align="center">
  <a href="#features">Features</a> · <a href="#installation">Installation</a> · <a href="#quickstart">Quickstart</a> · <a href="#running-the-cli-examples">Running the CLI Examples</a> · <a href="#documentation">Documentation</a> · <a href="#contributing">Contributing</a> · <a href="#support">Support</a> · <a href="#license">License</a>
</p>

---

## Features

- **Authentication**:
  - Full registration flow (account creation + email verification)
  - Login (supports both v1 and v2/PBKDF2 authentication)
  - Session management and caching
  - Password Change (`change_password`)

- **Filesystem**:
  - Fetch filesystem tree
  - List files and directories
  - Get node information (`stat`)
  - Create directories (`mkdir`)
  - Remove files/folders (`rm`)
  - Rename files/folders (`rename`)
  - Move files/folders (`mv`)
  - Access Public Folders (`open_folder`)

- **File Transfer**:
  - File upload with optional resume support
  - File download with resume support
  - Parallel transfer workers support
  - Progress callbacks for monitoring transfers
  - Text/Video/Image streaming support
  - Automatic thumbnail generation on upload
  - Public link generation (`export`, `export_many`)
  - Proxy support (HTTP/HTTPS/SOCKS5)

- **Node Operations**:
  - Get node by handle
  - Check ancestor relationships
  - Check write permissions

- **Sharing & Contacts**:
  - Share folders with other users by path (`share_folder`)
  - List contacts (`list_contacts`)
  - Access incoming shared folders

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
megalib = "0.8.1"
tokio = { version = "1", features = ["full"] }
```

## Quickstart

Minimal login + list to confirm everything works:

```rust
use megalib::SessionHandle;

#[tokio::main]
async fn main() -> megalib::Result<()> {
    let session = SessionHandle::login("user@example.com", "password").await?;
    session.refresh().await?;

    // Cloud Drive paths are rooted at /Root
    for node in session.list("/Root", false).await? {
        println!("{} ({} bytes)", node.name, node.size);
    }

    Ok(())
}
```

## Examples

Run any command as shown (replace placeholder values with your own).

```bash
# Auth + listing
cargo run --example login -- --email you@example.com --password "your-password"
cargo run --example ls -- --email you@example.com --password "your-password" --path /Root

# Upload / download
cargo run --example upload -- --email you@example.com --password "your-password" ./local-file.txt /Root
cargo run --example download -- --email you@example.com --password "your-password" /Root/remote-file.txt ./downloaded-file.txt

# Resume transfers
cargo run --example upload_resume -- --email you@example.com --password "your-password" ./large-file.bin /Root
cargo run --example download_resume -- --email you@example.com --password "your-password" /Root/large-file.bin ./large-file.bin

# Sharing + links
cargo run --example export -- --email you@example.com --password "your-password" --path /Root/file.txt
cargo run --example share -- --email you@example.com --password "your-password" --folder /Root/shared --recipient friend@example.com --level 0

# Public links / folders
cargo run --example folder -- "https://mega.nz/folder/<FOLDER_ID>#<KEY>"
cargo run --example download_public -- "https://mega.nz/file/<FILE_ID>#<KEY>" ./public-file.bin

# In-memory / reader uploads
cargo run --example upload_bytes -- --email you@example.com --password "your-password" /Root
cargo run --example upload_reader -- --email you@example.com --password "your-password" /Root
```
`--proxy <PROXY_URL>` is also supported on credential-based examples.

## Documentation

For detailed API documentation, visit [docs.rs/megalib](https://docs.rs/megalib).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/cool-feature`)
3. Commit your changes (`git commit -m 'Add some cool feature'`)
4. Push to the branch (`git push origin feature/cool-feature`)
5. Open a Pull Request

## Support

If this crate saves you time or helps your work, support is appreciated:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/11philip22)

## License

This project is licensed under the MIT License; see the [license](https://opensource.org/licenses/MIT) for details.

## Disclaimer

This is an unofficial client library and is not affiliated with, associated with, authorized by, endorsed by, or in any way officially connected with Mega Limited.
