# megalib

[![Crates.io](https://img.shields.io/crates/v/megalib.svg)](https://crates.io/crates/megalib)
[![Documentation](https://docs.rs/megalib/badge.svg)](https://docs.rs/megalib)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/11philip22/megalib/pulls)

<img src="https://upload.wikimedia.org/wikipedia/commons/b/bc/MEGA_logo.png" alt="MEGA Logo" width="300">

A Rust client library for the MEGA cloud storage service.

This library provides a clean, asynchronous Rust interface for interacting with MEGA, supporting authentication, filesystem access, and file management.

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
  - Share folders with other users (`share_folder`)
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

    for node in session.list("/Root", false).await? {
        println!("{} ({} bytes)", node.name, node.size);
    }

    Ok(())
}
```

## More Examples

```bash
cargo run --example <name> -- <args>
```

Suggested starting points: `login`, `ls`, `upload`, `download`, `upload_resume`, `download_resume`,
`export`, `share`, `folder`, `download_public`, `upload_bytes`, `upload_reader`.
See `examples/` for the full list and example-specific flags.

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

This project is licensed under the MIT License; see [license](license) for details.

## Disclaimer

This is an unofficial client library and is not affiliated with, associated with, authorized by, endorsed by, or in any way officially connected with Mega Limited.
