# megalib

[![Crates.io](https://img.shields.io/crates/v/megalib.svg)](https://crates.io/crates/megalib)
[![Documentation](https://docs.rs/megalib/badge.svg)](https://docs.rs/megalib)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

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
megalib = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

## Usage Examples

### 1. Authentication

#### Registration

```rust
use megalib::session::registration::{register, verify_registration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Step 1: Initiate registration
    let state = register("newuser@example.com", "MySecretPassword", "New User").await?;
    println!("Registration initiated! Check your email for the confirmation link.");
    
    // Save state string to use after user clicks the link
    let state_str = state.serialize();
    
    // ... User clicks link ...
    
    // Step 2: Complete registration with the link
    let link = "https://mega.nz/#confirm..."; // From email
    let restored_state = megalib::session::registration::RegistrationState::deserialize(&state_str)?;
    
    verify_registration(&restored_state, link).await?;
    println!("Account verified successfully!");
    
    Ok(())
}
```

#### Login (Standard)

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::login("user@example.com", "password").await?;
    println!("Logged in as: {}", session.email);
    Ok(())
}
```

#### Login (With Proxy)

The library supports HTTP, HTTPS, and SOCKS5 proxies.

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a SOCKS5 proxy
    let session = Session::login_with_proxy(
        "user@example.com", 
        "password", 
        "socks5://127.0.0.1:9050"
    ).await?;
    
    println!("Logged in via proxy as: {}", session.email);
    Ok(())
}
```

#### Change Password
 
```rust
use megalib::Session;
 
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "old_password").await?;
    
    session.change_password("new_secure_password").await?;
    println!("Password changed successfully!");
    
    Ok(())
}
```
 
### 2. Session Management

#### Session Caching

Save your session to avoid logging in every time.

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

#### Loading Session with Proxy

When loading a cached session, you can optionally specify a proxy to use for the restored session.

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = match Session::load_with_proxy("session.json", "http://proxy:8080").await? {
        Some(s) => s,
        None => {
            // Login with proxy if no cache
            let s = Session::login_with_proxy("user@example.com", "password", "http://proxy:8080").await?;
            s.save("session.json")?;
            s
        }
    };
    
    session.refresh().await?;
    Ok(())
}
```

### 3. Filesystem Operations

#### List Files and Get Info

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

#### File Management (mkdir, mv, rename, rm)

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    // Create directory
    session.mkdir("/Root/Project").await?;

    // Move a file
    session.mv("/Root/draft.txt", "/Root/Project").await?;

    // Rename a file
    session.rename("/Root/Project/draft.txt", "final.txt").await?;

    // Delete a file
    session.rm("/Root/Project/old_notes.txt").await?;

    Ok(())
}
```

#### Storage Quota

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    
    let quota = session.quota().await?;
    println!("Used: {} / {} bytes ({:.1}%)", 
        quota.used, quota.total, quota.usage_percent());
    println!("Free: {} bytes", quota.free());
    
    Ok(())
}
```

#### Node Type Checks

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    for node in session.list("/Root", true)? {
        if node.is_file() {
            println!("File: {} ({} bytes)", node.name, node.size);
        } else if node.is_folder() {
            println!("Folder: {}/", node.name);
        }
        
        // Check if already exported
        if node.is_exported() {
            if let Some(url) = node.get_link(true) {
                println!("  Public link: {}", url);
            }
        }
    }
    
    Ok(())
}
```

#### Node Operations

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    // Get node by handle (useful for API integrations)
    if let Some(node) = session.get_node_by_handle("ABC123xyz") {
        println!("Found: {}", node.name);
    }

    // Check if a node is inside a folder
    let file = session.stat("/Root/Documents/report.pdf").unwrap();
    let folder = session.stat("/Root/Documents").unwrap();
    if session.node_has_ancestor(file, folder) {
        println!("File is inside Documents folder");
    }

    // Check if node is writable
    if file.is_writable() {
        println!("Can modify this file");
    }

    Ok(())
}
```

#### List Contacts

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    // List users who have shared files with you
    for contact in session.list_contacts() {
        println!("Contact: {} ({})", contact.name, contact.handle);
    }

    Ok(())
}
```

### 4. File Transfer

#### Upload

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    let node = session.upload("local_file.txt", "/Root/Project").await?;
    println!("Uploaded: {}", node.name);
    
    Ok(())
}
```

#### Upload with Thumbnail Generation

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    // Enable automatic thumbnail generation for images/videos
    session.enable_previews(true);

    // Upload will now generate and attach thumbnails
    let node = session.upload("photo.jpg", "/Root/Photos").await?;
    println!("Uploaded with thumbnail: {}", node.name);
    
    Ok(())
}
```

#### Download

```rust
use megalib::Session;
use std::fs::File;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    if let Some(node) = session.stat("/Root/Project/final.txt").cloned() {
        let mut file = File::create("downloaded_final.txt")?;
        session.download(&node, &mut file).await?;
    }
    
    Ok(())
}
```

#### Download Resume Support

Enable resumption of interrupted downloads.

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;
    
    // Enable resume support
    session.set_resume(true);
    
    // Speed up large downloads with parallel workers
    session.set_workers(4);
    
    // download_to_file automatically resumes partial downloads
    if let Some(node) = session.stat("/Root/LargeVideo.mp4").cloned() {
        session.download_to_file(&node, "video.mp4").await?;
    }
    
    Ok(())
}
```

#### Upload with Resume Support

For large uploads that may be interrupted:

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    // Speed up large uploads with parallel workers
    session.set_workers(4);
    
    // upload_resumable saves state to .megalib_upload file
    // If interrupted, re-running will resume from last chunk
    let node = session.upload_resumable("large_file.zip", "/Root").await?;
    println!("Uploaded: {}", node.name);
    
    Ok(())
}
```

#### Progress Callbacks

Monitor transfer progress:

```rust
use megalib::{Session, progress::TransferProgress};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;
    
    // Set progress callback
    session.watch_status(Box::new(|progress: &TransferProgress| {
        println!("{:.1}% - {}", progress.percent(), progress.filename);
        true // Return false to cancel
    }));
    
    // Upload/download will now report progress
    session.upload("file.txt", "/Root").await?;
    
    Ok(())
}
```

### 5. Sharing

#### Export Public Link

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    let url = session.export("/Root/Project/final.txt").await?;
    println!("Public Download Link: {}", url);
    
    Ok(())
}
```

#### Export Multiple Files

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    // Export multiple files in one batch (more efficient)
    let paths = &["/Root/doc1.pdf", "/Root/doc2.pdf", "/Root/image.png"];
    let results = session.export_many(paths).await?;
    
    for (path, url) in results {
        println!("{} -> {}", path, url);
    }
    
    Ok(())
}
```

#### Get Existing Export Link

```rust
use megalib::Session;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    if let Some(node) = session.stat("/Root/shared_file.txt") {
        // Get link if already exported
        if let Some(url) = node.get_link(true) {
            println!("Existing link: {}", url);
        }
        
        // Get just the key (for manual link construction)
        if let Some(key) = node.get_key() {
            println!("Node key: {}", key);
        }
    }
    
    Ok(())
}
```

#### Share a folder
 
Share a folder with another MEGA user.
 
```rust
// Share folder with friend@example.com (Read-only)
session.share_folder("FOLDER_HANDLE", "friend@example.com", 0).await?;
```
 
Access levels:
- `0`: Read-only
- `1`: Read/Write
- `2`: Full Access
 

### 6. Public Links & Folders (No Login Required)

You can interact with public MEGA links without logging in.

#### Download a Public File

```rust
use megalib::public::download_public_file;
use std::fs::File;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create("shared_file.zip")?;
    
    // Download directly from a public link
    download_public_file("https://mega.nz/file/ABC123#key...", &mut file).await?;
    println!("Download complete!");
    
    Ok(())
}
```

#### Browse and Download from Public Folder

```rust
use megalib::public::open_folder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Open a public folder
    let folder = open_folder("https://mega.nz/folder/XYZ789#key...").await?;
    
    // List files
    for node in folder.list("/", true) {
        println!("Found: {} ({} bytes)", node.name, node.size);
        
        // Download a specific file
        if node.name == "image.jpg" {
            let mut file = std::fs::File::create("image.jpg")?;
            folder.download(node, &mut file).await?;
        }
    }
    
    Ok(())
}
```

## Running Examples

Clone the repository and run the included examples:

```bash
# Register
cargo run --example register -- --email test@example.com --password TestPass123 --name "Test User"

# Verify Registration
cargo run --example verify -- "https://mega.nz/#confirm..."

# Change Password
cargo run --example passwd -- --email test@example.com --old OldPass --new NewPass

# Login and list files
cargo run --example ls -- --email test@example.com --password TestPass123 --path /Root/

# Session Caching
cargo run --example cached_session -- --email test@example.com --password TestPass123

# File Operations
cargo run --example mkdir -- --email test@example.com --password TestPass123 /Root/NewFolder
cargo run --example mv -- --email test@example.com --password TestPass123 /Root/file.txt /Root/NewFolder/
cargo run --example rename -- --email test@example.com --password TestPass123 /Root/file.txt "new_name.txt"
cargo run --example rm -- --email test@example.com --password TestPass123 /Root/delete_me.txt
cargo run --example stat -- --email test@example.com --password TestPass123 /Root/file.txt

# Upload (standard)
cargo run --example upload -- --email test@example.com --password TestPass123 local_file.txt /Root/

# Upload with resume support & parallel workers
cargo run --example upload_resume -- --email test@example.com --password TestPass123 large_file.zip /Root/

# Download (standard)
cargo run --example download -- --email test@example.com --password TestPass123 /Root/file.zip ./file.zip

# Download with resume support & parallel workers
cargo run --example download_resume -- --email test@example.com --password TestPass123 /Root/file.zip ./file.zip

# Export public link
cargo run --example export -- --email test@example.com --password TestPass123 /Root/file.txt

# Share a folder
cargo run --example share -- --email test@example.com --password TestPass123 --folder /Root/Documents --recipient friend@example.com --level 0

# Public File Download (no login)
cargo run --example download_public -- "https://mega.nz/file/..."

# Public Folder Browser (no login)
cargo run --example folder -- "https://mega.nz/folder/..."
```

## Contributing

PRs are welcome!  
Please run `cargo fmt` and `cargo clippy` before submitting.

If you’re changing behavior, please document it in the PR.

## Support

If this crate saves you time or helps your work, support is appreciated:

[![Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/11philip22)

## License

This project is licensed under the MIT License; see [license](license) for details.

## Disclaimer

This is an unofficial client library and is not affiliated with, associated with, authorized by, endorsed by, or in any way officially connected with Mega Limited.
