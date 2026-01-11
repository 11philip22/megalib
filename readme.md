# megalib

A Rust client library for the MEGA cloud storage service.

This library provides a clean, asynchronous Rust interface for interacting with MEGA, supporting authentication, filesystem access, and file management.

## Features

- **Authentication**:
  - Full registration flow (account creation + email verification)
  - Login (supports both v1 and v2/PBKDF2 authentication)
  - Session management and caching

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
  - Progress callbacks for monitoring transfers
  - Text/Video/Image streaming support
  - Automatic thumbnail generation on upload
  - Public link generation (`export`, `export_many`)
  - Proxy support (HTTP/HTTPS/SOCKS5)

- **Node Operations**:
  - Get node by handle
  - Check ancestor relationships
  - Check write permissions

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

#### Download

```rust
use megalib::Session;
use std::fs::File;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::login("user@example.com", "password").await?;
    session.refresh().await?;

    if let Some(node) = session.stat("/Root/Project/final.txt") {
        let mut file = File::create("downloaded_final.txt")?;
        session.download(node, &mut file).await?;
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
    
    // download_to_file automatically resumes partial downloads
    if let Some(node) = session.stat("/Root/LargeVideo.mp4") {
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

# Login and list files
cargo run --example ls -- --email test@example.com --password TestPass123 --path /Root/

# Upload (standard)
cargo run --example upload -- --email test@example.com --password TestPass123 local_file.txt /Root/

# Upload with resume support
cargo run --example upload_resume -- --email test@example.com --password TestPass123 large_file.zip /Root/

# Download with resume support
cargo run --example download_resume -- --email test@example.com --password TestPass123 /Root/file.zip ./file.zip

# Export public link
cargo run --example export -- --email test@example.com --password TestPass123 /Root/file.txt
```
