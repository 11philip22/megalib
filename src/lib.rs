//! # megalib
//!
//! Rust client library for Mega.nz cloud storage.
//!
//! ## Features
//!
//! - **Authentication**: Login with email/password, support for HTTP proxies, and specific session handling.
//!   - Full account registration flow (register + verify).
//! - **Filesystem Operations**:
//!   - List files and folders (support for recursive listing).
//!   - Create directories (`mkdir`).
//!   - Move (`mv`), rename, and delete (`rm`) files/folders.
//!   - Get file attributes (`stat`) and user quota information.
//! - **File Transfers**:
//!   - Robust upload and download with automatic resume support.
//!   - Parallel transfer workers for improved performance.
//!   - Progress tracking with custom callbacks.
//!   - Optional preview generation for media uploads.
//! - **Sharing & Public Access**:
//!   - Export public download links (`export`).
//!   - Parse and download files from public MEGA links.
//!   - Open and browse public folders (`open_folder`) without login.
//!
//! Path-based operations (`list`, `stat`, `mkdir`, `export`, uploads, etc.) rely on
//! the cached node tree, so call `SessionHandle::refresh()` after login and after
//! remote changes to keep paths accurate.
//!
//! ## Example: Basic Usage
//!
//! ```no_run
//! use megalib::SessionHandle;
//!
//! # async fn example() -> megalib::Result<()> {
//! // Login
//! let session = SessionHandle::login("user@example.com", "password").await?;
//!
//! // List files in root (Cloud Drive root is /Root)
//! let files = session.list("/Root", false).await?;
//! for file in files {
//!     println!("{} ({} bytes)", file.name, file.size);
//! }
//!
//! // Upload a file with resume support
//! session.upload_resumable("local_file.txt", "/Root").await?;
//!
//! // Download a file to local disk
//! if let Some(node) = session.stat("/Root/remote_file.txt").await? {
//!     session.download_to_file(&node, "downloaded_file.txt").await?;
//! }
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Example: Account Registration
//!
//! Registration is a two-step process:
//!
//! ```no_run
//! use megalib::session::{register, verify_registration};
//!
//! # async fn example() -> megalib::Result<()> {
//! // Step 1: Initiate registration (sends verification email)
//! let state = register("user@example.com", "SecurePassword123", "John Doe", None).await?;
//! println!("Check your email! State to save: {}", state.serialize());
//!
//! // Step 2: After receiving email, complete registration
//! // let signup_key = "..."; // Extract from email link
//! // verify_registration(&state, signup_key).await?;
//! # Ok(())
//! # }
//! ```

pub mod api;
pub mod base64;
pub mod crypto;
pub mod error;
pub mod fs;
pub mod http;
pub mod preview;
pub mod progress;
pub mod public;
pub mod session;

// Re-export commonly used types
pub use error::{MegaError, Result};
pub use fs::{Node, NodeType, Quota};
pub use progress::{ProgressCallback, TransferProgress};
pub use public::{
    PublicFile, PublicFolder, download_public_file, get_public_file_info, open_folder,
    parse_folder_link, parse_mega_link,
};
pub use session::{
    AccountInfo, FolderSessionBlob, RegistrationState, SessionBlob, SessionHandle, register,
    verify_registration,
};
