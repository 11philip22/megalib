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
//! Call `SessionHandle::fetch_nodes()` after login to populate the cached node tree.
//! Path-based helpers (`list`, `stat`, `mkdir`, `export`, uploads, etc.) remain
//! available as compatibility APIs over the cached tree, but their old
//! canonical names are deprecated. Use explicit `*_by_path` aliases such as
//! `list_by_path` and `upload_by_path` if you still want path-oriented calls,
//! or prefer working directly with cached [`Node`] values.
//!
//! ## Example: Basic Usage
//!
//! ```no_run
//! use megalib::SessionHandle;
//!
//! # async fn example() -> megalib::Result<()> {
//! // Login
//! let session = SessionHandle::login("user@example.com", "password").await?;
//! session.fetch_nodes().await?;
//!
//! let root = session
//!     .root_nodes()
//!     .await?
//!     .into_iter()
//!     .find(|node| node.node_type == megalib::NodeType::Root)
//!     .expect("missing cloud drive root");
//!
//! for file in session.children(&root).await? {
//!     println!("{} ({:?})", file.name, file.node_type);
//! }
//!
//! if let Some(docs) = session.child_node_by_name(&root, "Documents").await? {
//!     println!("Found docs folder: {}", docs.handle);
//! }
//!
//! let all_descendants = session.descendants(&root).await?;
//! println!("{} total descendants", all_descendants.len());
//!
//! // Upload a file with resume support
//! session.upload_resumable_to_node("local_file.txt", &root).await?;
//!
//! // Download a file to local disk
//! if let Some(node) = session
//!     .children(&root)
//!     .await?
//!     .into_iter()
//!     .find(|node| node.name == "remote_file.txt")
//! {
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
#[cfg(feature = "preview")]
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
