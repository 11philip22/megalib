//! Filesystem operations module.
//!
//! Most filesystem behavior is implemented as `impl Session` in `fs/operations/*`
//! and surfaced via `Session`/`SessionHandle` methods (e.g., list/stat/upload).

pub(crate) mod node;
mod operations;
pub mod upload_state;

pub use node::{Node, NodeType, Quota};
pub use upload_state::UploadState;
