//! Filesystem operations module.

pub(crate) mod node;
mod operations;

pub use node::{Node, NodeType, Quota};
