//! Session management and registration.

pub mod actor;
mod auth;
mod device_id;
pub mod key_sync;
pub mod registration;
mod sharing;
mod core;
mod action_packets;

pub use actor::{AccountInfo, SessionHandle};
pub use key_sync::ContactPublicKeys;
pub use registration::{RegistrationState, register, verify_registration};
pub(crate) use core::Session;
pub use core::{FolderSessionBlob, SessionBlob};
