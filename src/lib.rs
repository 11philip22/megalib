//! # mega-rs
//!
//! Rust client library for Mega.nz cloud storage.
//!
//! ## Features
//!
//! - Account registration
//! - (More features coming soon)
//!
//! ## Example: Account Registration
//!
//! Registration is a two-step process:
//!
//! ```no_run
//! use mega_rs::session::{register, verify_registration};
//!
//! # async fn example() -> mega_rs::error::Result<()> {
//! // Step 1: Initiate registration (sends verification email)
//! let state = register("user@example.com", "SecurePassword123", "John Doe").await?;
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
pub mod http;
pub mod session;

// Re-export commonly used types
pub use error::{MegaError, Result};
pub use session::{register, verify_registration, RegistrationState, Session};
