//! Example: Verify MEGA account registration
//!
//! Usage:
//!   cargo run --example verify -- --state "SESSION_KEY_FROM_STEP_1" --link "CONFIRMATION_LINK_OR_FRAGMENT"

use megalib::{RegistrationState, verify_registration};
use std::env;
use tracing_subscriber::{EnvFilter, fmt};

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("megalib=debug"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut state_str = None;
    let mut link = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--state" | "-s" => {
                state_str = args.get(i + 1).cloned();
                i += 2;
            }
            "--link" | "-l" => {
                link = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let state_str = state_str.expect("--state is required");
    let link = link.expect("--link is required (confirmation link or fragment from the email)");

    // Parse state
    let state = RegistrationState::deserialize(&state_str).expect("Invalid state format");

    println!("Verifying registration...");
    println!("Session key: {}", state.session_key);
    println!();

    match verify_registration(&state, &link, None).await {
        Ok(()) => {
            println!("✅ Account registered successfully!");
            println!();
            println!("You can now log in with your email and password.");
        }
        Err(e) => {
            eprintln!("❌ Verification failed: {}", e);
            std::process::exit(1);
        }
    }
}

// Link parsing is handled by verify_registration (SDK-compatible).
