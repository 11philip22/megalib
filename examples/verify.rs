//! Example: Verify MEGA account registration
//!
//! Usage:
//!   cargo run --example verify -- --state "STATE_FROM_STEP_1" --link "SIGNUP_KEY_FROM_EMAIL"

use megalib::{verify_registration, RegistrationState};
use std::env;

#[tokio::main]
async fn main() {
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
    let link = link.expect("--link is required (the signup key from the email)");

    // Parse state
    let state = RegistrationState::deserialize(&state_str).expect("Invalid state format");

    // Extract signup key from link if it's a full URL
    let signup_key = extract_signup_key(&link);

    println!("Verifying registration...");
    println!("User handle: {}", state.user_handle);
    println!();

    match verify_registration(&state, &signup_key, None).await {
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

/// Extract the signup key from a MEGA confirmation link
fn extract_signup_key(link: &str) -> String {
    // Handle full URL: https://mega.nz/#confirm<KEY>
    if link.starts_with("https://mega") {
        if let Some(pos) = link.find("#confirm") {
            return link[pos + 8..].to_string();
        }
        // New format: https://mega.nz/confirm<KEY>
        if let Some(pos) = link.find("/confirm") {
            return link[pos + 8..].to_string();
        }
    }

    // Assume it's already just the key
    link.to_string()
}
