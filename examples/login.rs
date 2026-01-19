//! Example: Login to MEGA account
//!
//! Usage:
//!   cargo run --example login -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY]

mod cli;

use cli::{parse_credentials, usage_and_exit};

const USAGE: &str =
    "Usage: cargo run --example login -- --email EMAIL --password PASSWORD [--proxy PROXY]";

#[tokio::main]
async fn main() {
    let creds = parse_credentials(USAGE);
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Logging in as: {}", creds.email);
    println!();

    match creds.login().await {
        Ok(session) => {
            println!("ƒo. Login successful!");
            println!();
            println!("Email: {}", session.email);
            println!("Name: {}", session.name.as_deref().unwrap_or("(not set)"));
            println!("User Handle: {}", session.user_handle);
            println!("Session ID: {}...", &session.session_id()[..20]);
        }
        Err(e) => {
            eprintln!("ƒ?O Login failed: {}", e);
            std::process::exit(1);
        }
    }
}
