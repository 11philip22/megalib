//! Example: Login to MEGA account
//!
//! Usage:
//!   cargo run --example login -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY]

mod cli;

use cli::{parse_credentials, usage_and_exit};
use tracing_subscriber::{fmt, EnvFilter};

const USAGE: &str =
    "Usage: cargo run --example login -- --email EMAIL --password PASSWORD [--proxy PROXY]";

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("megalib=debug"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let creds = parse_credentials(USAGE);
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Logging in as: {}", creds.email);
    println!();

    match creds.login().await {
        Ok(session) => {
            let info = match session.account_info().await {
                Ok(info) => info,
                Err(e) => {
                    eprintln!("ƒ?O Failed to read account info: {}", e);
                    std::process::exit(1);
                }
            };
            println!("ƒo. Login successful!");
            println!();
            println!("Email: {}", info.email);
            println!("Name: {}", info.name.as_deref().unwrap_or("(not set)"));
            println!("User Handle: {}", info.user_handle);
            println!("Session ID: {}...", &info.session_id[..20]);
        }
        Err(e) => {
            eprintln!("ƒ?O Login failed: {}", e);
            std::process::exit(1);
        }
    }
}
