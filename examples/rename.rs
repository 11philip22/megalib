//! Example: Rename a file or folder
//!
//! Usage:
//!   cargo run --example rename -- --email EMAIL --password PASSWORD [--proxy PROXY] <PATH> <NEW_NAME>

mod cli;

use cli::{parse_credentials, usage_and_exit};

const USAGE: &str =
    "Usage: cargo run --example rename -- --email EMAIL --password PASSWORD [--proxy PROXY] <PATH> <NEW_NAME>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 2 {
        usage_and_exit(USAGE);
    }
    let path = creds.positionals[0].clone();
    let new_name = creds.positionals[1].clone();

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Renaming {} to {}...", path, new_name);
    session.rename(&path, &new_name).await?;

    println!("✅ Rename complete!");

    Ok(())
}
