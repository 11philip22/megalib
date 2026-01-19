//! Example: Move a file or folder
//!
//! Usage:
//!   cargo run --example mv -- --email EMAIL --password PASSWORD [--proxy PROXY] <SOURCE> <DEST_FOLDER>

mod cli;

use cli::{parse_credentials, usage_and_exit};
use megalib::Session;

const USAGE: &str =
    "Usage: cargo run --example mv -- --email EMAIL --password PASSWORD [--proxy PROXY] <SOURCE> <DEST>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 2 {
        usage_and_exit(USAGE);
    }
    let source = creds.positionals[0].clone();
    let dest = creds.positionals[1].clone();

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Moving {} to {}...", source, dest);
    session.mv(&source, &dest).await?;

    println!("✅ Move complete!");

    Ok(())
}
