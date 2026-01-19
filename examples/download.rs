//! Example: Download a file
//!
//! Usage:
//!   cargo run --example download -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>

mod cli;

use cli::{parse_credentials, usage_and_exit};
use megalib::error::Result;
use megalib::Session;
use std::fs::File;
use std::io::BufWriter;

const USAGE: &str = "Usage: cargo run --example download -- --email EMAIL --password PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>";

#[tokio::main]
async fn main() -> Result<()> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 2 {
        usage_and_exit(USAGE);
    }
    let remote_path = creds.positionals[0].clone();
    let local_path = creds.positionals[1].clone();

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Looking for: {}", remote_path);
    // Find the node
    // Simple path lookup based on full path matching (which needs build_node_paths logic internally or manually traversing)
    // Note: Session::stat expects a full path.

    let node = session
        .stat(&remote_path)
        .ok_or_else(|| {
            megalib::error::MegaError::Custom(format!("File not found: {}", remote_path))
        })?
        .clone();

    println!("Found node: {} ({} bytes)", node.name, node.size);

    println!("Downloading to: {}", local_path);
    let file = File::create(&local_path).map_err(|e| {
        megalib::error::MegaError::Custom(format!("Failed to create local file: {}", e))
    })?;
    let mut writer = BufWriter::new(file);

    session.download(&node, &mut writer).await?;

    println!("Download complete!");

    Ok(())
}
