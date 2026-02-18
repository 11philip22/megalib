//! Example: Download a file
//!
//! Usage:
//!   cargo run --example download -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>

mod cli;

use cli::{parse_credentials, usage_and_exit};
use megalib::error::Result;

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
    let session = creds.login().await?;
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Looking for: {}", remote_path);
    // Find the node
    // Simple path lookup based on full path matching (which needs build_node_paths logic internally or manually traversing)
    // Note: SessionHandle::stat expects a full path like "/Root/..."

    let node = session
        .stat(&remote_path)
        .await?
        .ok_or_else(|| {
            megalib::error::MegaError::Custom(format!("File not found: {}", remote_path))
        })?
        .clone();

    println!("Found node: {} ({} bytes)", node.name, node.size);

    println!("Downloading to: {}", local_path);
    session.download_to_file(&node, &local_path).await?;

    println!("Download complete!");

    Ok(())
}
