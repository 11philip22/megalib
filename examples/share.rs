//! Example: Share a folder with another user (megashare equivalent)
//!
//! Usage:
//!   cargo run --example share -- --email <EMAIL> --password <PASSWORD> [--proxy PROXY] --folder <FOLDER_HANDLE_OR_PATH> --recipient <RECIPIENT_EMAIL> --level <0|1|2>

mod cli;

use cli::{ArgParser, credentials_from_parser, usage_and_exit};

const USAGE: &str = "Usage: cargo run --example share -- --email EMAIL --password PASSWORD [--proxy PROXY] --folder PATH --recipient USER --level <0|1|2>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ArgParser::new(USAGE);
    let mut creds = credentials_from_parser(&mut parser, USAGE);
    let folder_path = parser
        .take_value(&["--folder"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let recipient = parser
        .take_value(&["--recipient"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let level = parser
        .take_value(&["--level"])
        .and_then(|l| l.parse().ok())
        .unwrap_or(0);
    creds.positionals = parser.remaining();
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Logging in...");
    let session = creds.login().await?;
    let info = session.account_info().await?;
    println!("Logged in as {}", info.email);

    println!("Fetching file list...");
    session.refresh().await?;

    // Resolve folder path to node
    let nodes = session.nodes().await?;
    let node = if folder_path.starts_with('/') {
        // Path lookup
        // We need to implement lookup or just iterate.
        // session.nodes has paths if we call something that populates them? No, paths are computed.
        // For simplicity, let's just find by name or handle?
        // Or implement a simple path resolver here.
        // session.nodes is flat list.
        // Root is type 2.
        // If path is "/Root/Folder", we can traverse.
        // For this example, let's assume we search by name or handle.
        // Let's search by handle if it looks like one (8 chars), else search by name in Root?

        // Simple search: Find first folder with matching name or path
        nodes.iter().find(|n| {
            n.name == folder_path
                || n.handle == folder_path
                || n.path().map_or(false, |p| p == folder_path.as_str())
        })
    } else {
        // Handle
        nodes.iter().find(|n| n.handle == folder_path)
    };

    let node = node.ok_or("Folder not found")?;
    let handle = node.handle.clone();

    println!(
        "Sharing folder '{}' ({}) with {} (Level {})...",
        node.name, handle, recipient, level
    );

    session.share_folder(&handle, &recipient, level).await?;

    println!("Share command sent successfully!");

    Ok(())
}
