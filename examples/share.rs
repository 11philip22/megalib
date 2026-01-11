//! Example: Share a folder with another user (megashare equivalent)
//!
//! Usage:
//!   cargo run --example share -- --email <EMAIL> --password <PASSWORD> --folder <FOLDER_HANDLE_OR_PATH> --recipient <RECIPIENT_EMAIL> --level <0|1|2>

use megalib::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;
    let mut folder_path = None; // Can be handle or path? For simplicity, handle first, or path lookup
    let mut recipient = None;
    let mut level = 0; // Default Read-only

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--email" => {
                email = args.get(i + 1).cloned();
                i += 2;
            }
            "--password" => {
                password = args.get(i + 1).cloned();
                i += 2;
            }
            "--folder" => {
                folder_path = args.get(i + 1).cloned();
                i += 2;
            }
            "--recipient" => {
                recipient = args.get(i + 1).cloned();
                i += 2;
            }
            "--level" => {
                if let Some(l) = args.get(i + 1) {
                    level = l.parse().unwrap_or(0);
                }
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let email = email.expect(
        "Usage: share --email <EMAIL> --password <PASS> --folder <PATH> --recipient <USER>",
    );
    let password = password.expect(
        "Usage: share --email <EMAIL> --password <PASS> --folder <PATH> --recipient <USER>",
    );
    let folder_path = folder_path.expect(
        "Usage: share --email <EMAIL> --password <PASS> --folder <PATH> --recipient <USER>",
    );
    let recipient = recipient.expect(
        "Usage: share --email <EMAIL> --password <PASS> --folder <PATH> --recipient <USER>",
    );

    println!("Logging in...");
    let mut session = Session::login(&email, &password).await?;
    println!("Logged in as {}", session.email);

    println!("Fetching file list...");
    session.refresh().await?;

    // Resolve folder path to node
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
        session.nodes().iter().find(|n| {
            n.name == folder_path
                || n.handle == folder_path
                || n.path().map_or(false, |p| p == folder_path.as_str())
        })
    } else {
        // Handle
        session.nodes().iter().find(|n| n.handle == folder_path)
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
