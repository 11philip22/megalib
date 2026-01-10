//! Example: Download a file
//!
//! Usage:
//!   cargo run --example download -- --email YOUR_EMAIL --password YOUR_PASSWORD <REMOTE_PATH> <LOCAL_PATH>

use mega_rs::error::Result;
use mega_rs::Session;
use std::env;
use std::fs::File;
use std::io::BufWriter;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;
    let mut remote_path = None;
    let mut local_path = None;

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
            arg => {
                if remote_path.is_none() {
                    remote_path = Some(arg.to_string());
                } else if local_path.is_none() {
                    local_path = Some(arg.to_string());
                }
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let remote_path = remote_path
        .expect("Usage: download --email <EMAIL> --password <PASSWORD> <REMOTE_PATH> <LOCAL_PATH>");
    let local_path = local_path
        .expect("Usage: download --email <EMAIL> --password <PASSWORD> <REMOTE_PATH> <LOCAL_PATH>");

    println!("Logging in...");
    let mut session = Session::login(&email, &password).await?;
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
            mega_rs::error::MegaError::Custom(format!("File not found: {}", remote_path))
        })?
        .clone();

    println!("Found node: {} ({} bytes)", node.name, node.size);

    println!("Downloading to: {}", local_path);
    let file = File::create(&local_path).map_err(|e| {
        mega_rs::error::MegaError::Custom(format!("Failed to create local file: {}", e))
    })?;
    let mut writer = BufWriter::new(file);

    session.download(&node, &mut writer).await?;

    println!("Download complete!");

    Ok(())
}
