/// Example: Upload data from memory using upload_from_bytes
///
/// This demonstrates uploading in-memory data without writing to disk first.
/// Useful when data is generated programmatically.
mod cli;

use cli::{parse_credentials, usage_and_exit};
use std::process;

const USAGE: &str = "Usage: cargo run --example upload_bytes -- --email EMAIL --password PASSWORD [--proxy PROXY] <REMOTE_PATH>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 1 {
        usage_and_exit(USAGE);
    }
    let remote_path = &creds.positionals[0];

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Create some in-memory data
    let data = b"Hello from megalib!\n\nThis file was uploaded using upload_from_bytes().";
    let file_name = "hello_from_memory.txt";

    println!(
        "Uploading {} bytes as '{}' to {}...",
        data.len(),
        file_name,
        remote_path
    );

    match session
        .upload_from_bytes(data, file_name, remote_path)
        .await
    {
        Ok(node) => {
            println!("Upload complete!");
            println!("Created node: {} ({} bytes)", node.name, node.size);
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
            process::exit(1);
        }
    }

    Ok(())
}
