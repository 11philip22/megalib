mod cli;

use cli::{parse_credentials, usage_and_exit};
use std::process;

const USAGE: &str = "Usage: cargo run --example upload -- --email EMAIL --password PASSWORD [--proxy PROXY] <LOCAL_FILE> <REMOTE_PATH>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 2 {
        usage_and_exit(USAGE);
    }
    let local_file = &creds.positionals[0];
    let remote_path = &creds.positionals[1];

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Uploading {} to {}...", local_file, remote_path);
    match session.upload(local_file, remote_path).await {
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
