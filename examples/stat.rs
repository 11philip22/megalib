//! Example: Get information about a file or folder
//!
//! Usage:
//!   cargo run --example stat -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] --path /path/to/node

mod cli;

use cli::{ArgParser, credentials_from_parser, usage_and_exit};
use std::process;

const USAGE: &str = "Usage: cargo run --example stat -- --email EMAIL --password PASSWORD [--proxy PROXY] --path PATH";

#[tokio::main]
async fn main() {
    let mut parser = ArgParser::new(USAGE);
    let mut creds = credentials_from_parser(&mut parser, USAGE);
    let path = parser
        .take_value(&["--path"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    creds.positionals = parser.remaining();
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Logging in...");
    let session = creds.login().await.expect("Login failed");

    println!("Refreshing filesystem...");
    session.refresh().await.expect("Refresh failed");

    println!("Getting info for: {}", path);
    match session.stat(&path).await {
        Ok(Some(node)) => {
            println!("\n🔍 Node Information:");
            println!("  Name:          {}", node.name);
            println!("  Type:          {:?}", node.node_type);
            println!("  Size:          {}", format_size(node.size));
            println!("  Handle:        {}", node.handle);
            if let Some(p) = &node.parent_handle {
                println!("  Parent Handle: {}", p);
            }
            println!("  Timestamp:     {}", node.timestamp);
            if let Some(p) = node.path() {
                println!("  Full Path:     {}", p);
            }
        }
        Ok(None) => {
            eprintln!("❌ Node not found: {}", path);
            process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Failed to fetch node: {}", e);
            process::exit(1);
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}
