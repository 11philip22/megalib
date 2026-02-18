//! Example: List files in MEGA account
//!
//! Usage:
//!   cargo run --example ls -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] [--path /Root/path]

mod cli;

use cli::{ArgParser, credentials_from_parser, usage_and_exit};

const USAGE: &str = "Usage: cargo run --example ls -- --email EMAIL --password PASSWORD [--proxy PROXY] [--path /Root/path]";

#[tokio::main]
async fn main() {
    let mut parser = ArgParser::new(USAGE);
    let mut creds = credentials_from_parser(&mut parser, USAGE);
    let path = parser
        .take_value(&["--path"])
        .unwrap_or_else(|| "/Root".to_string());
    creds.positionals = parser.remaining();
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Logging in...");
    let session = creds.login().await.expect("Login failed");

    println!("Refreshing filesystem...");
    session.refresh().await.expect("Refresh failed");

    // Get quota
    let quota = session.quota().await.expect("Failed to get quota");
    println!(
        "\n📊 Storage: {:.2} GB / {:.2} GB ({:.1}% used)",
        quota.used as f64 / 1_073_741_824.0,
        quota.total as f64 / 1_073_741_824.0,
        quota.usage_percent()
    );

    // List path
    println!("\n📁 Listing: {}\n", path);

    match session.list(&path, false).await {
        Ok(nodes) => {
            if nodes.is_empty() {
                println!("  (empty)");
            } else {
                for node in nodes {
                    let type_icon = if node.is_file() { "📄" } else { "📁" };
                    let size_str = if node.is_file() {
                        format_size(node.size)
                    } else {
                        String::new()
                    };
                    println!("  {} {} {}", type_icon, node.name, size_str);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to list: {}", e);
        }
    }
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2}GB", bytes as f64 / 1_073_741_824.0)
    }
}
