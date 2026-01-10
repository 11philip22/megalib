//! Example: List files in MEGA account
//!
//! Usage:
//!   cargo run --example ls -- --email YOUR_EMAIL --password YOUR_PASSWORD [--path /path]

use megalib::Session;
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut email = None;
    let mut password = None;
    let mut path = "/Root".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--email" | "-e" => {
                email = args.get(i + 1).cloned();
                i += 2;
            }
            "--password" | "-p" => {
                password = args.get(i + 1).cloned();
                i += 2;
            }
            "--path" => {
                path = args.get(i + 1).cloned().unwrap_or(path);
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");

    println!("Logging in...");
    let mut session = Session::login(&email, &password)
        .await
        .expect("Login failed");

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

    match session.list(&path, false) {
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
