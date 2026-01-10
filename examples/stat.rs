//! Example: Get information about a file or folder
//!
//! Usage:
//!   cargo run --example stat -- --email YOUR_EMAIL --password YOUR_PASSWORD --path /path/to/node

use mega_rs::Session;
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut email = None;
    let mut password = None;
    let mut path = None;

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
                path = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    if email.is_none() || password.is_none() || path.is_none() {
        eprintln!(
            "Usage: cargo run --example stat -- --email EMAIL --password PASSWORD --path PATH"
        );
        process::exit(1);
    }

    let email = email.unwrap();
    let password = password.unwrap();
    let path = path.unwrap();

    println!("Logging in...");
    let mut session = Session::login(&email, &password)
        .await
        .expect("Login failed");

    println!("Refreshing filesystem...");
    session.refresh().await.expect("Refresh failed");

    println!("Getting info for: {}", path);
    match session.stat(&path) {
        Some(node) => {
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
        None => {
            eprintln!("❌ Node not found: {}", path);
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
