//! Example: Get information about a file or folder
//!
//! Usage:
//!   cargo run --example stat -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] --path /Root/path/to/node

use clap::Parser;
use megalib::SessionHandle;
use std::process;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "stat")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    path: String,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = Args::parse();

    println!("Logging in...");
    let login = if let Some(proxy) = &args.proxy {
        SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await
    } else {
        SessionHandle::login(&args.email, &args.password).await
    };
    let session = login.expect("Login failed");

    println!("Refreshing filesystem...");
    session.refresh().await.expect("Refresh failed");

    println!("Getting info for: {}", args.path);
    match session.stat_by_path(&args.path).await {
        Ok(Some(node)) => {
            println!("\nNode Information:");
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
            eprintln!("Node not found: {}", args.path);
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to fetch node: {}", e);
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
