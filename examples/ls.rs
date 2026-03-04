//! Example: List files in MEGA account
//!
//! Usage:
//!   cargo run --example ls -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] [--path /Root/path]

use clap::Parser;
use megalib::SessionHandle;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "ls")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long, default_value = "/Root")]
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

    let quota = session.quota().await.expect("Failed to get quota");
    println!(
        "\nStorage: {:.2} GB / {:.2} GB ({:.1}% used)",
        quota.used as f64 / 1_073_741_824.0,
        quota.total as f64 / 1_073_741_824.0,
        quota.usage_percent()
    );

    println!("\nListing: {}\n", args.path);

    match session.list(&args.path, false).await {
        Ok(nodes) => {
            if nodes.is_empty() {
                println!("  (empty)");
            } else {
                for node in nodes {
                    let type_icon = if node.is_file() { "[F]" } else { "[D]" };
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
            eprintln!("Failed to list: {}", e);
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
