//! Example: Session caching to avoid repeated logins
//!
//! This example demonstrates how to cache a session and reuse it.
//! The cache file stores the raw SDK-compatible session string.
//!
//! Usage:
//!   cargo run --example cached_session -- --email EMAIL --password PASSWORD [--proxy PROXY]

use clap::Parser;
use megalib::SessionHandle;
use tracing_subscriber::{EnvFilter, fmt};

const SESSION_FILE: &str = "mega_session";

#[derive(Debug, Parser)]
#[command(name = "cached_session")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();

    println!("Checking for cached session...");
    let session = match if let Some(proxy) = args.proxy.as_deref() {
        SessionHandle::load_with_proxy(SESSION_FILE, proxy).await?
    } else {
        SessionHandle::load(SESSION_FILE).await?
    } {
        Some(s) => {
            let info = s.account_info().await?;
            println!("Loaded cached session for: {}", info.email);
            s
        }
        None => {
            println!("No cached session found, logging in...");
            let s = if let Some(proxy) = args.proxy.as_deref() {
                SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await?
            } else {
                SessionHandle::login(&args.email, &args.password).await?
            };
            let info = s.account_info().await?;
            println!("Logged in as: {}", info.email);

            s.save(SESSION_FILE).await?;
            println!("Session saved to {}", SESSION_FILE);
            s
        }
    };

    println!("\nRefreshing filesystem...");
    session.refresh().await?;

    let quota = session.quota().await?;
    println!(
        "Storage: {} / {} ({:.1}% used)",
        format_size(quota.used),
        format_size(quota.total),
        (quota.used as f64 / quota.total as f64) * 100.0
    );

    let root_items = session.list_by_path("/Root", false).await?;
    println!("\nRoot directory: {} items", root_items.len());

    Ok(())
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
