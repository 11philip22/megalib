//! Example: Session caching to avoid repeated logins
//!
//! This example demonstrates how to cache a session and reuse it.
//! The cache file stores the raw SDK-compatible session string.
//!
//! Usage:
//!   cargo run --example cached_session -- --email EMAIL --password PASSWORD [--proxy PROXY]

mod cli;

use cli::{parse_credentials, usage_and_exit};
use megalib::SessionHandle;

const SESSION_FILE: &str = "mega_session";
const USAGE: &str = "Usage: cargo run --example cached_session -- --email EMAIL --password PASSWORD [--proxy PROXY]";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let creds = parse_credentials(USAGE);
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    // Try to load cached session first
    println!("Checking for cached session...");
    let session = match if let Some(proxy) = creds.proxy.as_deref() {
        SessionHandle::load_with_proxy(SESSION_FILE, proxy).await?
    } else {
        SessionHandle::load(SESSION_FILE).await?
    } {
        Some(s) => {
            let info = s.account_info().await?;
            println!("✅ Loaded cached session for: {}", info.email);
            s
        }
        None => {
            println!("No cached session found, logging in...");
            let s = creds.login().await?;
            let info = s.account_info().await?;
            println!("Logged in as: {}", info.email);

            // Save session for next time
            s.save(SESSION_FILE).await?;
            println!("💾 Session saved to {}", SESSION_FILE);
            s
        }
    };

    // Demonstrate the session works
    println!("\nRefreshing filesystem...");
    session.refresh().await?;

    let quota = session.quota().await?;
    println!(
        "📊 Storage: {} / {} ({:.1}% used)",
        format_size(quota.used),
        format_size(quota.total),
        (quota.used as f64 / quota.total as f64) * 100.0
    );

    let root_items = session.list("/Root", false).await?;
    println!("\n📁 Root directory: {} items", root_items.len());

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
