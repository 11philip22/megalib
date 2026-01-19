//! Example: Download a file with resume support
//!
//! This example demonstrates the download_to_file method which automatically
//! handles resume for interrupted downloads.
//!
//! Usage:
//!   cargo run --example download_resume -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>
//!
//! To test resume:
//! 1. Start a large file download
//! 2. Cancel it mid-way (Ctrl+C)
//! 3. Run the same command again - it will resume from where it left off

mod cli;

use cli::{parse_credentials, usage_and_exit};
use megalib::error::Result;
use megalib::progress::TransferProgress;

const USAGE: &str = "Usage: cargo run --example download_resume -- --email EMAIL --password PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>";

#[tokio::main]
async fn main() -> Result<()> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 2 {
        usage_and_exit(USAGE);
    }
    let remote_path = creds.positionals[0].clone();
    let local_path = creds.positionals[1].clone();

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Enable parallel downloads
    session.set_workers(4);

    println!("Looking for: {}", remote_path);
    let node = session
        .stat(&remote_path)
        .ok_or_else(|| {
            megalib::error::MegaError::Custom(format!("File not found: {}", remote_path))
        })?
        .clone();

    println!("Found: {} ({} bytes)", node.name, node.size);

    // Enable resume support
    session.set_resume(true);
    println!("Resume enabled: downloads will continue from partial files");

    // Set up progress callback
    let file_name = node.name.clone();
    session.watch_status(Box::new(move |progress: &TransferProgress| {
        let percent = progress.percent();
        let done_mb = progress.done as f64 / 1_000_000.0;
        let total_mb = progress.total as f64 / 1_000_000.0;

        print!(
            "\r[{:>6.2}%] {:.2} MB / {:.2} MB - {}",
            percent, done_mb, total_mb, file_name
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();

        true // Continue download
    }));

    // Check if partial file exists
    let local_path_buf = std::path::Path::new(&local_path);
    if local_path_buf.exists() {
        let existing_size = std::fs::metadata(local_path_buf)
            .map(|m| m.len())
            .unwrap_or(0);
        if existing_size > 0 && existing_size < node.size {
            println!(
                "\nFound partial file ({} bytes), will resume...",
                existing_size
            );
        }
    }

    println!("Downloading to: {}", local_path);
    session.download_to_file(&node, &local_path).await?;

    println!("\nDownload complete!");

    Ok(())
}
