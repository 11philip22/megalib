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
use indicatif::{ProgressBar, ProgressStyle};
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
    let session = creds.login().await?;
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Enable parallel downloads
    session.set_workers(4).await?;

    println!("Looking for: {}", remote_path);
    let node = session
        .stat(&remote_path)
        .await?
        .ok_or_else(|| {
            megalib::error::MegaError::Custom(format!("File not found: {}", remote_path))
        })?
        .clone();

    println!("Found: {} ({} bytes)", node.name, node.size);

    // Enable resume support
    session.set_resume(true).await?;
    println!("Resume enabled: downloads will continue from partial files");

    // Set up progress callback
    let progress_bar = ProgressBar::new(node.size);
    progress_bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=>-"),
    );
    progress_bar.set_message(node.name.clone());
    let progress_bar_for_cb = progress_bar.clone();
    let mut finished = false;
    session
        .watch_status(Box::new(move |progress: &TransferProgress| {
            if progress.total > 0 {
                progress_bar_for_cb.set_length(progress.total);
                progress_bar_for_cb.set_position(progress.done.min(progress.total));
            } else {
                progress_bar_for_cb.set_length(progress.done.max(1));
                progress_bar_for_cb.set_position(progress.done);
            }
            progress_bar_for_cb.set_message(progress.filename.clone());

            if progress.is_complete() && !finished {
                finished = true;
                progress_bar_for_cb.finish_with_message(format!("{} complete", progress.filename));
            }

            true // Continue download
        }))
        .await?;

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

    println!("Download complete!");

    Ok(())
}
