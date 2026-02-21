//! Example: Upload a file with resume support
//!
//! This example demonstrates the upload_resumable method which saves
//! state after each chunk, allowing interrupted uploads to be resumed.
//!
//! Usage:
//!   cargo run --example upload_resume -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] <LOCAL_PATH> <REMOTE_PARENT>
//!
//! To test resume:
//! 1. Start uploading a large file
//! 2. Cancel it mid-way (Ctrl+C)
//! 3. Run the same command again - it will resume from where it left off
//!
//! Note: A .megalib_upload file is created next to the source file to track progress.

mod cli;

use cli::{parse_credentials, usage_and_exit};
use indicatif::{ProgressBar, ProgressStyle};
use megalib::error::Result;
use megalib::progress::TransferProgress;

const USAGE: &str = "Usage: cargo run --example upload_resume -- --email EMAIL --password PASSWORD [--proxy PROXY] <LOCAL_PATH> <REMOTE_PARENT>";

#[tokio::main]
async fn main() -> Result<()> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 2 {
        usage_and_exit(USAGE);
    }
    let local_path = creds.positionals[0].clone();
    let remote_parent = creds.positionals[1].clone();

    // Check if local file exists
    let path = std::path::Path::new(&local_path);
    if !path.exists() {
        eprintln!("Error: File not found: {}", local_path);
        std::process::exit(1);
    }

    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    println!("Logging in...");
    let session = creds.login().await?;
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Enable parallel uploads (e.g., 4 concurrent chunks)
    session.set_workers(4).await?;

    // Check if remote parent exists
    if session.stat(&remote_parent).await?.is_none() {
        eprintln!("Error: Remote directory not found: {}", remote_parent);
        std::process::exit(1);
    }

    // Check for existing state file (indicates a previous interrupted upload)
    let state_path = megalib::fs::UploadState::state_file_path(&local_path);
    if state_path.exists() {
        println!("Found upload state file - will attempt to resume...");
    }

    // Set up progress callback
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let progress_bar = ProgressBar::new(file_size.max(1));
    progress_bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta}) {msg}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=>-"),
    );
    progress_bar.set_message(file_name.clone());
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

            true // Continue upload
        }))
        .await?;

    println!(
        "Uploading {} ({:.2} MB) to {}",
        file_name,
        file_size as f64 / 1_000_000.0,
        remote_parent
    );

    let node = session
        .upload_resumable(&local_path, &remote_parent)
        .await?;

    println!("Upload complete!");
    println!("Created: {} (handle: {})", node.name, node.handle);

    Ok(())
}
