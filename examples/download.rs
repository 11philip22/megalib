//! Example: Download a file
//!
//! Usage:
//!   cargo run --example download -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>

mod cli;

use cli::{parse_credentials, usage_and_exit};
use indicatif::{ProgressBar, ProgressStyle};
use megalib::error::Result;
use megalib::progress::TransferProgress;

const USAGE: &str = "Usage: cargo run --example download -- --email EMAIL --password PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>";

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

    println!("Looking for: {}", remote_path);
    // Find the node
    // Simple path lookup based on full path matching (which needs build_node_paths logic internally or manually traversing)
    // Note: SessionHandle::stat expects a full path like "/Root/..."

    let node = session
        .stat(&remote_path)
        .await?
        .ok_or_else(|| {
            megalib::error::MegaError::Custom(format!("File not found: {}", remote_path))
        })?
        .clone();

    println!("Found node: {} ({} bytes)", node.name, node.size);

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

            true
        }))
        .await?;

    println!("Downloading to: {}", local_path);
    session.download_to_file(&node, &local_path).await?;

    println!("Download complete!");

    Ok(())
}
