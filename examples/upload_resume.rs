//! Example: Upload a file with resume support
//!
//! This example demonstrates upload_resumable, which saves
//! state after each chunk so interrupted uploads can continue.
//!
//! Usage:
//!   cargo run --example upload_resume -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] <LOCAL_PATH> <REMOTE_PARENT>

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use megalib::SessionHandle;
use megalib::error::Result;
use megalib::progress::TransferProgress;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "upload_resume")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    local_path: String,
    remote_parent: String,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let path = std::path::Path::new(&args.local_path);
    if !path.exists() {
        eprintln!("Error: File not found: {}", args.local_path);
        std::process::exit(1);
    }

    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    println!("Logging in...");
    let session = if let Some(proxy) = &args.proxy {
        SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await?
    } else {
        SessionHandle::login(&args.email, &args.password).await?
    };
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Enable parallel uploads (e.g., 4 concurrent chunks)
    session.set_workers(4).await?;

    if session.stat_by_path(&args.remote_parent).await?.is_none() {
        eprintln!("Error: Remote directory not found: {}", args.remote_parent);
        std::process::exit(1);
    }

    let state_path = megalib::fs::UploadState::state_file_path(&args.local_path);
    if state_path.exists() {
        println!("Found upload state file; attempting resume...");
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
        args.remote_parent
    );

    let node = session
        .upload_resumable_by_path(&args.local_path, &args.remote_parent)
        .await?;

    println!("Upload complete!");
    println!("Created: {} (handle: {})", node.name, node.handle);

    Ok(())
}
