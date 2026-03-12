//! Example: Download a file
//!
//! Usage:
//!   cargo run --example download -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY] <REMOTE_PATH> <LOCAL_PATH>

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use megalib::SessionHandle;
use megalib::error::Result;
use megalib::progress::TransferProgress;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "download")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    remote_path: String,
    local_path: String,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

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

    println!("Looking for: {}", args.remote_path);
    let node = session
        .stat_by_path(&args.remote_path)
        .await?
        .ok_or_else(|| {
            megalib::error::MegaError::Custom(format!("File not found: {}", args.remote_path))
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

    println!("Downloading to: {}", args.local_path);
    session.download_to_file(&node, &args.local_path).await?;

    println!("Download complete!");

    Ok(())
}
