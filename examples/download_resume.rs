//! Example: Download a file with resume support
//!
//! This example demonstrates the download_to_file method which automatically
//! handles resume for interrupted downloads.
//!
//! Usage:
//!   cargo run --example download_resume -- --email YOUR_EMAIL --password YOUR_PASSWORD <REMOTE_PATH> <LOCAL_PATH>
//!
//! To test resume:
//! 1. Start a large file download
//! 2. Cancel it mid-way (Ctrl+C)
//! 3. Run the same command again - it will resume from where it left off

use megalib::error::Result;
use megalib::progress::TransferProgress;
use megalib::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;
    let mut remote_path = None;
    let mut local_path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--email" => {
                email = args.get(i + 1).cloned();
                i += 2;
            }
            "--password" => {
                password = args.get(i + 1).cloned();
                i += 2;
            }
            arg => {
                if remote_path.is_none() {
                    remote_path = Some(arg.to_string());
                } else if local_path.is_none() {
                    local_path = Some(arg.to_string());
                }
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let remote_path = remote_path.expect(
        "Usage: download_resume --email <EMAIL> --password <PASSWORD> <REMOTE_PATH> <LOCAL_PATH>",
    );
    let local_path = local_path.expect(
        "Usage: download_resume --email <EMAIL> --password <PASSWORD> <REMOTE_PATH> <LOCAL_PATH>",
    );

    println!("Logging in...");
    let mut session = Session::login(&email, &password).await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

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
