//! Example: Upload a file with resume support
//!
//! This example demonstrates the upload_resumable method which saves
//! state after each chunk, allowing interrupted uploads to be resumed.
//!
//! Usage:
//!   cargo run --example upload_resume -- --email YOUR_EMAIL --password YOUR_PASSWORD <LOCAL_PATH> <REMOTE_PARENT>
//!
//! To test resume:
//! 1. Start uploading a large file
//! 2. Cancel it mid-way (Ctrl+C)
//! 3. Run the same command again - it will resume from where it left off
//!
//! Note: A .megalib_upload file is created next to the source file to track progress.

use megalib::error::Result;
use megalib::progress::TransferProgress;
use megalib::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;
    let mut local_path = None;
    let mut remote_parent = None;

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
                if local_path.is_none() {
                    local_path = Some(arg.to_string());
                } else if remote_parent.is_none() {
                    remote_parent = Some(arg.to_string());
                }
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let local_path = local_path.expect(
        "Usage: upload_resume --email <EMAIL> --password <PASSWORD> <LOCAL_PATH> <REMOTE_PARENT>",
    );
    let remote_parent = remote_parent.expect(
        "Usage: upload_resume --email <EMAIL> --password <PASSWORD> <LOCAL_PATH> <REMOTE_PARENT>",
    );

    // Check if local file exists
    let path = std::path::Path::new(&local_path);
    if !path.exists() {
        eprintln!("Error: File not found: {}", local_path);
        std::process::exit(1);
    }

    let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    println!("Logging in...");
    let mut session = Session::login(&email, &password).await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Check if remote parent exists
    if session.stat(&remote_parent).is_none() {
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
    let file_name_clone = file_name.clone();

    session.watch_status(Box::new(move |progress: &TransferProgress| {
        let percent = progress.percent();
        let done_mb = progress.done as f64 / 1_000_000.0;
        let total_mb = progress.total as f64 / 1_000_000.0;

        print!(
            "\r[{:>6.2}%] {:.2} MB / {:.2} MB - {}",
            percent, done_mb, total_mb, file_name_clone
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();

        true // Continue upload
    }));

    println!(
        "Uploading {} ({:.2} MB) to {}",
        file_name,
        file_size as f64 / 1_000_000.0,
        remote_parent
    );

    let node = session
        .upload_resumable(&local_path, &remote_parent)
        .await?;

    println!("\nUpload complete!");
    println!("Created: {} (handle: {})", node.name, node.handle);

    Ok(())
}
