//! Example: Share a folder with another user (megashare equivalent)
//!
//! Usage:
//!   cargo run --example share -- --email <EMAIL> --password <PASSWORD> [--proxy PROXY] --folder <FOLDER_PATH> --recipient <RECIPIENT_EMAIL> --level <0|1|2>

mod cli;

use cli::{ArgParser, credentials_from_parser, usage_and_exit};

const USAGE: &str = "Usage: cargo run --example share -- --email EMAIL --password PASSWORD [--proxy PROXY] --folder /Root/path --recipient USER --level <0|1|2>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ArgParser::new(USAGE);
    let mut creds = credentials_from_parser(&mut parser, USAGE);
    let folder_path = parser
        .take_value(&["--folder"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let recipient = parser
        .take_value(&["--recipient"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let level = parser
        .take_value(&["--level"])
        .and_then(|l| l.parse().ok())
        .unwrap_or(0);
    creds.positionals = parser.remaining();
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Logging in...");
    let session = creds.login().await?;
    let info = session.account_info().await?;
    println!("Logged in as {}", info.email);

    println!("Fetching file list...");
    session.refresh().await?;

    println!(
        "Sharing folder '{}' with {} (Level {})...",
        folder_path, recipient, level
    );

    session
        .share_folder(&folder_path, &recipient, level)
        .await?;

    println!("Share command sent successfully!");

    Ok(())
}
