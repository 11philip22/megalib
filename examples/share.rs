//! Example: Share a folder with another user (megashare equivalent)
//!
//! Usage:
//!   cargo run --example share -- --email <EMAIL> --password <PASSWORD> [--proxy PROXY] --folder <FOLDER_PATH> --recipient <RECIPIENT_EMAIL> --level <0|1|2>

use clap::Parser;
use megalib::SessionHandle;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "share")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    folder: String,
    #[arg(long)]
    recipient: String,
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(i32).range(0..=2))]
    level: i32,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();

    println!("Logging in...");
    let session = if let Some(proxy) = &args.proxy {
        SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await?
    } else {
        SessionHandle::login(&args.email, &args.password).await?
    };
    let info = session.account_info().await?;
    println!("Logged in as {}", info.email);

    println!("Fetching file list...");
    session.refresh().await?;

    println!(
        "Sharing folder '{}' with {} (Level {})...",
        args.folder, args.recipient, args.level
    );

    session
        .share_folder(&args.folder, &args.recipient, args.level)
        .await?;

    println!("Share command sent successfully!");

    Ok(())
}
