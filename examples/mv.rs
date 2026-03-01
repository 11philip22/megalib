//! Example: Move a file or folder
//!
//! Usage:
//!   cargo run --example mv -- --email EMAIL --password PASSWORD [--proxy PROXY] <SOURCE> <DEST_FOLDER>

use clap::Parser;
use megalib::SessionHandle;

#[derive(Debug, Parser)]
#[command(name = "mv")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    source: String,
    dest: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    println!("Moving {} to {}...", args.source, args.dest);
    session.mv(&args.source, &args.dest).await?;

    println!("Move complete!");

    Ok(())
}
