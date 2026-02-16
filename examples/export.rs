//! Example: Export a file to create a public download link
//!
//! Usage:
//!   cargo run --example export -- --email YOUR_EMAIL --password YOUR_PASSWORD --path /Root/file.txt [--proxy PROXY]

mod cli;

use cli::{ArgParser, credentials_from_parser, usage_and_exit};
use megalib::SessionHandle;

const USAGE: &str = "Usage: cargo run --example export -- --email EMAIL --password PASSWORD --path <PATH> [--proxy PROXY]";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ArgParser::new(USAGE);
    let mut creds = credentials_from_parser(&mut parser, USAGE);
    let path = parser
        .take_value(&["--path"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    creds.positionals = parser.remaining();
    if !creds.positionals.is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Logging in...");
    let session = if let Some(p) = creds.proxy.as_deref() {
        println!("Using proxy: {}", p);
        SessionHandle::login_with_proxy(&creds.email, &creds.password, p).await?
    } else {
        SessionHandle::login(&creds.email, &creds.password).await?
    };
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Exporting: {}", path);
    match session.export(&path).await {
        Ok(url) => {
            println!("\n✅ Export successful!");
            println!("\n🔗 Public link:");
            println!("{}", url);
        }
        Err(e) => {
            eprintln!("❌ Export failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
