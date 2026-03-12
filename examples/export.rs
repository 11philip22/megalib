//! Example: Export a file to create a public download link
//!
//! Usage:
//!   cargo run --example export -- --email YOUR_EMAIL --password YOUR_PASSWORD --path /Root/file.txt [--proxy PROXY]

use clap::Parser;
use megalib::SessionHandle;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "export")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long)]
    path: String,
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
    let session = if let Some(proxy) = args.proxy.as_deref() {
        println!("Using proxy: {}", proxy);
        SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await?
    } else {
        SessionHandle::login(&args.email, &args.password).await?
    };
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Exporting: {}", args.path);
    match session.export_by_path(&args.path).await {
        Ok(url) => {
            println!("\nExport successful!");
            println!("\nPublic link:");
            println!("{}", url);
        }
        Err(e) => {
            eprintln!("Export failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
