//! Example: Login to MEGA account
//!
//! Usage:
//!   cargo run --example login -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY]

use clap::Parser;
use megalib::SessionHandle;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "login")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("megalib=debug"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = Args::parse();

    println!("Logging in as: {}", args.email);
    println!();

    let login = if let Some(proxy) = &args.proxy {
        SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await
    } else {
        SessionHandle::login(&args.email, &args.password).await
    };

    match login {
        Ok(session) => {
            let info = match session.account_info().await {
                Ok(info) => info,
                Err(e) => {
                    eprintln!("Failed to read account info: {}", e);
                    std::process::exit(1);
                }
            };
            println!("Login successful!");
            println!();
            println!("Email: {}", info.email);
            println!("Name: {}", info.name.as_deref().unwrap_or("(not set)"));
            println!("User Handle: {}", info.user_handle);
            println!("Session ID: {}...", &info.session_id[..20]);
        }
        Err(e) => {
            eprintln!("Login failed: {}", e);
            std::process::exit(1);
        }
    }
}
