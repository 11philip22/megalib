//! Example: Change account password (megapass equivalent)
//!
//! Usage:
//!   cargo run --example passwd -- --email <EMAIL> --password <CURRENT_PASSWORD> --new <NEW_PASSWORD> [--proxy PROXY]

use clap::Parser;
use megalib::SessionHandle;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "passwd")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long = "password", alias = "old")]
    current_password: String,
    #[arg(long = "new")]
    new_password: String,
    #[arg(long)]
    proxy: Option<String>,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let args = Args::parse();

    println!("Logging in with old password...");
    let session = if let Some(proxy) = &args.proxy {
        SessionHandle::login_with_proxy(&args.email, &args.current_password, proxy).await?
    } else {
        SessionHandle::login(&args.email, &args.current_password).await?
    };
    println!("Logged in successfully.");

    println!("Changing password...");
    session.change_password(&args.new_password).await?;
    println!("Password changed successfully!");

    println!("Verifying new password...");
    let session_new = SessionHandle::login(&args.email, &args.new_password).await;
    match session_new {
        Ok(_) => println!("Verification successful: logged in with new password."),
        Err(e) => println!("Verification failed: {}", e),
    }

    Ok(())
}
