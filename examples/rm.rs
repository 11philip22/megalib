mod cli;

use cli::{parse_credentials, usage_and_exit};
use megalib::error::Result;
use megalib::Session;

const USAGE: &str =
    "Usage: cargo run --example rm -- --email EMAIL --password PASSWORD [--proxy PROXY] <PATH>";

#[tokio::main]
async fn main() -> Result<()> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 1 {
        usage_and_exit(USAGE);
    }
    let target = creds.positionals[0].clone();

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Removing: {}", target);
    match session.rm(&target).await {
        Ok(_) => {
            println!("Removed successfully!");
        }
        Err(e) => {
            eprintln!("Failed to remove: {}", e);
        }
    }

    Ok(())
}
