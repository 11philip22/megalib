mod cli;

use cli::{parse_credentials, usage_and_exit};
use megalib::error::Result;

const USAGE: &str =
    "Usage: cargo run --example mkdir -- --email EMAIL --password PASSWORD [--proxy PROXY] <PATH>";

#[tokio::main]
async fn main() -> Result<()> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 1 {
        usage_and_exit(USAGE);
    }
    let target = creds.positionals[0].clone();

    println!("Logging in...");
    let session = creds.login().await?;
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Creating directory: {}", target);
    match session.mkdir(&target).await {
        Ok(node) => {
            println!("Directory created successfully!");
            println!("Name: {}", node.name);
            println!("Handle: {}", node.handle);
        }
        Err(e) => {
            eprintln!("Failed to create directory: {}", e);
        }
    }

    Ok(())
}
