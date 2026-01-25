//! Example: Change account password (megapass equivalent)
//!
//! Usage:
//!   cargo run --example passwd -- --email <EMAIL> --password <CURRENT_PASSWORD> --new <NEW_PASSWORD> [--proxy PROXY]

mod cli;

use cli::{ArgParser, Credentials, usage_and_exit};
use megalib::Session;

const USAGE: &str = "Usage: cargo run --example passwd -- --email EMAIL --password CURRENT --new NEW [--proxy PROXY]";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = ArgParser::new(USAGE);
    let email = parser
        .take_value(&["--email", "-e"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let current_password = parser
        .take_value(&["--password", "-p", "--old"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let new_password = parser
        .take_value(&["--new"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let proxy = parser.take_value(&["--proxy"]);

    let remaining = parser.remaining();
    if !remaining.is_empty() {
        usage_and_exit(USAGE);
    }
    let creds = Credentials {
        email,
        password: current_password.clone(),
        proxy,
        positionals: Vec::new(),
    };

    println!("Logging in with old password...");
    let mut session = creds.login().await?;
    println!("Logged in successfully.");

    println!("Changing password...");
    session.change_password(&new_password).await?;
    println!("Password changed successfully!");

    println!("Verifying new password...");
    // Try to login with new password
    let session_new = Session::login(&creds.email, &new_password).await;
    match session_new {
        Ok(_) => println!("Verification successful: Logged in with new password."),
        Err(e) => println!("Verification failed: {}", e),
    }

    Ok(())
}
