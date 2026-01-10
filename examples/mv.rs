//! Example: Move a file or folder
//!
//! Usage:
//!   cargo run --example mv -- --email EMAIL --password PASSWORD <SOURCE> <DEST_FOLDER>

use mega_rs::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;
    let mut source = None;
    let mut dest = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--email" => {
                email = args.get(i + 1).cloned();
                i += 2;
            }
            "--password" => {
                password = args.get(i + 1).cloned();
                i += 2;
            }
            arg => {
                if source.is_none() {
                    source = Some(arg.to_string());
                } else if dest.is_none() {
                    dest = Some(arg.to_string());
                }
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let source = source.expect("Usage: mv --email <EMAIL> --password <PASSWORD> <SOURCE> <DEST>");
    let dest = dest.expect("Usage: mv --email <EMAIL> --password <PASSWORD> <SOURCE> <DEST>");

    println!("Logging in...");
    let mut session = Session::login(&email, &password).await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Moving {} to {}...", source, dest);
    session.mv(&source, &dest).await?;

    println!("✅ Move complete!");

    Ok(())
}
