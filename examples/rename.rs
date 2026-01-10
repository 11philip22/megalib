//! Example: Rename a file or folder
//!
//! Usage:
//!   cargo run --example rename -- --email EMAIL --password PASSWORD <PATH> <NEW_NAME>

use mega_rs::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;
    let mut path = None;
    let mut new_name = None;

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
                if path.is_none() {
                    path = Some(arg.to_string());
                } else if new_name.is_none() {
                    new_name = Some(arg.to_string());
                }
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let path = path.expect("Usage: rename --email <EMAIL> --password <PASSWORD> <PATH> <NEW_NAME>");
    let new_name = new_name.expect("Usage: rename --email <EMAIL> --password <PASSWORD> <PATH> <NEW_NAME>");

    println!("Logging in...");
    let mut session = Session::login(&email, &password).await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Renaming {} to {}...", path, new_name);
    session.rename(&path, &new_name).await?;

    println!("✅ Rename complete!");

    Ok(())
}
