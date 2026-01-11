//! Example: Change account password (megapass equivalent)
//!
//! Usage:
//!   cargo run --example passwd -- --email <EMAIL> --old <OLD_PASSWORD> --new <NEW_PASSWORD>

use megalib::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut old_password = None;
    let mut new_password = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--email" => {
                email = args.get(i + 1).cloned();
                i += 2;
            }
            "--old" => {
                old_password = args.get(i + 1).cloned();
                i += 2;
            }
            "--new" => {
                new_password = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let email = email.expect("Usage: passwd --email <EMAIL> --old <OLD> --new <NEW>");
    let old_password = old_password.expect("Usage: passwd --email <EMAIL> --old <OLD> --new <NEW>");
    let new_password = new_password.expect("Usage: passwd --email <EMAIL> --old <OLD> --new <NEW>");

    println!("Logging in with old password...");
    let mut session = Session::login(&email, &old_password).await?;
    println!("Logged in successfully.");

    println!("Changing password...");
    session.change_password(&new_password).await?;
    println!("Password changed successfully!");

    println!("Verifying new password...");
    // Try to login with new password
    let session_new = Session::login(&email, &new_password).await;
    match session_new {
        Ok(_) => println!("Verification successful: Logged in with new password."),
        Err(e) => println!("Verification failed: {}", e),
    }

    Ok(())
}
