//! Example: Login to MEGA account
//!
//! Usage:
//!   cargo run --example login -- --email YOUR_EMAIL --password YOUR_PASSWORD

use mega_rs::Session;
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut email = None;
    let mut password = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--email" | "-e" => {
                email = args.get(i + 1).cloned();
                i += 2;
            }
            "--password" | "-p" => {
                password = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");

    println!("Logging in as: {}", email);
    println!();

    match Session::login(&email, &password).await {
        Ok(session) => {
            println!("✅ Login successful!");
            println!();
            println!("Email: {}", session.email);
            println!("Name: {}", session.name.as_deref().unwrap_or("(not set)"));
            println!("User Handle: {}", session.user_handle);
            println!("Session ID: {}...", &session.session_id()[..20]);
        }
        Err(e) => {
            eprintln!("❌ Login failed: {}", e);
            std::process::exit(1);
        }
    }
}
