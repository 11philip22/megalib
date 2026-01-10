//! Example: Register a new MEGA account
//!
//! Usage:
//!   cargo run --example register -- --email YOUR_EMAIL --password YOUR_PASSWORD --name "Your Name"

use mega_rs::register;
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut email = None;
    let mut password = None;
    let mut name = None;

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
            "--name" | "-n" => {
                name = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let name = name.expect("--name is required");

    println!("Registering account for: {}", email);
    println!("Name: {}", name);
    println!();

    match register(&email, &password, &name).await {
        Ok(state) => {
            println!("✅ Registration initiated successfully!");
            println!();
            println!("Check your email ({}) for the verification link.", email);
            println!();
            println!("Save this state for step 2:");
            println!("----------------------------------------");
            println!("{}", state.serialize());
            println!("----------------------------------------");
            println!();
            println!("After receiving the email, run:");
            println!(
                "  cargo run --example verify -- --state \"{}\" --link \"SIGNUP_KEY_FROM_EMAIL\"",
                state.serialize()
            );
        }
        Err(e) => {
            eprintln!("❌ Registration failed: {}", e);
            std::process::exit(1);
        }
    }
}
