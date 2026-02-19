//! Example: Register a new MEGA account
//!
//! Usage:
//!   cargo run --example register -- --email YOUR_EMAIL --password YOUR_PASSWORD --name "Your Name"

mod cli;

use cli::{ArgParser, usage_and_exit};
use megalib::register;
use tracing_subscriber::{EnvFilter, fmt};

const USAGE: &str =
    "Usage: cargo run --example register -- --email EMAIL --password PASSWORD --name \"Your Name\"";

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("megalib=debug"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let mut parser = ArgParser::new(USAGE);
    let email = parser
        .take_value(&["--email", "-e"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let password = parser
        .take_value(&["--password", "-p"])
        .unwrap_or_else(|| usage_and_exit(USAGE));
    let name = parser
        .take_value(&["--name", "-n"])
        .unwrap_or_else(|| usage_and_exit(USAGE));

    if !parser.remaining().is_empty() {
        usage_and_exit(USAGE);
    }

    println!("Registering account for: {}", email);
    println!("Name: {}", name);
    println!();

    match register(&email, &password, &name, None).await {
        Ok(state) => {
            println!("✅ Registration initiated successfully!");
            println!();
            println!("Check your email ({}) for the verification link.", email);
            println!();
            println!("Save this session key for step 2:");
            println!("----------------------------------------");
            println!("{}", state.serialize());
            println!("----------------------------------------");
            println!();
            println!("After receiving the email, run:");
            println!(
                "  cargo run --example verify -- --state \"{}\" --link \"CONFIRMATION_LINK_OR_FRAGMENT\"",
                state.serialize()
            );
        }
        Err(e) => {
            eprintln!("❌ Registration failed: {}", e);
            std::process::exit(1);
        }
    }
}
