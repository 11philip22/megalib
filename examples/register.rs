//! Example: Register a new MEGA account
//!
//! Usage:
//!   cargo run --example register -- --email YOUR_EMAIL --password YOUR_PASSWORD --name "Your Name"

use clap::Parser;
use megalib::register;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "register")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(short = 'n', long)]
    name: String,
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("megalib=debug"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = Args::parse();

    println!("Registering account for: {}", args.email);
    println!("Name: {}", args.name);
    println!();

    match register(&args.email, &args.password, &args.name, None).await {
        Ok(state) => {
            println!("Registration initiated successfully!");
            println!();
            println!("Check your email ({}) for the verification link.", args.email);
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
            eprintln!("Registration failed: {}", e);
            std::process::exit(1);
        }
    }
}
