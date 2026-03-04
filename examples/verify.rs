//! Example: Verify MEGA account registration
//!
//! Usage:
//!   cargo run --example verify -- --state "SESSION_KEY_FROM_STEP_1" --link "CONFIRMATION_LINK_OR_FRAGMENT"

use clap::Parser;
use megalib::{RegistrationState, verify_registration};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "verify")]
struct Args {
    #[arg(short = 's', long)]
    state: String,
    #[arg(short = 'l', long)]
    link: String,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = Args::parse();

    let state = RegistrationState::deserialize(&args.state).expect("Invalid state format");

    println!("Verifying registration...");
    println!("Session key: {}", state.session_key);
    println!();

    match verify_registration(&state, &args.link, None).await {
        Ok(()) => {
            println!("Account registered successfully!");
            println!();
            println!("You can now log in with your email and password.");
        }
        Err(e) => {
            eprintln!("Verification failed: {}", e);
            std::process::exit(1);
        }
    }
}

// Link parsing is handled by verify_registration (SDK-compatible).
