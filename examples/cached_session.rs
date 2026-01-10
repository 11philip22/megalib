//! Example: Session caching to avoid repeated logins
//!
//! This example demonstrates how to cache a session and reuse it.
//!
//! Usage:
//!   cargo run --example cached_session -- --email EMAIL --password PASSWORD

use mega_rs::Session;
use std::env;

const SESSION_FILE: &str = "mega_session.json";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;

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
            _ => i += 1,
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");

    // Try to load cached session first
    println!("Checking for cached session...");
    let mut session = match Session::load(SESSION_FILE).await? {
        Some(s) => {
            println!("✅ Loaded cached session for: {}", s.email);
            s
        }
        None => {
            println!("No cached session found, logging in...");
            let s = Session::login(&email, &password).await?;
            println!("Logged in as: {}", s.email);

            // Save session for next time
            s.save(SESSION_FILE)?;
            println!("💾 Session saved to {}", SESSION_FILE);
            s
        }
    };

    // Demonstrate the session works
    println!("\nRefreshing filesystem...");
    session.refresh().await?;

    let quota = session.quota().await?;
    println!(
        "📊 Storage: {} / {} ({:.1}% used)",
        format_size(quota.used),
        format_size(quota.total),
        (quota.used as f64 / quota.total as f64) * 100.0
    );

    let root_items = session.list("/Root", false)?;
    println!("\n📁 Root directory: {} items", root_items.len());

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}
