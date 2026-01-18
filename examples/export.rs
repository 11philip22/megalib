//! Example: Export a file to create a public download link
//!
//! Usage:
//!   cargo run --example export -- --email YOUR_EMAIL --password YOUR_PASSWORD --path /Root/file.txt

use megalib::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut email = None;
    let mut password = None;
    let mut path = None;
    let mut proxy = None;

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
            "--path" => {
                path = args.get(i + 1).cloned();
                i += 2;
            }
            "--proxy" => {
                proxy = args.get(i + 1).cloned();
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let path = path.expect("--path is required");
    // Allow proxy from env if not provided via flag
    if proxy.is_none() {
        if let Ok(p) = env::var("MEGA_PROXY") {
            proxy = Some(p);
        }
    }

    println!("Logging in...");
    let mut session = if let Some(p) = proxy.as_deref() {
        println!("Using proxy: {}", p);
        Session::login_with_proxy(&email, &password, p).await?
    } else {
        Session::login(&email, &password).await?
    };
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Exporting: {}", path);
    match session.export(&path).await {
        Ok(url) => {
            println!("\n✅ Export successful!");
            println!("\n🔗 Public link:");
            println!("{}", url);
        }
        Err(e) => {
            eprintln!("❌ Export failed: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
