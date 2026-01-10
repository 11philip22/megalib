//! Example: Download from a public MEGA link
//!
//! Usage:
//!   cargo run --example dl -- <URL> [OUTPUT_FILE]

use megalib::public::{download_public_file, get_public_file_info};
use std::env;
use std::fs::File;
use std::io::BufWriter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: dl <MEGA_URL> [OUTPUT_FILE]");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  cargo run --example dl -- \"https://mega.nz/file/ABC123#key\"");
        std::process::exit(1);
    }

    let url = &args[1];

    // First, get file info
    println!("Fetching file info...");
    let info = get_public_file_info(url).await?;

    println!();
    println!("📄 File: {}", info.name);
    println!("📦 Size: {}", format_size(info.size));
    println!("🔑 Handle: {}", info.handle);

    // Determine output path
    let output_path = if args.len() > 2 {
        args[2].clone()
    } else {
        info.name.clone()
    };

    println!();
    println!("Downloading to: {}", output_path);

    let file = File::create(&output_path)?;
    let mut writer = BufWriter::new(file);

    download_public_file(url, &mut writer).await?;

    println!();
    println!("✅ Download complete!");

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
