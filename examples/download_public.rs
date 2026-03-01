//! Example: Download from a public MEGA link
//!
//! Usage:
//!   cargo run --example download_public -- <URL> [OUTPUT_FILE]

use clap::Parser;
use megalib::public::{download_public_file, get_public_file_info};
use std::fs::File;
use std::io::BufWriter;

#[derive(Debug, Parser)]
#[command(name = "download_public")]
struct Args {
    url: String,
    output_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Fetching file info...");
    let info = get_public_file_info(&args.url).await?;

    println!();
    println!("File: {}", info.name);
    println!("Size: {}", format_size(info.size));
    println!("Handle: {}", info.handle);

    let output_path = args.output_file.unwrap_or_else(|| info.name.clone());

    println!();
    println!("Downloading to: {}", output_path);

    let file = File::create(&output_path)?;
    let mut writer = BufWriter::new(file);

    download_public_file(&args.url, &mut writer).await?;

    println!();
    println!("Download complete!");

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
