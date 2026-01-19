/// Example: Upload data from an async reader using upload_from_reader
///
/// This demonstrates uploading from any source implementing AsyncRead + AsyncSeek.
/// In this example we use a Cursor wrapping a Vec<u8>, but you could use any
/// compatible reader, making this suitable for WASM environments.
mod cli;

use cli::{parse_credentials, usage_and_exit};
use futures::io::Cursor;
use megalib::Session;
use std::process;

const USAGE: &str = "Usage: cargo run --example upload_reader -- --email EMAIL --password PASSWORD [--proxy PROXY] <REMOTE_PATH>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let creds = parse_credentials(USAGE);
    if creds.positionals.len() != 1 {
        usage_and_exit(USAGE);
    }
    let remote_path = &creds.positionals[0];

    println!("Logging in...");
    let mut session = creds.login().await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Generate some data
    let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let file_size = data.len() as u64;
    let file_name = "random_data.bin";

    // Create a Cursor that implements AsyncRead + AsyncSeek
    let cursor = Cursor::new(data);

    println!(
        "Uploading {} bytes as '{}' to {} using reader...",
        file_size, file_name, remote_path
    );

    match session
        .upload_from_reader(cursor, file_name, file_size, remote_path)
        .await
    {
        Ok(node) => {
            println!("Upload complete!");
            println!("Created node: {} ({} bytes)", node.name, node.size);
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
            process::exit(1);
        }
    }

    Ok(())
}
