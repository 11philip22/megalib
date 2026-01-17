/// Example: Upload data from memory using upload_from_bytes
///
/// This demonstrates uploading in-memory data without writing to disk first.
/// Useful for WASM environments or when data is generated programmatically.
use megalib::Session;
use std::env;
use std::process;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        println!("Usage: upload_bytes <email> <password> <remote_path>");
        println!();
        println!("This example uploads a sample text string to the specified remote path.");
        process::exit(1);
    }

    let email = &args[1];
    let password = &args[2];
    let remote_path = &args[3];

    println!("Logging in...");
    let mut session = Session::login(email, password).await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Create some in-memory data
    let data = b"Hello from megalib!\n\nThis file was uploaded using upload_from_bytes().";
    let file_name = "hello_from_memory.txt";

    println!(
        "Uploading {} bytes as '{}' to {}...",
        data.len(),
        file_name,
        remote_path
    );

    match session
        .upload_from_bytes(data, file_name, remote_path)
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
