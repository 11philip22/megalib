/// Example: Upload data from an async reader using upload_from_reader
///
/// This demonstrates uploading from any source implementing AsyncRead + AsyncSeek.
/// In this example we use a Cursor wrapping a Vec<u8>, but you could use any
/// compatible reader, making this suitable for WASM environments.
use megalib::Session;
use std::env;
use std::io::Cursor;
use std::process;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 4 {
        println!("Usage: upload_reader <email> <password> <remote_path>");
        println!();
        println!("This example uploads 1KB of random data to the specified remote path.");
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
