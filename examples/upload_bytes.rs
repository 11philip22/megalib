/// Example: Upload data from memory using upload_from_bytes.
///
/// This demonstrates uploading in-memory data without writing to disk first.
use clap::Parser;
use megalib::SessionHandle;
use std::process;

#[derive(Debug, Parser)]
#[command(name = "upload_bytes")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    remote_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Logging in...");
    let session = if let Some(proxy) = &args.proxy {
        SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await?
    } else {
        SessionHandle::login(&args.email, &args.password).await?
    };
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Create some in-memory data
    let data = b"Hello from megalib!\n\nThis file was uploaded using upload_from_bytes().";
    let file_name = "hello_from_memory.txt";

    println!(
        "Uploading {} bytes as '{}' to {}...",
        data.len(),
        file_name,
        args.remote_path
    );

    match session
        .upload_from_bytes(data, file_name, &args.remote_path)
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
