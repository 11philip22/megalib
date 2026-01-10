use megalib::Session;
use std::env;
use std::process;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 {
        println!("Usage: upload <email> <password> <local_file> <remote_path>");
        process::exit(1);
    }

    let email = &args[1];
    let password = &args[2];
    let local_file = &args[3];
    let remote_path = &args[4];

    println!("Logging in...");
    let mut session = Session::login(email, password).await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Uploading {} to {}...", local_file, remote_path);
    match session.upload(local_file, remote_path).await {
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
