use megalib::error::Result;
use megalib::Session;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut email = None;
    let mut password = None;
    let mut target = None;

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
            arg => {
                if target.is_none() {
                    target = Some(arg.to_string());
                }
                i += 1;
            }
        }
    }

    let email = email.expect("--email is required");
    let password = password.expect("--password is required");
    let target = target.expect("Usage: mkdir --email <EMAIL> --password <PASSWORD> <PATH>");

    println!("Logging in...");
    let mut session = Session::login(&email, &password).await?;
    println!("Logged in as: {}", session.email);

    println!("Refreshing filesystem...");
    session.refresh().await?;

    println!("Creating directory: {}", target);
    match session.mkdir(&target).await {
        Ok(node) => {
            println!("Directory created successfully!");
            println!("Name: {}", node.name);
            println!("Handle: {}", node.handle);
        }
        Err(e) => {
            eprintln!("Failed to create directory: {}", e);
        }
    }

    Ok(())
}
