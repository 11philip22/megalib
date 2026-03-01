use clap::Parser;
use megalib::SessionHandle;
use megalib::error::Result;

#[derive(Debug, Parser)]
#[command(name = "mkdir")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
    path: String,
}

#[tokio::main]
async fn main() -> Result<()> {
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

    println!("Creating directory: {}", args.path);
    match session.mkdir(&args.path).await {
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
