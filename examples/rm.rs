use clap::Parser;
use megalib::SessionHandle;
use megalib::error::Result;

#[derive(Debug, Parser)]
#[command(name = "rm")]
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

    println!("Removing: {}", args.path);
    match session.rm(&args.path).await {
        Ok(_) => {
            println!("Removed successfully!");
        }
        Err(e) => {
            eprintln!("Failed to remove: {}", e);
        }
    }

    Ok(())
}
