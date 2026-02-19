mod cli;

use cli::parse_credentials;
use megalib::SessionHandle;
use megalib::make_progress_bar;
use megalib::api::ApiErrorCode;
use megalib::error::{MegaError, Result};
use std::io::{self, Write};
use tracing_subscriber::{EnvFilter, fmt};

const USAGE: &str = "Usage: cargo run --example sequence -- --email EMAIL --password PASSWORD [--proxy PROXY] [FOLDER1 FOLDER2 LOCAL1 LOCAL2]

Defaults: FOLDER1=/Root/lol1 FOLDER2=/Root/lol2 LOCAL1=./Cargo.toml LOCAL2=./Cargo.lock";

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("megalib=debug"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let creds = parse_credentials(USAGE);
    let folder1 = creds
        .positionals
        .get(0)
        .cloned()
        .unwrap_or_else(|| "/Root/lol1".to_string());
    let folder2 = creds
        .positionals
        .get(1)
        .cloned()
        .unwrap_or_else(|| "/Root/lol2".to_string());
    let local1 = creds
        .positionals
        .get(2)
        .cloned()
        .unwrap_or_else(|| "./Cargo.toml".to_string());
    let local2 = creds
        .positionals
        .get(3)
        .cloned()
        .unwrap_or_else(|| "./Cargo.lock".to_string());

    println!("Logging in...");
    let session = creds.login().await?;
    let info = session.account_info().await?;
    println!("Logged in as: {}", info.email);

    session.watch_status(make_progress_bar()).await?;

    println!("Refreshing filesystem...");
    session.refresh().await?;

    // Sequence mirrored from mega-sequence.ps1
    ensure_folder(&session, &folder1).await?;
    upload_and_export(&session, &local1, &folder1).await?;
    wait_for_enter("Verify if the exported link is correct and press Enter to upload Cargo.lock")?;

    upload_and_export(&session, &local2, &folder1).await?;
    wait_for_enter(
        "Check if both files are in the folder and login to upgrade encryption. Then press Enter to continue",
    )?;

    ensure_folder(&session, &folder2).await?;
    upload_and_export(&session, &local2, &folder2).await?;
    wait_for_enter("Verify if the exported link is correct and press Enter to upload Cargo.toml")?;

    upload_and_export(&session, &local1, &folder2).await?;
    println!("Please verify if both files are in the folder now.");

    println!("Sequence complete.");
    Ok(())
}

async fn ensure_folder(session: &SessionHandle, path: &str) -> Result<()> {
    match session.mkdir(path).await {
        Ok(_) => {
            println!("Created folder: {}", path);
        }
        Err(MegaError::ApiError { code, .. }) if code == ApiErrorCode::Exist as i32 => {
            println!("Folder already exists: {}", path);
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

async fn upload_and_export(
    session: &SessionHandle,
    local: &str,
    remote_folder: &str,
) -> Result<()> {
    println!("Uploading {local} to {remote_folder} ...");
    let remote_path = format!("{}/", remote_folder.trim_end_matches('/'));
    let node = session.upload(local, &remote_path).await?;
    println!("Uploaded as {} ({} bytes)", node.name, node.size);

    println!("Exporting {} ...", remote_folder);
    let link = session.export(remote_folder).await?;
    println!("Public link: {link}");
    Ok(())
}

fn wait_for_enter(prompt: &str) -> Result<()> {
    print!("{prompt}: ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| MegaError::Custom(format!("stdin error: {e}")))?;
    Ok(())
}
