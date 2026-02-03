mod cli;

use cli::parse_credentials;
use megalib::api::client::ApiErrorCode;
use megalib::error::{MegaError, Result};
use megalib::Session;
use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::signal;
use tokio::sync::Mutex;
use tokio::time::sleep;
use std::time::Duration;

const USAGE: &str = "Usage: cargo run --example sequence -- --email EMAIL --password PASSWORD [--proxy PROXY] [FOLDER1 FOLDER2 LOCAL1 LOCAL2]

Defaults: FOLDER1=/Root/lol1 FOLDER2=/Root/lol2 LOCAL1=./Cargo.toml LOCAL2=./Cargo.lock";

#[tokio::main]
async fn main() -> Result<()> {
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
    println!("Logged in as: {}", session.email);

    let session = Arc::new(Mutex::new(session));
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Start SC loop immediately (SDK-style).
    let sc_session = session.clone();
    let stop_for_loop = stop_flag.clone();
    let sc_handle = tokio::spawn(async move {
        let mut delay_ms = 1_000u64;
        let max_delay = 60_000u64;
        loop {
            if stop_for_loop.load(Ordering::SeqCst) {
                break;
            }
            let mut guard = sc_session.lock().await;
            match guard.poll_action_packets_once().await {
                Ok(_) => delay_ms = 1_000,
                Err(MegaError::ServerBusy) | Err(MegaError::InvalidResponse) => {
                    delay_ms = (delay_ms * 2).min(max_delay);
                }
                Err(e) => {
                    eprintln!("SC loop fatal: {e}");
                    break;
                }
            }
            drop(guard);
            sleep(Duration::from_millis(delay_ms)).await;
        }
    });

    {
        let mut s = session.lock().await;
        println!("Refreshing filesystem...");
        s.refresh().await?;
    }

    // Sequence mirrored from mega-sequence.ps1
    ensure_folder(&session, &folder1).await?;
    upload_and_export(&session, &local1, &folder1).await?;
    wait_for_enter("Verify if the exported link is correct and press Enter to upload Cargo.lock")?;

    upload_and_export(&session, &local2, &folder1).await?;
    wait_for_enter("Check if both files are in the folder and login to upgrade encryption. Then press Enter to continue")?;

    ensure_folder(&session, &folder2).await?;
    upload_and_export(&session, &local2, &folder2).await?;
    wait_for_enter("Verify if the exported link is correct and press Enter to upload Cargo.toml")?;

    upload_and_export(&session, &local1, &folder2).await?;
    println!("Please verify if both files are in the folder now.");

    println!("Sequence complete. SC loop is still running (Ctrl+C to stop)...");
    let stop_signal = stop_flag.clone();
    signal::ctrl_c().await.ok();
    stop_signal.store(true, Ordering::SeqCst);
    let _ = sc_handle.await;
    Ok(())
}

async fn ensure_folder(session: &Arc<Mutex<Session>>, path: &str) -> Result<()> {
    let mut guard = session.lock().await;
    match guard.mkdir(path).await {
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
    session: &Arc<Mutex<Session>>,
    local: &str,
    remote_folder: &str,
) -> Result<()> {
    let mut guard = session.lock().await;
    println!("Uploading {local} to {remote_folder} ...");
    let remote_path = format!("{}/", remote_folder.trim_end_matches('/'));
    let node = guard.upload(local, &remote_path).await?;
    println!("Uploaded as {} ({} bytes)", node.name, node.size);

    println!("Exporting {} ...", remote_folder);
    let link = guard.export(remote_folder).await?;
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
