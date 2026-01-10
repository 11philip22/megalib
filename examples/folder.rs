//! Example: Browse and download from a public folder
//!
//! Usage:
//!   cargo run --example folder -- <FOLDER_URL>

use mega_rs::public::open_folder;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let url = args.get(1).expect("Usage: folder <FOLDER_URL>");

    println!("Opening public folder...");
    let folder = open_folder(url).await?;

    println!("\n📁 Folder contents:");
    println!("{:-<60}", "");

    // Get root folder
    let root = folder.nodes().first().expect("Empty folder");
    let root_path = root.path().unwrap_or("/");
    println!("📂 {} (root)\n", root.name);

    // List all items in root folder
    for node in folder.list(root_path, false) {
        let prefix = if node.node_type.is_container() {
            "📁"
        } else {
            "📄"
        };

        if node.size > 0 {
            println!("{} {} ({} bytes)", prefix, node.name, node.size);
        } else {
            println!("{} {}", prefix, node.name);
        }
    }

    // Show total stats (excluding root)
    let total_files = folder
        .nodes()
        .iter()
        .filter(|n| !n.node_type.is_container())
        .count();

    // Count subfolders only (exclude root)
    let total_subfolders = folder
        .nodes()
        .iter()
        .filter(|n| n.node_type.is_container() && n.path().unwrap_or("") != root_path)
        .count();

    let total_size: u64 = folder.nodes().iter().map(|n| n.size).sum();

    println!("\n{:-<60}", "");
    println!(
        "📊 Contents: {} files, {} subfolders (Total size: {} bytes)",
        total_files, total_subfolders, total_size
    );

    Ok(())
}
