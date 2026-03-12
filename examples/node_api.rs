//! Example: Browse MEGA using cached nodes instead of remote path strings.
//!
//! Usage:
//!   cargo run --example node_api -- --email YOUR_EMAIL --password YOUR_PASSWORD [--proxy PROXY]

use clap::Parser;
use megalib::{NodeType, SessionHandle};
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "node_api")]
struct Args {
    #[arg(short = 'e', long)]
    email: String,
    #[arg(short = 'p', long)]
    password: String,
    #[arg(long)]
    proxy: Option<String>,
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    fmt().with_env_filter(filter).with_target(false).init();
}

#[tokio::main]
async fn main() {
    init_tracing();
    let args = Args::parse();

    let login = if let Some(proxy) = &args.proxy {
        SessionHandle::login_with_proxy(&args.email, &args.password, proxy).await
    } else {
        SessionHandle::login(&args.email, &args.password).await
    };
    let session = login.expect("Login failed");

    session.fetch_nodes().await.expect("Fetch nodes failed");

    let root = session
        .root_nodes()
        .await
        .expect("Failed to load root nodes")
        .into_iter()
        .find(|node| node.node_type == NodeType::Root)
        .expect("Cloud Drive root not found");

    println!("Cloud Drive root: {} ({})", root.name, root.handle);

    let children = session
        .children(&root)
        .await
        .expect("Failed to list children");
    if children.is_empty() {
        println!("  (empty)");
        return;
    }

    for node in children {
        let kind = if node.is_file() { "file" } else { "dir" };
        println!("  {} {} [{}]", kind, node.name, node.handle);
    }

    if let Some(documents) = session
        .child_node_by_name(&root, "Documents")
        .await
        .expect("Failed to look up child by name")
    {
        println!(
            "\nFound child by name: {} [{}]",
            documents.name, documents.handle
        );
    }
}
