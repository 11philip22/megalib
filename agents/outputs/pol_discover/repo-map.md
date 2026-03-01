# Repository Map (Discovery)

## Crate / Workspace Layout
- Single crate package: `megalib` (no Cargo workspace members declared).
- Evidence: `Cargo.toml`

## Important Directories
- `src/`: library implementation (`api`, `crypto`, `fs`, `session`, `http`, `public`, etc.).
- `examples/`: runnable example binaries and shared CLI helper (`examples/cli/mod.rs`).
- `assets/`: README/media assets.
- `agents/`: task/policy/playbook artifacts.
- No top-level `tests/` directory found.
- No top-level `benches/` directory found.
- Evidence: `src/lib.rs`, `src/session/mod.rs`, `src/fs/operations/mod.rs`, `examples/login.rs`

## Entrypoints
- Library entrypoint: `src/lib.rs`
- Binary-style entrypoints: `examples/*.rs` (for example `examples/login.rs`)
- No `src/main.rs` found.
- Evidence: `src/lib.rs`, `examples/login.rs`

## Build / Test / Lint / Format Commands
### Commands explicitly documented in-repo
- `cargo run --example login -- --email you@example.com --password "your-password"`
- `cargo run --example ls -- --email you@example.com --password "your-password" --path /Root`
- `cargo run --example upload -- --email you@example.com --password "your-password" ./local-file.txt /Root`
- `cargo run --example download -- --email you@example.com --password "your-password" /Root/remote-file.txt ./downloaded-file.txt`
- Evidence: `README.md`

### CI-derived canonical commands
- CI workflow files were not found (`.github/workflows` is absent), so canonical CI build/test/lint/format commands are not discoverable from repo metadata.
- TODO: confirm and document canonical commands (for example `cargo check`, `cargo test`, `cargo fmt --check`, `cargo clippy`) in CI or contributor docs.
- Evidence: repository root scan (no `.github/workflows` directory)
