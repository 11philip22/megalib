# Toolchain and CI Discovery

## Rust Toolchain / MSRV
- `rust-toolchain` / `rust-toolchain.toml` not found at repo root.
- Explicit MSRV is not declared in the files reviewed.
- Rust edition is explicitly set to `2024`.
- Evidence: `Cargo.toml`

## Cargo Features Strategy
- Features are explicit and minimal:
  - `default = []`
  - `preview = ["dep:image"]`
- Feature-gated code is enabled with `#[cfg(feature = "preview")]` in public module exposure and upload path logic.
- Evidence: `Cargo.toml`, `src/lib.rs`, `src/fs/operations/upload.rs`

## Formatting / Linting Tooling
- No `rustfmt.toml` found.
- No `clippy.toml` found.
- No `deny.toml`/`cargo-deny` config found in reviewed files.
- No audit workflow/config discovered in reviewed files.
- TODO: confirm whether formatting/linting are enforced externally (pre-commit hooks, external CI, or local developer convention).
- Evidence: root config scan + `Cargo.toml`

## CI Workflow Summary
- `.github/workflows` directory not present in this repository snapshot.
- As a result, CI jobs and exact CI commands are unknown from local evidence.
- TODO: add or reference CI workflows with canonical checks.
- Evidence: repository root scan

## Runtime / Build-Relevant Notes
- Async runtime uses `tokio` with `features = ["full"]`.
- HTTP transport uses `reqwest` with `default-features = false` and `rustls-tls`.
- Error handling uses `thiserror`.
- Evidence: `Cargo.toml`
