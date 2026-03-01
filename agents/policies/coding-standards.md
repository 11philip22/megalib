# Coding Standards Policy (megalib)

Scope: Rust source under `src/` and runnable examples under `examples/`.

## MUST
1. Use Rust edition 2024 for crate code and examples.
Evidence: `Cargo.toml` (`edition = "2024"`).
How to verify: `cargo check`.

2. Keep code rustfmt-clean using default rustfmt behavior unless a repo config is added.
Evidence: `src/lib.rs`, `src/api/client.rs`, `src/http.rs`; no `rustfmt.toml` found.
How to verify: `cargo fmt --all -- --check`.

3. Keep module/file names in snake_case and type names in PascalCase.
Evidence: `src/session/mod.rs`, `src/fs/operations/mod.rs`, `src/api/client.rs`, `src/error.rs`.
How to verify: `rg --files src examples`.

4. Keep public surface intentional: expose user-facing API from `lib.rs`/module re-exports, not accidental broad `pub`.
Evidence: `src/lib.rs`, `src/session/mod.rs`.
How to verify: `rg -n "pub mod|pub use" src/lib.rs src/session/mod.rs`.

5. Preserve focused module splits by concern (for example API client vs HTTP transport vs FS operations).
Evidence: `src/api/client.rs`, `src/http.rs`, `src/fs/operations/mod.rs`.
How to verify: `rg -n "^mod " src/session/mod.rs src/fs/operations/mod.rs`.

6. Keep optional behavior behind explicit Cargo features with localized `#[cfg(feature = "...")]`.
Evidence: `Cargo.toml` (`default = []`, `preview = ["dep:image"]`), `src/lib.rs`, `src/fs/operations/upload.rs`.
How to verify: `cargo check --no-default-features` and `cargo check --features preview`.

7. Use colocated unit tests (`#[cfg(test)]`) for deterministic logic in touched modules.
Evidence: `src/api/error.rs`, `src/http.rs`, `src/api/client.rs`.
How to verify: `cargo test`.

8. Keep examples runnable via `cargo run --example ...` and aligned with shared CLI parser patterns where credentials are needed.
Evidence: `README.md`, `examples/login.rs`, `examples/cli/mod.rs`.
How to verify: `cargo run --example login -- --help`.

## SHOULD
1. Use the crate-level `Result`/`MegaError` conventions for fallible public APIs.
Evidence: `src/error.rs`, `src/lib.rs`, `src/api/client.rs`.
How to verify: `rg -n "pub .*-> .*Result<" src`.

2. Add/maintain targeted tests when adding conversion tables, retry logic, or protocol mapping logic.
Evidence: `src/api/error.rs` tests, `src/api/client.rs` tests.
How to verify: `cargo test api::error` (or module-specific test filters).

3. Keep README example commands synchronized with existing `examples/*.rs`.
Evidence: `README.md`, `examples/login.rs`, `examples/upload.rs`, `examples/download.rs`.
How to verify: `rg --files examples` and compare with `README.md` command blocks.

## MAY
1. Use narrowly scoped `#[allow(dead_code)]` in shared example helpers when not all examples consume every helper.
Evidence: `examples/cli/mod.rs`.
How to verify: `rg -n "#\\[allow\\(dead_code\\)\\]" examples`.

2. Introduce new optional dependencies via `dep:` feature wiring, following the `preview` pattern.
Evidence: `Cargo.toml` (`preview = ["dep:image"]`).
How to verify: inspect `[features]` in `Cargo.toml`.

## TODO / Unknowns
- No CI workflow file was found; canonical enforced commands for fmt/lint/test are unknown.
- No explicit clippy policy/config (`clippy.toml` or CI clippy args) was found; lint severity policy is currently inferred, not declared.
- No workspace-level policy exists because only one package is declared in `Cargo.toml`.
