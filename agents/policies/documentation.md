# Documentation Policy (megalib)

Scope: crate docs, API docs, examples docs, and release notes.

## MUST
1. Maintain crate-level rustdoc in `src/lib.rs` with capability overview and at least one end-to-end usage example.
Evidence: `src/lib.rs`.
How to verify: `cargo doc --no-deps`.

2. Keep networked examples in docs marked `no_run` unless they are guaranteed deterministic/offline.
Evidence: `src/lib.rs` code fences use `no_run`.
How to verify: `rg -n "```no_run" src/lib.rs`.

3. Document user-facing public APIs with `///` comments; include arguments/returns where behavior is non-trivial.
Evidence: `src/api/client.rs`, `src/http.rs`, `src/error.rs`.
How to verify: `rg -n "///" src/api/client.rs src/http.rs src/error.rs`.

4. Keep README quickstart and example command sections current with real example binaries.
Evidence: `README.md`, `examples/login.rs`, `examples/download.rs`, `examples/upload.rs`.
How to verify: `rg --files examples` and compare against `README.md` example command list.

5. Document user-visible changes in `CHANGELOG.md` under `Unreleased` before release tagging.
Evidence: `CHANGELOG.md` uses `## [Unreleased]`.
How to verify: `rg -n "^## \\[Unreleased\\]" CHANGELOG.md`.

6. Keep changelog section structure aligned with existing Added/Changed/Removed pattern.
Evidence: `CHANGELOG.md`.
How to verify: `rg -n "^### (Added|Changed|Removed)" CHANGELOG.md`.

7. Keep docs links and package metadata aligned (`docs.rs`, crate name/version path references).
Evidence: `Cargo.toml` (`documentation`), `README.md` badges/links.
How to verify: inspect links in `README.md` and `Cargo.toml`.

## SHOULD
1. Preserve module-level `//!` summaries for major modules and examples.
Evidence: `src/lib.rs`, `src/session/mod.rs`, `src/http.rs`, `examples/login.rs`.
How to verify: `rg -n "^//!" src examples`.

2. Mirror feature-gated behavior documentation when adding/changing features.
Evidence: `Cargo.toml` (`preview` feature), `src/lib.rs` feature text.
How to verify: compare `[features]` in `Cargo.toml` with docs in `src/lib.rs`/`README.md`.

3. Keep public docs examples on `megalib::Result`-based signatures for consistency with crate API.
Evidence: `src/lib.rs`, `src/session/auth.rs` (example patterns), `src/session/core.rs` (example patterns).
How to verify: `rg -n "megalib::Result|megalib::error::Result" src`.

## MAY
1. Include concise CLI usage blocks in example module docs and a `USAGE` constant in example binaries.
Evidence: `examples/login.rs`, `examples/cli/mod.rs`.
How to verify: `rg -n "Usage:|const USAGE" examples`.

2. Add protocol-specific notes in comments when behavior intentionally follows SDK semantics.
Evidence: `src/http.rs` (SC timeout policy comments), `src/api/client.rs` (SC polling comments).
How to verify: `rg -n "SDK|SC|timeout" src/http.rs src/api/client.rs`.

## TODO / Unknowns
- No `CONTRIBUTING.md` was found with doc-update requirements; documentation process is inferred from existing files.
- No release automation/CI workflow was found; cannot verify if changelog/docs checks are enforced automatically.
