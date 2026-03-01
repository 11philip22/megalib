# Policy Evidence Map

## Formatting
- `Cargo.toml` (edition baseline)
- `src/lib.rs`, `src/api/client.rs`, `src/http.rs` (representative formatting style)
- TODO: no `rustfmt.toml` and no CI workflow evidence found

## Lint Rules
- No explicit lint config discovered (`clippy.toml`, CI clippy args not found)
- `examples/cli/mod.rs` uses targeted `#[allow(dead_code)]` for shared example helpers
- TODO: verify project-level clippy policy and deny/allow baseline

## Module Layout / Visibility
- `src/lib.rs` (top-level module declarations + re-exports)
- `src/session/mod.rs` (submodule visibility and re-exports)
- `src/fs/operations/mod.rs` (focused split by operation)

## Naming Conventions
- `src/session/mod.rs`, `src/fs/operations/mod.rs`, `src/http.rs`, `src/api/client.rs`

## Feature Flags
- `Cargo.toml` (`default = []`, `preview = ["dep:image"]`)
- `src/lib.rs` (`#[cfg(feature = "preview")]`)
- `src/fs/operations/upload.rs` (feature-gated implementation points)

## Tests
- `src/api/error.rs` (`#[cfg(test)]`, deterministic conversion tests)
- `src/http.rs` (`#[cfg(test)]`, constructor/proxy tests)
- `src/api/client.rs` (`#[cfg(test)]`, session state tests)
- Repo scan evidence: no top-level `tests/`/`benches/` dirs

## Documentation
- `src/lib.rs` (crate-level rustdoc + no_run examples)
- `src/api/client.rs`, `src/http.rs`, `src/error.rs` (public API docs)
- `README.md` (quickstart and `cargo run --example` usage)
- `CHANGELOG.md` (Keep a Changelog + SemVer framing)

## Error Handling
- `src/error.rs` (`MegaError`, `Result<T>`, `thiserror`)
- `src/api/error.rs` (API code enum + descriptions)
- `src/api/client.rs` (API code mapping, retries, timeout errors, invalid response handling)
- `src/http.rs` (request policy by request kind, timeout/redirect policy)

## CI / Quality Gates
- No `.github/workflows` directory found in repository snapshot
- TODO: confirm canonical CI jobs and exact check commands
