# Observed Conventions (Discovery)

## Module Structure Patterns
- Top-level `lib.rs` declares domain modules (`api`, `crypto`, `fs`, `session`, etc.) and re-exports selected public API types.
- Domain modules use `mod.rs` aggregators and split focused submodules by concern.
- Example:
  - `src/session/mod.rs` groups auth/core/actor/key sync/sc polling.
  - `src/fs/operations/mod.rs` splits browse/dir_ops/download/export/quota/tree/upload.
- Evidence: `src/lib.rs`, `src/session/mod.rs`, `src/fs/operations/mod.rs`

## Naming Patterns
- File and module names are snake_case (`sc_poller.rs`, `action_packets.rs`, `upload_state.rs`).
- Type names are PascalCase (`ApiClient`, `HttpClient`, `MegaError`, `ApiErrorCode`).
- Public methods are verb-first and operation-oriented (`login`, `refresh`, `request_batch`, `poll_sc`, `upload_resumable`).
- Evidence: `src/api/client.rs`, `src/http.rs`, `src/error.rs`, `src/session/mod.rs`

## Documentation Style
- Crate-level docs in `src/lib.rs` use `//!` and include feature summary + `no_run` examples.
- Public API docs use `///`, including `# Arguments` and `# Returns` on non-trivial methods.
- Example binaries include module docs with usage text and explicit CLI usage strings.
- Evidence: `src/lib.rs`, `src/api/client.rs`, `src/http.rs`, `examples/login.rs`

## Test Style
- Tests are colocated unit tests inside module files using `#[cfg(test)]`.
- Representative tests validate deterministic conversion behavior and constructor/session state behavior.
- No top-level integration test directory (`tests/`) observed.
- Evidence: `src/api/error.rs`, `src/http.rs`, `src/api/client.rs`

## Feature Flags Conventions
- Features are opt-in (`default = []`).
- Optional code is localized with `#[cfg(feature = "preview")]` rather than broad crate-wide branching.
- The `preview` feature gates image-related functionality via optional dependency.
- Evidence: `Cargo.toml`, `src/lib.rs`, `src/fs/operations/upload.rs`

## Example CLI Conventions
- Examples share reusable argument parsing helpers under `examples/cli/mod.rs`.
- Example files define a `USAGE` constant and fail-fast on invalid args via `usage_and_exit`.
- Evidence: `examples/cli/mod.rs`, `examples/login.rs`
