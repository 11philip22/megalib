# Testing

## Current Test Layout
- Tests are embedded in source modules under `#[cfg(test)]` blocks.
- There is no `tests/` integration test directory in the repo.

Evidence:
- `src/http.rs::tests`
- `src/public.rs::tests`
- `src/fs/node.rs::tests`

## Current Dependencies
- `tokio-test` is the only dev-dependency listed.

Evidence:
- `Cargo.toml::dev-dependencies`

## HTTP Mocking
No HTTP mocking crate is present in dev-dependencies, and existing tests do not rely on a mock server.

Evidence:
- `Cargo.toml::dev-dependencies`
- `src/http.rs::tests`

## Guidance For New Tests
- Prefer deterministic inputs and avoid live network calls.
- Favor small unit tests colocated with the module they validate.
- For doc examples that perform network I/O, use `no_run` as in existing rustdoc examples.

Evidence:
- `src/lib.rs::Session`
- `src/session/session.rs::login`
