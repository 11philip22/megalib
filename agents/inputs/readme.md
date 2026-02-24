# Documentation Index

## Purpose
These documents describe the SDK as implemented in code and must be updated from repo evidence only. Code is the source of truth; if README or docs diverge from code, note the discrepancy explicitly and follow the code behavior in these files.

Evidence:
- `src/lib.rs::Session`
- `src/error.rs::MegaError`
- `README.md > Features`

## Docs Index
- `agent/inputs/architecture.md` – Module layout and request/operation flow.
- `agent/inputs/public_api.md` – Public surface area (modules, types, functions).
- `agent/inputs/api.md` – SDK-level API behavior (what users call).
- `agent/inputs/errors.md` – Error model and mapping.
- `agent/inputs/testing.md` – Testing reality and contribution rules.
- `agent/inputs/decisions.md` – Evidence-backed implementation decisions.

Evidence:
- `src/api/mod.rs::ApiClient`
- `src/fs/mod.rs::Node`
- `src/session/mod.rs::Session`

## Rules
- No invention. If uncertain, mark “Unknown” and add a TODO describing the missing evidence.
- Public API changes require updates to `agent/inputs/public_api.md`.
- Error behavior changes require updates to `agent/inputs/errors.md`.

Evidence:
- `src/lib.rs::Session`
- `src/error.rs::MegaError`

## Preferred Workflow
- Make small, focused PRs that touch one domain at a time (API, FS, session, crypto) to keep evidence mapping tight.
- Update docs in this folder as part of any behavior change.

Evidence:
- `src/api/client.rs::ApiClient`
- `src/fs/operations/browse.rs::list`
- `src/session/session.rs::login`

## Known Discrepancies With Root README
- Installation snippet uses `megalib = "0.1.0"`, but `Cargo.toml` lists version `0.6.0`.
- README feature line “Text/Video/Image streaming support” does not map to a named API; the closest streaming-style APIs are `Session::upload_from_reader` and `Session::download`/`download_to_file`.

Evidence:
- `README.md > Installation`
- `Cargo.toml::package`
- `README.md > Features`
- `src/fs/operations/upload.rs::upload_from_reader`
- `src/fs/operations/download.rs::download`
