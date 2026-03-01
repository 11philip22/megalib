# Documentation Policy (megalib)

Scope: crate docs, API docs, examples docs, and release notes.

## MUST
1. Maintain crate-level rustdoc in `src/lib.rs` with capability overview and at least one end-to-end usage example.
Evidence: `src/lib.rs`.
How to verify: `cargo doc --no-deps`.

2. Keep networked examples in docs marked `no_run` unless they are guaranteed deterministic/offline.
Evidence: `src/lib.rs` code fences use `no_run`.
How to verify: `rg -n "```no_run" src/lib.rs`.

3. All public APIs that are intended for users of the SDK MUST include rustdoc written from a consumer perspective.

    - Documentation MUST explain what the API does, when it should be used, and any important constraints or side effects.
    - For non-trivial behavior, documentation MUST describe inputs, return values, and error conditions.
    - Documentation MUST avoid describing internal implementation details unless they affect observable behavior.
    - Where appropriate, include a minimal usage example.

    Evidence:
    - Public API documentation patterns in `src/api/client.rs`, `src/http.rs`, `src/error.rs`.

    How to verify:
    - `rg -n "^pub " src` and confirm corresponding `///` documentation exists.
    - `cargo doc --no-deps`

4. The README MUST provide a working quickstart path that reflects the real SDK usage and example binaries.

    - The quickstart MUST show a realistic minimal flow a new user can follow.
    - Command-line example invocations MUST match actual `examples/*.rs` binaries.
    - Flags, arguments, and option names shown in documentation MUST reflect current code behavior.
    - The README MUST not describe features or flows that are not implemented.

    Evidence:
    - `README.md`
    - `examples/login.rs`
    - `examples/download.rs`
    - `examples/upload.rs`

    How to verify:
    - `rg --files examples`
    - `cargo run --example <example_name> -- --help`
    - Manually compare README command blocks with actual example behavior

5. Every merged change MUST be documented in `CHANGELOG.md` under `## [Unreleased]`.

    - Each PR MUST add at least one entry describing what changed.
    - Entries MUST be written in terms of observable impact (behavior, API, errors, performance, docs), not implementation detail.
    - Changes MUST be categorized under existing sections (e.g., Added/Changed/Fixed/Removed) and MAY use an `Internal` section for refactors that do not affect behavior.
    - Dependency updates MUST be listed (at minimum: crate name + reason), and MUST be placed under `Internal` unless user-visible impact is known.
    - Formatting-only changes MAY be omitted, but only if they do not alter behavior and do not change public API docs.
    - If `Internal` does not exist, it SHOULD be added to `CHANGELOG.md` to keep non-user-facing changes readable.

    Evidence:
    - `CHANGELOG.md` contains `## [Unreleased]` and uses categorized sections.

    How to verify:
    - `rg -n "^## \\[Unreleased\\]" CHANGELOG.md`
    - For each PR, confirm at least one new entry was added under `Unreleased`.

6. Keep changelog section structure aligned with existing Added/Changed/Removed pattern.
Evidence: `CHANGELOG.md`.
How to verify: `rg -n "^### (Added|Changed|Removed)" CHANGELOG.md`.

7. Documentation links and package metadata MUST accurately reflect the published crate identity and documentation location.

    - The `documentation`, `repository`, and crate name/version metadata in `Cargo.toml` MUST match the actual project URLs.
    - README badges and documentation links MUST point to the correct crate name and version path (e.g., docs.rs path).
    - If the crate name or documentation URL changes, all references MUST be updated in the same PR.
    - Hardcoded version strings in documentation SHOULD be avoided; where present, they MUST match `Cargo.toml`.

    Evidence:
    - `Cargo.toml` (`documentation`, `repository`, crate name/version fields)
    - `README.md` badges and documentation links

    How to verify:
    - Inspect `Cargo.toml` metadata fields
    - Verify README badge URLs and docs.rs links resolve correctly
    - Ensure crate name/version in README matches `Cargo.toml`

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
