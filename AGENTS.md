# AGENTS.md

## Repository Type

This repository is a **Rust SDK**.

All automated changes must respect:
- Public API stability
- Existing module structure
- The policies in `agents/policies/`

Discovery artifacts live in:
- `agents/outputs/pol_discover/`

Agents must treat discovery outputs as supporting evidence, not as policy.

---

## Source of Truth

Primary behavioral rules are defined in:

- `agents/policies/coding-standards.md`
- `agents/policies/documentation.md`
- `agents/policies/error-handling.md`

If a policy conflicts with existing code:
- Prefer existing code.
- Add a TODO in the relevant policy.
- Do NOT silently “fix” the code to match policy.

Policies must reflect repo reality — not generic Rust advice.

---

## Work Model

All changes must follow **small-slice principle**:

- One logical change per PR.
- No mixed refactor + feature + formatting commits.
- Preserve public API unless explicitly instructed otherwise.
- Avoid touching unrelated files.

If scope grows:
- Stop.
- Propose a split into multiple slices.

---

## Allowed Changes

Agents MAY:
- Add or edit Markdown files under `agents/`
- Add tests
- Improve documentation
- Fix clearly isolated bugs
- Add minimal internal refactors strictly required for a change

Agents MUST NOT:
- Perform large refactors without instruction
- Change public API without explicit request
- Reorganize modules
- Rename crates/modules
- Change Cargo workspace structure
- Introduce new major dependencies casually

---

## Mandatory Verification Before Completion

If a change modifies Rust source code (`src/`, `examples/`, `tests/`, `benches/`, or `Cargo.toml`), agents MUST run:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

If the repository defines alternative commands in CI,
those commands take precedence and must be used.

No task is complete if:
- Formatting differs
- Clippy fails
- Tests fail
- New warnings are introduced (unless explicitly allowed)

If the change only modifies:
- Markdown files
- Files under agents/
- Non-Rust configuration files that do not affect compilation

then Rust verification commands are NOT required.

If uncertain whether a change affects Rust compilation or behavior, default to running the verification commands.

---

## Error Handling Discipline

All changes touching error paths must follow:
- `agents/policies/error-handling.md`

Never:
- Introduce unwrap() in library code
- Leak internal error types through public API unless policy allows
- Downgrade structured errors to String

---

## Documentation Discipline

All changes touching public API must:
- Update doc comments
- Keep examples compiling (if repo uses doc tests)
- Follow agents/policies/documentation.md

If unsure, add documentation rather than remove it.

## Dependency Rules

- No new dependency without justification.
- Prefer existing crates already used in the workspace.
- Avoid introducing alternative patterns (e.g., second async runtime).

If adding a dependency:
- Explain why existing ones are insufficient.
- Keep feature surface minimal.

## Large Changes Protocol

For architectural or cross-cutting changes:
1. Produce a short written plan (bullet list).
2. Identify affected crates/modules.
3. Confirm public API impact.
4. Wait for approval before proceeding.

## Output Style

When completing work:
- Summarize what changed.
- List affected files.
- List verification commands executed.
- State whether public API changed.
- Mention any follow-up TODOs.

#  Stability Bias

This is an SDK.

Bias towards:
- Stability
- Predictability
- Explicit behavior
- Backwards compatibility

Avoid:
- Cleverness
- Hidden magic
- Implicit side effects