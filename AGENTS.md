# AGENTS.md
## Mandatory Workflow: Structural-First Editing (agentic-codebase required)

This repository uses `agentic-codebase` (ACB) for structural analysis.
All non-trivial edits MUST follow the workflow defined below.

---

## 0. Graph Freshness Rule

Before performing structural changes:

- If `project.acb` does not exist → compile it.
- If large refactors happened → recompile.
- If unsure → recompile.

Command:

    acb compile . -o project.acb

---

## 1. Navigation-First Policy (MANDATORY)

Before editing any of the following:
- public functions
- exported structs
- trait implementations
- shared modules
- cross-module logic
- anything used outside its immediate file

You MUST:

1. Identify symbols involved.
2. Query their callers and reverse dependencies.
3. Run impact analysis.

Required queries:

    acb query project.acb symbol --name "<SymbolName>"
    acb query project.acb calls --unit-id <ID> --depth 3
    acb query project.acb rdeps --unit-id <ID> --depth 3
    acb query project.acb impact --unit-id <ID> --depth 5

Do NOT modify structural code without this analysis.

---

## 2. Blast Radius Discipline

Rules:

- Prefer minimal change that satisfies the task.
- Do not modify unrelated units.
- If `impact` shows high surface area, consider:
  - adapter layer instead of signature change
  - deprecation instead of replacement
  - wrapper instead of mutation

---

## 3. After Editing (Verification Pass)

After finishing edits:

1. Re-run impact on modified units.
2. Ensure no unintended high-risk propagation.
3. Run tests / build.
4. If structural changes occurred → recompile graph.

---

## 4. When ACB Can Be Skipped

ACB queries are NOT required for:

- formatting
- pure comments
- single-file typo fixes
- strictly local logic not referenced externally

When in doubt → run ACB queries.

---

## 5. Refactor Protocol

For refactors:

1. Map full dependency tree first.
2. Stage changes in smallest viable increments.
3. Re-run impact between increments.
4. Keep changes bisect-safe.

---

## 6. Failure Rule

If ACB fails:
- Do NOT proceed blindly.
- Attempt to recompile.
- If still failing, restrict changes to strictly local logic.

---

## 7. Core Principle

Navigate structure before mutation.

Never guess dependency impact.
Always verify graph impact.

This rule overrides convenience.