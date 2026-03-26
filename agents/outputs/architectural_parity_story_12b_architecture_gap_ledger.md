# Story 12B Spec: Add Architecture Gap Ledger And Epic Audit Discipline

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, the sibling upstream SDK at `../sdk`, and the current parity documents under `agents/outputs/`.

This document refines Story 12B from `agents/outputs/architectural_parity_epic.md` into an implementation-ready planning and discipline story. Unlike Stories 2 through 11, this is not primarily a runtime-bearing story. Its job is to make the epic self-auditing so architectural gaps are visible as first-class engineering work rather than discovered midway through implementation.

Story type:

- Documentation / operational-discipline story

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_report.md`
- `agents/outputs/parity_report.md`

---

## Status

Not started as a formal artifact set.

Current implementation status on 2026-03-26:

- the epic already contains a top-level architecture-gap coverage matrix
- the architectural parity report already lists stable dimensions that should stay explicit
- the parity report already tracks capability families separately from architecture
- there is not yet a dedicated permanent ledger artifact that binds those dimensions to owner stories, closure states, and evidence
- update discipline is still manual and partially implicit

This means the project now has the right insight, but not yet the durable mechanism to keep that insight correct over time.

---

## Story Goal

Create a permanent architecture-gap ledger and update discipline that ensures every tracked SDK architectural dimension has one of the following:

- an owning story
- a validated closure status with evidence
- or an explicit out-of-scope rationale

Story 12B exists to prevent this failure mode:

- the epic appears comprehensive
- later work uncovers a real architectural gap with no owner story
- the team must retrofit the plan mid-flight

That already happened once with the production persistence backend gap between Stories 3 and 4. Story 12B is the discipline story that prevents that class of omission from recurring.

---

## Why This Story Exists

The upstream SDK is large enough that architectural parity cannot be managed by memory alone. The parity reports already prove that:

- the SDK has more runtime layers than the current Rust crate
- some gaps are feature gaps
- some gaps are structural/runtime-shape gaps
- some gaps are intentional scope exclusions

Those categories need to stay explicit.

Without a ledger:

- the epic can overclaim coverage
- a report can add a new dimension without any owning story
- a completed story can be mistaken for full closure when it only landed part of the target
- capability and architecture reports can drift out of sync

The persistence-backend omission exposed the exact problem Story 12B is meant to solve:

- Story 3 defined the persistence SPI
- Story 4 consumed that SPI for tree/cache coherency
- only later did it become obvious that no story actually owned production backend rollout

The issue was not lack of effort. The issue was lack of a durable audit artifact. Story 12B fixes that.

---

## Scope

In scope:

- define the permanent architecture-gap ledger artifact set under `agents/outputs/`
- define the exact ledger rows that must be maintained
- define row ownership, status, evidence, and out-of-scope fields
- define the update discipline tying the ledger to:
  - `architectural_parity_epic.md`
  - `architectural_parity_report.md`
  - `parity_report.md`
  - detailed story specs under `agents/outputs/architectural_parity_story_*.md`
- define the closure rules that prevent partial work from being mistaken for fully closed gaps
- define refresh and audit checkpoints for future epic/report updates

Out of scope:

- replacing code, tests, or story specs as the source of truth
- inventing generic project-management workflow detached from architecture work
- turning parity planning into a ticketing system
- adding runtime behavior
- auto-generating the ledger from code in this story

This story is successful if the epic becomes mechanically auditable for architecture coverage.

---

## Story 1 And Story 12 Constraints

Story 12B must preserve these existing decisions:

- Story 1 remains the ownership baseline for subsystem homes and dependency rules
- Story 12 remains the executable validation harness story
- Story 12B is not a replacement for tests or runnable parity checks
- architecture closure claims must still be backed by code, tests, and story implementations

Practical consequence:

- Story 12B owns the audit layer
- Story 12 owns executable validation
- detailed story specs own the implementation contracts
- reports remain analysis artifacts, but their tracked dimensions must map into the ledger

If Story 12B starts redefining subsystem homes or runtime behavior, it has crossed back into Story 1 territory and should be narrowed again.

---

## SDK Awareness And Parity Target

The ledger is SDK-aware in a specific way:

- it treats the SDK as the reference architecture whose major runtime dimensions must be represented explicitly
- it does not attempt to model every SDK file or symbol
- it does require that the Rust parity effort track every major runtime family that materially affects future feature porting

This means the ledger should be driven by stable architectural dimensions such as:

- request orchestration
- durable persistence and tree/cache coherency
- transfer runtime
- filesystem/watch abstraction
- platform layering
- public event and adapter staging
- query/indexing
- sync / backup / mount desktop subsystems
- side-service pipeline homes
- secondary durable state domains

The ledger is not trying to become a feature checklist. It is trying to prevent architectural blind spots.

---

## Current Discipline Gaps To Close

Story 12B is specifically targeting these current planning gaps:

1. The epic has a matrix, but no dedicated authoritative ledger artifact yet.
2. Architecture dimensions in `architectural_parity_report.md` are not yet tied to a durable per-row audit record.
3. Capability families in `parity_report.md` are not yet explicitly cross-checked against architecture rows.
4. Story completion can still be misread as full closure even when a later hardening or production story remains outstanding.
5. No refresh checklist currently forces report changes, epic changes, and ledger changes to land together.

---

## Upstream C++ Ground Truth For Ledger Rows

Story 12B is documentation-only, but the ledger rows are not allowed to float free of the SDK. The initial population of `architectural_gap_ledger.md` should use the concrete upstream subsystem homes below as its C++ ground truth, alongside the owning story docs and the parity reports.

This section exists so Story 12B implementers do not have to reconstruct the upstream architecture from memory or from scattered report prose.

If an owning story doc already cites a narrower upstream slice for one row, that story doc remains the implementation-level reference. Story 12B's job is to make sure the ledger starts from the correct architectural anchors.

| Ledger row | Primary upstream C++ anchors |
|-----------|------------------------------|
| Core runtime ownership | `../sdk/include/megaapi_impl.h`, `../sdk/include/mega/megaclient.h`, `../sdk/src/megaapi_impl.cpp`, `../sdk/src/megaclient.cpp` |
| Public-folder runtime separation | `../sdk/include/megaapi.h`, `../sdk/include/mega/megaclient.h`, `../sdk/src/megaapi_impl.cpp`, `../sdk/src/megaclient.cpp` |
| Request orchestration | `../sdk/src/request.cpp`, `../sdk/include/mega/megaclient.h`, `../sdk/src/megaapi_impl.cpp`, `../sdk/src/commands.cpp` |
| Persistence runtime SPI | `../sdk/include/mega/db.h`, `../sdk/include/mega/megaclient.h`, `../sdk/include/mega/nodemanager.h`, `../sdk/src/nodemanager.cpp` |
| Production persistence backend | `../sdk/include/mega/db/sqlite.h`, `../sdk/src/db/sqlite.cpp`, `../sdk/src/megaclient.cpp` |
| Tree/cache coherency | `../sdk/include/mega/nodemanager.h`, `../sdk/src/nodemanager.cpp`, `../sdk/src/node.cpp`, `../sdk/src/megaclient.cpp` |
| SC/AP lifecycle | `../sdk/src/megaclient.cpp`, `../sdk/src/commands.cpp` |
| Transfer runtime | `../sdk/include/mega/transfer.h`, `../sdk/src/transfer.cpp`, `../sdk/src/transferslot.cpp`, `../sdk/src/megaapi_impl.cpp`, `../sdk/src/megaclient.cpp` |
| Filesystem/watch abstraction | `../sdk/include/mega/filesystem.h`, `../sdk/src/filesystem.cpp`, `../sdk/src/drivenotify.cpp`, `../sdk/src/posix/drivenotifyposix.cpp`, `../sdk/src/osx/drivenotifyosx.cpp`, `../sdk/src/win32/drivenotifywin.cpp`, `../sdk/src/sync.cpp`, `../sdk/src/node.cpp` |
| Platform/runtime layering | `../sdk/src/posix/fs.cpp`, `../sdk/src/posix/waiter.cpp`, `../sdk/src/osx/fs.cpp`, `../sdk/src/win32/fs.cpp`, `../sdk/src/win32/waiter.cpp`, `../sdk/src/android/androidFileSystem.cpp`, `../sdk/src/common/platform/` |
| Public event subsystem | `../sdk/include/mega/megaapp.h`, `../sdk/include/mega/common/client.h`, `../sdk/src/common/client.cpp`, `../sdk/src/megaapi_impl.cpp` |
| Public adapter/callback staging | `../sdk/include/mega/common/pending_callbacks.h`, `../sdk/src/common/client_adapter.cpp`, `../sdk/src/common/pending_callbacks.cpp`, `../sdk/src/megaapi_impl.cpp`, `../sdk/src/nodemanager.cpp` |
| Query/index substrate | `../sdk/include/mega/nodemanager.h`, `../sdk/include/mega/db.h`, `../sdk/src/nodemanager.cpp`, `../sdk/src/db/sqlite.cpp` |
| Secondary durable state domains | `../sdk/include/mega/megaclient.h`, `../sdk/src/megaclient.cpp`, `../sdk/src/user.cpp`, `../sdk/src/pendingcontactrequest.cpp`, `../sdk/src/useralerts.cpp` |
| Sync subsystem | `../sdk/include/mega/sync.h`, `../sdk/src/sync.cpp`, `../sdk/src/megaapi_impl_sync.cpp` |
| Scheduled backup/copy | `../sdk/src/megaapi.cpp`, `../sdk/include/megaapi.h`, `../sdk/src/megaapi_impl.cpp`, `../sdk/include/mega/heartbeats.h`, `../sdk/src/heartbeats.cpp`, `../sdk/src/sync.cpp` |
| Mount/FUSE subsystem | `../sdk/src/fuse/supported/common/mount.cpp`, `../sdk/src/fuse/supported/common/mount_db.cpp`, `../sdk/src/fuse/supported/common/inode_db.cpp`, `../sdk/src/fuse/supported/common/file_cache.cpp`, `../sdk/src/fuse/supported/platform/service_context.cpp`, `../sdk/src/fuse/supported/platform/posix/mount.cpp`, `../sdk/src/fuse/supported/platform/windows/mount.cpp`, `../sdk/src/fuse/supported/platform/posix/libfuse/3/session.cpp`, `../sdk/src/fuse/unsupported/service_context.cpp` |
| Side-service pipeline homes | `../sdk/include/mega/gfx.h`, `../sdk/src/gfx.cpp`, `../sdk/src/gfx/worker/`, `../sdk/include/mega/file_service/file_service.h`, `../sdk/src/file_service/file_service.cpp`, `../sdk/src/file_service/file_service_context.cpp`, `../sdk/include/mega/megaclient.h`, `../sdk/src/megaclient.cpp` |

Important interpretation rules for this reference map:

- the `Side-service pipeline homes` row is intentionally a family of upstream homes, not one literal SDK subsystem name
- the event and adapter rows are separate on purpose because the SDK distinguishes outward callback families from callback staging, observer fan-out, and deferred delivery mechanics
- the persistence, tree/cache, and SC/AP rows are distinct on purpose even though they all touch `MegaClient`; the ledger should preserve those seams rather than collapsing them back together
- Story 12B should cite these anchors when creating the initial ledger rows, and later row evidence should get narrower as the owning stories land code and tests

---

## Design Decisions

### Decision 1. The detailed ledger lives in its own artifact

Why:

- the epic needs a readable summary matrix
- the reports need analysis narrative
- neither is a good place for full per-row audit state, evidence links, and closure notes

Consequence:

- Story 12B should create `agents/outputs/architectural_gap_ledger.md` as the authoritative detailed ledger
- `architectural_parity_epic.md` should retain only the summary coverage matrix

### Decision 2. The ledger is architecture-first, not generic PM tracking

Why:

- the failure mode is architectural coverage drift, not general task management
- the ledger should only track dimensions that matter for SDK-shaped runtime parity

Consequence:

- ledger rows must map to architecture audit units, not arbitrary work items
- each row must name the SDK reference shape and the Rust architectural target
- `architectural_parity_report.md` remains the source of dimension families and rationale
- the epic and the ledger may split one dimension family into multiple rows when the SDK has distinct runtime seams that need separate ownership or closure states
- each ledger row must map back to exactly one dimension family

### Decision 3. Governance tracks stay explicit, but outside the architecture row set

Why:

- Story 12 and Story 12B gate parity claims
- neither one is itself an SDK runtime dimension
- mixing governance rows into architecture closure makes “architectural parity” claims harder to read and easier to misstate

Consequence:

- `Validation harness` and `Gap-ledger / audit discipline` must stay explicit in the epic and the refresh checklist
- they are gating tracks, not rows in `architectural_gap_ledger.md`
- any architectural parity claim requires both architecture-row closure and completion of those two gating tracks

### Decision 4. Row status must distinguish partial closure from full closure

Why:

- Stories 4, 4B, and 4C already demonstrated that “implemented” can mean different things
- the ledger must prevent prematurely closing a dimension after only a seam, test backend, or structural slice has landed

Consequence:

- Story 12B should standardize row statuses such as:
  - `Unowned`
  - `Planned`
  - `In Progress`
  - `Structurally Landed`
  - `Production Landed`
  - `Validated Closed`
  - `Out Of Scope`

### Decision 5. Every row must have one primary owner or an explicit out-of-scope rationale

Why:

- this is the core protection against omission
- a row without an owner is a planning bug, not just missing polish

Consequence:

- a new dimension added to `architectural_parity_report.md` must update the ledger in the same change
- each row must name exactly one `Primary Owning Story`
- rows may also list `Supporting Stories` when multiple stories contribute structural, production, or validation slices
- the primary owner is responsible for row status movement and `Last Reviewed`
- if the project intentionally excludes a dimension, the ledger must say why

### Decision 6. The ledger must link to evidence, not just claims

Why:

- architectural closure is not real if it cannot be traced to code, tests, or a detailed story
- the reports are analytical, but story completion and closure must be evidence-backed

Consequence:

- each row should carry links to:
  - owner story docs
  - implemented code paths or modules when landed
  - tests or validation harness scenarios when available
- docs alone are never enough evidence for `Structurally Landed`, `Production Landed`, or `Validated Closed`

### Decision 7. Capability and architecture reports must cross-check, not duplicate each other

Why:

- `architectural_parity_report.md` is runtime-first
- `parity_report.md` is capability-first
- both should stay aligned without collapsing into one giant document

Consequence:

- the ledger should include a `Capability Cross-Check` field or notes column
- capability families without an architecture row should be questioned
- architecture rows with no capability impact should still explain why they matter for future porting

---

## Target Artifact Structure

Story 12B should establish this permanent artifact layout:

```text
agents/outputs/
  architectural_parity_epic.md
  architectural_parity_report.md
  parity_report.md
  architectural_gap_ledger.md
  architectural_gap_refresh_checklist.md
  architectural_parity_story_*.md
```

Roles:

- `architectural_parity_epic.md`
  - summary matrix
  - story ownership and order
- `architectural_parity_report.md`
  - runtime-first analysis of current parity state
- `parity_report.md`
  - capability-first parity analysis
- `architectural_gap_ledger.md`
  - authoritative detailed gap ledger with row ownership, status, evidence, and closure notes
- `architectural_gap_refresh_checklist.md`
  - update discipline and audit checklist used whenever the epic or parity reports change materially

This separation is intentional:

- epic for strategy
- reports for analysis
- ledger for auditability
- checklist for operational discipline

---

## Exact File Homes And Ownership

Story 12B should use these file homes:

- `agents/outputs/architectural_gap_ledger.md`
  - authoritative row-by-row architecture gap ledger
- `agents/outputs/architectural_gap_refresh_checklist.md`
  - required update checklist for epic/report/story refreshes

Expected existing integration points:

- `agents/outputs/architectural_parity_epic.md`
  - keeps the compact matrix and links to the ledger
- `agents/outputs/architectural_parity_report.md`
  - remains the source for tracked architecture dimension families and rationale
- `agents/outputs/parity_report.md`
  - remains the capability cross-check source
- `agents/outputs/architectural_parity_story_*.md`
  - remain the implementation contracts for owning stories

No new code module under `src/` is required for Story 12B.

---

## Required Ledger Rows

At minimum, the ledger must maintain architecture rows for these SDK-shaped audit units:

1. Core runtime ownership
2. Public-folder runtime separation
3. Request orchestration
4. Persistence runtime SPI
5. Production persistence backend
6. Tree/cache coherency
7. SC/AP lifecycle
8. Transfer runtime
9. Filesystem/watch abstraction
10. Platform/runtime layering
11. Public event subsystem
12. Public adapter/callback staging
13. Query/index substrate
14. Secondary durable state domains
15. Sync subsystem
16. Scheduled backup/copy
17. Mount/FUSE subsystem
18. Side-service pipeline homes

These are audit rows, not necessarily one-to-one with the higher-level dimension families in `architectural_parity_report.md`. A single report dimension may expand into multiple ledger rows when the SDK separates structural seams that need distinct owner stories or closure states.

Two tracks must stay explicit, but they are not ledger rows:

19. Validation harness
20. Gap-ledger / audit discipline itself

If the architecture report later adds another first-class dimension family, the ledger must add or remap the affected row set in the same refresh.

---

## Required Ledger Columns

Each ledger row should carry at least these fields:

- `Dimension Family`
- `Ledger Row`
- `SDK Reference Shape`
- `Rust Target Shape`
- `Why This Matters`
- `Primary Owning Story`
- `Supporting Stories`
- `Current Status`
- `Work Class`
  - one of:
    - `Structural Slice`
    - `Production Slice`
    - `Validation Slice`
    - `Scope Decision`
    - `None`
- `Closure Criteria`
- `Evidence Links`
- `Capability Cross-Check`
- `Out-Of-Scope Rationale`
- `Last Reviewed`

`Work Class` is intentionally not another status field. It describes the dominant slice the row represents or still requires. It must not restate closure level.

These columns are intentionally operational. They are what make the ledger auditable instead of decorative.

---

## Dependency Rules

The ledger should obey these rules:

1. `architectural_parity_report.md` defines the tracked architecture dimension families.
   - if a dimension family is added or materially reworded there, the ledger family mapping must be updated in the same change

2. `architectural_parity_epic.md` defines owner stories, ordering, and any approved row splits.
   - if a new story is added for gap coverage, or a family is split into finer rows, the relevant ledger rows must be updated in the same change

3. detailed story specs define implementation contracts.
   - a ledger row must not claim closure without a primary owner story or explicit out-of-scope rationale
   - a supporting story may add evidence, but row closure still belongs to the current primary owner until the ledger explicitly hands ownership forward

4. Story 12 defines executable validation.
   - a row should not move to `Validated Closed` without landed code/tests plus either Story 12 evidence or equivalent row-level story-specific validation evidence

5. Story 12B defines audit discipline.
   - parity claims require the ledger and refresh checklist to be current, but Story 12B is not itself a ledger row

6. `parity_report.md` provides capability cross-checking.
   - if a capability family is materially affected by a row, the ledger should note that relationship

7. code and tests remain authoritative.
   - the ledger may summarize status, but it must never override implemented behavior or test results

---

## Update Discipline

Story 12B must define and enforce this refresh discipline:

### Rule 1. No new architecture dimension family without a ledger mapping

If `architectural_parity_report.md` gains a new dimension family:

- add or update the ledger row set in the same change
- assign an owner story or explicit out-of-scope rationale

### Rule 2. No new ledger row without family mapping and a primary owner

If the epic or a story spec introduces a new architecture row:

- map it back to exactly one dimension family
- assign exactly one primary owner story
- optionally list supporting stories

### Rule 3. No new owner story without row mapping

If `architectural_parity_epic.md` gains a new story:

- update the ledger rows that story owns
- if ownership is split across slices, update primary and supporting ownership explicitly
- note whether the story is primarily a:
  - structural slice
  - production slice
  - validation slice
  - scope decision

### Rule 4. No story completion claim without row review

When a story is marked complete:

- review every row where it is primary or supporting owner
- update closure state
- update `Work Class`
- attach evidence links
- explicitly hand off primary ownership if the next mandatory slice belongs to a later story
- explicitly note whether further production or validation stories still keep the row only partially closed

### Rule 5. No report refresh without epic/ledger cross-check

When either parity report is refreshed:

- compare dimension families, ledger rows, and capability families against each other
- confirm no architecture row is missing
- confirm no out-of-scope rationale has silently changed

### Rule 6. No “full parity” language without row and gate audit

Any claim approaching “architectural parity” must first confirm:

- every architecture row is either `Validated Closed` or `Out Of Scope`
- every `Out Of Scope` row has a documented rationale
- Story 12 and Story 12B gating tracks are complete and current
- the reports, epic, and ledger agree

This is the specific rule designed to catch future omissions like the persistence-backend gap.

---

## Recommended Closure Semantics

Story 12B should standardize status meaning as follows:

- `Unowned`
  - no primary story or rationale exists; this is a planning defect
- `Planned`
  - owner story exists, no implementation landed yet
- `In Progress`
  - implementation has started but does not yet satisfy story acceptance criteria
- `Structurally Landed`
  - the architectural seam or subsystem home exists, but production behavior or broader validation is still pending
  - `Work Class` must be `Production Slice` or `Validation Slice`
- `Production Landed`
  - production-grade behavior exists, but the row still lacks complete validation coverage
  - `Work Class` must be `Validation Slice`
- `Validated Closed`
  - implementation, hardening, and validation all exist
  - `Work Class` must be `None`
- `Out Of Scope`
  - intentionally excluded, with rationale
  - `Work Class` must be `Scope Decision`

Minimum evidence by status:

- `Planned`
  - owner story link is sufficient
- `In Progress`
  - owner story plus any landed code/test links already present
- `Structurally Landed`
  - owner story plus concrete Rust code/module links proving the seam or subsystem home exists
- `Production Landed`
  - structural evidence plus tests or restart/real-backend evidence proving production behavior for that row
- `Validated Closed`
  - production evidence plus Story 12 coverage or equivalent row-level validation evidence that exercises the landed runtime path
- `Out Of Scope`
  - explicit rationale and scope decision link

Docs-only evidence is never sufficient for `Structurally Landed`, `Production Landed`, or `Validated Closed`.

This status model is intentionally stricter than “done / not done.” It is what keeps partial closure honest.

---

## Deliverables

Story 12B should produce:

1. `agents/outputs/architectural_gap_ledger.md`
   - populated with the required rows and columns

2. `agents/outputs/architectural_gap_refresh_checklist.md`
   - explicit update checklist used whenever epic/report/story scope changes

3. updates to the summary matrix in `agents/outputs/architectural_parity_epic.md`
   - only as needed to keep the epic in sync with the ledger

4. cross-links from:
   - `architectural_parity_epic.md`
   - `architectural_parity_report.md`
   - `parity_report.md`
   - owner story docs where helpful

The deliverables are lightweight documents, but they must be precise enough to drive engineering decisions.

---

## Agent-Sized Tasks

### Task 12B.1. Create the authoritative ledger artifact

Add `agents/outputs/architectural_gap_ledger.md` and populate the initial architecture rows.

Deliverables:

- initial row set
- row schema
- owner story mapping

### Task 12B.2. Add the refresh checklist

Add `agents/outputs/architectural_gap_refresh_checklist.md`.

Deliverables:

- required update rules
- audit steps for epic/report/story refreshes

### Task 12B.3. Cross-map reports and epic

Tie the ledger rows back to:

- the architectural parity report
- the capability parity report
- the epic summary matrix

Deliverables:

- cross-links
- explicit handling for rows that are intentionally out of scope

### Task 12B.4. Add closure and evidence discipline

Standardize row statuses, closure criteria, and evidence requirements.

Deliverables:

- row status definitions
- evidence-link rules
- partial-vs-full closure guidance

### Task 12B.5. Backfill the current epic state

Use the existing story set to populate current status honestly.

Deliverables:

- row statuses reflecting current reality
- explicit notation where stories such as 4, 4B, and 4C split one dimension across structural, production, and validation slices

---

## Acceptance Criteria

Story 12B is complete when:

- the project has a dedicated architecture-gap ledger artifact
- every architecture dimension family tracked by `architectural_parity_report.md` maps to one or more ledger rows
- every row has:
  - a dimension family mapping
  - a primary owner story
  - an explicit status
  - an explicit `Work Class`
  - closure criteria
  - evidence, or a clear note that evidence is pending for non-landed rows
  - an out-of-scope rationale if applicable
- the epic can be audited for coverage without rereading every story spec in full
- the public-folder runtime split is tracked explicitly as its own architecture row
- Story 12 and Story 12B remain explicit gating tracks outside the row set
- the reports, epic, and ledger can be refreshed together without silent omission of major dimensions
- the update discipline explicitly prevents a repeat of the persistence-backend omission class of error

---

## Verification

Because Story 12B is documentation-only, Rust verification commands are not required unless another implementation slice touches Rust code.

Story-specific verification should include:

- a family-to-row comparison between `architectural_parity_report.md` and `architectural_gap_ledger.md`
- a check that every story named in the epic summary matrix appears in at least one relevant ledger row
- a check that no row is left `Unowned` unless that is the explicit defect to be fixed next
- a check that every `Validated Closed` row has code/test evidence plus Story 12 or equivalent row-level validation evidence
- a check that Story 12 and Story 12B gating tracks are current even though they are not ledger rows
- a check that capability families in `parity_report.md` do not reveal an untracked architecture dimension

Recommended audit commands after implementation:

```bash
rg -n "^\\| " agents/outputs/architectural_gap_ledger.md
rg -n "Parity Dimensions To Track Explicitly|Capability Families To Track Explicitly" agents/outputs/architectural_parity_report.md agents/outputs/parity_report.md
rg -n "Story 12B|Architecture Gap Coverage Matrix" agents/outputs/architectural_parity_epic.md
```

---

## How Later Stories Consume This Story

Later stories should use Story 12B in these ways:

- when a new detailed story spec is written, the relevant ledger rows must be checked and updated
- when a story claims completion, its owned rows must be reviewed before the closure claim is accepted
- when a parity report is refreshed, the ledger is the audit layer that proves no tracked dimension was silently dropped
- when scope is intentionally narrowed, the ledger is where the explicit out-of-scope rationale lives

In practice:

- Story 6 and 6B should update event and adapter rows
- Story 7 and 7B should update filesystem/watch and platform rows
- Story 8 and 8B should update query/index and secondary state rows
- Stories 9, 10, and 11 should update sync, backup, and mount rows
- Story 12 should add executable evidence links that allow rows to move toward `Validated Closed`

---

## Non-Goals And Explicit Deferrals

Story 12B does not attempt to:

- replace Story 12’s executable parity harness
- generate truth automatically from code graphs
- track every individual API method
- act as a release checklist
- act as a generic roadmap tracker for unrelated work

Its job is narrower and more architectural:

- keep the parity plan honest
- keep architecture dimensions explicit
- make omissions visible early

---

## Completion Notes

When this story is complete, the epic should be able to claim:

- architectural parity planning is self-auditing rather than memory-driven
- every major SDK architectural dimension is either owned or explicitly excluded
- partial closure versus full closure is visible
- governance gates are explicit without being confused for architecture rows
- future report refreshes and epic expansions have a mandatory audit path

That is the correct notion of parity for Story 12B. It is not runtime parity itself. It is the discipline layer that keeps the runtime-parity plan complete and trustworthy.
