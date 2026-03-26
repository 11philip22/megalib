# Story 12 Spec: Add Parity Validation Harness

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 12 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Unlike the feature-bearing stories before it, this story is about measurement infrastructure. Its job is to establish a stable validation harness that can prove architectural parity work with executable evidence instead of relying on manual report updates and scattered inline tests.

Story type:

- Infrastructure story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_report.md`
- `agents/outputs/parity_report.md`

---

## Status

Not started.

Current validation status on 2026-03-26:

- the Rust crate has no dedicated `tests/` integration harness yet
- most Rust verification currently lives in inline `#[cfg(test)]` modules under `src/`
- those inline tests are valuable for local correctness, but they do not form a reusable parity-measurement substrate
- the crate has example programs under `examples/`, but they are manual probes rather than structured parity scenarios
- there is no benchmark or soak lane in the current Rust repository
- the architectural and capability parity reports are still hand-maintained and not tied to executable scenario IDs

Upstream SDK validation is structurally different:

- `../sdk/tests/CMakeLists.txt` separates common test tooling from the integration and unit suites
- `../sdk/tests/integration/CMakeLists.txt` assembles a large integration target with shared utilities, listener mocks, scenario files, and fixture data
- `../sdk/tests/integration/SdkTest_test.cpp` and companion files show the SDK already treats login, fetch-nodes, persistence restart, alerts, sync, and backup lifecycles as executable scenario families

This means `megalib` currently has useful regression coverage, but no architectural parity harness.

---

## Story Goal

Establish a stable parity validation harness that:

- gives architectural stories executable scenario coverage instead of only narrative claims
- compares `megalib` behavior against the upstream SDK through a normalized reference-oracle model where practical
- distinguishes parity assertions, regression assertions, and performance or soak assertions
- provides named scenario families for:
  - login and session restore
  - fetch-nodes and tree restore
  - SC or action-packet catch-up
  - transfer resume and transfer recovery
  - public event delivery
  - sync restart and backup recovery
  - mount lifecycle and filesystem-visible behavior where those features exist

The harness should be SDK-informed, Rust-idiomatic, and additive. It should not turn the repository into a direct clone of the SDK’s test layout, but it should create a similarly explicit architectural home for parity measurement.

---

## Why This Story Exists

The current parity reports identify architectural gaps, but they are still validated mostly by reading code and manually summarizing what exists. That is not enough once the crate starts accumulating multiple runtime layers:

- request runtime
- persistence runtime
- tree-cache coherency
- production persistence backend
- transfer runtime
- public event runtime
- filesystem and query layers
- sync, backup, and mount subsystems

Without a stable validation harness:

- “parity achieved” remains subjective
- architectural regressions can hide behind green unit tests
- report updates can drift away from executable evidence
- later feature work has no standard place to add cross-runtime scenarios

The upstream SDK already treats end-to-end scenarios as first-class infrastructure:

- shared test tooling in `../sdk/tests/CMakeLists.txt`
- shared account and fixture handling in `../sdk/tests/integration/`
- async listener synchronization helpers in `../sdk/tests/integration/mock_listeners.h`
- restart and persistence scenarios in files such as `../sdk/tests/integration/sdk_test_user_alerts.cpp`
- sync and backup lifecycle scenarios in `../sdk/tests/integration/Sync_test.cpp` and `../sdk/tests/integration/backup_sync_operations_test.cpp`
- filesystem-visible comparison tooling in `../sdk/tests/tool/compare_ops_in_two_folders.sh`

Story 12 is the Rust equivalent of that measurement substrate.

---

## Scope

In scope:

- add a dedicated parity harness under `tests/`
- define shared Rust harness support for:
  - accounts and environment configuration
  - temporary workspaces and local fixtures
  - normalized observations and assertions
  - optional upstream-SDK oracle adapters
  - scenario classification and execution lanes
- define scenario families and module homes for core, persistence, transfers, events, sync, backup, and mount parity checks
- add a small performance and soak lane architecture for startup, cache restore, and transfer behavior
- tie scenario coverage back to the parity reports and Story 12B audit discipline

Out of scope:

- porting every SDK integration test
- building a full MEGA SDK test runner inside `megalib`
- making performance benchmarks gating in the default test lane
- implementing every scenario category in one slice
- broad test-only production API redesign
- replacing existing inline unit tests in `src/`

Story 12 is a harness-architecture story. It creates the substrate that later stories and later parity refreshes can consume.

---

## Story 1 And Existing Story Constraints

Story 12 must preserve these existing architectural decisions:

- `Session` remains the engine root
- the major runtime seams already established by Stories 2 through 6 remain the things being measured, not redefined
- production persistence comes from the Story 3 plus 4B runtime and backend architecture
- public event behavior comes from Story 6 and later Story 6B, not from ad hoc test callbacks
- sync, backup, and mount scenarios only become active once Stories 9, 10, and 11 land

Validation harness code must observe and measure the architecture; it must not become a second owner of runtime behavior.

---

## Current Rust Validation State

The current Rust repository has three relevant characteristics:

1. Most tests are inline `#[cfg(test)]` modules in `src/`
- examples: `src/session/core.rs`, `src/session/actor.rs`, `src/session/runtime/persistence.rs`, `src/fs/operations/tree.rs`, and `src/fs/operations/upload.rs`
- this is good for focused invariants, but weak for cross-module parity scenarios

2. There is no dedicated integration harness tree yet
- there is currently no `tests/` directory
- that means public API flows are not grouped into reusable scenario families

3. There are many examples already
- `examples/login.rs`
- `examples/cached_session.rs`
- `examples/upload_resume.rs`
- `examples/download_resume.rs`
- `examples/share.rs`
- `examples/sequence.rs`
- and others

Those examples are useful probes and fixture ideas, but they are not a parity harness by themselves.

The Story 12 design should respect those facts:

- keep inline tests for local invariants
- add a real `tests/` harness for public and cross-runtime scenarios
- use examples only as optional fixture inspiration or manual diagnostics, not as the primary parity substrate

---

## SDK Parity Target

Story 12 should align with the upstream SDK in these ways:

1. Validation has a dedicated home rather than being scattered across runtime code.
2. Shared scenario utilities are separated from scenario files.
3. Async request, event, and lifecycle scenarios have reusable waiting and normalization helpers.
4. Restart, persistence, and sync-style scenarios are treated as first-class validations, not one-off debugging aids.
5. Mount and filesystem-visible behavior can be checked through scenario-driven comparisons, not just API return values.

Story 12 should not attempt these upstream behaviors in one step:

- full gtest-style breadth
- every upstream integration scenario
- a complete clone of the SDK’s test infrastructure layout

The Rust harness should be smaller and more idiomatic, but just as explicit in structure.

---

## Target Harness Architecture

The parity harness should converge on four layers.

### Layer 1. Shared harness support

Owns:

- account and environment setup
- temp directories and fixture files
- scenario IDs and scenario metadata
- normalized result capture
- oracle adapters
- assertion classification
- performance timing helpers

### Layer 2. Scenario-family tests

Owns:

- login and session restore scenarios
- fetch-nodes and tree restore scenarios
- SC/AP catch-up scenarios
- transfer resume and recovery scenarios
- public event delivery scenarios
- sync and backup restart scenarios
- mount lifecycle and filesystem-visible scenarios

### Layer 3. Oracle and normalization adapters

Owns:

- normalization of `megalib` observations into stable parity shapes
- optional normalization of upstream SDK observations into the same shapes
- comparison rules that avoid comparing internal implementation noise

### Layer 4. Performance and soak lanes

Owns:

- opt-in timing baselines
- longer-running or resource-heavy durability scenarios
- non-default execution policy

The architectural rule is simple:

- inline tests remain for local invariants
- the new harness owns cross-runtime parity measurement

---

## Exact Module Homes

Story 12 should create and use these homes.

### Shared test support

- `tests/common/mod.rs`
- `tests/common/accounts.rs`
- `tests/common/fixtures.rs`
- `tests/common/scenario.rs`
- `tests/common/oracle.rs`
- `tests/common/normalize.rs`
- `tests/common/assertions.rs`
- `tests/common/perf.rs`

### Scenario suites

- `tests/parity_core.rs`
- `tests/parity_persistence.rs`
- `tests/parity_transfers.rs`
- `tests/parity_events.rs`
- `tests/parity_sync.rs`
- `tests/parity_mount.rs`
- `tests/parity_perf.rs`
- `tests/parity_soak.rs`

### Optional test fixtures

- `tests/fixtures/data/`
- `tests/fixtures/oracles/`

### Documentation and report tie-in

- `agents/outputs/architectural_parity_report.md`
- `agents/outputs/parity_report.md`
- later Story 12B audit notes

These exact homes matter because the repository currently has no dedicated integration-harness architecture at all.

---

## Execution Lanes And Account Policy

Story 12 should define explicit harness lanes rather than letting each test invent its own execution policy.

### Lane 1. Default lane

Purpose:

- runs under the normal repository verification command
- remains practical for local development and CI

Rules:

- default-lane scenarios must be hermetic Rust regressions or frozen-oracle parity checks
- default-lane scenarios must not require live MEGA credentials
- default-lane scenarios must not implicitly shell out to the sibling SDK tree

### Lane 2. Live-account parity lane

Purpose:

- runs real-account parity scenarios against MEGA using the Rust crate only

Rules:

- this lane is opt-in, not part of the default `cargo test --all` path
- `tests/common/accounts.rs` should model fixed SDK-style account slots rather than ad hoc env lookup
- the initial slot names should match the upstream SDK integration harness:
  - primary account: `MEGA_EMAIL` and `MEGA_PWD`
  - auxiliary account: `MEGA_EMAIL_AUX` and `MEGA_PWD_AUX`
  - second auxiliary account: `MEGA_EMAIL_AUX2` and `MEGA_PWD_AUX2`
- if a live-account scenario is explicitly invoked and its required account vars are absent, it should fail early with a message naming the missing variables
- missing credentials must not make the default lane flaky because the live-account lane is already opt-in

### Lane 3. Direct SDK-oracle lane

Purpose:

- runs Rust scenarios alongside an explicit upstream-SDK oracle adapter

Rules:

- this lane is opt-in and separate from the default lane
- it should be enabled only when an explicit adapter executable or command path is configured
- the harness must not try to build or discover `../sdk` implicitly during ordinary `cargo test`
- if no adapter is configured, the direct-oracle lane remains unavailable rather than silently downgrading to a different oracle mode

### Lane 4. Performance and soak lanes

Purpose:

- hosts ignored or explicitly requested timing and long-running durability checks

Rules:

- these remain non-default
- they should use the same scenario metadata and normalization model as parity tests where practical
- they should never become accidental default-lane work through broad test discovery

Rust-idiomatic execution policy:

- prefer `#[ignore]` plus explicit harness helpers for opt-in lanes
- only use compile-time `#[cfg(feature = "...")]` gating when the corresponding production feature already exists in the crate
- Story 12 should not invent fake Cargo features solely to hide placeholder suites

---

## Scenario Metadata And Stable IDs

Story 12 should not rely on Rust function names alone for durable evidence tracking.

The upstream SDK uses the current suite and test name for logging and file-prefix stability. Rust should keep the same spirit while making scenario identity explicit and stable across refactors.

`tests/common/scenario.rs` should own a small metadata model such as:

- stable `ScenarioId`
- scenario family
- assertion class
- execution lane
- oracle source
- owning story or stories
- optional coverage notes for report or ledger traceability

Rules:

- every executable parity or regression scenario must declare exactly one stable `ScenarioId`
- scenario IDs must be explicit metadata constants, not derived from the Rust test function name at runtime
- reports and Story 12B evidence links should cite the `ScenarioId`, while the Rust test function name remains a diagnostic detail
- a report may cite a scenario family only when several concrete scenario IDs together provide the evidence

Recommended ID shape:

- lowercase, dot-separated, family-first identifiers such as:
  - `core.login.fast_restore`
  - `persistence.tree.restore_roundtrip`
  - `transfers.upload.resume_after_restart`
  - `events.request.lifecycle_basic`

This keeps the IDs readable, stable, and easy to map into report tables or frozen-oracle file names.

---

## Dependency Rules

The validation harness should obey these dependency directions.

### Harness support rules

- `tests/common/*` may depend on public crate APIs, environment configuration, temp-file helpers, and normalization code.
- `tests/common/*` must not depend on private crate internals by default.
- if a scenario truly cannot be expressed through the public API, the escape hatch should be narrow and story-specific rather than a broad permanent test backdoor.

### Scenario rules

- `tests/parity_core.rs` owns bootstrap and steady-state API scenarios whose primary assertion is not restart durability.
- `tests/parity_persistence.rs` owns scenarios whose primary assertion is restore, backend fallback, or restart semantics across a new `Session` or reopened durable store.
- `tests/parity_transfers.rs` owns transfer-runtime behavior within a live session such as resume, cancel, progress, and non-restart recovery.
- if a scenario's primary claim is durable restart of transfer state, it belongs in `tests/parity_persistence.rs`, not `tests/parity_transfers.rs`.
- `tests/parity_events.rs` owns outward event-surface assertions; if a scenario's primary claim is event shape or ordering, it belongs there even if transfers or alerts are involved.
- alert and state restore after restart belong in `tests/parity_persistence.rs`; alert or account-update delivery shape belongs in `tests/parity_events.rs`.
- `tests/parity_sync.rs` and `tests/parity_mount.rs` must exist as compile-safe homes from day one, but they may remain ignored placeholders until their owning subsystems land.
- `tests/parity_perf.rs` and `tests/parity_soak.rs` must also exist as compile-safe homes and remain opt-in.

### Performance rules

- performance and soak scenarios must not fail the default `cargo test --all` lane by default
- they should be opt-in through `#[ignore]`, environment variables, or both
- Story 12 should not introduce a heavy benchmark framework unless the repository actually needs one later

### Oracle rules

- parity comparisons should use normalized observations, not raw internal structs or logs
- the upstream SDK reference path should be optional and explicit
- when a direct SDK oracle is unavailable, the scenario should declare whether it is still a parity assertion, a Rust-side regression assertion, or a performance or soak assertion
- direct SDK-oracle execution should use an explicit adapter contract in `tests/common/oracle.rs`, not ad hoc shell-outs embedded in scenario files
- frozen oracles must be checked-in artifacts under `tests/fixtures/oracles/`; ordinary test runs must never rewrite them
- frozen-oracle refresh should happen only in an explicit oracle-refresh workflow that records the source SDK scenario or upstream reference file used to validate the payload

---

## SDK References

Story 12 should not treat `../sdk/tests/integration/SdkTest_test.cpp` as the only C++ oracle. The upstream harness is split across build wiring, reusable helpers, and scenario families. Use the following references by role.

- Harness assembly and shared test substrate:
  - `../sdk/tests/CMakeLists.txt:6`
    - defines the shared `test_tools` and `test_common` split that separates reusable test support from concrete suites
  - `../sdk/tests/integration/CMakeLists.txt:1`
    - shows the actual integration-target composition, including which files are treated as common harness pieces versus scenario families
  - `../sdk/tests/integration/common/common.cmake:1`
    - shows the SDK also has a second shared test substrate for model-based and real-client helpers, not only one giant fixture file
- Account-slot, login, and session bootstrap substrate:
  - `../sdk/tests/integration/env_var_accounts.h:6`
  - `../sdk/tests/integration/env_var_accounts.cpp:17`
    - authoritative source for how the SDK maps account slots to `MEGA_EMAIL`, `MEGA_EMAIL_AUX`, and `MEGA_EMAIL_AUX2`
  - `../sdk/tests/integration/SdkTest_test.h:49`
    - documents account cleanliness assumptions and the default timeout and polling contract used across the integration harness
  - `../sdk/tests/integration/SdkTest_test.cpp:1434`
  - `../sdk/tests/integration/SdkTest_test.cpp:1441`
  - `../sdk/tests/integration/SdkTest_test.cpp:1469`
  - `../sdk/tests/integration/SdkTest_test.cpp:1480`
  - `../sdk/tests/integration/SdkTest_test.cpp:2086`
    - core login, fetch-nodes, dump-session, resume-session, and wait-loop helpers that many scenario files build on
- Async listener, request, and transfer capture helpers:
  - `../sdk/tests/integration/SdkTest_test.h:67`
  - `../sdk/tests/integration/SdkTest_test.h:217`
    - reusable sync-listener and transfer-tracker helpers used by the classic MegaApi-facing integration suite
  - `../sdk/tests/integration/integration_test_utils.h:28`
  - `../sdk/tests/integration/integration_test_utils.cpp:20`
  - `../sdk/tests/integration/integration_test_utils.cpp:84`
  - `../sdk/tests/integration/integration_test_utils.cpp:141`
    - canonical SDK helpers for waiting on sync state and for driving sync or backup lifecycle requests through a normalized helper layer
  - `../sdk/tests/integration/mock_listeners.h:17`
  - `../sdk/tests/integration/mock_listeners.h:69`
  - `../sdk/tests/integration/mock_listeners.h:218`
    - promise-backed synchronization and capture helpers that are closer to the Rust harness shape than the older raw bool-flag polling helpers
- MegaApi-facing scenario oracles:
  - `../sdk/tests/integration/sdk_test_user_alerts.cpp:32`
    - direct reference for alert persistence, local logout plus fast-login restart, and post-restart fetch-nodes validation
  - `../sdk/tests/integration/SdkTest_test.cpp:19335`
    - resume-session-in-folder-link-deleted scenario for login plus fetch-nodes restart behavior under invalidated session context
  - `../sdk/tests/integration/SdkTest_test.cpp:22155`
    - public-folder login plus repeated fetch-nodes coverage for folder-link session flows
  - `../sdk/tests/integration/SdkTest_test.cpp:22752`
    - strongest single MegaApi-facing reference for transfer recovery across local logout, fast login, and post-reconnect action-packet catch-up
- Internal sync and backup model oracles:
  - `../sdk/tests/integration/Sync_test.cpp:1205`
    - reusable client-pool and account-slot provisioning for the model-driven sync harness
  - `../sdk/tests/integration/Sync_test.cpp:1575`
  - `../sdk/tests/integration/Sync_test.cpp:1651`
    - callback-side sync-restored and user-alert capture points used by the sync harness
  - `../sdk/tests/integration/Sync_test.cpp:2184`
  - `../sdk/tests/integration/Sync_test.cpp:2232`
  - `../sdk/tests/integration/Sync_test.cpp:2746`
    - direct login-from-env, login-from-session, and fetch-nodes helpers for the lower-level engine-facing harness
  - `../sdk/tests/integration/Sync_test.cpp:3123`
  - `../sdk/tests/integration/Sync_test.cpp:3205`
  - `../sdk/tests/integration/Sync_test.cpp:3421`
  - `../sdk/tests/integration/Sync_test.cpp:3933`
  - `../sdk/tests/integration/Sync_test.cpp:4026`
    - backup and sync setup, config import or export, backup-id recovery, and three-way model confirmation against remote, local-node, and local-filesystem views
  - `../sdk/tests/integration/Sync_test.cpp:7580`
  - `../sdk/tests/integration/Sync_test.cpp:7656`
  - `../sdk/tests/integration/Sync_test.cpp:9352`
    - concrete restart, restore, and exported-config reimport scenarios that are especially relevant for later parity-harness frozen-oracle cases
  - `../sdk/tests/integration/backup_sync_operations_test.cpp:20`
  - `../sdk/tests/integration/backup_sync_operations_test.cpp:69`
  - `../sdk/tests/integration/backup_sync_operations_test.cpp:140`
    - deconfigured-backup archive and removal lifecycle coverage through the public API surface
  - `../sdk/tests/integration/DisableBackupSync_test.cpp:28`
  - `../sdk/tests/integration/DisableBackupSync_test.cpp:77`
  - `../sdk/tests/integration/DisableBackupSync_test.cpp:188`
    - disabled-backup resume semantics, including remove, modify, create, and rename local changes while the backup is disabled
- Filesystem-visible comparison oracle:
  - `../sdk/tests/tool/compare_ops_in_two_folders.sh:1`
    - concrete reference for "perform mirrored filesystem operations and diff the visible result", which is the right upstream inspiration for mount-visible parity rather than direct internal-struct comparison

Story 12 should use those files as oracle and harness-design evidence, not as a mandate to mirror the SDK test tree one-to-one.

---

## Reference Oracle Model

The harness should support three validation modes.

### Mode 1. Direct parity oracle

Best case.

- run the Rust scenario and the upstream SDK reference scenario against the same account and fixture setup
- normalize both observations into the same parity shape
- compare those normalized results
- execute this mode only in the explicit direct-oracle lane
- route all SDK interaction through a narrow adapter interface in `tests/common/oracle.rs`
- require explicit configuration of the adapter path or command before this mode can run

This is the closest equivalent to “the C++ SDK is the oracle.”

Likely sources for direct oracle inspiration:

- login, fetch-nodes, and session resume helpers:
  - `../sdk/tests/integration/SdkTest_test.cpp:1434`
  - `../sdk/tests/integration/SdkTest_test.cpp:1441`
  - `../sdk/tests/integration/SdkTest_test.cpp:1480`
- alert-persistence restart oracle:
  - `../sdk/tests/integration/sdk_test_user_alerts.cpp:32`
- transfer-recovery oracle:
  - `../sdk/tests/integration/SdkTest_test.cpp:22752`
- sync restore and model-confirmation oracle:
  - `../sdk/tests/integration/Sync_test.cpp:7580`
  - `../sdk/tests/integration/Sync_test.cpp:7656`
  - `../sdk/tests/integration/Sync_test.cpp:9352`
  - `../sdk/tests/integration/Sync_test.cpp:4026`
- backup disable, archive, and deconfigured-backup lifecycle oracle:
  - `../sdk/tests/integration/DisableBackupSync_test.cpp:28`
  - `../sdk/tests/integration/backup_sync_operations_test.cpp:69`

### Mode 2. Frozen parity oracle

Used when running the SDK directly is too heavy for the default lane.

- capture normalized expected observations derived from validated SDK behavior
- store them under `tests/fixtures/oracles/`
- compare Rust observations to the frozen normalized oracle
- name frozen-oracle files from the stable `ScenarioId`
- treat frozen oracles as source-controlled evidence, not test output cache files
- refresh them only through an explicit workflow, never during a normal `cargo test` run

This is acceptable only when the oracle payload is explicitly documented and traceable to an upstream SDK behavior or scenario.

### Mode 3. Regression-only assertion

Used when:

- the scenario is Rust-structural rather than cross-SDK comparable
- the upstream feature is not yet implemented in `megalib`
- the scenario is only checking a previously fixed bug or invariant

Regression-only scenarios are still useful, but they must not be mislabeled as parity proof.

---

## Normalization Contract

`tests/common/normalize.rs` should define the canonical parity shapes used by both Rust-side capture and optional SDK-oracle capture.

At minimum, the normalized model should converge on typed shapes for:

- session or bootstrap outcome
- tree or node snapshot
- persistence restore outcome
- transfer outcome
- public event record or event stream
- later sync, backup, and mount observations when those stories land

Normalization rules:

- normalize unordered collections before comparing them
- sort by stable semantic keys such as path, name, type, parent relation, or declared scenario-local identifier
- compare handles only when the scenario explicitly declares them stable and meaningful for the claim
- drop volatile implementation noise such as raw timestamps, row IDs, seqtags, listener addresses, or temporary local paths unless the scenario explicitly tests them
- treat transfer progress as milestones or terminal outcomes, not as exact byte-by-byte cadence across implementations
- compare cross-family event interleaving only when a scenario explicitly declares that ordering contract; otherwise compare per-family logical ordering and payload shape

Architectural rule:

- normalization is the place where SDK-vs-Rust differences are intentionally collapsed into stable parity language
- scenario files should assert on normalized data, not keep reimplementing one-off comparison logic

---

## Assertion Taxonomy

Story 12 must distinguish three classes of assertions.

### 1. Parity assertions

Purpose:

- prove that `megalib` behavior matches the upstream SDK or a frozen normalized oracle

Examples:

- login plus session restore normalization
- fetch-nodes result shape
- tree restore after restart
- SC/AP catch-up end state
- event delivery shape once Story 6 lands

Requirements:

- each parity scenario has a scenario ID
- each parity scenario declares its oracle source
- each parity scenario uses normalized comparisons

### 2. Regression assertions

Purpose:

- prevent Rust regressions in architecture work even where no direct SDK oracle is available

Examples:

- non-blocking event receiver lag behavior
- failed AP batch does not overwrite durable tree state
- persistence schema recycle behaves like empty durable state

Requirements:

- clearly marked as regression-only
- tied to a concrete runtime contract or bug class

### 3. Performance and soak assertions

Purpose:

- watch for catastrophic architectural regressions in startup, restore, and long-running flows

Examples:

- cold login plus fetch-nodes startup time
- cache restore time
- large upload or download resume time
- long-running sync or mount stability once those stories land

Requirements:

- non-default lane
- thresholds should be broad and regression-oriented, not micro-benchmark vanity numbers
- results should inform architecture decisions, not pretend to be product benchmarks

---

## Scenario Categories

The harness should grow by scenario family rather than by scattered one-off tests.

### Core scenarios

Live in:

- `tests/parity_core.rs`

Initial categories:

- login and fast session restore
- fetch-nodes/bootstrap
- path and node-tree expectations
- exports and share-facing core behaviors as those stories mature

### Persistence and restore scenarios

Live in:

- `tests/parity_persistence.rs`

Initial categories:

- cached session restart
- durable tree restore
- alert and state restore
- persistence fallback after malformed or recycled state

### Transfer scenarios

Live in:

- `tests/parity_transfers.rs`

Initial categories:

- resumable upload
- resumable download
- cancel and restart recovery
- durable checkpoint behavior after Story 5 lands

### Event scenarios

Live in:

- `tests/parity_events.rs`

Initial categories:

- transfer progress and public event coexistence
- request lifecycle events
- node/tree event delivery after refresh and AP batches
- alert/account event delivery

### Sync and backup scenarios

Live in:

- `tests/parity_sync.rs`

Initial categories:

- sync bootstrap
- sync restart recovery
- backup restart or archive recovery

These remain gated until Stories 9 and 10 land.

### Mount scenarios

Live in:

- `tests/parity_mount.rs`

Initial categories:

- mount startup and shutdown lifecycle
- browse/open/read semantics
- filesystem-visible comparison scenarios inspired by `../sdk/tests/tool/compare_ops_in_two_folders.sh`

These remain gated until Story 11 lands.

### Placeholder suite rule

For Story 12 itself, `tests/parity_events.rs`, `tests/parity_sync.rs`, `tests/parity_mount.rs`, `tests/parity_perf.rs`, and `tests/parity_soak.rs` should be real compile-safe files even when some families are not yet active.

Until their owning subsystem lands or the lane is intentionally enabled:

- the file may contain module documentation, shared imports, and ignored placeholder tests
- placeholder tests should name the owning story or activation condition explicitly
- placeholder suites must not force new production features or broaden the crate's public API

This matches the SDK's explicit test-home discipline without pretending every family is active on day one.

---

## Non-Goals

Story 12 must explicitly avoid these traps:

- becoming a second feature-delivery epic hidden inside test code
- forcing every scenario through a live upstream SDK run in the default lane
- baking Tokio- or actor-internal details into the public parity language
- treating all tests as parity tests
- adding heavyweight benchmark dependencies by default
- using examples as the primary validation mechanism

The story is about stable harness structure first, not maximal scenario count on day one.

---

## Deliverables

Story 12 should deliver the following.

1. A dedicated `tests/` harness architecture
- shared support modules
- scenario-family files
- fixture and oracle homes

2. A normalized oracle and assertion model
- scenario IDs
- parity vs regression vs performance classification
- normalized observations

3. Core scenario families
- login and session restore
- fetch-nodes and tree restore
- SC/AP catch-up
- transfer resume and recovery
- event delivery

4. Expansion hooks for later stories
- sync restart family
- backup recovery family
- mount lifecycle family

5. A minimal performance and soak lane architecture
- startup
- cache restore
- large transfer

6. Report traceability rules
- report claims can cite scenario IDs or scenario families
- Story 12B can audit coverage against executable scenarios

---

## Implementation Tasks

### Task 12.1. Create the shared harness substrate

Add:

- `tests/common/`
- scenario metadata and assertion classification
- account and fixture helpers
- normalization and oracle interfaces
- explicit lane helpers for default, live-account, direct-oracle, perf, and soak execution policy

Keep it public-API-first and lightweight.

### Task 12.2. Add core parity scenario suites

Add first scenario families for:

- login and saved-session restore
- fetch-nodes and tree restore
- SC/AP catch-up
- transfer resume

These are the core architectural flows already covered by Stories 2 through 5 and 4B or 4C.

For the initial Story 12 delivery:

- `tests/parity_core.rs`, `tests/parity_persistence.rs`, and `tests/parity_transfers.rs` are the first active suites
- each active scenario must declare metadata, lane, and oracle class from the start
- the default lane should prefer frozen-oracle or regression variants unless a scenario is fully hermetic

### Task 12.3. Add event and persistence parity suites

Add:

- event delivery scenarios once Story 6 or 6B lands
- persistence restart or fallback scenarios on the production backend

This is where Story 12 becomes a direct consumer of the runtime-hardening work.

If those subsystem stories are not yet implemented in the tree, Story 12 should still create the compile-safe suite homes and placeholder metadata rather than leaving the family location undefined.

### Task 12.4. Add performance and soak lanes

Add:

- ignored or opt-in startup timing checks
- cache restore timing checks
- larger transfer recovery checks

Do not make them default gating tests yet.

### Task 12.5. Add scenario-to-report traceability

Add documentation or metadata conventions so parity reports can say:

- which claims are backed by executable scenarios
- which claims remain manual or partial

This is the bridge to Story 12B.

---

## Minimum Story 12 Delivery

Story 12 is intentionally foundational. The minimum implementation that should count as Story 12 complete is:

1. shared harness support under `tests/common/` with stable scenario metadata, lane helpers, account-slot helpers, normalization shapes, and oracle interfaces
2. active scenario coverage in `tests/parity_core.rs`, `tests/parity_persistence.rs`, and `tests/parity_transfers.rs`
3. compile-safe placeholder homes for `tests/parity_events.rs`, `tests/parity_sync.rs`, `tests/parity_mount.rs`, `tests/parity_perf.rs`, and `tests/parity_soak.rs`
4. checked-in frozen-oracle support and report-traceability conventions from day one

Later stories expand the active scenario count inside those homes; they should not reinvent the harness shape.

---

## Acceptance Criteria

Story 12 is complete when all of the following are true:

1. The repository has a dedicated `tests/` parity harness with shared support modules and scenario-family files.
2. The harness distinguishes parity assertions, regression assertions, and performance or soak assertions explicitly, and every active scenario declares stable metadata including `ScenarioId`, lane, and oracle class.
3. The harness defines an explicit lane policy:
   - default lane is hermetic or frozen-oracle only
   - live-account parity is opt-in and uses SDK-style fixed account env vars
   - direct SDK-oracle execution is opt-in and requires explicit adapter configuration
   - performance and soak remain opt-in
4. Active scenario coverage exists for:
   - login or session restore
   - fetch-nodes or tree restore
   - SC/AP catch-up
   - transfer resume or recovery
   - at least one persistence restart or fallback scenario on the production backend
5. The harness has a normalized oracle model with canonical parity shapes and can compare Rust observations against upstream-SDK behavior or frozen normalized oracles.
6. Event, sync, backup, mount, perf, and soak scenario homes exist as compile-safe suites even if some remain gated or placeholder-only until their owning stories land.
7. Report authors and Story 12B can tie parity claims to executable `ScenarioId` values or explicitly named scenario families rather than only prose.
8. Default verification remains stable and Rust-idiomatic, while live-account, direct-oracle, performance, and soak checks remain opt-in.

---

## Verification Requirements

When Story 12 code is implemented, the slice must end with:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Additional harness lanes should be defined like this:

- default lane:
  - fast parity and regression scenarios
- opt-in parity-expansion lane:
  - environment-driven or heavier scenarios
- opt-in performance lane:
  - ignored timing checks
- opt-in soak lane:
  - longer-running durability scenarios

The exact commands may evolve, but the architectural rule should remain:

- default lane stays practical
- heavier architectural measurements are opt-in, not accidental

---

## How Later Stories Consume Story 12

Story 12 is not the last story in practice. It is a shared validation substrate that later work should plug into.

Later stories should consume it like this:

- Story 5 adds transfer-runtime scenarios and durable transfer recovery checks
- Story 6 and 6B add event-surface and callback-staging scenarios
- Story 7 and 8 add filesystem and query scenario families as those layers become real
- Story 8B adds secondary durable-state scenarios
- Story 9 and 10 activate sync and backup restart families
- Story 11 activates mount lifecycle and filesystem-visible comparison families
- Story 12B uses Story 12’s scenario IDs and coverage map to audit whether the epic truly closes each architectural gap

The key rule is:

- stories should add scenarios to the harness as they land
- no later story should invent a second ad hoc parity-validation structure

---

## Recommended First Implementation Slice

If Story 12 needs a small-slice starting point, begin here. This slice is also the intended minimum acceptance path for the story:

1. create `tests/common/`
2. add `tests/parity_core.rs`, `tests/parity_persistence.rs`, and `tests/parity_transfers.rs`
3. add normalized login/session, fetch-nodes/tree-restore, SC/AP, and transfer-resume scenarios
4. add one restart or persistence scenario on the production backend
5. add scenario metadata, lane classification, and frozen-oracle conventions from day one
6. add compile-safe placeholder files for events, sync, mount, perf, and soak families

That first slice is enough to prove the harness architecture and to start replacing report-only claims with executable evidence.
