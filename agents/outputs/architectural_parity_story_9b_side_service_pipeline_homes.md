# Story 9B Spec: Define Side-Service Pipeline Homes

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 9B from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. It is a code-bearing structural-alignment story: its job is to create explicit subsystem homes, lifecycle rules, and feature-gating patterns for non-core side-service pipelines, not to implement the full feature families themselves.

Story type:

- Implementation story / structural-alignment spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`
- `agents/outputs/architectural_parity_story_6b_public_adapter_callback_staging.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- the only concrete side-service-like family in Rust today is `src/preview.rs`
- `Session` still owns one loose `previews_enabled` flag in `src/session/core.rs`
- upload-time preview work is invoked directly from `src/fs/operations/upload.rs`
- the crate has no `src/services/` module and no side-service lifecycle owner
- there is no architectural home yet for media metadata, rich-preview metadata, or file-service-style local cache/runtime work
- the current `preview` feature gate is compile-time only and does not imply a runtime subsystem shape

That means `megalib` has a working preview helper, but it does not yet have SDK-shaped side-service/runtime breadth.

---

## Story Goal

Establish `src/services/` as the architectural home for non-core side-service pipelines and introduce a minimal runtime pattern that owns:

- service-family identity
- feature gating
- per-session lifecycle
- service-local configuration
- storage-root and platform-provider seams
- outward adapter integration points for service-originated events

Architecturally, that runtime should be owned once by `Session` for the life of the session, just as the SDK keeps `gfx` and `mFileService` under `MegaClient`, rather than being created ad hoc by uploads or top-level helper calls.

This story should make one existing family live through that structure:

- preview/thumbnail generation used by uploads

It should also reserve stable homes for later families without implementing them fully:

- media metadata / media file-attribute extraction
- file-service-style local file cache/runtime services
- rich-preview or similar metadata-fetch pipelines

This is the story that makes future side services land into known subsystem homes instead of re-shaping `Session`, `fs/operations/*`, or `lib.rs` again.

---

## Why This Story Exists

The upstream SDK already has broader side-service/runtime ownership than the current Rust crate:

- `MegaClient` owns a `GfxProc* gfx` graphics pipeline and an explicit `gfxdisabled` switch
- `MegaClient` also owns `file_service::FileService mFileService`
- media-property extraction is owned by `MediaFileInfo`, not by transfer helpers directly
- the file service has its own initialization, deinitialization, options, observers, and storage layout

Relevant upstream ground-truth references:

- owner fields and top-level toggles:
  - `../sdk/include/mega/megaclient.h:2008` for `GfxProc* gfx`
  - `../sdk/include/mega/megaclient.h:2011` for `bool gfxdisabled`
  - `../sdk/include/mega/megaclient.h:2330` for `MediaFileInfo mediaFileInfo`
  - `../sdk/include/mega/megaclient.h:3505` for `file_service::FileService mFileService`
  - `../sdk/src/megaclient.cpp:1990` for `MegaClient` construction wiring and default `gfxdisabled = false`
- preview/gfx provider seam and runtime behavior:
  - `../sdk/include/mega/gfx.h:97` for `IGfxProvider`
  - `../sdk/include/mega/gfx.h:160` for `GfxProc`
  - `../sdk/src/gfx.cpp:41` for `IGfxProvider::createInternalGfxProvider()`
  - `../sdk/src/gfx.cpp:52` for `GfxProc::isgfx(...)`
  - `../sdk/src/gfx.cpp:366` for `GfxProc::generateImages(...)`
  - `../sdk/src/gfx.cpp:410` for `GfxProc` construction and `../sdk/src/gfx.cpp:421` for teardown
  - `../sdk/src/megaapi_impl.cpp:87` for external-vs-internal gfx provider creation
  - `../sdk/src/megaapi_impl.cpp:12784` for public disable/enable plumbing through `gfxdisabled`
- media attribute ownership and upload integration:
  - `../sdk/include/mega/mediafileattribute.h:141` for `MediaFileInfo` upload/existing-file entry points
  - `../sdk/src/mediafileattribute.cpp:238` for queued upload attribute handling
  - `../sdk/src/mediafileattribute.cpp:258` for existing-file send-or-queue behavior
  - `../sdk/src/transfer.cpp:620` for transfer-side media extraction call-in
  - `../sdk/src/transfer.cpp:1035` for missing preview/thumbnail restoration checks
  - `../sdk/src/transfer.cpp:1241` for best-effort upload-time media attribute preparation
- file-service lifecycle, options, and storage roots:
  - `../sdk/include/mega/file_service/file_service.h:27` for the `FileService` owner surface
  - `../sdk/include/mega/file_service/file_service_options.h:15` for service-local options
  - `../sdk/src/file_service/file_service.cpp:21` for constructor shape
  - `../sdk/src/file_service/file_service.cpp:61` for `deinitialize()`
  - `../sdk/src/file_service/file_service.cpp:126` for `initialize(...)`
  - `../sdk/src/file_service/file_service.cpp:166` for `reclaim(...)`
  - `../sdk/src/file_service/file_service.cpp:188` for `storageUsed()`
  - `../sdk/src/file_service/file_storage.cpp:41` for storage rooted under `client.dbRootPath()` and `client.sessionID()`
  - `../sdk/src/commands.cpp:2037` for post-login/service initialization
  - `../sdk/src/megaclient.cpp:5053` for logout/deinitialize ordering

Current Rust architecture is much thinner:

- `src/preview.rs` is a standalone helper module behind `feature = "preview"`
- `src/fs/operations/upload.rs` calls `crate::preview::generate_thumbnail(path)` directly
- `SessionHandle::enable_previews(...)` toggles one flag on `Session`
- there is no side-service registry, no service lifecycle contract, and no service-local storage or provider seam

Without Story 9B, later feature families are likely to land in one of the wrong places:

- directly in transfer operation files
- as extra fields on `Session`
- as random top-level modules with no lifecycle owner
- as platform-specific code hidden inside otherwise generic helpers

Story 9B fixes that by creating the runtime skeleton first.

---

## Scope

In scope:

- introduce `src/services/` as the architectural root for side-service pipelines
- define a small runtime pattern for side-service lifecycle and feature gating
- define the build-time feature, runtime-config, and platform-capability contract for service availability
- define where side-service families integrate with:
  - `Session`
  - filesystem/runtime layers
  - platform/runtime layers
  - outward adapter/callback staging
- move the current preview family behind the new service home while preserving public compatibility
- define the preview-service ownership boundary relative to upload orchestration and node-attribute upload helpers
- define placeholder homes and contracts for later metadata and file-service families
- document which feature families remain intentionally deferred after the structural story lands
- add focused tests for:
  - service availability and feature gating
  - disabled-service behavior
  - per-session lifecycle ownership
  - compatibility of existing preview-facing public entry points

Out of scope:

- implementing the full SDK graphics pipeline
- implementing the full SDK file service
- implementing media-property extraction or rich-preview metadata fetching
- adding new major user-visible feature families in this story
- adding a new public service observer API in this story
- redesigning the public event model from Story 6
- redesigning platform layers from Story 7B
- redesigning transfer runtime beyond the integration seam needed to make preview a live consumer

This is a subsystem-home and lifecycle story, not a full media/file-service delivery story.

---

## Story 1, Story 6B, And Story 7B Constraints

Story 9B must preserve these existing decisions:

- side-service pipeline homes belong under `src/services/`
- `Session` remains the engine root
- `src/fs/operations/*` remain orchestration-first
- outward delivery semantics belong in the public adapter layer from Story 6B, not in service modules
- platform-sensitive provider code belongs under the platform/runtime layer from Story 7B, not inline in generic service code
- public API changes, if any, must be additive
- Story 9B should consume the service capability seam reserved by Story 7B rather than inventing a second platform-service capability API

Concretely:

- Story 9B should add one `Session`-owned side-service runtime handle
- Story 9B may move preview implementation behind `src/services/preview/`
- Story 9B must not turn `src/services/` into a second owner of engine state, request policy, or platform detection logic

If implementation pressure suggests placing preview, metadata, or file-service scaffolding back into `src/fs/operations/*`, Story 1 should be revised first rather than ignored.

---

## SDK Parity Target

The Rust side-service architecture should align with the SDK in these ways:

1. Side-service pipelines have explicit subsystem owners separate from the core request/tree/transfer runtime.
2. Optional service families can be enabled or disabled without changing core engine ownership.
3. Service-local storage and caches are not mixed into core engine-state persistence tables by accident.
4. Side-service lifecycles are explicit: initialize, use, update options, and shut down.
5. Service-originated events or observer callbacks have a clear path into the outward adapter layer instead of bypassing it.
6. Platform-specific worker/process implementations can be swapped or gated without re-shaping generic service logic.
7. Optional services expose explicit supported/unsupported/uninitialized-style status rather than implicit booleans.

Rust should stay idiomatic:

- do not clone the SDK's class count or nested service types line by line
- do not introduce a heavyweight service framework or trait-object maze
- do use a small explicit runtime owner with concrete service-family fields
- do prefer opt-in feature gates, explicit config, and graceful disabled-service behavior

---

## Current Gaps To Close

Story 9B is targeting these specific architectural gaps:

1. `src/preview.rs` is a free-standing helper, not a service runtime.
2. `src/fs/operations/upload.rs` knows too much about preview generation details.
3. `Session` stores preview enablement as a loose field rather than as side-service configuration.
4. There is no subsystem home for media metadata extraction analogous to `MediaFileInfo`.
5. There is no subsystem home for file-service-style local cache/runtime work analogous to `FileService`.
6. There is no agreed place for service-local storage roots, background workers, or observer integration.
7. Platform-sensitive service providers would currently have to live in generic modules.

---

## Design Decisions

### Decision 1. `src/services/` is the architectural root for side-service families

Why:

- Story 1 already reserved `src/services/` for this purpose
- side services are neither pure engine state nor pure filesystem runtime
- they should not remain scattered across top-level helper modules and operation files

Consequence:

- Story 9B should introduce `src/services/mod.rs`
- concrete families should live under `src/services/preview/`, `src/services/metadata/`, and `src/services/file_service/` or equivalent single-file homes beneath `src/services/`

### Decision 2. Use a small concrete runtime owner, not a generic plugin framework

Why:

- idiomatic Rust favors explicit ownership over highly dynamic service registries when the set of families is known
- the crate only needs a few named side-service families
- a plugin framework would add churn without parity value

Consequence:

- Story 9B should prefer a concrete `SideServicesRuntime` or similar owner with explicit family fields
- `Session` should own one long-lived `SideServicesRuntime` instance created during session construction for authenticated and public-link sessions alike
- families that need account-scoped storage may observe `account_handle: None` and stay unavailable in public-link contexts
- avoid trait-object registries unless a later story proves they are needed

### Decision 3. Build feature, runtime config, and platform/provider capability must combine into one explicit availability model

Why:

- current Rust has only a compile-time `preview` feature plus one loose runtime boolean
- the SDK uses explicit enable/disable and initialized/uninitialized behavior for side services rather than assuming availability from one boolean
- future metadata and file-service families will need exhaustive, testable disabled or unsupported behavior

Consequence:

- Story 9B should define one crate-owned availability/status model for service families, for example:
  - compiled out
  - disabled by runtime config
  - unsupported by platform/provider
  - ready
- the public `preview` module remains gated by the crate feature as a compatibility API
- the session-owned runtime should report service-family availability explicitly rather than inferring it from `cfg` plus loose booleans

### Decision 4. Preview is the first live consumer of the new side-service home

Why:

- preview generation already exists today
- moving one real family through the new structure keeps Story 9B grounded
- it gives later service families a concrete pattern to follow

Consequence:

- Story 9B should move preview implementation behind `src/services/preview/`
- the existing public `preview` module may remain as a compatibility facade or re-export
- `upload.rs` should stop depending on `crate::preview` as the architectural center
- the session-owned preview runtime should own media-type support checks, local preview-generation logic, provider selection, and failure normalization
- upload orchestration should remain the owner of whether generated preview data is attached to an upload and whether node-attribute upload is attempted, keeping transfer completion policy out of the service layer in the first slice

### Decision 5. Service-local storage is separate from core persistence runtime

Why:

- the SDK keeps account state cache and file-service storage distinct
- side-service caches may have different durability, reclaim, and corruption-handling needs
- mixing them into `PersistenceRuntime` by default would blur responsibilities

Consequence:

- Story 9B should define a separate service-storage root concept under the service runtime
- that root should be resolved once per session from the crate-owned platform path layer and namespaced per account when `account_handle` exists
- public-link or other account-less contexts may legitimately have no account-scoped service root
- future file-service-like caches may reuse the OS-specific account root family from Story 4B and Story 7B path discovery, but not the engine-state SQLite tables themselves

### Decision 6. Service families are optional and must degrade gracefully

Why:

- the SDK has explicit service switches such as `gfxdisabled`
- preview/media/file-service capabilities are not part of the minimum authenticated engine contract
- failing or unsupported services should not destabilize login, tree state, or transfer runtime

Consequence:

- Story 9B should require explicit feature availability and runtime-enabled/disabled state
- disabled or unavailable services should behave as clean no-ops or explicit capability errors, depending on the caller context
- upload/download should keep working when preview services are unavailable unless the user explicitly asked for service-dependent behavior
- preview generation during uploads should remain best-effort in the first slice: disabled, unsupported, or failed preview work must not fail the upload

### Decision 7. Platform providers live below services, not inside them

Why:

- Story 7B is intended to own OS-aware runtime layering
- SDK side services often rely on platform-specific providers or processes
- generic service modules should not become a hiding place for platform branches

Consequence:

- Story 9B should define provider seams for service families that need platform support
- Story 9B should consume `src/platform/services.rs` and `src/platform/paths.rs` style seams as the lower layer for provider capability and storage-root discovery
- concrete provider implementations should live under the Story 7B platform layer
- if Story 7B has not landed in code yet, Story 9B should introduce only the exact lower-layer call points and enums already reserved there rather than inventing a parallel shape

### Decision 8. Service-originated outward notifications flow through Story 6B

Why:

- observer/callback staging belongs in the outward adapter runtime
- side services should produce service events, not own their own public callback transport

Consequence:

- Story 9B may define internal service events or status updates
- outward observer/callback exposure should route through Story 6B patterns when those families become public
- the preview-first slice does not need to expose new outward events; preview failures may remain internal diagnostics and best-effort omission
- future service observer registrations should follow Story 6B cancellation and detachment rules rather than inventing a second lifecycle model

### Decision 9. Placeholder families must still be real runtime fields with explicit unsupported status

Why:

- empty modules alone do not actually reserve lifecycle or capability contracts
- the SDK file service is a real owner with initialize/deinitialize/options even before any given caller uses it
- later stories need concrete homes to extend, not just directories

Consequence:

- metadata and file-service placeholders should exist as concrete `SideServicesRuntime` fields or clearly owned family runtimes
- those placeholders may return explicit unsupported or disabled status everywhere in the first slice
- compile-safe placeholder behavior should mean construction, status inspection, and shutdown are all defined even when the feature family is not implemented

### Decision 10. Story 9B is structural, not a pretext for sneaking in full feature work

Why:

- the goal is to reserve correct subsystem homes
- broad feature implementation would make the slice too wide and blur acceptance criteria

Consequence:

- Story 9B should create scaffolding plus one live preview seam
- metadata, file-service, and other families stay implementation-deferred after their homes exist

---

## Recommended Rust Shape

The first implementation slice should aim for a small but real shape such as:

```rust
// src/services/mod.rs

pub(crate) mod runtime;
pub(crate) mod preview;
pub(crate) mod metadata;
pub(crate) mod file_service;

pub(crate) use runtime::{
    SideServiceConfig,
    SideServiceContext,
    SideServiceAvailability,
    SideServiceFeature,
    SideServiceStatus,
    SideServicesRuntime,
};
```

```rust
// src/services/runtime.rs

pub(crate) struct SideServicesRuntime {
    config: SideServiceConfig,
    preview: PreviewServiceRuntime,
    metadata: MetadataServiceRuntime,
    file_service: FileServiceRuntime,
}

pub(crate) struct SideServiceContext {
    pub(crate) account_handle: Option<String>,
    pub(crate) storage_root: Option<std::path::PathBuf>,
}

pub(crate) enum SideServiceAvailability {
    CompiledOut,
    Disabled,
    Unsupported,
    Ready,
}

pub(crate) struct SideServiceStatus {
    pub(crate) preview: SideServiceAvailability,
    pub(crate) metadata: SideServiceAvailability,
    pub(crate) file_service: SideServiceAvailability,
}

pub(crate) struct SideServiceConfig {
    pub(crate) preview_enabled: bool,
    pub(crate) metadata_enabled: bool,
    pub(crate) file_service_enabled: bool,
}

impl SideServicesRuntime {
    pub(crate) fn new(context: SideServiceContext, config: SideServiceConfig) -> Self;
    pub(crate) fn status(&self) -> &SideServiceStatus;
    pub(crate) fn availability(&self, feature: SideServiceFeature) -> SideServiceAvailability;
    pub(crate) fn shutdown(&mut self);
}
```

The exact file count may vary, but the architectural rules should stay the same:

- one explicit side-service runtime owner
- one home per service family
- one place for service configuration and lifecycle
- one place for service storage-root resolution
- one explicit per-family availability result that combines build feature, runtime config, and platform/provider support
- one session-owned runtime instance for every `Session`, with account-scoped storage optional rather than assumed

Avoid:

- adding raw provider logic to `src/session/core.rs`
- leaving preview as a top-level free-standing implementation forever
- exposing unfinished service families publicly just because their internal homes exist

---

## Current-To-Target Ownership Mapping

| Current owner | Current responsibility | Target owner after Story 9B |
|---------------|------------------------|-----------------------------|
| `src/preview.rs` | preview/thumbnail helper implementation | `src/services/preview/` |
| `src/fs/operations/upload.rs` | direct preview invocation during upload plus preview attach decision | transfer/upload orchestration calling side-service runtime for preview generation and retaining upload/attach policy |
| `src/session/core.rs` | loose preview enablement flag | side-service runtime config owned by `Session` |
| missing | media metadata pipeline home | `src/services/metadata/` |
| missing | file-service-style local cache/runtime home | `src/services/file_service/` |
| missing | side-service storage/lifecycle owner | `src/services/runtime.rs` or equivalent |

---

## Public API Stability Rules

Story 9B must preserve public API stability unless an additive API is explicitly approved.

That means:

- `SessionHandle::enable_previews(...)` remains available
- the optional public `preview` module remains available behind the `preview` crate feature
- no existing upload/download APIs are removed or renamed

If preview implementation moves behind `src/services/preview/`, the public compatibility path should be:

- keep `pub mod preview` in `src/lib.rs`
- have it delegate to or re-export stateless preview-generation helpers from the new internal preview family
- the public compatibility module does not need a `Session` or a `SideServicesRuntime`; session-owned runtime is for upload integration, config, and family availability

Story 9B may add internal-only service runtime APIs freely.

---

## C++ Ground-Truth Reference Map

Use this map when implementing Story 9B so the Rust scaffolding follows the actual C++ ownership and call paths rather than only the high-level story wording.

| Story 9B concern | Primary C++ ground truth | Why it matters |
| --- | --- | --- |
| session-owned side-service root | `../sdk/include/mega/megaclient.h:2008`, `../sdk/include/mega/megaclient.h:2330`, `../sdk/include/mega/megaclient.h:3505` | the upstream owner is `MegaClient`; side services are not ad hoc helpers hanging off transfers |
| preview/gfx runtime is optional | `../sdk/include/mega/megaclient.h:2011`, `../sdk/src/megaapi_impl.cpp:12784` | disabled state is explicit and separate from core engine viability |
| preview/gfx provider seam | `../sdk/include/mega/gfx.h:97`, `../sdk/src/gfx.cpp:41`, `../sdk/src/megaapi_impl.cpp:87` | provider selection is a lower-layer concern; runtime ownership stays in the service owner |
| preview generation behavior | `../sdk/src/gfx.cpp:52`, `../sdk/src/gfx.cpp:366`, `../sdk/src/gfx.cpp:410` | support checks, generation, and lifecycle live with the gfx runtime, not in upload orchestration |
| upload path remains orchestration owner | `../sdk/src/transfer.cpp:1035`, `../sdk/src/transfer.cpp:1241` | transfers decide when to attempt preview/media work and remain tolerant of unavailable side services |
| media metadata has its own subsystem home | `../sdk/include/mega/mediafileattribute.h:141`, `../sdk/src/mediafileattribute.cpp:238` | media extraction and file-attribute queuing belong to `MediaFileInfo`, not to free helpers |
| media metadata integrates through transfer calls | `../sdk/src/transfer.cpp:620` | transfer code calls into a service-like owner instead of inlining subsystem state there |
| file service is lifecycle-managed | `../sdk/include/mega/file_service/file_service.h:27`, `../sdk/src/file_service/file_service.cpp:61`, `../sdk/src/file_service/file_service.cpp:126` | the upstream file service is an owned subsystem with init/deinit, not just a namespace of helpers |
| file service has service-local options and observers | `../sdk/include/mega/file_service/file_service.h:47`, `../sdk/include/mega/file_service/file_service.h:68`, `../sdk/include/mega/file_service/file_service_options.h:15` | Story 9B should reserve a config/status home even before full file-service parity exists |
| service-local storage is separate from core state tables | `../sdk/src/file_service/file_storage.cpp:41` | file-service storage is rooted off the client db path but namespaced separately by service and session |
| service init/deinit follows session lifecycle | `../sdk/src/commands.cpp:2037`, `../sdk/src/megaclient.cpp:4971`, `../sdk/src/megaclient.cpp:5053` | side-service startup and teardown happen during client/session lifecycle, not lazily in random operation files |

If implementation questions arise, prefer following these C++ call sites and owner boundaries over the generic phrase "side-service pipeline", which is Rust design vocabulary rather than an upstream SDK type name.

---

## Deferred Feature Families After Story 9B

After Story 9B lands, these families should still be considered intentionally deferred:

- richer preview/thumbnail pipeline behavior beyond current upload-time generation
- video/audio/media property extraction and file-attribute upload analogous to `MediaFileInfo`
- file-service-style local cache, ranged reads, reclaim policy, and observers analogous to `FileService`
- rich-preview metadata fetchers and other non-core metadata service families
- public APIs for those families beyond current preview compatibility

Story 9B succeeds when those families have correct homes and lifecycle patterns, not when they are fully implemented.

---

## Agent-Sized Tasks

### Task 9B.1. Introduce the side-service runtime root

Create `src/services/` plus the runtime owner and service-family config/context types.

This task should:

- add the side-service runtime root
- define runtime-owned config and capability status
- define service storage-root context
- make `Session` own one runtime instance with explicit shutdown semantics
- keep everything internal-only

### Task 9B.2. Move preview behind the service home

Use the existing preview family as the first live side-service seam.

This task should:

- move preview implementation behind `src/services/preview/`
- preserve the public `preview` module as compatibility API if needed
- route upload-time preview behavior through the service runtime rather than direct free helper ownership
- keep preview ownership scoped to support detection, generation, and provider selection while leaving transfer completion and node-attribute upload policy with upload orchestration in the first slice

### Task 9B.3. Add placeholder homes for metadata and file-service families

Create minimal, compile-safe, internal module scaffolding for:

- `src/services/metadata/`
- `src/services/file_service/`

This task should:

- define family-local config/capability placeholders
- make them real runtime fields with explicit unsupported or disabled status
- avoid implementing the full feature families
- make their lifecycle and storage ownership explicit

### Task 9B.4. Add lifecycle and feature-gating tests and deferred-work docs

Add focused tests and documentation proving:

- disabled side services are explicit and non-fatal
- preview compatibility still works
- service runtime ownership is per-session and explicit
- build feature, runtime-config, and unsupported-provider states map to explicit service availability results
- deferred families remain deferred but architecturally placed

---

## Acceptance Criteria

Story 9B is complete when all of the following are true:

- `src/services/` exists as the named architectural root for side-service pipelines
- Rust has one explicit session-owned side-service runtime owner with service-family config/lifecycle context
- the existing preview family is no longer architecturally centered on `src/preview.rs` plus direct calls from `upload.rs`
- metadata and file-service-style families have reserved internal module homes
- service-local storage and platform-provider seams are explicit
- service availability is explicit per family across build feature, runtime config, and platform/provider support
- Story 9B consumes the lower platform service/path seams reserved by Story 7B rather than inventing a parallel capability layer
- preview upload integration remains best-effort and does not fail uploads solely because preview generation is disabled, unsupported, or unavailable
- public API compatibility for existing preview-related behavior is preserved
- future non-core SDK service families can land without reshaping `Session`, `fs/operations/*`, or top-level crate layout again

---

## Verification Requirements

If Story 9B changes Rust code, it must end with:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

Focused tests for this story should cover at least:

- preview feature-gate compatibility
- disabled preview/service behavior
- session-owned service runtime initialization and teardown
- explicit availability mapping for compiled-out, disabled, unsupported, and ready states
- upload-time preview path still functioning through the new service home
- compile-safe placeholder behavior for deferred service families

---

## Relationship To Later Stories

Story 9B is not the story that fully implements side-service features. It is the story that makes later implementation stories land cleanly.

It should leave the architecture ready for later work such as:

- richer preview/media pipelines
- media metadata and file-attribute extraction
- file-service-style local cache and observer systems
- outward adapter exposure for service events through Story 6B patterns
- platform-specific providers through Story 7B patterns

That means Story 9B should be judged by structural correctness and future portability, not by raw feature breadth.
