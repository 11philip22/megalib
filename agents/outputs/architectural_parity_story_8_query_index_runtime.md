# Story 8 Spec: Add Query/Index Layer Over Cached Nodes

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 8 from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, 4, 4B, and 5, this is a code-bearing story. Its job is to turn the current browse helpers into clients of a real internal query/index substrate instead of leaving tree traversal, path filtering, and share-family filtering scattered across public-facing `Session` helpers.

## Validation Findings

Verdict: grounded, with Rust-side runtime shape still a design choice.

Grounded against the upstream SDK:

- `NodeSearchFilter` already carries the core query vocabulary Story 8 needs: parent/ancestor scope, included share families, name/type/time filters, and `includeVersions`; `NodeSearchPage` is the explicit offset/size paging model in [`../sdk/include/mega/nodemanager.h`](/Users/woldp001/Documents/Devel/mega/sdk/include/mega/nodemanager.h) (`NodeSearchFilter` at lines 41-257, `NodeSearchPage` at lines 259-269).
- The internal query owner really is `NodeManager`: it exposes direct-child loading via `getChildren(const Node* ...)`, filtered/paged child queries via `getChildren(const NodeSearchFilter& ...)`, recursive queries via `searchNodes(...)`, recent-file queries via `getRecentNodes(...)`, and share/root helpers in [`../sdk/include/mega/nodemanager.h`](/Users/woldp001/Documents/Devel/mega/sdk/include/mega/nodemanager.h) (lines 303-315, 358-366) and [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 411-634, 795-810, 1033-1165, 2268-2280).
- The backend seam also exists exactly where Story 8 expects it: `DBTableNodes` owns `getChildren(...)`, `searchNodes(...)`, `getRecentNodes(...)`, `getRootNodes(...)`, `getNodesWithSharesOrLink(...)`, `createIndexes(...)`, and `dropSearchDBIndexes()` in [`../sdk/include/mega/db.h`](/Users/woldp001/Documents/Devel/mega/sdk/include/mega/db.h) (lines 157-222).
- SQLite is concrete ground truth for query semantics. `getChildren(...)` applies `matchFilter(...)` plus explicit `ORDER BY`, `LIMIT`, and `OFFSET`; `searchNodes(...)` uses a recursive CTE seeded by ancestors and `includedShares`, excludes version nodes during recursion, and pages after ordering; `getRecentNodes(...)` is file-only, excludes versions and rubbish, and orders by `ctime DESC` in [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp) (lines 1780-1847, 2042-2218, 2302-2338).
- Share-family and root-family queries are first-class SDK concepts rather than public-helper accidents: `getNodesWithInShares()`, `getNodesWithOutShares()`, `getNodesWithPendingOutShares()`, `getNodesWithSharesOrLink(...)`, `getRootNodes()`, and `getRootNodesAndInshares()` are implemented in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 795-816, 1033-1165, 2268-2280) and [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp) (lines 1596-1660).
- Query/index lifecycle also lives with the node-cache layer upstream. `NodeManager::initCompleted()` creates indexes after initial node load, `NodeManager::dropSearchDBIndexes()` delegates index removal to the backend, `SqliteAccountState::createIndexes(...)` creates query-relevant indexes, and `SqliteAccountState::dropSearchDBIndexes()` removes them in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 1846-1938), [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp) (lines 1216-1323), and [`../sdk/src/megaclient.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/megaclient.cpp) (lines 843-845).
- The public layer is an adapter, not the owner. `MegaApiImpl::searchToNodeFilter(...)` translates external search parameters into `NodeSearchFilter`, then delegates to `NodeManager::searchNodes(...)` or `NodeManager::getChildren(...)`; the public `ORDER_NONE` path is explicitly preserved for large-folder traversal in [`../sdk/src/megaapi_impl.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/megaapi_impl.cpp) (lines 13207-13258, 18624-18703, 32721-32722).

Partially grounded / Rust-side design choices:

- A dedicated Rust `src/fs/runtime/query.rs` is the right Story 1 architectural home, but it is still a Rust-owned packaging choice; upstream keeps the same responsibilities on `NodeManager` plus DB backends rather than on a separate runtime file.
- An in-memory-first evaluator is a parity-informed adaptation, not a 1:1 SDK mechanism. Upstream's mature query path assumes a node backend and database-backed filtering, while Rust currently has coherent tree state in memory already.

Unsupported as originally implied:

- Path-based browse semantics are not the upstream query primitive. The C++ ground truth is handle/topology-driven, so Rust `list(...)` and `stat_by_path(...)` should be treated as compatibility adapters over handle-scoped query results rather than as a model to port directly.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_story_4_tree_cache_coherency.md`
- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`
- `agents/outputs/architectural_parity_story_4c_production_tree_cache_hardening.md`
- `agents/outputs/architectural_parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- cached browse behavior lives directly in `src/fs/operations/browse.rs`
- current helpers traverse `Session.nodes` linearly and often rely on derived `Node.path`
- exact and family-specific lookups such as `children_by_handle`, `descendants_by_handle`, `nodes_with_inshares`, and `nodes_with_outshares` do not share a query substrate
- Stories 4, 4B, and 4C now provide coherent, production-backed durable tree state through `PersistedTreeState`, but no query/index runtime consumes that durable state yet
- there is no internal page/filter/order abstraction analogous to upstream `NodeSearchFilter`, `NodeSearchPage`, `NodeManager::getChildren(...)`, or `NodeManager::searchNodes(...)`
- there is no internal home at `src/fs/runtime/query.rs` yet

This means browse behavior works today, but it is still architecturally thin compared with the SDK.

---

## Story Goal

Establish a dedicated query/index runtime at `src/fs/runtime/query.rs` that owns:

- query intent types for cached-node access
- scope/filter/order/page semantics for internal browse and search-like use cases
- lightweight in-memory index structures derived from coherent tree state
- SDK-shaped node-backend hook seams for later query/index acceleration, tied to the Story 4 and 4C tree/cache commit boundaries

The story must preserve the current public browse API surface while making `browse.rs` a thin adapter over a real query runtime.

This story does not promise a new public `search()` API. Its job is to create the internal substrate that later search/filter/page public APIs can safely build on.

---

## Why This Story Exists

Today, Rust node access is functional but structurally shallow:

- `list(...)` filters cached nodes by derived path prefix
- `stat_by_path(...)` scans cached nodes for exact path equality
- child and descendant helpers scan `self.nodes` directly
- share-family helpers are separate one-off filters

That is enough for current browse behavior, but it does not create the architecture needed for later parity work.

Upstream has a stronger ownership split:

- `NodeManager` owns children, recursive search, recent-node queries, fingerprint queries, and share-family query helpers
- `NodeSearchFilter` and `NodeSearchPage` define query intent separately from public adapters
- `DBTableNodes` exposes `getChildren(...)`, `searchNodes(...)`, `getRecentNodes(...)`, `getRootNodes(...)`, and optional search indexes through `createIndexes(...)` / `dropSearchDBIndexes()`

Relevant upstream references:

- query model and primary internal entry points:
  - [`../sdk/include/mega/nodemanager.h`](/Users/woldp001/Documents/Devel/mega/sdk/include/mega/nodemanager.h)
  - [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp)
- backend query/index seam:
  - [`../sdk/include/mega/db.h`](/Users/woldp001/Documents/Devel/mega/sdk/include/mega/db.h)
  - [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp)
- public adapter layer that maps external search/browse requests into the internal query model:
  - [`../sdk/src/megaapi_impl.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/megaapi_impl.cpp)
  - [`../sdk/src/megaclient.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/megaclient.cpp)

Story 8 is the slice that closes the architectural gap between “cached tree exists” and “cached tree has a stable query/index substrate.”

---

## Scope

In scope:

- introduce `src/fs/runtime/query.rs`
- define internal query intent types for:
  - direct children queries
  - recursive cached-tree search
  - SDK-style recent-file queries
  - share-family queries that already exist in Rust
- add a first in-memory query implementation over coherent cached tree state
- define the internal backend-hook seam that later DB-backed query/index work should use, without widening the generic persistence SPI in this slice
- add lifecycle hooks so the query runtime can rebuild or invalidate derived indexes after:
  - startup restore
  - successful `refresh()`
  - successful actor-side `ScPollerEvent::ScBatch` processing
- route existing browse helpers through the new internal query runtime, keeping path-based APIs as compatibility adapters rather than primary query owners
- add tests for:
  - scope filtering
  - deterministic ordering and paging
  - SDK-style recent-file semantics
  - share-family queries
  - restart-safe rebuild behavior
  - version-flag behavior

Out of scope:

- a new public `search()` API
- full SDK `NodeSearchFilter` parity in one slice
- DB-backed full-text search indexes in the same slice
- tag, description, favourite, sensitivity, mime-category, or fingerprint query parity
- contact/user-directory query features
- version-browsing features beyond preserving an internal `include_versions` seam
- sensitivity exclusion in recent queries until Rust `Node` state carries sensitivity
- widening `src/session/runtime/persistence.rs` with query-specific methods
- changing the Story 4 persistence model or the Story 4B SQLite backend schema to store query truth

This is a query/index substrate story, not the final public search feature story.

---

## Story 1, Story 3, Story 4, Story 4B, And Story 4C Constraints

Story 8 must preserve these existing decisions:

- query/index runtime lives at `src/fs/runtime/query.rs`
- `Session` remains the engine root
- browse-facing helpers in `src/fs/operations/browse.rs` stay public API adapters, not the long-term home of query logic
- coherent tree truth still comes from `nodes`, `pending_nodes`, `outshares`, `pending_outshares`, and `scsn`-driven restore/commit behavior from Stories 4 and 4C
- production durability still flows through the Story 3 SPI and Story 4B backend, not around them
- public browse APIs remain source-compatible in this story

If implementation pressure suggests bypassing the coherent tree/cache boundary or persisting separate query truth without revising the tree snapshot contract first, Story 4 must be revised before Story 8 proceeds.

---

## SDK Parity Target

Story 8 should align with the SDK in these ways:

1. Cached-node query behavior is owned by an internal subsystem, not by public browse helpers.
2. Children queries, recursive search, and recent-file queries share one internal query model.
3. Query filtering, ordering, and paging are represented as dedicated internal types rather than ad hoc function parameters.
4. Search-oriented indexes live with the node-query/backend layer like `NodeManager` and `DBTableNodes`, not with public adapters and not as generic persistence truth.
5. Recent queries follow the SDK’s `getRecentNodes` shape: file nodes only, creation-time ordered, version/rubbish excluded.
6. Query execution consumes coherent restored tree state and follows the same refresh/AP rebuild boundaries as the cache it depends on.

Rust should stay idiomatic:

- do not clone `NodeManager` class shape line by line
- do create a stable Rust-owned query runtime with explicit intent types and clear rebuild boundaries

## Implementation Reference Map

For Story 8 implementation work, the closest C++ reference points are:

1. Rust `children_by_handle(...)`
   - Upstream equivalents are `NodeManager::getChildren(const Node* ...)` for direct child loading and `NodeManager::getChildren(const NodeSearchFilter& ...)` for explicit filter/order/page queries in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 411-570).
2. Rust `child_node_by_name_handle(...)` and `child_node_by_name_type_handle(...)`
   - Upstream direct reference is `NodeManager::childNodeByNameType(...)` plus the DB fast path `DBTableNodes::childNodeByNameType(...)` in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 969-1030) and [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp) (lines 2393-2440).
3. Rust `descendants_by_handle(...)`
   - Upstream equivalent is `NodeManager::searchNodes(...)` with ancestor scope in `NodeSearchFilter`, backed by the recursive SQLite query in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 751-792) and [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp) (lines 2042-2218).
4. Rust `nodes_with_inshares(...)`, `nodes_with_outshares(...)`, and `nodes_with_pending_outshares(...)`
   - Upstream direct references are `NodeManager::getNodesWithInShares()`, `getNodesWithOutShares()`, `getNodesWithPendingOutShares()`, and `getNodesWithSharesOrLink_internal(...)` in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 795-816, 1152-1165) plus the DB query in [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp) (lines 1624-1660).
5. Rust `root_nodes_and_inshares(...)`
   - Upstream direct reference is `NodeManager::getRootNodesAndInshares()` in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 2268-2280), which composes `getRootNodes_internal()` with `MegaClient::getInShares()`.
6. Story 8 recent-query support
   - Upstream direct references are `NodeManager::getRecentNodes(...)`, `NodeManager::getRecentNodes_internal(...)`, `MegaClient::getRecentActions(...)`, and the SQLite recent query in [`../sdk/src/nodemanager.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/nodemanager.cpp) (lines 573-634), [`../sdk/src/megaclient.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/megaclient.cpp) (lines 19418-19424), and [`../sdk/src/db/sqlite.cpp`](/Users/woldp001/Documents/Devel/mega/sdk/src/db/sqlite.cpp) (lines 2302-2338).
7. Rust `list(...)` and `stat_by_path(...)`
   - There is no direct path-based `NodeManager` query to port. The upstream pattern is to query by handle/topology first and let higher layers adapt presentation, so Story 8 should resolve query scope through the query runtime and only preserve exact path matching at the compatibility edge.

---

## Current Query Gaps To Close

Story 8 is specifically targeting these gaps:

1. `browse.rs` owns direct tree traversal instead of delegating to a query runtime.
2. Path-based browse helpers use derived `Node.path` directly as primary query state instead of treating path as an adapter over tree structure.
3. There is no internal ordering or paging model.
4. There is no internal query scope abstraction for “children of parent,” “descendants under ancestors,” or “share-family views.”
5. Durable tree/cache state now exists, but there is no query runtime that rebuilds from it after restore or refresh.
6. There is no internal place where later DB-backed or backend-owned search indexes can land cleanly.

---

## Design Decisions

### Decision 1. The query runtime lives under `fs`, not `session`

Why:

- Story 1 already fixed that ownership
- the runtime is primarily about cached node access and browse/search-like filesystem views
- later sync, backup, mount, and public search work should consume the same file-oriented substrate

Consequence:

- Story 8 must introduce `src/fs/runtime/query.rs`
- `Session` may own a query runtime handle or embed query helpers, but the architectural home stays under `fs`

### Decision 2. Public browse helpers stay stable, but delegate inward

Why:

- `list(...)`, `stat_by_path(...)`, `children_by_handle(...)`, `descendants_by_handle(...)`, and share-family helpers already exist
- the goal is ownership change, not public API churn

Consequence:

- current helpers remain available
- internally they should call query-runtime entry points rather than filter `self.nodes` directly
- Story 8 must not add a public `search()` promise just because the substrate exists

### Decision 3. Query truth comes from coherent tree state, not separate persisted search state

Why:

- Stories 4, 4B, and 4C already established the authoritative tree/cache domain
- query indexes must be derived from that domain, not become a second source of truth

Consequence:

- startup restore, refresh replacement, and successful `ScBatch` application become the query-runtime rebuild boundaries
- Story 8 may add persistent-index hooks, but it must not make query indexes authoritative over the tree snapshot

### Decision 4. Handle-based scope is primary; path is an adapter

Why:

- path strings are derived and rebuilt during tree restore
- children, descendants, and share-family queries fundamentally operate on handles and tree topology
- upstream `NodeManager` query APIs are topology-aware, not path-string-centric

Consequence:

- internal query scope should be expressed in terms of parent handles, ancestor handles, root families, or share families
- path-based public helpers should translate into query runtime calls where possible, then adapt to derived `Node.path` for exact legacy semantics

### Decision 5. The first filter set must be limited to fields Rust already owns

Why:

- the SDK supports broader filters such as tags, descriptions, favourites, sensitivity, categories, and richer version controls
- current Rust `Node` data does not yet own most of those fields

Consequence:

- Story 8 should only live-wire filters for fields already present or derivable today, such as:
  - name text
  - node type
  - ancestor/parent scope
  - share-family inclusion
  - exported-link presence
  - current creation timestamp field
- the internal query model should stay extensible so later stories can add richer filters without redesigning the substrate

### Decision 6. Persistent-index hooks follow the SDK’s node-backend layering, but Story 8 stays runtime-first

Why:

- in the SDK, query/index acceleration belongs to `NodeManager` and `DBTableNodes`, not to a generic persistence SPI
- the current Rust tree is already in memory
- Story 8 is about establishing the runtime seam, not implementing full DB search parity in one slice

Consequence:

- Story 8 should implement a real in-memory query evaluator first
- it should also define the runtime/backend hook points where later node-backend query acceleration or search-index creation can land
- Story 8 should not widen `src/session/runtime/persistence.rs` just to host query methods
- if later SDK-style node-cache index work needs node-cache DB recycle or index recreation, that is acceptable and does not need to preserve a separate query-truth store
- physical on-disk search indexes remain deferred

### Decision 7. Recent-query semantics follow the SDK’s `getRecentNodes` contract

Why:

- upstream recent queries are not generic “sort by any timestamp”; they are a specific recent-file flow
- `DBTableNodes::getRecentNodes(...)` and `NodeManager::getRecentNodes(...)` already pin down file-only and creation-time semantics
- current Rust `Node.timestamp` is populated from API `ts`, which is the closest available creation-time field

Consequence:

- Story 8’s recent query kind must target file nodes only
- recent queries must exclude version nodes and rubbish nodes
- recent results must be ordered by creation timestamp descending
- recent query intent must carry a `since` lower bound plus offset/limit paging
- Story 8 should treat current `Node.timestamp` as the creation-time field for this slice
- sensitivity exclusion is explicitly deferred until Rust `Node` state carries that field

### Decision 8. Ordering and paging must be explicit, but compatibility helpers keep SDK-style `ORDER_NONE` behavior

Why:

- upstream separates filtering from ordering and paging through `NodeSearchPage`
- upstream also preserves an explicit “order none” mode for compatibility and performance-sensitive browse flows
- current Rust browse helpers return iteration-order results from `self.nodes`

Consequence:

- the query model must include an explicit no-order mode
- existing browse compatibility helpers should use that no-order mode and preserve current observable result order in Story 8
- internal query execution must sort before paging whenever an explicit order other than no-order is requested
- Story 8 should define stable zero-based page semantics using offset plus limit
- `limit == 0` should return an empty result without error
- recent queries are the exception: they always use creation-time descending ordering

### Decision 9. `include_versions` should exist internally now, but stay behaviorally conservative

Why:

- upstream query types already carry version-awareness
- current Rust tree model does not yet expose version nodes as a first-class query family

Consequence:

- Story 8 should include an internal `include_versions` flag in the query model
- until a real version model lands, the flag must preserve current behavior instead of inventing partial version semantics
- tests should prove the flag is accepted and does not regress current browse results

---

## Recommended Rust Shape

The first implementation slice should aim for a small but real internal shape such as:

```rust
// src/fs/runtime/query.rs

pub(crate) struct QueryRuntime {
    index: Box<dyn QueryIndexHooks>,
}

pub(crate) struct QueryView<'a> {
    pub(crate) nodes: &'a [Node],
    pub(crate) pending_outshares: &'a HashMap<String, HashSet<String>>,
    pub(crate) handle_to_index: &'a HashMap<String, usize>,
}

pub(crate) enum NodeQueryKind {
    Children,
    Search,
    Recent,
    ShareFamily,
}

pub(crate) struct NodeQuery {
    pub(crate) kind: NodeQueryKind,
    pub(crate) scope: NodeQueryScope,
    pub(crate) filter: NodeQueryFilter,
    pub(crate) order: NodeQueryOrder,
    pub(crate) page: NodeQueryPage,
}

pub(crate) enum NodeQueryScope {
    Parent(String),
    Ancestors(Vec<String>),
    RootFamilies,
    InShares,
    OutShares,
    PendingOutShares,
    All,
}

pub(crate) struct NodeQueryFilter {
    pub(crate) name_text: Option<String>,
    pub(crate) node_type: Option<NodeType>,
    pub(crate) exported_only: bool,
    pub(crate) include_versions: bool,
    pub(crate) creation_lower_bound: Option<i64>,
    pub(crate) creation_upper_bound: Option<i64>,
}

pub(crate) struct NodeQueryPage {
    pub(crate) offset: usize,
    pub(crate) limit: usize,
}

pub(crate) enum NodeQueryOrder {
    None,
    NameAsc,
    NameDesc,
    CreationAsc,
    CreationDesc,
}

pub(crate) trait QueryIndexHooks {
    fn rebuild_from_tree(&mut self, tree: &PersistedTreeState) -> Result<()>;
    fn invalidate(&mut self);
}
```

The exact type names can differ. The required shape is:

- one runtime owner
- one query intent model
- one view over coherent tree state
- one extension point for later persistent/backend-owned indexes

Implementation guidance:

- the in-memory evaluator should return stable node handles or session-local node indices, not borrowed `&Node` references and not cloned `Node` values
- derived indexes should be rebuilt from coherent tree state, not mutated ad hoc from random callers
- a no-op `QueryIndexHooks` implementation is acceptable in the first slice as long as rebuild boundaries are explicit and the backend hook seam stays under query/node-cache ownership rather than `persistence.rs`

---

## Affected Modules

Primary implementation targets:

- `src/fs/runtime/query.rs`
- `src/fs/runtime/mod.rs`
- `src/fs/operations/browse.rs`
- `src/fs/operations/tree.rs`
- `src/session/action_packets.rs`
- `src/session/actor.rs`
- `src/session/core.rs`

Likely supporting modules:

- `src/fs/node.rs`

Story 8 should not need to touch `src/session/runtime/persistence.rs` in the first slice.

The story should avoid spreading query behavior across unrelated modules once the runtime exists.

---

## Current Rust Grounding

The story should be built around the code that exists today:

- `browse.rs` already exposes children, descendant, exact-path, and share-family views
- `tree.rs` already defines the coherent post-refresh boundary and persists tree/cache state there
- `Session::capture_tree_state()`, `persist_tree_cache_state()`, and `restore_tree_cache_state()` already define the durable restart seam from Stories 4, 4B, and 4C
- actor-side successful `ScPollerEvent::ScBatch` handling already defines the durable AP batch commit boundary

Story 8 should consume those boundaries rather than invent new ones.

In practical terms:

- startup restore should leave the query runtime ready to rebuild from restored coherent tree state
- successful `refresh()` should trigger query-runtime rebuild or invalidation after the tree snapshot is coherent
- successful actor-side `ScBatch` handling should trigger one query-runtime rebuild/invalidation boundary after durable tree state is updated

---

## Internal Query Surface For Story 8

Story 8 should make these internal use cases first-class:

1. Direct children by parent handle
2. Recursive descendants/search below one or more ancestors
3. Recent-file selection using SDK-style creation-time semantics
4. Share-family selections:
   - inbound shares
   - outbound shares
   - pending outbound shares
   - roots plus inbound shares
5. Exact path adapter support for existing `list(...)` / `stat_by_path(...)` semantics

The following should stay deferred:

- wildcard text semantics identical to the SDK
- tag/description/favourite/sensitivity filters
- fingerprint queries
- public paging/search feature APIs
- DB-backed full-text or secondary index implementations

---

## Agent-Sized Tasks

### Task 8.1. Define the query runtime seam and intent types

Deliverables:

- add `src/fs/runtime/query.rs`
- define the internal query kind/scope/filter/order/page types
- add a no-op or simple default index hook implementation
- add `Session` helpers needed to expose a coherent `QueryView`

Done when:

- internal query types exist in the agreed module home
- the story no longer depends on ad hoc traversal as the only internal model

### Task 8.2. Implement the in-memory query evaluator and migrate core browse helpers

Deliverables:

- implement in-memory query execution over current coherent tree state
- migrate existing browse helpers so they delegate to the query runtime where appropriate

Recommended first migrated helpers:

- `children_by_handle(...)`
- `descendants_by_handle(...)`
- `nodes_with_inshares(...)`
- `nodes_with_outshares(...)`
- `nodes_with_pending_outshares(...)`
- `root_nodes_and_inshares(...)`

`list(...)` and `stat_by_path(...)` should remain compatibility adapters, but they must resolve candidate scope through the query runtime and only use derived-path checks for final legacy path semantics.

Done when:

- public browse behavior is unchanged
- query logic stops living only in `browse.rs`

### Task 8.3. Add rebuild/invalidation hooks at the durable tree boundaries

Deliverables:

- wire query-runtime rebuild or invalidation through:
  - startup restore success/fallback
  - successful `refresh()`
  - successful actor-side `ScPollerEvent::ScBatch` durability boundary
- keep the hook surface compatible with later backend-owned indexes

Done when:

- query-runtime rebuild policy is explicit and tied to the same coherent boundaries as tree truth
- the story leaves a clean place for later physical index implementations

### Task 8.4. Add focused regression coverage

Required coverage:

- children queries preserve current semantics
- recursive search under ancestors behaves deterministically
- explicit ordered queries sort before paging, while no-order compatibility helpers preserve current observable order
- recent queries match SDK-style recent-file semantics
- share-family queries preserve current helper behavior
- startup restore plus refresh/AP rebuild paths leave query behavior correct
- `include_versions` does not widen behavior prematurely

Done when:

- Story 8 can prove the new substrate preserves current browse behavior while making the new internal seam real

---

## Acceptance Criteria

Story 8 is complete when:

1. `src/fs/runtime/query.rs` exists as the internal home for cached-node query/index behavior.
2. Current browse helpers no longer own the only query logic.
3. Query behavior is represented through explicit internal scope/filter/order/page types.
4. One real in-memory query evaluator exists over coherent cached tree state.
5. The query runtime rebuilds or invalidates at the same startup/refresh/AP boundaries established by Stories 4 and 4C.
6. Recent queries follow SDK-style recent-file semantics using the current Rust creation-time field.
7. Persistent-index hooks exist for later node-backend index work, without widening Story 8 into a DB-search implementation story or generic persistence-SPI redesign.
8. Current public browse behavior remains source-compatible, including no-order compatibility helper behavior.
9. Path-based browse APIs are compatibility adapters over the query runtime rather than direct `self.nodes` scans.
10. No new public search feature promise is introduced in this story.

---

## Verification Requirements

Because this story will touch Rust runtime code, completion requires:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

Focused tests should include:

- browse-helper compatibility against the new runtime
- paging and ordering determinism
- rebuild behavior after tree restore and refresh
- actor/AP batch rebuild behavior
- no-op `include_versions` behavior until a real version model exists

---

## Relationship To Later Stories

Story 8 is the cached-node query substrate story. It deliberately stops before public feature widening.

Later work can build on it like this:

- Story 6 and 6B can consume query-runtime results for event staging without reimplementing traversal logic
- Story 7 and 7B can use the same query substrate for filesystem- and mount-facing views
- Story 9 and Story 10 can use the same ancestor/children/recent-node substrate for sync and backup planners
- Story 11 can use the same query runtime for mount namespace views
- later public search features can expose safe public APIs on top of the internal substrate instead of reintroducing direct tree traversal
- later backend/index stories can decide whether to store physical search indexes in the production backend without redefining query intent types

The main success condition for Story 8 is architectural: after it lands, later features should have one obvious internal home for cached-node queries instead of inventing parallel traversal helpers.
