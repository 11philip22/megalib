# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added node-first session APIs for cached-tree browsing and remote operations: `fetch_nodes`, `root_nodes`, `children_by_handle`, `create_folder_in`, `move_node`, `rename_node`, `remove_node`, `export_node`, `share_folder_node`, and node-based upload variants.
- Added explicit `*_by_path` compatibility aliases for the existing path-first session APIs so callers have stable migration names for path-oriented code.
- Added a new `node_api` example demonstrating cached-node browsing without remote path strings.
- Added node-first recursive browsing (`descendants`) and batch export (`export_many_nodes`) helpers so remaining recursive-list/export conveniences do not require remote paths.
- Added node-first child lookup helpers (`child_node_by_name` and `child_node_by_name_type`) for cached-parent navigation without `stat_by_path`.

### Deprecated
- Deprecated the old canonical path-first `SessionHandle` method names such as `list`, `stat`, `mkdir`, `mv`, `rename`, `rm`, `export`, `share_folder`, and path-based upload helpers in favor of explicit `*_by_path` aliases or the newer node-first APIs.

### Removed
- Removed the redundant node-taking `children` helpers from the cached browse layer and `SessionHandle`; callers should use `children_by_handle` instead.

## [0.11.0]

### Fixed
- Public folder download no longer returns API -9 "Resource does not exist". The "g" request now includes the folder handle (`n` parameter) in the API URL, matching C++ SDK behavior via `getAuthURI()`.

## [0.10.0]

### Added
- Introduced a dedicated SC polling worker in `src/session/sc_poller.rs` to decouple SC long-polling from the actor command lane.
- Added deferred key-work scheduling and retry/coalescing support for action-packet-driven key operations in the session actor/runtime.
- Added startup state-gating primitives (`state_current`, `action_packets_current`) for SDK-style catch-up behavior.
- Added a bounded deferred node queue (`pending_nodes`) to stash node JSON when share keys are not yet available, with automatic oldest-entry eviction at capacity.
- Added unit tests for deferred node queue recovery, structural validation, corruption handling, queue-cap enforcement, and no-op draining behavior.
- Added share metadata on `Node` (`share_key`, `share_handle`, inbound/outbound share flags, and share access level) plus public accessors.
- Added share-focused node queries on `SessionHandle`: `nodes_with_inshares`, `nodes_with_outshares`, `nodes_with_pending_outshares`, and `root_nodes_and_inshares`.
- Added authring convenience APIs: `AuthringType`, `is_authring_attr`, `AuthRing::is_tracked`, `AuthRing::tracked_users`, `AuthRing::get_auth_method`, and `AuthRing::fingerprint`.

### Changed
- Refactored session processing to keep command handling responsive while SC polling/reconnect/backoff runs independently.
- Made action packet key handling non-blocking by deferring key-network/persist work out of the AP dispatch hot path.
- Implemented SDK-style `a:"pk"` trigger behavior for pending key fetch flow with account/readiness gating.
- Added `state_current`-style gating and startup reconciliation flow to avoid premature key-network churn during initial catch-up.
- Debounced/coalesced key persistence (`^!keys` updates) to reduce redundant persist bursts while preserving correctness.
- Removed upload hot-path key preflight behavior before upload URL requests (`a:"u"`), keeping upload preflight minimal.
- Aligned SC timeout/retry policy separation between SC long-poll and user-alert polling paths.
- Migrated all runnable examples to `clap`-based argument parsing and removed manual example CLI parsing paths.
- Added `clap` as a dev-dependency for examples and development tooling.
- Updated tree refresh and action-packet node ingestion to parse via deferred stashing (`try_parse_or_stash`) so nodes can be recovered once keys arrive.
- Drained deferred nodes after share-key updates from action packets and key-sync merges, improving eventual node recovery for shared content.
- Moved share-key/authring/warnings/backups state to `KeyManager` as the single source of truth in session internals, removing duplicated session-side caches.
- Updated tree parsing to carry the share key used for decryption onto nodes and to derive inshare/outshare markers and share access from tree/action-packet data.
- Updated `Node::is_writable` to respect inbound-share access levels instead of treating all cached nodes as writable.
- Persisted export/share-created share keys through `^!keys` consistently and switched share-key lookups/updates to indexed `KeyManager` paths.
- Added `init_tracing()` startup initialization across all runnable examples with `EnvFilter` defaulting to `off`.
- Gated proxy-debug TLS relaxations (`danger_accept_invalid_certs` and `danger_accept_invalid_hostnames`) behind `MEGALIB_INSECURE_PROXY_TLS` env-var presence.
- Aligned SC catch-up endpoint selection with SDK behavior: catch-up polls now use `/sc/wsc`, while non-catch-up polls continue to use `w` (if present) or `/wsc`.
- Tightened pending share-key promotion verification policy to match SDK defaults: non-manual mode now requires Ed25519 authring state at least `Seen`, while manual mode requires verified credentials.
- Updated pending-keys processing flow to explicitly separate read and delete-ack (`pk` with `d`) paths and send immediate delete-ack after successful local processing/persist.

### Deprecated
- None.

### Removed
- Removed generated graph visualization artifacts `mods.dot`, `mods.svg`, `types.dot`, and `types.svg` from versioned files.
- Removed unused `Session::poll_user_alerts_once` from `src/session/action_packets.rs`; user-alert polling now runs through `ScPoller`.
- Removed unused `Session::handle_contact_key_update` from `src/session/key_sync.rs`; contact key updates now flow through deferred action-packet key work.
- Removed unused `Session::sync_keys_attribute` from `src/session/key_sync.rs`; callers now use `sync_keys_attribute_internal` through startup reconciliation and action-packet key maintenance paths.

### Fixed
- Added explicit SC poll failure classification and control-flow handling so terminal failures stop the SC channel and reload-required failures trigger a session refresh path instead of generic backoff-only behavior.
- Added targeted tests for SC catch-up URL selection and SC failure classification to guard parity-sensitive behavior.

### Security
- `HttpClient::with_proxy` now keeps TLS certificate and hostname validation enabled by default; insecure proxy TLS mode is opt-in via `MEGALIB_INSECURE_PROXY_TLS`.
