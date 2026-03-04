# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Deprecated
- None.

### Removed
- Removed generated graph visualization artifacts `mods.dot`, `mods.svg`, `types.dot`, and `types.svg` from versioned files.
- Removed unused `Session::poll_user_alerts_once` from `src/session/action_packets.rs`; user-alert polling now runs through `ScPoller`.
- Removed unused `Session::handle_contact_key_update` from `src/session/key_sync.rs`; contact key updates now flow through deferred action-packet key work.
- Removed unused `Session::sync_keys_attribute` from `src/session/key_sync.rs`; callers now use `sync_keys_attribute_internal` through startup reconciliation and action-packet key maintenance paths.

### Fixed
- None.

### Security
- None.
