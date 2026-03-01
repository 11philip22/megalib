# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Introduced a dedicated SC polling worker in `src/session/sc_poller.rs` to decouple SC long-polling from the actor command lane.
- Added deferred key-work scheduling and retry/coalescing support for action-packet-driven key operations in the session actor/runtime.
- Added startup state-gating primitives (`state_current`, `action_packets_current`) for SDK-style catch-up behavior.
- Added operational artifacts and tooling under `agents/`, including:
  - `agents/tasks/06-keep-upload-preflight-minimal.md`
  - `agents/mitm/lib_sequence1.jsonl`
  - `agents/tools/generate_test_files.sh`

### Changed
- Refactored session processing to keep command handling responsive while SC polling/reconnect/backoff runs independently.
- Made action packet key handling non-blocking by deferring key-network/persist work out of the AP dispatch hot path.
- Implemented SDK-style `a:"pk"` trigger behavior for pending key fetch flow with account/readiness gating.
- Added `state_current`-style gating and startup reconciliation flow to avoid premature key-network churn during initial catch-up.
- Debounced/coalesced key persistence (`^!keys` updates) to reduce redundant persist bursts while preserving correctness.
- Removed upload hot-path key preflight behavior before upload URL requests (`a:"u"`), keeping upload preflight minimal.
- Aligned SC timeout/retry policy separation between SC long-poll and user-alert polling paths.
- Reorganized repository automation assets from `agent/*` to `agents/*`.

### Removed
- Removed generated graph visualization artifacts `mods.dot`, `mods.svg`, `types.dot`, and `types.svg` from versioned files.
- Removed legacy `agent/` path copies replaced by `agents/` equivalents.

