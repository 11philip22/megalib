# Story 10 Umbrella: Backup Subsystem Split

Validated on 2026-03-31 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document is now an umbrella for the backup work previously tracked as a single Story 10.

The backup track is split into two implementation stories so the epic matches the actual SDK-shaped architecture and the intended small-slice execution order:

1. `Story 10A`
   - `agents/outputs/architectural_parity_story_10a_backup_sync_runtime.md`
   - establishes `src/backup/` and implements the sync-backed half:
     - stable backup ids
     - mirror/monitor backup-sync policy state
     - backup-specific reporting metadata
     - sync-facing runtime seam

2. `Story 10B`
   - `agents/outputs/architectural_parity_story_10b_scheduled_copy_controller.md`
   - implements the scheduled-copy controller half:
     - period-or-cron schedule evaluation
     - `attendPastBackups` catch-up semantics
     - timestamped child backup folders
     - recovery and `maxBackups` retention pruning

Shared architectural rules remain unchanged:

- backup lives under `src/backup/`
- `Session` remains the engine root
- backup sync is layered on Story 9 sync runtime contracts
- scheduled copy is backup-owned and must not be forced through sync config/runtime types
- neither slice may introduce a second general-purpose filesystem engine

C++ ground-truth entrypoints for implementation:

- Story 10A primarily ports against:
  - `../sdk/include/mega/sync.h`
  - `../sdk/include/mega/types.h`
  - `../sdk/src/megaapi_impl_sync.cpp`
  - `../sdk/src/megaclient.cpp`
  - `../sdk/src/heartbeats.cpp`
  - `../sdk/src/sync.cpp`
- Story 10B primarily ports against:
  - `../sdk/include/megaapi.h`
  - `../sdk/src/megaapi.cpp`
  - `../sdk/src/megaapi_impl.cpp`
- Use the split story specs for the exact symbol-level references:
  - `agents/outputs/architectural_parity_story_10a_backup_sync_runtime.md`
  - `agents/outputs/architectural_parity_story_10b_scheduled_copy_controller.md`

Execution order:

1. Story 10A
2. Story 10B
3. Story 11

This file remains in place as a compatibility entrypoint for earlier references. New implementation work should use the Story 10A and Story 10B specs directly.
