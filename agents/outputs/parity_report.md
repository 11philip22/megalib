# megalib Parity Report: C++ SDK vs Rust Port

**Focus: Can end users do the same things? Same or better performance? Known bugs?**

Generated from codebase comparison and `agents/outputs/report.md`. Unit counts are from MCP graphs; functionality assessment is from manual review.

---

## Executive Summary

| Question | Answer |
|----------|--------|
| **Can end users do the same things?** | **No.** Core happy path (login, browse, upload, download, share links, public access) **works in both**. Missing: sync engine, FUSE virtual drive, 2FA, rubbish bin, file versioning, scheduled backup, full contact/sharing flows. |
| **Same or better performance?** | **Unknown.** No benchmarks exist. C++ SDK is mature and heavily optimized. Rust may be comparable for I/O-bound work; no data to compare. |
| **Bugs megalib has that C++ doesn’t?** | **Possibly.** Known parity gaps have been fixed (SC catch-up, failure handling). Remaining gaps: gzip login body, TLS flag, and partial feature parity may expose edge cases. |

---

## Functional Parity (End-User Capabilities)

### Works in both (core path)

| Feature | Status | Notes |
|---------|--------|------|
| **Login / Auth** | ✓ | `SessionHandle::login`, proxy, session restore |
| **File Upload** | ✓ | Resumable via state file |
| **File Download** | ✓ | Including public file download |
| **Browse / List** | ✓ | `list`, `stat`, node tree |
| **Sharing / Public Links** | ✓ | `export`, `share_folder`, `parse_folder_link`, `open_folder`, `download_public_file` |
| **Encryption / Crypto** | ✓ | AES (ECB/CBC/CTR), RSA, key derivation |
| **Key Management** | ✓ | KeyManager, authring, keyring, pending keys |
| **Thumbnails / Previews** | ✓ | Image + video via `preview` feature |
| **Transfer Progress** | ✓ | Callbacks |
| **Registration** | ✓ | Core flow; no ephemeral/resume |

### Partial in megalib (gaps vs C++)

| Feature | Present | Missing vs C++ |
|---------|---------|----------------|
| **File/Folder Mgmt** | `rename`, delete via action packets | `create_folder`, `move_node` as first-class APIs |
| **Contacts** | `list_contacts`, cleanup | Invite, accept, deny contact requests |
| **Events / Notifications** | `ScPoller`, action packets | Listener/callback registration like `MegaGlobalListener` |
| **Account / Quota** | `Quota`, `AccountInfo` | Subscription, payment methods, pricing |
| **Password** | `change_password` | Reset flow: `resetPassword`, `queryResetPasswordLink`, `confirmResetPassword` |
| **User Attributes** | `get_user_attribute` | Avatar, richer `getUserData`, credentials verification |

### Missing from megalib (not ported)

| Feature | C++ Scope | Impact |
|---------|-----------|--------|
| **File Sync Engine** | Bidirectional sync, local-remote reconciliation | **High** — core desktop feature |
| **FUSE Virtual Filesystem** | Mount cloud as drive (posix + windows) | **High** — virtual drive feature |
| **Two-Factor Auth (2FA)** | Setup, check, enable, disable, get code | **Medium** — security |
| **Rubbish Bin** | `cleanRubbishBin`, autopurge | **Medium** — data recovery |
| **File Versioning** | Version control, latest version APIs | **Medium** — history |
| **Scheduled Backup** | `MegaScheduledCopy`, scheduling | **Medium** — automation |
| **Node Search** | Search APIs | **Medium** — discovery |
| **Sets / Albums** | Set management | **Low** |
| **Chat** | `sendFileToUser` (messaging) | **Low** — may be separate SDK |

---

## Performance

| Aspect | C++ SDK | megalib |
|--------|---------|---------|
| **Benchmarks** | None found in tree | None (`benches/` absent) |
| **Transfer throughput** | Unmeasured | Unmeasured |
| **Memory** | Unmeasured | Unmeasured |
| **Assessment** | Mature, long-used, likely tuned | Async/await, streaming; no comparative data |

**Conclusion:** No meaningful performance comparison is possible today. Adding benchmarks (e.g. upload/download throughput, memory per session) would be needed to compare.

---

## Known Bugs & Parity Gaps

### Fixed (in CHANGELOG)

- SC catch-up endpoint (`/sc/wsc` vs `/sc`)
- SC failure classification (terminal vs retryable)
- Share-key promotion verification policy
- Pending-keys delete ACK timing

### Remaining TODOs (from `TODO.md`)

- `gzip login body` — may affect login performance/size
- `flag for tls` — unclear scope

### Possible Behavioral Differences

Behavior that was adjusted for parity (see `agents/outputs/plan.md`) suggests prior divergence in:

- SC polling semantics
- Share-key verification
- Pending-keys ACK

Similar gaps may exist in other flows (e.g. upload chunking, download resume). No formal C++ vs Rust behavioral test suite exists to verify them.

---

## Recommended Next Steps

1. **Functional:** Add `create_folder`, `move_node`; rubbish bin; 2FA.
2. **Quality:** Add C++ vs Rust integration tests for critical flows.
3. **Performance:** Add `cargo bench` for upload/download and session startup.
4. **Minor:** Implement gzip login body and document TLS flag behavior.
