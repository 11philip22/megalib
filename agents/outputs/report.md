# End-User Functionality Coverage: C++ SDK vs Rust Port

> Generated 2026-03-03 by comparing codebase graphs `agents/sdk.acb` (C++ SDK, 12,815 units) and `agents/project.acb` (Rust port, 968 units) via the `codebase-cpp` and `codebase-rust` MCP servers.

## Summary

The Rust port covers **10 of 21** identified end-user feature areas fully, with **6 partially covered** and **5 missing entirely**.

The core "happy path" for a MEGA user — login, browse files, upload, download, share links, encryption, key management, and thumbnails — is functional. The biggest gaps are the sync engine, FUSE virtual filesystem, and security features like 2FA.

---

## Present in Rust (core functionality works)

| Feature | C++ SDK | Rust Port | Notes |
|---|---|---|---|
| **Login / Auth** | `MegaApi::login`, `CommandPrelogin`, `killSessions`, session mgmt | `Session::login`, `login_with_proxy`, `login_with_session`, `set_session_id`, `decrypt_session_id` | Solid coverage |
| **File Upload** | `startUpload`, `MegaFolderUploadController`, transfer listeners | `Session::upload`, `UploadState` (hash-based resume), `upload_node_attribute` | Resumable upload via state file |
| **File Download** | `downloadFile`, `MegaFolderDownloadController`, streaming | `Session::download`, `download_to_file`, `download_public_file`, `download_public_file_data` | Includes public file download |
| **Browse / List Files** | `getChildren`, `getRootNode`, `CommandFetchNodes` | `Session::list`, `browse` module, `tree` module, `Node`/`NodeType` | Working tree navigation |
| **Sharing / Public Links** | `exportLink`, `getPublicLink`, `buildPublicLink`, `getPublicLinkInformation`, `ExportedLink` | `share_folder`, `export`, `parse_public_link_handle`, `PublicFile`, `PublicFolder`, `parse_folder_link`, `parse_mega_link`, `open_folder` | Good coverage |
| **Encryption / Crypto** | AES (ECB/CBC/GCM), RSA, `SymmCipher`, node key encryption | `aes128_ecb_decrypt/encrypt`, `MegaRsaKey`, `KeyManager`, `keyring`, `authring`, `derive_key_v2`, `make_password_key` | Comprehensive |
| **Key Management** | `CommandPendingKeys`, key share system | `KeyManager`, `key_sync`, `pending_in/out`, `authring`, `keyring`, key promotion | Well-developed |
| **Thumbnails / Previews** | Full GFX subsystem: `GfxProc`, `IGfxLocalProvider`, isolated process | `preview` module: `generate_thumbnail`, `generate_image_thumbnail`, `generate_video_thumbnail`, `is_image`, `has_ffmpegthumbnailer` | Image + video |
| **Transfer Progress** | `MegaTransfer`, `MegaTransferListener::onTransferStart/Update/Finish` | `TransferProgress`, `ProgressCallback` | Present |
| **Registration** | `createAccount`, `resumeCreateAccount`, ephemeral accounts, signup link | `register`, `verify_registration`, `RegistrationState` | Core flow works; no ephemeral/resume |

## Partial in Rust (some functionality, gaps remain)

| Feature | What Exists in Rust | What's Missing vs C++ SDK |
|---|---|---|
| **File/Folder Mgmt** | `rename` (in `dir_ops`), `handle_actionpacket_delete_node` | No explicit `create_folder`, `move_node` session-level APIs |
| **Contacts** | `list_contacts`, `cleanup_pending_outshares_for_deleted_contacts` | No invite, accept, deny contact request APIs |
| **Notifications / Events** | `poll_user_alerts`, `action_packets` dispatch, `ScPoller`/`ScPollerEvent` | No listener/callback registration system like `MegaGlobalListener` |
| **Account / Quota** | `Quota` type, `quota()` function, `AccountInfo` | No subscription details, payment methods, pricing/plans |
| **Password Mgmt** | `change_password` | No `resetPassword`, `queryResetPasswordLink`, `confirmResetPassword` recovery flow |
| **User Attributes** | `get_user_attribute` | No `getUserAvatar`, `getUserData` (multiple), credentials verification |

## Missing from Rust (not ported)

| Feature | C++ SDK Scope | Impact |
|---|---|---|
| **File Sync Engine** | Full bidirectional sync: `synchronize`/`desynchronize`, sync adapters, local-remote reconciliation | **High** — core desktop app feature |
| **FUSE Virtual Filesystem** | Massive subsystem (thousands of units): mounts, inodes, file I/O, platform-specific (posix/windows) | **High** — virtual drive feature |
| **Two-Factor Auth (2FA)** | `multiFactorAuthSetup/Check/Enable/Disable/GetCode/ChangePassword` | **Medium** — security feature |
| **Rubbish Bin Mgmt** | `cleanRubbishBin`, autopurge period, server-side autopurge | **Medium** — data recovery |
| **File Versioning** | `setFileVersionsOption`, `getFileVersionsOption`, `latestFileVersion`, versioning control | **Medium** — version history |
| **Scheduled Backup** | `MegaScheduledCopy`, backup scheduling, state management, max backups | **Medium** — backup automation |
| **Chat / Messaging** | `sendFileToUser`, messaging support (full chat likely in separate MEGAchat SDK) | **Low** — may be out of scope |
| **Sets / Albums** | `getPublicLinkForExportedSet`, set management | **Low** |
| **Node Search** | Various node lookup/search APIs via MegaApi | **Medium** — file search |

---

## Scale Comparison

| Metric | C++ SDK | Rust Port | Ratio |
|---|---|---|---|
| Units | 12,815 | 968 | ~13:1 |
| Edges | 10,042 | 815 | ~12:1 |
| Dimension | 256 | 256 | 1:1 |

The Rust port represents roughly **7.5%** of the C++ SDK by unit count. The edge-to-unit ratio is comparable (0.78 C++ vs 0.84 Rust), suggesting similar internal coupling density per unit.

---

## Recommended Priority for Next Features

1. **File/Folder Management** (create folder, move node) — low effort, high user value, partial foundation exists
2. **Rubbish Bin** — moderate effort, important for data safety
3. **2FA/MFA** — moderate effort, important for security
4. **File Versioning** — moderate effort, important for data integrity
5. **Password Reset Flow** — low effort, `change_password` already exists
6. **Contact Requests** (invite/accept/deny) — moderate effort, `list_contacts` already exists
7. **Node Search** — moderate effort, enables file discovery
8. **Scheduled Backup** — higher effort, automation feature
9. **Sync Engine** — very high effort, large architectural undertaking
10. **FUSE Filesystem** — very high effort, platform-specific, may not be needed for all use cases
