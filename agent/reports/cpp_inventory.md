# C++ SDK Inventory (MEGA SDK)

## SDK Root
- `sdk/` (contains `include/`, `src/`, `bindings/`, `tests/`, etc.)

## Inventory Table

| Subsystem | C++ files | Key classes | Key methods | Invariants / assumptions |
| --- | --- | --- | --- | --- |
| Public API facade | `sdk/include/megaapi.h`, `sdk/include/megaapi_impl.h`, `sdk/src/megaapi.cpp`, `sdk/src/megaapi_impl.cpp`, `sdk/src/megaapi_impl_sync.cpp` | `MegaApi`, `MegaApiImpl`, `MegaApiLock`, `MegaRequest`, `MegaTransfer`, `MegaNode`, `MegaUser`, `MegaError` | `MegaApi::login`, `MegaApi::fetchNodes`, `MegaApi::logout`, `MegaApi::startUpload`, `MegaApi::startDownload`, `MegaApi::exportNode`, `MegaApi::createAccount` | Usage contract: login then `fetchNodes` before filesystem ops; many methods return ownership via `new`/`new[]` (caller must delete). |
| Core client engine | `sdk/include/mega/megaclient.h`, `sdk/src/megaclient.cpp`, `sdk/include/mega/megaapp.h` | `MegaClient`, `MegaApp` | `MegaClient::login`, `MegaClient::dumpsession`, `MegaClient::fetchnodes`, `MegaClient::logout` | Client holds session state, node cache, transfer queues, and request dispatcher; retry/backoff managed via `BackoffTimer` across CS and transfers. |
| Request / command pipeline | `sdk/include/mega/command.h`, `sdk/src/command.cpp`, `sdk/src/commands.cpp`, `sdk/include/mega/request.h`, `sdk/src/request.cpp` | `Command`, `Request`, `RequestDispatcher` | `Command::procresult`, `Request::get`, `RequestDispatcher::serverrequest`, `RequestDispatcher::serverresponse` | Request batching with `MAX_COMMANDS`; `Command::batchSeparately` forces isolation; retries must reuse cached JSON/idempotence token. |
| HTTP / network I/O | `sdk/include/mega/http.h`, `sdk/src/http.cpp`, `sdk/src/mega_http_parser.cpp` | `HttpReq`, `HttpIO` (and related) | `HttpReq::post`, `HttpIO::post` (via platform impls) | TLS key pinning constants for API/chat/SFU; backoff and retry reasons handled at client/request layer. Timeouts: UNKNOWN (platform-specific). |
| Node model + node manager | `sdk/include/mega/node.h`, `sdk/src/node.cpp`, `sdk/include/mega/nodemanager.h`, `sdk/src/nodemanager.cpp` | `Node`, `NodeCore`, `NewNode`, `PublicLink`, `NodeManager` | `Node::nodekey`, `Node::keyApplied`, `Node::hasZeroKey`, `NodeManager::getNode` | Node handles are 6 bytes; node keys must be present/valid for decryption; `PublicLink` has expiry/takedown metadata. |
| Filesystem + local file model | `sdk/include/mega/file.h`, `sdk/src/file.cpp`, `sdk/include/mega/filesystem.h`, `sdk/src/filesystem.cpp`, `sdk/include/mega/filefingerprint.h`, `sdk/src/filefingerprint.cpp` | `File`, `FileFingerprint`, `LocalPath` | `FileFingerprint::genfingerprint` (implied), path conversion methods | File fingerprint (size/mtime/CRC) is central to dedupe and transfers; local path normalization rules are platform-specific (UNKNOWN details). |
| Transfers | `sdk/include/mega/transfer.h`, `sdk/src/transfer.cpp`, `sdk/include/mega/transferslot.h`, `sdk/src/transferslot.cpp`, `sdk/include/mega/transferstats.h`, `sdk/src/transferstats.cpp` | `Transfer`, `TransferSlot`, `TransferCategory` | `Transfer::failed`, `Transfer::complete`, `Transfer::serialize`, `Transfer::transfercipher` | Transfers are keyed by `FileFingerprint`; temp URLs can be cached and expire; chunk MACs and meta MAC used for upload completion; retry/backoff via `BackoffTimer`. |
| Sync engine | `sdk/include/mega/sync.h`, `sdk/src/sync.cpp`, `sdk/include/mega/syncfilter.h`, `sdk/src/syncfilter.cpp`, `sdk/src/syncinternals/*` | `SyncConfig`, `LocalNode`, `Sync` (and internals) | `SyncConfig::setEnabled`, `SyncConfig::getSyncDbStateCacheName` | Sync uses filesystem change detection (notifications vs periodic); external backup syncs require matching external drive path; local fsid is persisted and must remain stable. |
| Sharing / public links | `sdk/include/mega/share.h`, `sdk/src/share.cpp`, `sdk/include/mega/sharenodekeys.h`, `sdk/src/sharenodekeys.cpp`, `sdk/include/mega/node.h` | `Share`, `ShareNodeKeys`, `PublicLink` | `MegaApi::exportNode`, `MegaClient::getpubliclink` (implied) | Public link carries handle + optional auth/expiry; share keys are managed and tracked for access control. |
| Key management (^!keys) | `sdk/include/mega/megaclient.h` (KeyManager), `sdk/src/megaclient.cpp`, `sdk/src/tlv.cpp` | `KeyManager` | `KeyManager::fromKeysContainer`, `KeyManager::toKeysContainer`, `KeyManager::promotePendingShares` | ^!keys container includes generation; downgrade detection triggers; share key flags (`trusted`, `in-use`) tracked and synced. |
| Crypto primitives | `sdk/include/mega/crypto/cryptopp.h`, `sdk/src/crypto/cryptopp.cpp`, `sdk/include/mega/crypto/sodium.h`, `sdk/src/crypto/sodium.cpp` | `SymmCipher`, `AsymmCipher`, `Ed25519`, `Cu25519` (names inferred) | Encryption/decryption + signatures (exact APIs: UNKNOWN) | AES/RSA/Curve25519/Ed25519 used for node keys, session keys, and contact verification. Exact invariants in crypto layer: UNKNOWN. |
| User/accounts + attributes | `sdk/include/mega/user.h`, `sdk/src/user.cpp`, `sdk/include/mega/user_attribute*.h`, `sdk/src/user_attribute*.cpp`, `sdk/include/mega/account.h` | `User`, `UserAttributeManager`, `UserAttribute` | `MegaApi::getUserAttribute`, `MegaApi::setUserAttribute` (public API), `UserAttributeManager::fetch` (implied) | User attributes include authrings, keyring, avatar, etc. Versioned/private/public scopes enforced by attribute type. |
| Logging + diagnostics | `sdk/include/mega/logging.h`, `sdk/src/logging.cpp`, `sdk/include/mega/log_level.h` | `Logger` (and helpers) | `setLogLevel`, `log` (implied) | Logging is globally scoped; verbose logs gated by build flags. |

## Behavior-Critical Paths And State Machines

- Authentication and session bootstrap: `MegaApi::login` -> `MegaClient::login` -> session key + SID establishment; `MegaApi::fetchNodes` required before node operations. (`sdk/include/megaapi.h`, `sdk/include/mega/megaclient.h`, `sdk/src/megaclient.cpp`)
- Request batching / idempotence: `RequestDispatcher` builds batches, caches JSON for retries, enforces `batchSeparately`. (`sdk/include/mega/request.h`, `sdk/src/request.cpp`)
- Command execution: `Command::procresult` parses API replies; command classes in `commands.cpp` implement specific actions. (`sdk/include/mega/command.h`, `sdk/src/commands.cpp`)
- Node parsing and key application: `Node::keyApplied`, `Node::nodekey`, plus share keys and `PublicLink` metadata. (`sdk/include/mega/node.h`, `sdk/src/node.cpp`)
- Transfer pipeline: `Transfer` + `TransferSlot` manage chunking, temp URLs, MACs, progress, and retries/backoff. (`sdk/include/mega/transfer.h`, `sdk/src/transfer.cpp`, `sdk/src/transferslot.cpp`)
- Upload completion: `Transfer::filekey`, `metamac`, `chunkmacs` used to finalize node creation and attributes. (`sdk/include/mega/transfer.h`, `sdk/src/transfer.cpp`)
- Download path: `Transfer` + HTTP fetch, decryption, and resume logic. (Exact resume invariants: UNKNOWN)
- Retry/backoff: `MegaClient` and `RequestDispatcher` use `BackoffTimer` for CS, transfers, and file-attribute requests. (`sdk/src/megaclient.cpp`, `sdk/src/request.cpp`)
- Sync engine: `SyncConfig` + sync internals manage state, scanning, conflict resolution, and database persistence. (`sdk/include/mega/sync.h`, `sdk/src/sync.cpp`, `sdk/src/syncinternals/*`)
- Key management: `KeyManager` handles ^!keys container, pending share promotions, trust/in-use flags, downgrade detection. (`sdk/include/mega/megaclient.h`, `sdk/src/megaclient.cpp`, `sdk/src/tlv.cpp`)
- TLS pinning: HTTP layer embeds pinned public keys for API/chat/SFU. (`sdk/include/mega/http.h`)

## Gaps / Unknowns
- Exact request signing details (beyond SID and idempotence): UNKNOWN.
- Precise timeout defaults per HTTP implementation and per platform: UNKNOWN.
- Exact transfer resume semantics and temp file naming at C++ layer: UNKNOWN.
