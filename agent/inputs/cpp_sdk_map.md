# C++ SDK Map (Stable Index)

## SDK Root
- `sdk/`

## Public API Surface (megaapi.h)
- `MegaApi`: primary facade (login, fetchNodes, transfers, shares, sync, attributes).
- `MegaRequest`, `MegaTransfer`, `MegaNode`, `MegaUser`, `MegaError`: public data types and error codes.
- `MegaListener`/`MegaRequestListener`/`MegaTransferListener`/`MegaGlobalListener`: callback interfaces.

Files:
- `sdk/include/megaapi.h`
- `sdk/include/megaapi_impl.h`
- `sdk/src/megaapi.cpp`
- `sdk/src/megaapi_impl.cpp`

## Core Engine
- `MegaClient`: core state machine, request dispatcher, transfer queues, node cache, session handling.
- `MegaApp`: app callback interface.

Files:
- `sdk/include/mega/megaclient.h`
- `sdk/src/megaclient.cpp`
- `sdk/include/mega/megaapp.h`

## Request / Command Pipeline
- `Command`: base class for API commands and JSON parsing.
- `Request`, `RequestDispatcher`: batching, retries, idempotence.

Files:
- `sdk/include/mega/command.h`
- `sdk/src/command.cpp`
- `sdk/src/commands.cpp`
- `sdk/include/mega/request.h`
- `sdk/src/request.cpp`

## Nodes & Filesystem Model
- `Node`, `NodeCore`, `NewNode`, `PublicLink`, `NodeData`.
- `NodeManager`: node cache + DB boundary, LRU, pending apply-keys queue.
- `File`, `FileFingerprint`, `LocalPath`, `FileSystemAccess`, `FSNode`, `fsfp_t`, `fsfp_tracker_t`, `FileDistributor`.
- `Node::applykey` picks a compound key segment (user handle or share handle), decrypts with master/share key, and calls `setattr` (AES-CBC base64, `MEGA{\"` prefix). Foreign share key failures keep encrypted key for retry.
- `Node::keyApplied` implies nodekey length equals file/folder key length; `Node::nodekey()` asserts `keyApplied()` for non-root nodes.
- `NodeManager::addNode_internal` keeps root/first-level/notify nodes in RAM; other nodes can be DB-only during fetch; incoming shares are loaded on `mergenewshares`.
- `fsfp_t` combines legacy fingerprint and UUID; `fsStableIDs` is used to validate sync identity; `LocalPath` abstracts platform paths and URIs (UTF-16 on Windows, UTF-8 elsewhere).
- `FileDistributor` resolves clashing names via rename/copy strategies (bracketed numbers, oldN, overwrite, debris).

Files:
- `sdk/include/mega/node.h`
- `sdk/src/node.cpp`
- `sdk/include/mega/nodemanager.h`
- `sdk/src/nodemanager.cpp`
- `sdk/include/mega/file.h`
- `sdk/src/file.cpp`
- `sdk/include/mega/filefingerprint.h`
- `sdk/src/filefingerprint.cpp`
- `sdk/include/mega/filesystem.h`
- `sdk/src/filesystem.cpp`
- `sdk/include/mega/localpath.h`

## Transfers
- `Transfer`, `TransferSlot`, `TransferCategory`, `TransferStats`.

Files:
- `sdk/include/mega/transfer.h`
- `sdk/src/transfer.cpp`
- `sdk/include/mega/transferslot.h`
- `sdk/src/transferslot.cpp`
- `sdk/include/mega/transferstats.h`
- `sdk/src/transferstats.cpp`

## Sync Engine
- `SyncConfig`, `Sync` (internal), change detection + sync internals.

Files:
- `sdk/include/mega/sync.h`
- `sdk/src/sync.cpp`
- `sdk/include/mega/syncfilter.h`
- `sdk/src/syncfilter.cpp`
- `sdk/src/syncinternals/*`

## Sharing / Public Links
- `Share`, `NewShare`, `ShareNodeKeys`, `PublicLink`.
- Public links are created via `MegaApi::exportNode`; exported nodes are *not* considered shared nodes.
- Folder links use a share key (generated or reused); file links use the node key.
- `MegaApi::buildPublicLink` constructs a URL from public handle + key without creating it.
- `MegaApi::getPublicNode` parses a file link and opens it; if the key is missing, it opens without key for existence check (`API_EINCOMPLETE` treated as OK in the request path).
- `MegaApi::loginToFolder` uses a folder link (+ optional auth key) to create a public-folder session.
- `MegaClient::setshare` updates ^!keys (pending outshares / share key) before issuing `CommandSetShare` when needed; in-use flags are set/cleared in KeyManager when shares are created/removed.
- Adding nodes under an exported folder: `CommandPutNodes` generates a `cr` payload via `ShareNodeKeys` that encrypts each new node key with the share key of any share in the parent chain (including the exported folder), so the existing public link continues to decrypt new files without link regeneration.

Files:
- `sdk/include/mega/share.h`
- `sdk/src/share.cpp`
- `sdk/include/mega/sharenodekeys.h`
- `sdk/src/sharenodekeys.cpp`
- `sdk/include/megaapi.h`
- `sdk/src/megaapi_impl.cpp`
- `sdk/src/megaclient.cpp`
- `sdk/src/commands.cpp`

## Key Management / Authrings
- `KeyManager` manages the ^!keys container, share keys, pending in/out shares, authrings, warnings.
- Container format: header bytes `{20,0}` + 12-byte IV + AES-GCM ciphertext; key derived from master key via HKDF-SHA256 (info byte = 1).
- Generation is serialized as big-endian `gen+1`; downgrade detection blocks updates and notifies app.
- Pending outshares encode uid length (0=user handle, non-zero=email); pending inshares and warnings use LTLV.
- Commits are queued (`commit` -> `nextCommit` -> `updateAttribute`); on `API_EEXPIRED` it refetches ^!keys and retries.
- Share-key encryption/decryption is gated by `verificationRequired` (authring SEEN or manual verification).
- Share promotion: pending outshares encrypt share keys to recipients and send `CommandPendingKeys`; pending inshares decrypt keys (legacy base64 fix if size > 16), add share key as trusted, and enqueue `NewShare`.
- Authring validation: `trackKey` computes fingerprints and rejects mismatches for Ed25519 authring; `trackSignature` verifies Cu25519 signatures with Ed25519 signing key; updates are buffered in `mAuthRingsTemp` during initial scan and persisted via ^!keys commit when migrated.

Files:
- `sdk/include/mega/megaclient.h` (KeyManager definition)
- `sdk/src/megaclient.cpp`
- `sdk/src/tlv.cpp`
- `sdk/include/mega/user.h` (AuthRing)

## HTTP / Network
- `HttpReq`/`HttpIO` and TLS pinning constants.

Files:
- `sdk/include/mega/http.h`
- `sdk/src/http.cpp`
- `sdk/src/mega_http_parser.cpp`

## Crypto
- Symmetric AES-128: `SymmCipher` (ECB/CBC/CTR/CCM/GCM), `Hash`, `HashSHA256`, `HashCRC32`, `HMACSHA256`, `PBKDF2_HMAC_SHA512`.
- Asymmetric RSA: `AsymmCipher` (key decode/serialize/validate, genkeypair, serializekeyforjs padding).
- Ed25519 signatures: `EdDSA` (seed + pubkey; `verifyKey` uses `keyauth` + timestamp + pubkey).
- X25519 ECDH: `ECDH` (shared secret + HKDF-SHA256 salt derivation, crypto_box encrypt/decrypt, nonce uniqueness + zero-prefix padding).
- `SymmCipher::setkey(string)` only accepts 16/32-byte node keys; `setkey(type=0)` XORs second half into first; GCM/CCM IV lengths 7–13 bytes; GCM tag length expected 4/8/16 on decrypt; CBC IV is 16 bytes; `isZeroKey` supports 16/32-byte keys only.

Files:
- `sdk/include/mega/crypto/cryptopp.h`
- `sdk/src/crypto/cryptopp.cpp`
- `sdk/include/mega/crypto/sodium.h`
- `sdk/src/crypto/sodium.cpp`

## User Accounts / Attributes
- `User`, `UserAttributeManager`, `UserAttribute`.

Files:
- `sdk/include/mega/user.h`
- `sdk/src/user.cpp`
- `sdk/include/mega/user_attribute.h`
- `sdk/src/user_attribute.cpp`
- `sdk/include/mega/user_attribute_manager.h`
- `sdk/src/user_attribute_manager.cpp`

## Notes / Unknowns
- Exact request signing mechanics beyond SID + idempotence: UNKNOWN.
- Transfer resume on-disk layout: UNKNOWN.
