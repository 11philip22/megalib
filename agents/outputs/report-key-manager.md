# Deep Dive: Key Management — C++ SDK vs Rust Port

> Generated 2026-03-03 from source analysis of `agents/sdk.acb` (codebase-cpp) and `agents/project.acb` (codebase-rust).

## Architecture Overview

| Aspect | C++ SDK | Rust Port |
|---|---|---|
| **Central type** | `KeyManager` class — logic spread across `commands.cpp`, `node.cpp`, `nodemanager.cpp`, `megaapi_impl.cpp` | `KeyManager` struct in `src/crypto/key_manager.rs` — single self-contained module |
| **Container format** | `^!keys` user attribute, LTLV-encoded, AES-128-GCM encrypted | Same: `^!keys`, same LTLV tag layout (compatible wire format), same AES-128-GCM with HKDF-SHA256 key derivation |
| **Node key handling** | `Node::setkey`, `Node::applykey`, `NodeManager::applyKeys`, deferred key application via `addNodePendingApplykey` | `Session::decrypt_node_key` in `tree.rs`, `pack_node_key` in `keys.rs`, `decrypt_public_node_key` in `public.rs` |
| **Share key store** | Scattered across `NodeManager`, `MegaNodePrivate::getSharekey`, command layer | Centralized in `KeyManager.share_keys: Vec<ShareKeyEntry>` with flag bits |
| **Authring** | `AuthRing` class in `src/user.cpp` — fingerprint, credential verification, authring per key type | `AuthRing` struct in `src/crypto/authring.rs` — same model: per-handle SHA-256 fingerprint + `AuthState` enum (Seen/Verified/Changed) |
| **Keyring** | `*keyring` user attribute — TLV with AES-GCM/CCM encryption, stores Ed25519/Cu25519 private seeds | `Keyring` struct in `src/crypto/keyring.rs` — same TLV format, supports all 7 `encSetting` variants (GCM-12-16, GCM-10-8, CCM-12-16, CCM-10-16, CCM-10-8, plus two "broken" GCM-as-CCM modes) |

---

## ^!keys Container (KeyManager)

Both implementations use the same LTLV (Length-Tag-Length-Value) binary format with these tag IDs:

| Tag | ID | C++ SDK | Rust Port |
|---|---|---|---|
| Version | 1 | Read/write | Read/write |
| Creation time | 2 | Read/write | Read/write |
| Identity | 3 | Read/write (u64) | Read/write (u64, LE) |
| Generation | 4 | Stored as `gen+1` on wire | Same: `gen+1` on wire, `saturating_sub(1)` on read |
| Attr | 5 | Read/write | Read/write |
| Priv Ed25519 | 16 | Read/write (32 bytes) | Read/write (32 bytes) |
| Priv Cu25519 | 17 | Read/write (32 bytes) | Read/write (32 bytes) |
| Priv RSA | 18 | Read/write (>=512 bytes or empty) | Read/write, same validation (reject <512 non-empty) |
| Authring Ed25519 | 32 | Read/write | Read/write, with LTLV validation + 64KB cap |
| Authring Cu25519 | 33 | Read/write | Read/write, same |
| Share keys | 48 | Per-entry: 6B handle + 16B key + 1B flags | Same binary layout: `[handle:6][key:16][flags:1]` |
| Pending outshares | 64 | Email or user-handle variant | Same: `PendingUid::Email` / `PendingUid::UserHandle` with identical wire encoding |
| Pending inshares | 65 | LTLV sub-map | Same LTLV sub-map, plus legacy base64 value detection |
| Backups | 80 | Opaque blob | Opaque blob with 1MB cap |
| Warnings | 96 | LTLV sub-map | Same LTLV sub-map (cv flag) |

**Encryption**: Both derive the AES-128-GCM key from the master key using HKDF-SHA256 with `salt=zeros(32)` and `info=[1]`. The Rust implementation is explicit about this in `derive_keys_cipher()`.

**Downgrade protection**: Both reject containers where the incoming generation is lower than the current in-memory generation. The Rust port returns `MegaError::DowngradeDetected`.

---

## Key Derivation

| Function | C++ SDK | Rust Port |
|---|---|---|
| **Password -> Key (v1)** | 65,536-round AES-ECB loop in `MegaClient::pw_key` | `make_password_key()` — identical: fixed IV, 65,536 rounds of AES-ECB-encrypt per 16-byte password chunk |
| **Password -> Key (v2)** | PBKDF2-HMAC-SHA512, 100,000 iterations | `derive_key_v2()` — identical: PBKDF2-HMAC-SHA512, 100,000 iterations |
| **Username hash** | XOR-fold username into 16 bytes, 16,384 AES-ECB rounds | `make_username_hash()` — identical algorithm |
| **^!keys cipher** | HKDF-SHA256(masterkey) -> 16 bytes | `derive_keys_cipher()` — identical |
| **Pairwise share-key exchange** | X25519 ECDH -> first 16 bytes of shared secret | `derive_pairwise_key()` — X25519 via `x25519_dalek`, first 16 bytes |

---

## Share Key Lifecycle

### C++ SDK flow

Logic distributed across `commands.cpp`, `node.cpp`, `nodemanager.cpp`, `megaapi_impl.cpp`:

1. Share creation: `CommandSetShare` constructs a share with key
2. `Node::testShareKey` validates incoming share keys
3. `NodeManager::applyKeys` applies keys to nodes with pending key state
4. `CommandPendingKeys` sends/receives pending key promotions
5. `CommandNodeKeyUpdate` updates node keys
6. Share keys tracked in `Node` objects and `MegaNodePrivate::getSharekey`

### Rust port flow

Centralized in `key_sync.rs` + `key_manager.rs`:

1. Share keys stored in `KeyManager.share_keys` with `TRUSTED` and `IN_USE` flag bits
2. `Session::promote_pending_shares()` orchestrates the full pending-key lifecycle:
   - Fetches remote pending keys via `pk` API command
   - For **outgoing** shares: fetches contact's Cu25519 public key, derives pairwise X25519 key, AES-ECB encrypts share key, sends via `pk` command
   - For **incoming** shares: derives pairwise key, AES-ECB decrypts share key, stores in KeyManager
   - Updates authring with contact fingerprints
3. `Session::handle_actionpacket_keys()` responds to server events:
   - Clears IN_USE flags for removed shares
   - Drops share keys for deleted roots
   - Clears TRUSTED flags for missing shares
   - Syncs remote `^!keys` and promotes pending shares
4. `Session::persist_keys_with_retry()` saves to server with merge-retry on conflict (up to 3 attempts)

---

## Authring

| Aspect | C++ SDK | Rust Port |
|---|---|---|
| **Fingerprint** | `AuthRing::getFingerprint`, `AuthRing::fingerprint` — SHA-256 of public key | `AuthRing::compute_fingerprint()` — SHA-256 of public key |
| **Verification states** | `areCredentialsVerified` — binary check | `AuthState` enum: `Seen`, `Verified`, `Changed` — more explicit state machine |
| **Storage** | Raw blob in `^!keys` (tags 32, 33) | LTLV-serialized `HashMap<String, AuthEntry>` with `[state_byte || fingerprint]` value format |
| **Merge** | Implicit through `^!keys` update | `merge_union()` — preserves existing entries on collision |
| **Manual verification** | SDK flag gating share-key exchange | `manual_verification` flag on `KeyManager`; `key_sync.rs` checks both Cu25519 AND Ed25519 authring states are `Verified` before promoting pending shares |

---

## Keyring (`*keyring` attribute)

| Aspect | C++ SDK | Rust Port |
|---|---|---|
| **Format** | `[encSetting][IV][ciphertext||tag]` with TLV payload inside | Same format, same `encSetting` byte values |
| **Encryption modes** | GCM-12-16, GCM-10-8, CCM-12-16, CCM-10-16, CCM-10-8, plus "broken" GCM variants treated as CCM | All 7 modes supported for decryption; always writes GCM-12-16 (0x10) |
| **Key generation** | Creates random Ed25519 seed + Cu25519 private key | `Keyring::generate()` — random 32-byte seeds with X25519 clamping |
| **Contents** | `prEd255` (Ed25519) + `prCu255` (Cu25519) as TLV records | Same TLV keys, same null-terminated key format |

---

## Node Key Operations

| Operation | C++ SDK | Rust Port |
|---|---|---|
| **Set key from JSON** | `Node::setkeyfromjson` | `Session::decrypt_node_key` in `tree.rs` |
| **Apply key** | `Node::applykey` — tries owner key, then share keys | `Session::decrypt_node_key` — decrypts with master key or share key from KeyManager |
| **Deferred apply** | `NodeManager::addNodePendingApplykey`, `NodeManager::applyKeys_internal` — queue then batch | `SessionActor::enqueue_pending_keys_fetch` — polls and processes pending |
| **Node key packing** | XOR-based obfuscation (file_key, nonce, meta_mac) | `pack_node_key()` — identical XOR layout |
| **Public node key** | `MegaNode::getNodeKey`, `isNodeKeyDecrypted` | `decrypt_public_node_key()` in `public.rs` |
| **Base64 key** | `MegaNode::getBase64Key`, `MegaNodePrivate::getBase64Key` | `Node::get_key()` returns raw bytes; base64 encoding done at call site |
| **Link auth key** | `MegaNode::getWritableLinkAuthKey` | Not implemented |

---

## What's Different (Summary)

1. **Consolidation vs Distribution**: The Rust port concentrates key management in two files (~2,400 lines) whereas the C++ SDK spreads it across Node, NodeManager, Command, and MegaApiImpl (thousands of lines across 10+ files). This makes the Rust version more auditable.

2. **Explicit state machine**: The Rust `AuthState` enum (`Seen`/`Verified`/`Changed`) makes contact verification state transitions explicit, where the C++ SDK uses boolean checks.

3. **Merge semantics**: The Rust `KeyManager::merge_from()` explicitly documents its strategy: union share keys (OR flags), union pending shares (deduplicate), union authrings (preserve existing on collision), take max generation. The C++ SDK handles merging implicitly through `^!keys` attribute updates.

4. **Persistence with retry**: The Rust `persist_keys_with_retry()` implements an explicit merge-retry loop (up to 3 attempts on `-8`/`-3`/`-11` errors), fetching remote state and re-merging. The C++ SDK handles this through its command completion/retry infrastructure.

5. **Missing in Rust**:
   - `Node::testShareKey` (share key validation against known nodes)
   - `ECDH::deriveSharedKeyWithSalt` (salted ECDH — Rust uses plain X25519 without salt)
   - `CommandNodeKeyUpdate` (bulk node key update command)
   - `MegaNode::getWritableLinkAuthKey` (writable link auth)
   - The C++ `NoKeyLogger` pattern for tracking nodes with missing keys

6. **Wire compatibility**: The Rust port is **wire-compatible** with the C++ SDK. Same LTLV encoding, same tag IDs, same share key binary layout (6+16+1 bytes), same generation+1 encoding, same HKDF derivation, same keyring `encSetting` values. A session initialized by one implementation can be read by the other.
