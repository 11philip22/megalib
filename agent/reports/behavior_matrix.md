# Behavior Matrix: C++ SDK vs Rust Port

This matrix compares behavior contracts and observable outcomes between the C++ SDK (`sdk/`) and the Rust port (`megalib/`). Sources: `agent/reports/cpp_inventory.md`, `agent/reports/rust_inventory.md`, and `agent/inputs/*.md`.

**Subsystem: Auth & Session Bootstrap**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| Login derives password keys, decrypts master key + RSA key + session id, then fetches user data and initializes key state (^!keys, authrings, pending shares). | API calls `us0` (pre-login), `us`, `ug`; session id is set; key material is parsed; pending shares may be promoted; callbacks for login/fetchnodes are invoked. | `sdk/src/megaclient.cpp` (`MegaClient::login`, `MegaClient::fetchnodes`, `initializekeys`), `sdk/src/commands.cpp` (`CommandGetUserData` / `ATTR_KEYS`), `sdk/src/megaclient.cpp` (`KeyManager::fromKeysContainer`). | `megalib/src/session/session.rs` (`login_internal`, `load_keys_attribute`), `megalib/src/session/keys.rs` (`promote_pending_shares`). |

**Subsystem: API Request Pipeline / HTTP / Retries**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| Requests are JSON commands with idempotence; `sid` is included when available; retries/backoff on `EAGAIN`; HTTP errors propagate distinctly. | Retry count/backoff on `EAGAIN`; request timeouts; non-2xx -> error; `s2` includes browser-style `bc=1`. | `sdk/include/mega/request.h`, `sdk/src/request.cpp` (`RequestDispatcher`), `sdk/src/http.cpp` (`HttpReq`/`HttpIO`), `sdk/src/megaclient.cpp` (`BackoffTimer`). | `megalib/src/api/client.rs` (`request_with_allowed`), `megalib/src/http.rs` (`HttpClient::post`). |

**Subsystem: Node Tree Parsing & Key Resolution**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| Node keys are resolved from `k` (master key for user handle, share key otherwise), and attributes decrypt via AES-CBC with `MEGA` prefix. Missing/incorrect keys leave nodes undecryptable. | `MEGA` prefix check; nodes without usable keys remain encrypted/ignored; share keys sourced from `ok` or share-key cache. | `sdk/src/node.cpp` (`decryptattr`, `setattr`, `applykey`), `sdk/src/nodemanager.cpp` (`applyKeys`). | `megalib/src/fs/operations/tree.rs` (`refresh`, `parse_share_keys`, `decrypt_node_key`, `decrypt_node_attrs`). |

**Subsystem: Filesystem Model & Mutations**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| `mkdir`/`rename` encrypt attrs with node key; `mv` requires destination container; `rm` issues delete. Path building must be deterministic and cycle-safe. | `p`/`a`/`m`/`d` commands; attrs padded to 16 bytes; path cache updated; depth caps prevent loops. | `sdk/src/megaclient.cpp` (`putnodes_prepareOneFolder`), `sdk/src/commands.cpp` (`CommandSetAttr`, `CommandPutNodes`), `sdk/src/megaapi_impl.cpp`. | `megalib/src/fs/operations/dir_ops.rs`, `megalib/src/fs/operations/tree.rs`. |

**Subsystem: Sharing / Export (Authenticated)**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| Folder export uses `s2` (share) + `l` (link); file export uses `l` only. Share key is persisted and flagged trusted/in_use when available. CR mapping is produced for descendants. | `s2` payload with `ok/ha/cr`, `l` returns link handle; share key cached in ^!keys; in-use flag toggled. | `sdk/src/megaclient.cpp` (`exportnode`, `setshare`), `sdk/src/sharenodekeys.cpp` (`ShareNodeKeys`), `sdk/src/commands.cpp` (`CommandSetShare`). | `megalib/src/fs/operations/export.rs` (`export`), `megalib/src/session/session.rs` (`share_folder`, `compute_handle_auth`, `build_cr_for_nodes`, `find_share_for_handle`). |

**Subsystem: Exported Folder Updates (New Files)**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| New nodes under an exported folder must include CR mapping so the existing public link can decrypt them without regenerating the link. | `p` (putnodes) includes `cr` that encrypts node key with share key; existing public link remains valid. | `sdk/src/commands.cpp` (`CommandPutNodes`), `sdk/src/sharenodekeys.cpp` (`ShareNodeKeys::get`). | `megalib/src/fs/operations/upload.rs` (`finalize_upload`), `megalib/src/session/session.rs` (`build_cr_for_nodes`, `find_share_for_handle`). |

**Subsystem: Public Links (Anonymous)**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| File links use 32-byte key; folder links use 16-byte key; link parsing supports legacy and new formats; folder browsing uses direct CS POST with `n=<handle>`. | `g` for download URL + `at`; attribute decrypt requires `MEGA` prefix; folder nodes may have empty `k` (fallback to folder key). | `sdk/src/megaclient.cpp` (`parsepubliclink`, `openfilelink`, `loginToFolder`), `sdk/src/megaapi_impl.cpp` (`MegaApi::getPublicNode`). | `megalib/src/public.rs` (`parse_mega_link`, `parse_folder_link`, `get_public_file_info`, `open_folder`). |

**Subsystem: Transfers (Upload/Download)**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| Uploads compute chunk MACs and meta-MAC, pack node keys, and finalize with `p`. Downloads use AES-CTR with nonce derived from node key. | `u` for upload URL; `p` for node creation; temp resume file; progress callbacks; AES-CTR decrypt uses nonce + counter. | `sdk/include/mega/transfer.h`, `sdk/src/transfer.cpp`, `sdk/src/transferslot.cpp`, `sdk/src/megaclient.cpp` (`putnodes`). | `megalib/src/fs/operations/upload.rs`, `megalib/src/fs/operations/download.rs`, `megalib/src/crypto/aes.rs`. |

**Subsystem: Key Management (^!keys) & Authrings**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| ^!keys container is AES-GCM encrypted with HKDF-derived key; generation must be monotonic; downgrade detection blocks updates; pending share promotion depends on verification; authrings record key fingerprints/signatures. | `^!keys` attr updates via `upv`; `API_EEXPIRED` triggers retry; share keys have TRUSTED/INUSE flags; manual verification can block promotion; authring mismatch yields error/state change. | `sdk/src/megaclient.cpp` (`KeyManager::*`, `trackKey`, `trackSignature`), `sdk/src/tlv.cpp`, `sdk/include/mega/user.h`. | `megalib/src/crypto/key_manager.rs`, `megalib/src/session/keys.rs`, `megalib/src/crypto/authring.rs`, `megalib/src/session/session.rs` (`load_keys_attribute`). |

**Subsystem: Crypto Primitives & Encoding**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| AES-128 ECB/CBC/CTR per MEGA spec; RSA-2048 with exponent e=3; legacy KDF; base64url without padding. | CBC uses zero IV for attrs; CTR nonce from key; RSA encrypt/decrypt are integer ops (no padding); base64url restores padding on decode. | `sdk/include/mega/crypto/cryptopp.h`, `sdk/src/crypto/cryptopp.cpp`, `sdk/include/mega/crypto/sodium.h`, `sdk/src/crypto/sodium.cpp`, `sdk/include/mega/base64.h` (base64). | `megalib/src/crypto/aes.rs`, `megalib/src/crypto/auth.rs`, `megalib/src/crypto/keys.rs`, `megalib/src/crypto/rsa.rs`, `megalib/src/base64.rs`, `megalib/src/crypto/keyring.rs`. |

**Subsystem: Action Packets & Polling**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| Polling `sc` updates `scsn`, applies action packets, and triggers key/authring updates; backoff on busy/invalid responses. | `scsn` advances; contact updates applied; key sync/promotion triggered; backoff doubles up to a max. | `sdk/src/megaclient.cpp` (SC handling, actionpacket processing). | `megalib/src/session/session.rs` (`poll_action_packets_once`, `run_action_packet_loop`), `megalib/src/session/keys.rs` (`handle_actionpacket_keys`). |

**Subsystem: Error Mapping & Propagation**

| Behavior contract | Observables | C++ reference location(s) | Rust reference location(s) |
| --- | --- | --- | --- |
| Negative API codes propagate through public APIs; HTTP failures are distinct; mapping to error enums is consistent. | `MegaApi` callbacks receive `MegaError`; `MegaError::ApiError` carries code + message; `HttpError` vs `RequestError`. | `sdk/include/megaapi.h` (`MegaError`), `sdk/src/megaapi_impl.cpp` (callbacks), `sdk/src/megaclient.cpp` (command error handling). | `megalib/src/error.rs`, `megalib/src/api/client.rs`, `megalib/src/http.rs`. |

## Parity Checkpoints (Testable Assertions)

1. Request canonicalization/signing
   - Minimal test: compute `ha` for a known handle + master key and assert against a fixed base64url output; verify CR triplet encryption uses AES-ECB over raw node key bytes.
2. JSON parsing of node tree
   - Minimal test: feed a fixture `f` response with a known `k` and `a` and assert name/path matches; include a bad `MEGA` prefix and assert node is rejected.
3. Base64/url encoding edge cases
   - Minimal test: encode/decode with `-`/`_` and missing padding; assert round-trip matches original bytes and invalid chars error out.
4. AES/RSA key schedule usage
   - Minimal test: AES-CBC zero-IV decrypt of a known attr blob returns `MEGA{...}`; RSA e=3 decrypt of a known encrypted share key yields 16 bytes.
5. Retry/backoff rules
   - Minimal test: stub `EAGAIN` responses and assert retry count (Rust: 6 for `s2`, 8 otherwise) and exponential backoff bounds; C++: assert `BackoffTimer` increases delay on `EAGAIN`.
6. Timeouts and polling loops
   - Minimal test: verify Rust HTTP client is configured with 60s timeout and API wrapper with 20s; action-packet loop doubles delay on busy/invalid until max.
7. Error mapping and propagation boundaries
   - Minimal test: simulate a negative API code and assert it becomes `MegaError::ApiError` (Rust) and `MegaError` callback (C++), preserving the code.
