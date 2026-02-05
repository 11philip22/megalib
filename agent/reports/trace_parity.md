# Trace Parity Plan & Instrumentation Map

Sources: `agent/reports/behavior_matrix.md` (no `agent/inputs/repro_cases.md` present).

## sequence.rs Endpoint Coverage (All Touched Commands)

The `examples/sequence.rs` flow exercises these endpoints/commands. Mark **conditional** if they only occur for upgraded accounts, previews, or pending shares.

1. `us0` (pre-login variant)  
2. `us` (login)  
3. `ug` (user data)  
4. `uga` (get user attribute) for `^!keys` and `*keyring` (**conditional**, depending on account state)  
5. `upv` (set private attribute) for `^!keys` (**conditional**, if `ensure_keys_attribute` creates/upgrades)  
6. `pk` (pending keys feed + promotions) (**conditional**, if pending shares exist)  
7. `sc` (action packet polling loop)  
8. `f` (fetch nodes / refresh)  
9. `p` (mkdir + upload finalize)  
10. `u` (upload URL fetch)  
11. **Storage upload URL** (non-API HTTP POST/PUT to `https://.../ul/` from `u` response)  
12. `s2` (share/export folder)  
13. `l` (public link handle)  
14. `ufa` (file attribute upload) (**conditional**, if previews enabled)  

Tracepoints to ensure coverage for sequence.rs:
- TP1, TP2: API request envelope + HTTP endpoint for all commands above.
- TP3–TP7: login + ^!keys import + pending share promotion (if any).
- TP8–TP11: fetch nodes + share key parse + node counts.
- TP12–TP15: export + CR mapping + upload finalize.
- TP18–TP19: retries/backoff + SC polling.

## Tracepoints (10–20) With Placement

Each tracepoint should emit a **structured log line** with a stable key set. Do **not** log secrets; use hashes or redacted summaries.

1) **API request envelope**
- **What**: request id, command name(s), `sid` present?, batch size
- **Rust placement**: `megalib/src/api/client.rs::request` / `request_batch`
- **C++ placement**: `sdk/src/request.cpp` (`RequestDispatcher::serverrequest`, request batching)

2) **HTTP endpoint + query + payload hash**
- **What**: URL host + path + query (redacted), SHA-256 of JSON payload
- **Rust**: `megalib/src/http.rs::HttpClient::post`
- **C++**: `sdk/src/http.cpp` (`HttpReq::post` / `HttpIO::post`)

3) **Login variant + KDF mode**
- **What**: login variant (v1/v2), KDF type, derived key hash prefix
- **Rust**: `megalib/src/session/session.rs::login_internal`
- **C++**: `sdk/src/megaclient.cpp` (`MegaClient::login`, prelogin `us0`)

4) **Session ID set**
- **What**: session id length + hash prefix
- **Rust**: `megalib/src/session/session.rs::login_internal` (after `api.set_session_id`)
- **C++**: `sdk/src/megaclient.cpp` (after `sid` set in login)

5) **User data (`ug`) parsed**
- **What**: user handle, `scsn` presence, attribute keys observed
- **Rust**: `megalib/src/session/session.rs::login_internal` (after `ug`)
- **C++**: `sdk/src/commands.cpp` (`CommandGetUserData::procresult`)

6) **^!keys decode**
- **What**: generation, version, share key count, pending in/out counts (no values)
- **Rust**: `megalib/src/session/session.rs::load_keys_attribute`
- **C++**: `sdk/src/megaclient.cpp` (`KeyManager::fromKeysContainer` + `updateValues`)

7) **Pending shares promotion**
- **What**: pending out count, pending in count, promotions attempted/succeeded
- **Rust**: `megalib/src/session/keys.rs::promote_pending_shares`
- **C++**: `sdk/src/megaclient.cpp` (`KeyManager::promotePendingShares`)

8) **Fetch nodes request**
- **What**: `f` request with flags (`c`, `r`, partial root if any)
- **Rust**: `megalib/src/fs/operations/tree.rs::refresh`
- **C++**: `sdk/src/megaclient.cpp` (`MegaClient::fetchnodes` / `CommandFetchNodes` creation)

9) **Share key parse from `ok`**
- **What**: ok entries count, RSA vs AES count (no key bytes)
- **Rust**: `megalib/src/fs/operations/tree.rs::parse_share_keys`
- **C++**: `sdk/src/megaclient.cpp` (`readok` / share key processing)

10) **Node parse summary**
- **What**: total nodes parsed, files/folders count, nodes with missing keys
- **Rust**: `megalib/src/fs/operations/tree.rs::refresh`
- **C++**: `sdk/src/megaclient.cpp` / `sdk/src/nodemanager.cpp` (after fetchnodes)

11) **Root handles discovered**
- **What**: root/inbox/trash handles (redacted: base64 prefix only)
- **Rust**: `megalib/src/fs/operations/tree.rs::refresh`
- **C++**: `sdk/src/megaclient.cpp` (rootnodes assignments)

12) **Export folder (s2)**
- **What**: share handle, share key hash prefix, CR item count
- **Rust**: `megalib/src/fs/operations/export.rs::export` (folder branch)
- **C++**: `sdk/src/megaclient.cpp::setshare` / `CommandSetShare`

13) **Export link (l)**
- **What**: link handle returned, exported node handle
- **Rust**: `megalib/src/fs/operations/export.rs::export`
- **C++**: `sdk/src/megaclient.cpp::exportnode` / `CommandSetPH`

14) **Upload finalize (p)**
- **What**: upload handle, parent handle, packed node key hash prefix
- **Rust**: `megalib/src/fs/operations/upload.rs::finalize_upload`
- **C++**: `sdk/src/commands.cpp::CommandPutNodes` and `sdk/src/megaclient.cpp::putnodes_prepareOneFile`

15) **CR mapping on upload**
- **What**: share handle + count of CR triplets
- **Rust**: `megalib/src/fs/operations/upload.rs::finalize_upload`
- **C++**: `sdk/src/sharenodekeys.cpp::ShareNodeKeys::get`

16) **Download URL fetch (g)**
- **What**: node handle, `g` response url host, filesize
- **Rust**: `megalib/src/fs/operations/download.rs::download_with_offset`
- **C++**: `sdk/src/megaclient.cpp` (`startxfer` / `CommandGetFile`) or download handler path

17) **AES-CTR setup**
- **What**: nonce hash prefix, counter start (offset/16)
- **Rust**: `megalib/src/crypto/aes.rs::aes128_ctr_decrypt`
- **C++**: `sdk/src/crypto/cryptopp.cpp::SymmCipher::ctr_crypt`

18) **Retry/backoff**
- **What**: retry counter, delay ms, error code
- **Rust**: `megalib/src/api/client.rs::request_with_allowed`
- **C++**: `sdk/src/request.cpp` / `sdk/src/megaclient.cpp` (`BackoffTimer` uses)

19) **SC polling**
- **What**: scsn before/after, packets count
- **Rust**: `megalib/src/session/session.rs::poll_action_packets_once`
- **C++**: `sdk/src/megaclient.cpp` (sc polling loop)

20) **Error propagation boundary**
- **What**: MEGA error code + mapped variant
- **Rust**: `megalib/src/api/client.rs` (after response parsing)
- **C++**: `sdk/src/commands.cpp::Command::procresult` and `MegaApi` callbacks

---

## Parity Check Execution Plan

### A) Login
1. Enable tracepoints 1–7, 19–20.
2. Run login on both SDKs with same account.
3. Compare:
   - `us0`/`us`/`ug` command order
   - session id length + hash prefix
   - ^!keys generation + counts
   - pending share promotion counts

### B) Fetch Nodes
1. Enable tracepoints 8–11.
2. Call `fetchnodes` / `Session::refresh`.
3. Compare:
   - total node count
   - file/folder split
   - roots discovered
   - share key parse counts from `ok`

### C) Upload Small File
1. Enable tracepoints 14–15, 18.
2. Upload a small file into:
   - normal folder
   - exported/shared folder (if possible)
3. Compare:
   - `p` payload size hash
   - CR triplet count for shared/exported
   - retry/backoff on any errors

### D) Download Small File
1. Enable tracepoints 16–17, 18.
2. Download a small file by node handle.
3. Compare:
   - `g` response URL host + file size
   - AES-CTR nonce hash prefix
   - retry/backoff if any

### E) Share Link Import/Export
1. Enable tracepoints 12–13, 15.
2. Export a folder (s2 + l), then add a file to the exported folder.
3. Compare:
   - share key hash prefix is stable
   - CR mapping emitted on upload
   - link handle remains unchanged

---

## Diff Format For Comparing Traces

Use a stable, line-oriented, JSONL format with canonical ordering of keys.

Example:
```
TRACE|ts=<iso8601>|sdk=<cpp|rust>|tp=<tracepoint_id>|data={...}
```

Rules:
- `tp` must be one of the 20 tracepoints above.
- `data` must include required fields for that tracepoint; redact secrets via SHA-256 prefix (e.g., `hash16=<first16hex>`).
- Compare by grouping on `tp` + request id (when present) and diffing key/value pairs.

Recommended comparison steps:
1. Normalize timestamps out.
2. Sort by `tp` then `request_id`.
3. Diff JSON objects (ignore fields marked `volatile`).
