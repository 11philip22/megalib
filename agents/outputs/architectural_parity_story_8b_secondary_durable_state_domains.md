# Story 8B Spec: Add Secondary Durable State Domains

Validated on 2026-03-26 against the current `megalib` tree, the Rust graph `project`, the upstream C++ graph `sdk`, and the sibling upstream SDK at `../sdk`.

This document refines Story 8B from `agents/outputs/architectural_parity_epic.md` into an implementation-ready story. Like Stories 2, 3, 4, 4B, and 5, this is a code-bearing story. Its job is to give non-node authenticated engine-state families a real architectural owner instead of leaving them as incidental `Session` fields, ad hoc persistence behavior, or helper-local caches.

Story type:

- Implementation story / detailed spec

Companion artifacts:

- `agents/outputs/architectural_parity_epic.md`
- `agents/outputs/architectural_parity_story_1_core_engine_boundary.md`
- `agents/outputs/architectural_parity_story_3_persistence_spi.md`
- `agents/outputs/architectural_parity_story_4b_production_persistence_backend.md`
- `agents/outputs/architectural_parity_story_4c_production_tree_cache_hardening.md`
- `agents/outputs/architectural_parity_story_5_transfer_runtime.md`
- `agents/outputs/architectural_parity_report.md`
- `agents/outputs/parity_report.md`

---

## Status

Not started.

Current implementation status on 2026-03-26:

- non-node secondary session state is still mostly owned directly by `src/session/core.rs`
- current Rust secondary state already includes:
  - `contacts: HashMap<String, Contact>`
  - `user_attr_cache: HashMap<String, Vec<u8>>`
  - `user_attr_versions: HashMap<String, String>`
  - `key_manager`
  - `last_keys_blob_b64`
  - `keys_persist_dirty`
  - `keys_persist_inflight`
  - `pending_keys_token`
  - `keys_downgrade_detected`
- contact updates are currently applied in `src/session/action_packets.rs`
- key/security coordination is currently spread across `src/session/key_sync.rs`, `src/session/sharing.rs`, `src/session/core.rs`, and actor-side retry/coalescing in `src/session/actor.rs`
- alerts already have explicit persistence ownership from Story 3
- tree/cache state already has explicit persistence ownership from Stories 4 and 4C
- transfer durability already has an explicit owner path from Stories 3, 4B, and 5
- there is no dedicated runtime home yet under `src/session/runtime/state/`
- there is no dedicated persistence domain yet for these secondary state families

This means the state is real and increasingly important, but it is still architecturally thin compared with the SDK.

---

## Story Goal

Introduce a dedicated secondary-state runtime under `src/session/runtime/state/` that owns the authenticated, non-node, non-transfer engine-state families needed for future parity work.

Architecturally, that runtime lives under `session/runtime/state`, but the concrete owner should be one long-lived session-owned runtime instance reused by action-packet handling, key/security helpers, and future collaboration features rather than a set of ad hoc helper-local caches.

This story must create explicit ownership for:

- contact directory state
- pending-contact-request state homes
- current-user raw user-attribute cache and version state
- key/authring/security coordination state layered on top of cached attributes

The story must preserve the existing public API surface while preventing these state families from remaining loose `Session` fields forever.

This story does not attempt to implement every broader SDK feature family. It only creates explicit ownership for the secondary engine-state band that already exists in Rust or is directly adjacent to existing Rust session logic.

---

## Why This Story Exists

Today, `megalib` already has meaningful non-node engine state, but it does not have one named subsystem that owns it:

- `src/session/core.rs` stores contacts, user-attribute cache/version state, and key-related flags directly
- `src/session/action_packets.rs` mutates contacts and user-attribute freshness directly as part of AP handling
- `src/session/key_sync.rs` owns pending-key processing, contact key fetches, and attribute refetch behavior
- `src/session/sharing.rs` and upload/export paths depend on key/share state that is conceptually broader than any one helper module
- actor-side code already coalesces and retries key persistence work, but there is no dedicated secondary-state owner behind that behavior

Upstream SDK breadth is wider and more explicit:

- `MegaClient` owns `users`, `umindex`, `pcrindex`, and `useralerts`
- `MegaClient::fetchsc()` restores `CACHEDUSER` and `CACHEDPCR` from durable cache alongside the rest of client state
- user-attribute and authring state are real engine concerns, not incidental helper caches
- the same upstream `statecache` also contains chats, sets, and other broader feature-family state, proving that the SDK treats secondary client state as first-class durable architecture

Relevant upstream references:

- Secondary-state ownership and cache record families:
  - `../sdk/include/mega/megaclient.h`
    - `user_map users`
    - `um_map umindex`
    - `handlepcr_map pcrindex`
    - `enum { ... CACHEDUSER ... CACHEDPCR ... } sctablerectype`
    - `bool fetchsc(DbTable*)`
    - `bool readusers(JSON*, bool actionpackets)`
    - `void notifyuser(User*)`
    - `void mappcr(handle, unique_ptr<PendingContactRequest>&&)`
    - `AuthRingsMap mAuthRings`
    - `AuthRingsMap mAuthRingsTemp`
    - `std::map<attr_t, set<handle>> mPendingContactKeys`
  - `../sdk/src/megaclient.cpp`
    - `MegaClient::initsc()`
    - `MegaClient::updatesc()`
    - `MegaClient::fetchsc(DbTable*)`
    - `MegaClient::readusers()` / `MegaClient::readuser()`
    - `MegaClient::finduser(handle, int)` / `MegaClient::finduser(const char*, int)`
    - `MegaClient::mapuser(handle, const char*)`
    - `MegaClient::findpcr(handle)` / `MegaClient::findpcr(const string&)`
    - `MegaClient::mappcr(handle, unique_ptr<PendingContactRequest>&&)`
    - `MegaClient::sc_contacts(JSON&)`
- Contact/user durable record shape and cached attribute substrate:
  - `../sdk/include/mega/user.h`
  - `../sdk/src/user.cpp`
    - `User::serialize()`
    - `User::unserialize()`
    - `User::setAttribute()`
    - `User::setAttributeExpired()`
    - `User::cacheNonExistingAttributes()`
    - `AuthRing::AuthRing(...)`
    - `AuthRing::serializeForJS()`
- Pending-contact-request durable record shape:
  - `../sdk/include/mega/pendingcontactrequest.h`
  - `../sdk/src/pendingcontactrequest.cpp`
    - `PendingContactRequest::serialize()`
    - `PendingContactRequest::unserialize()`
    - `PendingContactRequest::update()`
    - `PendingContactRequest::removed()`
- Current-user attribute cache/version semantics:
  - `../sdk/include/mega/user_attribute_manager.h`
  - `../sdk/src/user_attribute_manager.cpp`
    - `UserAttributeManager::set()`
    - `UserAttributeManager::setIfNewVersion()`
    - `UserAttributeManager::setExpired()`
    - `UserAttributeManager::eraseUpdateVersion()`
    - `UserAttributeManager::serializeAttributes()`
    - `UserAttributeManager::unserializeAttributes()`
  - `../sdk/include/mega/user_attribute_types.h`
    - attribute names
    - attribute scopes
    - versioning rules
    - max-size limits
  - `../sdk/src/commands.cpp`
    - `CommandGetUA::procresult()`
    - `CommandPutUA::procresult()`
    - `CommandPutUAVer::procresult()`
    - `CommandDelUA::procresult()`
- Key/authring reconstruction and contact-key tracking:
  - `../sdk/src/megaclient.cpp`
    - `MegaClient::loadAuthrings()`
    - `MegaClient::fetchContactsKeys()`
    - `MegaClient::fetchContactKeys(User*)`
    - `MegaClient::trackKey(attr_t, handle, const std::string&)`
    - `MegaClient::trackSignature(attr_t, handle, const std::string&)`
    - `MegaClient::updateAuthring(AuthRing*, attr_t, bool, handle)`
    - the `mKeyManager.setAuthRing(...)` / `mKeyManager.setAuthCU255(...)` bridge points used after authring reconstruction and during migration to `^!keys`

For implementation, treat these as the primary C++ ground-truth anchors:

- durability boundaries: `initsc()`, `updatesc()`, `fetchsc()`
- contact and PCR record shapes: `User::{serialize,unserialize}` and `PendingContactRequest::{serialize,unserialize}`
- attribute freshness/version behavior: `CommandGetUA::procresult()`, `CommandPutUA::procresult()`, `CommandPutUAVer::procresult()`, `CommandDelUA::procresult()`, plus `UserAttributeManager::*`
- derived key/authring runtime behavior: `loadAuthrings()`, `fetchContactsKeys()`, `trackKey()`, `trackSignature()`, `updateAuthring()`

The point of Story 8B is not to clone every upstream record type immediately. The point is to stop leaving these secondary state families architecturally homeless in Rust.

---

## Scope

In scope:

- introduce `src/session/runtime/state/` as the architectural home for secondary authenticated engine state
- define one session-owned `SecondaryStateRuntime` that becomes the internal owner for live-wired domains
- define explicit internal runtime owners for:
  - contact directory state
  - pending-contact-request state homes
  - current-user raw user-attribute cache/version state
  - key/authring/security coordination state
- add a dedicated persistence domain for secondary state through `src/session/runtime/persistence.rs`
- define persistence granularity and restore/commit boundaries for those domains
- migrate the first live-wired Rust-supported domains behind that ownership
- add restart and fallback coverage for the domains that become durable in this story
- define what belongs here versus later feature epics

Out of scope:

- node/tree/outshare state
- alert persistence or public alert APIs
- transfer runtime or transfer durability
- sync/backup runtime state
- mount/FUSE inode/runtime state
- public event or callback staging
- chat and meetings state families
- sets and set-element state families
- business/subuser/admin state families
- media, preview, thumbnail, or metadata side pipelines
- decoding or owning sync/backup business semantics for raw cached attributes such as `*~jscd`
- new public APIs for pending contact requests, chat, sets, or business features

This is a secondary engine-state ownership story, not a silent umbrella for every feature family the SDK caches.

---

## Story 1, Story 3, Story 4B, And Story 4C Constraints

Story 8B must preserve these existing architectural decisions:

- secondary durable state domains live under `src/session/runtime/state/`
- `Session` remains the engine root
- `Session` should own one long-lived `SecondaryStateRuntime` instance for these domains
- persistence backend ownership remains under `src/session/runtime/persistence.rs`
- production durability must build on the Story 4B backend and Story 4C hardening path rather than bypassing them
- tree/outshare durability remains owned by Story 4 and Story 4C
- alerts remain owned by Story 3
- transfer durability remains owned by Story 5
- public API stays unchanged in this story

If implementation pressure suggests folding this work into tree persistence, transfer persistence, or public callback APIs, Story 1 must be revised first.

---

## SDK Parity Target

The Rust architecture should align with the SDK in these ways:

1. Non-node client state families are explicit engine-owned domains, not loose helper caches.
2. Durable user/contact state is persisted through the same backend owner as other client state.
3. Contact directory state is distinct from node-tree state, even if contact nodes exist in the tree.
4. Contacts and pending-contact requests follow the SDK's record-family persistence model rather than being hidden inside an unrelated aggregate blob.
5. Current-user raw user-attribute cache/version state is explicit and durable enough to support restart-safe higher-level logic.
6. Key/authring/security coordination is engine state layered on top of cached attributes, not a hidden collection of side flags.
7. Broader feature-family caches such as chats and sets are recognized as real upstream state, but are kept out of this story unless and until their own feature epics own them.

Rust should stay idiomatic:

- it does not need to mimic the SDK’s exact `user_map`, `umindex`, or `handlepcr_map` types
- it does need equivalent ownership boundaries

---

## Current Rust Secondary-State Families

Story 8B is specifically about these existing or directly-adjacent Rust state families.

| State family | Current owner(s) | Current durable behavior | Story 8B role |
|--------------|------------------|--------------------------|---------------|
| Contact directory cache | `src/session/core.rs`, `src/session/action_packets.rs` | in-memory only | live-wire in this story |
| Pending contact request domain | not yet implemented in Rust public/runtime flows | none | define explicit home and durable model here, even if first live wiring stays narrow |
| Raw user-attribute cache/version state | `src/session/core.rs`, `src/session/auth.rs`, `src/session/action_packets.rs`, `src/session/key_sync.rs` | remote fetch/update only, no local durable owner | live-wire in this story |
| Key/authring/security coordination | `src/session/key_sync.rs`, `src/session/sharing.rs`, actor-side key persist flow | remote `upv`/attribute persistence plus local in-memory flags | move under explicit runtime ownership in this story |
| Alerts | Story 3 ownership | already durable | excluded |
| Tree/outshare state | Stories 4 and 4C ownership | already durable | excluded |
| Transfer resume/runtime state | Stories 3, 4B, and 5 ownership | already durable or planned | excluded |

Important distinction:

- contact nodes in the cached node tree remain part of tree/query ownership
- contact directory/account relationship state belongs to secondary state ownership

Those are related but not the same domain.

---

## Upstream Breadth And Scope Discipline

The upstream SDK persists and restores a wider band of client state than Rust currently does:

- `CACHEDUSER`
- `CACHEDPCR`
- `CACHEDALERT`
- `CACHEDCHAT`
- `CACHEDSET`
- `CACHEDSETELEMENT`
- status-table records such as business/account status

Story 8B must be disciplined about that breadth.

Owned here:

- user/contact directory state
- pending-contact-request state homes
- raw user-attribute cache/version state
- key/authring/security coordination state

Explicitly not owned here:

- alerts, because Story 3 already owns them
- nodes/outshares, because Stories 4 and 4C already own them
- chats/meetings, because those are a broader feature family
- sets/set elements, because those are a broader feature family
- business/subuser/admin state, because that is a separate product/admin family
- decoded sync-desired-state, backup, and other sync-owned attribute semantics, because those belong under sync/backup ownership
- side-service/media/preview-related state, because those belong to later service/pipeline stories

If a future feature epic needs durable state for chats, sets, business state, or other product families, it should reuse the architectural pattern created here rather than silently extending Story 8B.

---

## Design Decisions

### Decision 1. Secondary state lives under `src/session/runtime/state/`

Why:

- Story 1 already fixed this as the long-term home
- these domains are session-engine concerns, not filesystem or public-adapter concerns
- keeping them under `session` matches both current Rust reality and upstream client ownership

Consequence:

- Story 8B should introduce `src/session/runtime/state/`
- `Session` should own one long-lived `SecondaryStateRuntime` instance, just as it already owns other runtimes
- direct ownership should move out of incidental `Session` field groupings into that runtime for live-wired domains

### Decision 2. Contact directory state is not the same as contact nodes

Why:

- the cached tree may expose contact nodes for browsing convenience
- account relationship state, contact metadata, and future pending-contact-request state belong to a user/contact domain, not to tree ownership

Consequence:

- Story 8B owns the contact directory state family
- Story 4 and Story 8 continue to own tree/query semantics over node objects

### Decision 3. Raw user-attribute cache/version state is the durable substrate

Why:

- current Rust key/security logic already depends on cached raw attribute bytes and versions
- upstream user-attribute state is a core engine concern
- persisting only decoded higher-level structures would lose the canonical wire-facing cache

Consequence:

- Story 8B should make current-user raw attribute cache/version state durable
- supported attributes in the first slice should match the set Rust already depends on

### Decision 4. Contacts and PCRs should persist as record families, while current-user attr/security state may persist as a dedicated singleton domain

Why:

- the SDK stores users and pending-contact requests as separate cached records rather than one catch-all client blob
- current Rust contact and PCR domains are set-like collections, while current-user attribute/security cache is singleton state for the authenticated account
- mirroring that split is more idiomatic in Rust than forcing all secondary state through one opaque JSON document

Consequence:

- contact directory state should be persisted as contact-record families
- pending-contact-request state should be persisted as PCR-record families
- current-user raw attribute/version state plus explicitly durable warning markers may be persisted as one dedicated self-state domain
- Story 8B should not make one aggregate `PersistedSecondaryState` blob the only durable truth

### Decision 5. Key/security coordination is reconstructed from cached attribute substrate, not given a second durable truth

Why:

- `KeyManager`, authring-style state, pending-key fetch logic, and downgrade detection are semantics layered on top of persisted/cached user attributes
- treating them as an unrelated persistence silo would duplicate ownership and blur boundaries

Consequence:

- Story 8B should define a dedicated key/security runtime owner
- its durable source of truth should be the supported current-user attribute cache/version domain plus any explicitly durable warning/marker fields
- restart restore should rebuild `KeyManager`, authring state, warnings, manual-verification state, backups blob, pending share-key state, and `last_keys_blob_b64` from cached `^!keys` and companion supported attributes rather than persisting a second serialized `KeyManager` record
- `last_keys_blob_b64` is derived cache state and should be recomputed during restore, not persisted independently

### Decision 6. Dirty/inflight mechanics are runtime-only, not durable truth

Why:

- fields such as `keys_persist_dirty` and `keys_persist_inflight` describe current-process work
- persisting them would create stale restart behavior and couple durable state to actor scheduling details

Consequence:

- Story 8B should not persist dirty/inflight booleans
- `pending_keys_token` likewise remains runtime-only process coordination state
- they remain runtime-only fields under the new state runtime

### Decision 7. Pending contact requests belong architecturally here even if first live wiring is limited

Why:

- upstream `pcrindex` is part of `MegaClient` durable breadth
- current Rust does not yet expose full pending-contact-request features
- if Story 8B ignores the domain completely, later collaboration work will still have no home

Consequence:

- Story 8B should define `PendingContactRequest` durable/runtime ownership here
- the first live slice must provide real runtime and persistence support for PCR records, including startup restore/clear and round-trip tests, even if normal production flows still keep the set empty because public PCR features are not yet rolled out
- Story 8B does not require public PCR APIs or complete PCR action-packet handling

### Decision 8. Do not overload `PersistedEngineState` or replace SDK-shaped record families with one aggregate secondary blob

Why:

- Story 3 already uses `PersistedEngineState` for SC, alerts, and tree-oriented engine metadata
- secondary contact/attribute/key domains are a different family and should be independently loadable and clearable
- the SDK persists users and PCRs as independent cached record families rather than inside one monolithic "secondary state" record
- a dedicated domain is more idiomatic in Rust than turning one aggregate blob into a catch-all

Consequence:

- Story 8B should add domain-specific persistence methods such as:
  - `load_contact_records(...)`
  - `save_contact_records(...)`
  - `clear_contact_records(...)`
  - `load_pending_contact_records(...)`
  - `save_pending_contact_records(...)`
  - `clear_pending_contact_records(...)`
  - `load_self_user_state(...)`
  - `save_self_user_state(...)`
  - `clear_self_user_state(...)`
- the backend may still store those records in the same database, but the runtime boundary should stay domain-specific

### Decision 9. `*~jscd` is in scope only as raw cached attribute substrate, not as sync/backup-owned decoded policy

Why:

- current Rust already depends on `*~jscd` as part of the supported attribute cache set
- upstream caches raw user attributes as part of user state, even when later subsystems own their interpretation
- the contradiction is only resolved if Story 8B owns the bytes/version cache while later sync/backup stories own the decoded meaning

Consequence:

- Story 8B may persist raw `*~jscd` bytes and version token inside the current-user attribute domain
- Story 8B must not claim ownership of decoded sync/backup configuration semantics or lifecycle policy
- later sync/backup stories should consume that raw cached value through the secondary-state runtime rather than introducing a second cache

### Decision 10. Restore fallback should be isolated to the smallest affected secondary domain

Why:

- Story 4B already established that malformed persisted rows should behave like recoverable cache misses rather than fatal startup poison
- row-family storage makes it practical to recover contacts, PCRs, and self-state independently
- this is a better Rust fit than letting one malformed row wipe unrelated durable domains

Consequence:

- malformed contact or PCR rows should be treated as recoverable cache misses for the affected record or record family, not as fatal session-startup errors
- malformed current-user self-state should clear only that self-state domain and fall back to remote refetch behavior
- no secondary-state restore failure should poison authenticated session startup or tree-state restore

### Decision 11. This story owns state homes, not every feature that will later use them

Why:

- the user goal is SDK-shaped structure for future porting, not accidental feature creep
- chats, sets, business state, and side-service state need architectural homes too, but they are different feature families

Consequence:

- Story 8B should define the secondary account/session state band only
- later feature epics should plug into this pattern, not get smuggled into this story

---

## Recommended Rust Shape

The first implementation slice should aim for a small but real internal shape such as:

```rust
// src/session/runtime/state/mod.rs

pub(crate) mod attributes;
pub(crate) mod contacts;
pub(crate) mod keys;
pub(crate) mod pending_contacts;

pub(crate) struct SecondaryStateRuntime {
    pub(crate) self_attributes: SelfUserAttributeStateRuntime,
    pub(crate) contacts: ContactStateRuntime,
    pub(crate) pending_contacts: PendingContactStateRuntime,
    pub(crate) keys: KeyStateRuntime,
}
```

And durable models along the lines of:

```rust
pub(crate) struct PersistedSelfUserState {
    pub(crate) schema_version: u32,
    pub(crate) values: HashMap<String, Vec<u8>>,
    pub(crate) versions: HashMap<String, String>,
    pub(crate) keys_downgrade_detected: bool,
}

pub(crate) struct PersistedContactRecord {
    pub(crate) handle: String,
    pub(crate) email: Option<String>,
    pub(crate) status: i64,
    pub(crate) last_updated: i64,
}

pub(crate) struct PersistedPendingContactRecord {
    pub(crate) id: String,
    pub(crate) is_outgoing: bool,
    pub(crate) source_email: Option<String>,
    pub(crate) target_email: Option<String>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) message: Option<String>,
}
```

The exact names may differ, but the ownership split should preserve the distinction between:

- contact directory state
- pending-contact-request state
- current-user raw user-attribute state
- higher-level key/security runtime state

And the persistence split should preserve these SDK-shaped expectations:

- contacts are durable as contact-record families
- PCRs are durable as PCR-record families
- current-user raw attribute cache and durable warning markers are durable as a self-state domain
- runtime reconstruction derives higher-level key/security state from that self-state instead of persisting a second serialized `KeyManager`

This is the Rust-idiomatic equivalent of giving secondary `MegaClient` state families real subsystem homes without reproducing every upstream container type.

---

## First Live-Wired Domain Set

The first implementation slice should live-wire these domains:

1. Contact directory cache
   - current `Contact` records
   - current AP-driven update behavior
   - restart-safe restore/fallback behavior

2. Supported current-user attribute cache/version state
   - the attributes Rust already depends on today:
     - `^!keys`
     - `*keyring`
     - `*~usk`
     - `*~jscd` as raw cached bytes/version only
     - `+puCu255`
     - `+puEd255`
     - `+sigCu255`
     - `+sigPubk`

3. Security warning/marker state that is already user-visible or restart-relevant
   - `keys_downgrade_detected`
   - restart reconstruction of `KeyManager`, authrings, warnings, manual-verification state, pending share-key state, and `last_keys_blob_b64` from cached `^!keys`

4. Pending-contact-request state homes
   - real durable model and persistence round-trip support
   - startup restore/clear path for empty or test-populated PCR sets
   - no requirement for public PCR APIs or fully live production mutation sources yet

The first slice should define, but does not need to fully live-wire:

- richer user-directory indexing beyond the current `contacts` map

That keeps the story disciplined while still preventing future PCR work from landing into a void.

---

## Public API Preservation Rules

These are binding for Story 8B:

1. `SessionHandle` public contact APIs remain stable.
2. `keys_downgrade_detected()` remains stable.
3. No new public pending-contact-request API is introduced by this story unless separately approved.
4. No public chat, sets, or business APIs are introduced by this story.

---

## Durable State Rules

These are binding for Story 8B:

1. secondary durable state must go through `src/session/runtime/persistence.rs`
2. `Session` should own one long-lived `SecondaryStateRuntime` instance and route live-wired secondary-state mutations through it rather than keeping parallel direct ownership indefinitely.
3. contact and pending-contact-request domains should use SDK-shaped record-family persistence rather than one opaque aggregate secondary-state blob.
4. current-user supported attribute cache/version state plus `keys_downgrade_detected` should use a dedicated self-state domain.
5. startup restore should load secondary state during authenticated-session initialization as part of the same persistence window as engine-state restore, but secondary-state cache misses or corruption must remain recoverable.
6. successful full refresh or other authenticated full-state replacement that updates contact/self-attribute truth should capture the current secondary-state snapshot.
7. successful action-packet batches that modify contacts or supported current-user attribute versions should update the relevant secondary-state domains.
8. successful local key/security mutations that already complete their remote persistence path, such as `^!keys` updates and local warning/manual-verification setters, should refresh the durable self-state after the remote write succeeds.
9. dirty/inflight scheduling flags and `pending_keys_token` remain runtime-only.
10. raw attribute cache/version state is the durable substrate for key/security coordination.
11. `keys_downgrade_detected` may be persisted as durable warning state.
12. `KeyManager`, authring state, warnings, manual-verification state, backups blob, pending share-key state, and `last_keys_blob_b64` should be reconstructed from cached supported attributes on restore rather than persisted as a second durable truth.
13. malformed contact or PCR rows must fall back cleanly at the smallest affected record or domain instead of poisoning session startup.
14. malformed current-user self-state must fall back cleanly by clearing only that self-state domain and relying on remote refetch behavior.
15. broader feature-family state must not be silently folded into the same persisted model just because the backend can store it.
16. raw `*~jscd` bytes/version may be cached here, but decoded sync/backup semantics remain out of scope for Story 8B.

---

## What Belongs Here Versus Later Feature Epics

Belongs here:

- account/session-side contact directory state
- pending-contact-request state homes
- current-user raw user-attribute cache/version state
- key/authring/security coordination that already powers current Rust session logic

Belongs to later feature epics:

- collaboration request/lifecycle features built on top of PCR state
- chat/meetings state and APIs
- sets/set-element state and APIs
- business/subuser/admin state
- decoded sync/backup-specific semantics built on raw user attributes such as `*~jscd`
- side-service/media/preview pipeline state

Story 8B should give those later epics stable subsystem homes to depend on where appropriate, but it must not implement those product families itself.

---

## Affected Modules

Expected primary touch points:

- `src/session/core.rs`
- `src/session/action_packets.rs`
- `src/session/key_sync.rs`
- `src/session/sharing.rs`
- `src/session/runtime/persistence.rs`
- `src/session/runtime/state/mod.rs`
- `src/session/runtime/state/contacts.rs`
- `src/session/runtime/state/attributes.rs`
- `src/session/runtime/state/keys.rs`
- `src/session/runtime/state/pending_contacts.rs`

Potential secondary touch points:

- `src/session/auth.rs`
- `src/session/actor.rs`

---

## Agent-Sized Tasks

### Task 8B.1. Define the secondary-state runtime and persistence domain

Deliverables:

- add `src/session/runtime/state/`
- define a session-owned runtime owner for contacts, pending contacts, self attributes, and keys/security
- define SDK-shaped durable models for contact records, PCR records, and current-user self-state
- add dedicated persistence-runtime methods for contact records, PCR records, and self-state rather than overloading `PersistedEngineState`

### Task 8B.2. Migrate contact directory ownership

Deliverables:

- route contact cache ownership through the new runtime
- move AP-side contact update logic behind that owner
- add capture/restore/fallback coverage for current `Contact` records
- persist contact-directory changes on the same successful refresh/AP boundaries that update the in-memory contact truth

### Task 8B.3. Migrate user-attribute cache/version ownership

Deliverables:

- route supported current-user attribute cache/version logic through the new runtime
- stop mutating loose `user_attr_cache` / `user_attr_versions` maps directly across unrelated modules
- add persistence and malformed-cache fallback coverage
- treat `*~jscd` as raw cached bytes/version only, leaving decoded sync semantics out of scope

### Task 8B.4. Migrate key/security coordination ownership

Deliverables:

- move key/security coordination behind the new runtime owner
- keep dirty/inflight scheduling semantics runtime-only
- define durable handling for `keys_downgrade_detected`
- rebuild runtime key/security state from cached supported attributes on restore instead of persisting a second serialized `KeyManager`
- keep public behavior stable

### Task 8B.5. Define pending-contact-request homes without forcing feature rollout

Deliverables:

- define PCR runtime and durable models
- add real persistence-runtime support, startup restore/clear behavior, and round-trip tests for PCR records even if production flows still keep the set empty
- add explicit comments or scaffolding that future collaboration feature work must use these homes
- do not require public PCR APIs in this story

---

## Acceptance Criteria

Story 8B is complete when:

- `src/session/runtime/state/` exists as the named owner for secondary authenticated engine state
- `Session` owns one long-lived `SecondaryStateRuntime` instance for live-wired domains
- contact directory state no longer relies on incidental ownership in `Session` alone
- supported current-user attribute cache/version state no longer relies on incidental ownership in `Session` alone
- key/security coordination no longer relies on helper-local or actor-local ownership alone
- persistence runtime has explicit domain-specific APIs for contact records, PCR records, and current-user self-state
- contacts and PCRs are not persisted only as one opaque aggregate secondary-state blob
- restart/fallback coverage exists for the live-wired secondary state families
- pending-contact-request state has an explicit architectural home and real durable round-trip/restore path even if public PCR feature delivery remains later
- runtime key/security restore derives from cached supported attributes rather than from a second persisted `KeyManager` blob
- raw `*~jscd` caching is explicitly in scope only as raw attribute substrate, not as sync/backup-owned decoded policy
- the story still does not silently absorb chats, sets, business state, or media/service families

---

## Verification Plan

Story 8B should end with:

- unit tests for contact-state capture/restore/fallback
- unit tests for current-user attribute-cache capture/restore/fallback
- unit tests for key/security-state capture/restore/fallback
- unit tests for PCR-state round-trip and restore/clear behavior
- restart-style tests against the production backend introduced in Story 4B
- validation that malformed secondary-state rows fall back cleanly at the smallest affected record or domain

And, because the story touches Rust source, it must conclude with:

- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`

---

## Completion Notes For Later Stories

After Story 8B:

- collaboration/contact-request feature work should use the new secondary-state homes instead of adding new loose `Session` fields
- future user-attribute-heavy features should extend the attribute-state runtime instead of mutating raw maps across modules
- future key/security work should plug into the key-state runtime instead of expanding actor-local retry state
- later chat, sets, business, or side-service epics should copy the ownership discipline, not extend this story’s scope retroactively

---

Changed file:

- `agents/outputs/architectural_parity_story_8b_secondary_durable_state_domains.md`
