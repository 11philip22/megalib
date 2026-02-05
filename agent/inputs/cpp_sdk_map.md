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
- `Node`, `NodeCore`, `NewNode`, `PublicLink`.
- `NodeManager`: node cache with LRU support.
- `File`, `FileFingerprint`, `LocalPath`.

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
- `Share`, `ShareNodeKeys`, `PublicLink`.

Files:
- `sdk/include/mega/share.h`
- `sdk/src/share.cpp`
- `sdk/include/mega/sharenodekeys.h`
- `sdk/src/sharenodekeys.cpp`

## Key Management / Authrings
- `KeyManager` (for ^!keys container, pending shares, trust flags).

Files:
- `sdk/include/mega/megaclient.h` (KeyManager definition)
- `sdk/src/megaclient.cpp`
- `sdk/src/tlv.cpp`

## HTTP / Network
- `HttpReq`/`HttpIO` and TLS pinning constants.

Files:
- `sdk/include/mega/http.h`
- `sdk/src/http.cpp`
- `sdk/src/mega_http_parser.cpp`

## Crypto
- AES/RSA/Ed25519/Cu25519 primitives via Crypto++ and libsodium.

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
