# SDK-Level API

## Overview
This document describes the Rust surface users call. The SDK centers around `Session` for authenticated operations and a separate `public` module for unauthenticated link access. Low-level HTTP and API mechanics are available via `http::HttpClient` and `api::ApiClient`.

Evidence:
- `src/session/session.rs::Session`
- `src/public.rs::get_public_file_info`
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`

## Client Responsibilities
- `Session` manages authentication state, cached nodes, transfers, and account operations.
- `ApiClient` performs MEGA JSON API requests and manages retry/backoff for `EAGAIN`.
- `HttpClient` performs JSON POSTs and manual redirect handling.

Evidence:
- `src/session/session.rs::Session`
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`

## Authentication And Registration
- `Session::login`/`login_with_proxy` authenticate and build an authenticated session.
- `register` returns `RegistrationState` that is serialized between steps; `verify_registration` completes signup using the email link.
- `Session::save`/`load` persist and restore sessions on disk.

Evidence:
- `src/session/session.rs::login`
- `src/session/registration.rs::register`
- `src/session/registration.rs::RegistrationState`
- `src/session/session.rs::save`

## Filesystem Operations
- Cache refresh: `Session::refresh` fetches the full node tree; `list` and `stat` operate on cached paths.
- Browsing: `list`, `stat`, `get_node_by_handle`, `list_contacts`, `node_has_ancestor`.
- Mutations: `mkdir`, `mv`, `rename`, `rm`.
- Quota: `quota` returns `Quota`.

Evidence:
- `src/fs/operations/tree.rs::refresh`
- `src/fs/operations/browse.rs::list`
- `src/fs/operations/dir_ops.rs::mkdir`
- `src/fs/operations/quota.rs::quota`

## Transfers And Links
- Downloads: `download`, `download_with_offset`, `download_to_file` (resume uses temp files when enabled).
- Uploads: `upload`, `upload_resumable`, `upload_from_bytes`, `upload_from_reader`, `upload_node_attribute`.
- Export: `export` and `export_many` generate public links for files/folders.

Evidence:
- `src/fs/operations/download.rs::download`
- `src/fs/operations/upload.rs::upload`
- `src/fs/operations/export.rs::export`

## Transfer Configuration And Progress
- Resume support: `set_resume`, `is_resume_enabled`.
- Parallelism: `set_workers`, `workers` used by upload/download chunking.
- Progress callbacks: `watch_status`, `clear_status`, `ProgressCallback`/`TransferProgress`.
- Previews: `enable_previews` toggles thumbnail generation during uploads.

Evidence:
- `src/session/session.rs::set_resume`
- `src/session/session.rs::set_workers`
- `src/session/session.rs::watch_status`
- `src/session/session.rs::enable_previews`
- `src/progress.rs::ProgressCallback`

## Public Link Operations
- `parse_mega_link` and `parse_folder_link` parse public links.
- `get_public_file_info` and `download_public_file` fetch metadata and download file content without login.
- `open_folder` returns `PublicFolder` for listing and downloading shared folders.

Evidence:
- `src/public.rs::parse_mega_link`
- `src/public.rs::get_public_file_info`
- `src/public.rs::open_folder`

## HTTP Behavior (User-Visible)
- Base API URL is `https://g.api.mega.co.nz/cs`.
- Authenticated requests add `sid` query parameter from session.
- Requests are JSON POSTs with `Content-Type: application/json`.
- `ApiClient::request` retries on `EAGAIN` with exponential backoff; `HttpClient` follows redirects manually (up to 10).

Evidence:
- `src/api/client.rs::API_URL`
- `src/api/client.rs::ApiClient`
- `src/http.rs::HttpClient`
