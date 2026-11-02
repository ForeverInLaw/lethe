# Lethe

Open-core deletion engine for Untrace. Adapters, orchestration,
and crypto live here so behavior is verifiable — **no crate in this repo may
depend on `untrace`.**

## Crates

| Crate | Role |
|---|---|
| `lethe-adapter` | The platform contract (transport-free): `PlatformAdapter`, `AuthProvider`, types. |
| `lethe-net` | The single egress chokepoint + allowlist + request log. |
| `lethe-store` | SQLCipher run-state (checkpoints, activity log, receipts). |
| `lethe-crypto` | secretstream archive container + Ed25519 receipts. |
| `lethe-core` | Two-phase pipeline, per-account scheduler, filter predicate, run control. |
| `adapters/bluesky` | M1 tracer (AT Protocol). |
| `adapters/vk` | M1 #2 (stub). |
| `adapters/telegram` | M1 #3 (TDLib-gated bridge; one live run passed on a test group). |
| `lethe-cli` | Headless vertical runner — reproducible-build & zero-egress CI target. |

## Invariants

- **One-way deps:** `untrace/* → lethe/*`, never the reverse. `lethe-cli` builds
  and runs a full vertical with no `untrace` dependency.
- **dry-run == executed** is structural (two-phase snapshot; `lethe-core::pipeline`).
- **Idempotent resume:** key = `(run_id, platform_id)`; already-gone ⇒ deleted.
- **No own sockets:** adapters route through `lethe_net::Egress` only.

## Status

M1 scaffold with the Bluesky tracer live. Telegram has a narrow TDLib bridge for
chat-scope discovery, own-message page enumeration, media file download, and
message batch deletion behind feature gates:

- default builds do not link native TDLib;
- `tdlib-docs` is for `cargo check` against generated TDLib bindings;
- live builds must explicitly choose `tdlib-local` or `tdlib-download`.

Current verification baseline:

- `cargo check --workspace`
- `cargo check -p lethe-telegram --features tdlib-docs`
- `cargo test --workspace`
- `cargo test -p lethe-telegram --features tdlib-download`

Telegram has passed live runs on a test group, including one with media files.
Message text, media captions and media files go into the backup before the delete; a
message whose file cannot be fetched stays where it is. The backup also keeps each
message whole as TDLib returned it, which is where polls, locations and contacts live.
A message TDLib does not fully hand over is deleted only if the person agrees to that.

A network problem gets three retries, about 40 seconds in all. A file that still did not
reach the backup keeps its item, and `Store::unsaved_files` lists it. `Store::retry_unsaved_files`
opens a follow-up run for those items. With `RunRequest::allow_lost_files`, an item goes without
a file when the adapter reports `AdapterError::FileRefused`, and its backup entry says so. Any
other download error keeps the item.

In the desktop app, a Bluesky post goes into the backup with its text and every file
it owns: images, video, captions and link card thumbnails, along with the whole record
the platform returned, so alt text, links and quotes stay too. A post whose file cannot
be fetched stays where it is, and one with a broken file reference is deleted only if
the person agrees to that. This has passed a live cleanup of posts with files.

`lethe_core::archive::ArchiveExport` turns a backup back into a plain folder: readable
text, every record in full, and the files under their original names. A damaged or
unsealed backup exports up to the point it breaks. The folder is not encrypted.

External contributions are not accepted yet: a CLA comes first.

License: AGPL-3.0-only.
