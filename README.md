# Lethe

Open-core deletion engine for [Untrace](../untrace). Adapters, orchestration,
and crypto live here so behavior is verifiable — **no crate in this repo may
depend on the proprietary `untrace` tree.**

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
| `adapters/telegram` | M1 #3 (stub, BYO api_id). |
| `lethe-cli` | Headless vertical runner — reproducible-build & zero-egress CI target. |

## Invariants

- **One-way deps:** `untrace/* → lethe/*`, never the reverse. `lethe-cli` builds
  and runs a full vertical with no `untrace` dependency.
- **dry-run == executed** is structural (two-phase snapshot; `lethe-core::pipeline`).
- **Idempotent resume:** key = `(run_id, platform_id)`; already-gone ⇒ deleted.
- **No own sockets:** adapters route through `lethe_net::Egress` only.

## Status

M1 scaffold. Contract crates (`lethe-adapter`, `lethe-net`, `filter`, `scheduler`)
are implemented; pipeline Phase 1 is wired; adapter bodies and crypto/store
internals are `todo!()` stubs to be filled following the tracer-bullet sequence
in `../untrace/.claude/plans` (or the project plan).

License: AGPL-3.0-only.
