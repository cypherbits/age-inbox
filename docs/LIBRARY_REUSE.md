# Reusable Library Plan (No REST)

## What Was Refactored

The project now includes a reusable core module at:

- `src/inbox_core.rs`

This module contains inbox-domain and cryptographic logic without REST concerns:

- Vault name/path validation
- Vault config read/write (`.inbox-age.config`)
- Vault creation from password-derived keys
- Unlock/lock lifecycle with in-memory identities and expiration
- Age stream encryption/decryption helpers
- Metadata encryption/decryption helpers

## Public Library Surface

The core is exported from:

- `src/lib.rs` via `pub mod inbox_core;`

So external Rust projects can depend on this crate and import:

```rust
use age_inbox::inbox_core;
```

or specific items:

```rust
use age_inbox::inbox_core::{create_vault, unlock_vault, read_vault_config_file};
```

## Current Architecture

- `inbox_core` is framework-agnostic and reusable.
- `api/*` acts as transport adapters (HTTP), mapping errors and payloads.
- `api/create_inbox`, `api/unlock`, `api/lock`, and `api/config` now delegate core logic to `inbox_core`.

## Preparing for crates.io Publication

To publish this as a reusable crate cleanly:

1. Keep the core API stable under `inbox_core`.
2. Add rustdoc examples for primary functions (`create_vault`, `unlock_vault`, encryption helpers).
3. Optionally gate REST code behind a Cargo feature (for example `rest-api`) and keep core always enabled.
4. Fill `Cargo.toml` package metadata (`description`, `license`, `repository`, `readme`, `keywords`, `categories`).
5. Run:
   - `cargo check`
   - `cargo test`
   - `cargo package`
6. Publish with:
   - `cargo publish`

## Optional Next Refactor

For cleaner packaging, split into two crates in one workspace:

- `age-inbox-core` (pure reusable logic)
- `age-inbox-server` (Axum REST adapter that depends on core)

This is the most typical layout when the goal is long-term reusable cryptographic domain logic plus a separate HTTP service.
