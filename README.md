# Age Inbox Service

A secure, RESTful inbox service written in Rust that allows users to create password-protected encrypted vaults and stream file uploads securely directly to disk.

## Overview

The **Age Inbox Service** is designed as a drop-off encrypted inbox. It utilizes modern cryptography to ensure that uploaded files are securely encrypted at rest without keeping sensitive keys or large files in memory. 

- **Age Encryption:** Uses the [age specification](https://github.com/C2SP/C2SP/blob/main/age.md) powered by the `age` rust crate (specifically `X25519` recipients) for encrypting streams directly.
- **Argon2id Key Derivation:** Cryptographic keys are derived securely from user-provided passwords using Argon2id. Private keys are never persisted to disk.
- **Streaming I/O:** Both encryption and decryption operations are fully streamed. HTTP request bodies are piped directly through the `Encryptor` to disk block-by-block, ensuring O(1) RAM usage regardless of file size.
- **In-Memory Volatility:** When a vault is temporarily unlocked for downloading or listing files, the private key is held in memory for a maximum of 1 hour, and securely zeroed out (`zeroize`) upon expiration or immediate lock.

## Technology Stack

- **[Rust](https://www.rust-lang.org/)** (Edition 2021)
- **[Axum](https://github.com/tokio-rs/axum):** High-performance asynchronous web framework.
- **[Tokio](https://tokio.rs/):** Asynchronous runtime for I/O and streaming operations.
- **[Age](https://crates.io/crates/age):** Streamable, modern encryption.
- **[Argon2](https://crates.io/crates/argon2):** Password hashing and KDF algorithms.

## Endpoints

For a fully interactive schema, explore the OpenAPI 3 specification located in `docs/openapi.yaml`. 

### Vault Operations

- **Create Inbox**
  - `POST /inbox`
  - Body: `{"name": "myvault", "password": "super-secret", "allow_subfolders": false}`
  - *Generates a new `.inbox-age.config` with the vault's derived public footprint.*

- **Upload File (Vault Root)**
  - `POST /inbox/{name}/upload`
  - Body: Raw binary stream (`application/octet-stream`) OR `multipart/form-data` with a `file` field.
  - Metadata (`filename`, `origin`, `extended`) must be sent as multipart fields, not HTTP headers.
  - *Streams the upload through X25519 encryption and saves `.age` and `.meta.age` files.*

- **Upload File (Subfolder)**
  - `POST /inbox/{name}/upload/{path}`
  - Body: Raw binary stream (`application/octet-stream`) OR `multipart/form-data` with a `file` field.
  - Metadata (`filename`, `origin`, `extended`) must be sent as multipart fields, not HTTP headers.
  - *Stores encrypted files in a nested path when `allow_subfolders` is enabled.*

- **Unlock Vault**
  - `POST /inbox/{name}/unlock`
  - Body: `{"password": "super-secret"}`
  - *Derives the private vault key and temporarily caches it in memory (1 hr expiration).*

- **Lock Vault**
  - `POST /inbox/{name}/lock`
  - *Purges the private key early from in-memory state.*

- **List Files**
  - `GET /inbox/{name}/list`
  - *Lists available encrypted files inside an unlocked vault.*

- **Download File**
  - `GET /inbox/{name}/download/{path}`
  - *Returns only the decrypted file content (not metadata sidecars).* 

- **Get File Metadata**
  - `GET /inbox/{name}/metadata/{path}`
  - *Returns decrypted metadata JSON for the encrypted file path.*

## Deployment

The repository includes a complete `Dockerfile` and `docker-compose.yml` to set up the inbox service with an externally mounted volume for the vaults.

### Docker Compose

The simplest way to start the service is via Docker Compose:

```bash
docker-compose up --build -d
```

This will run the Axum API on port `3000` and permanently mount the host's local `./vaults` directory into the container to ensure encrypted files survive restarts.

### Native Execution

If you prefer running via Cargo directly, it runs on HTTP by default:

```bash
cargo run --release
```

The application will listen on HTTP `0.0.0.0:3000` and create a local `vaults` folder. 

## Environment Variables

The server currently supports CORS configuration via environment variables.

- `CORS_ALLOWED_ORIGINS` (optional): Comma-separated list of allowed origins (`https://app.example.com,http://localhost:5173`) or `*`.
  - If this variable is not set, CORS headers are not added.
- `CORS_ALLOWED_METHODS` (optional): Comma-separated methods (e.g. `GET,POST,OPTIONS`) or `*`.
- `CORS_ALLOWED_HEADERS` (optional): Comma-separated request headers allowed in preflight (e.g. `content-type,x-file-origin,x-filename,x-extended-metadata`) or `*`.
- `CORS_EXPOSE_HEADERS` (optional): Comma-separated response headers exposed to browsers.
- `CORS_ALLOW_CREDENTIALS` (optional): `true/false` (also accepts `1/0`, `yes/no`, `on/off`).
- `CORS_MAX_AGE_SECS` (optional): Preflight cache max age in seconds.

Example:

```bash
CORS_ALLOWED_ORIGINS=http://localhost:4200,https://app.example.com \
CORS_ALLOWED_METHODS=GET,POST,OPTIONS \
CORS_ALLOWED_HEADERS=content-type,x-file-origin,x-filename,x-extended-metadata \
CORS_ALLOW_CREDENTIALS=false \
CORS_MAX_AGE_SECS=600 \
cargo run --release
```

#### Enabling HTTPS
You can launch the server in HTTPS mode by passing the `--https` flag:

```bash
cargo run --release -- --https
```

Upon the first startup with `--https`, it will automatically generate a self-signed `cert.pem` and `key.pem` in the current directory.

### Certificate Pinning

Since the API generates a steady `cert.pem` on its first run (and uses it for all subsequent runs), you can implement **Certificate Pinning** on your clients. Pinning the exact public key or certificate hash of this `cert.pem` protects against Man-in-the-Middle (MITM) attacks.
