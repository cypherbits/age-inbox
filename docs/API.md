# API Reference

Endpoint-by-endpoint reference for the Age Inbox Service REST API.

- Machine-readable contract: [`openapi.yaml`](openapi.yaml)
- Protocol, naming rules and step-by-step flows: [`PROTOCOL.md`](PROTOCOL.md)
- Internal design: [`ARCHITECTURE.md`](ARCHITECTURE.md)

## Conventions

| Aspect | Value |
|--------|-------|
| Base URL | `http(s)://<host>:<port>` (default `http://0.0.0.0:3000`) |
| Control bodies | `application/json` |
| Uploads | `multipart/form-data` |
| File responses | `application/octet-stream` |
| Error bodies | `application/json` with `{ "error": "<message>" }` (handler-generated; extractor rejections and `416` are plain text) |
| Auth | No transport-level auth; decrypted reads and `delete` require an unlock session |

> The `info.version` field in `openapi.yaml` versions the **REST contract**, not the crate
> (`age-inbox-server` / `age-inbox-core` carry their own Cargo versions, currently `0.1.0`).

## Endpoint summary

| Method | Path | Permission | Unlock | Purpose |
|--------|------|-----------|--------|---------|
| `POST` | `/inbox` | — | No | Create a vault |
| `GET` | `/inbox/{name}/config` | — | No | Read public vault policy |
| `POST` | `/inbox/{name}/upload` | `allow_upload` | No | Upload to the vault root |
| `POST` | `/inbox/{name}/upload/{path}` | `allow_upload`, `allow_subfolders` | No | Upload into a subfolder |
| `POST` | `/inbox/{name}/unlock` | `allow_lock_unlock` | No | Open a 1-hour session |
| `POST` | `/inbox/{name}/lock` | `allow_lock_unlock` | No | Close the session |
| `GET` | `/inbox/{name}/list` | `allow_list` | **Yes** | List files with decrypted metadata |
| `GET` | `/inbox/{name}/metadata/{path}` | `allow_metadata` | **Yes** | Read one file's decrypted metadata |
| `GET` | `/inbox/{name}/download/{path}` | `allow_download` | **Yes** | Download decrypted content |
| `DELETE` | `/inbox/{name}/delete/{path}` | `allow_delete` | **Yes** | Delete a file |
| `GET` | `/inbox/{name}/raw/list` | `allow_list` | No | List encrypted files |
| `GET` | `/inbox/{name}/raw/download/{path}` | `allow_download` | No | Download ciphertext |
| `DELETE` | `/inbox/{name}/raw/delete/{path}` | `allow_delete` | No | Delete a file while locked |

Path parameters `{name}` and `{path}` are validated before any filesystem access:

- `name`: non-empty, no `/`, no `\`, no `..`.
- `path`: no `..`, no leading `/`, no `\`. (Empty segments and `.` are not normalised away.)

Both are rejected with `400 Invalid name or path`.

## Error model

Handler-generated errors use `{ "error": "<message>" }`:

| Status | Typical message | Cause |
|--------|-----------------|-------|
| `400` | `Invalid vault name` / `Invalid name or path` | Failed name/path validation |
| `400` | `Path must point to an encrypted file (.age)...` | Path not ending in `.age`, or pointing at `.meta.age` |
| `400` | `Invalid multipart: ...` / `Missing 'file' field in multipart form` | Malformed or incomplete upload |
| `400` | `Missing filename: ...` | No usable filename in the `filename` field or file part |
| `401` | `Invalid password` | Unlock with a wrong password |
| `401` | `Vault is locked` / `Vault unlock expired` | Read operation without a live session |
| `403` | `Permission denied for this operation` | Vault policy disables the operation |
| `403` | `Subfolders not allowed by vault config` | Path upload with `allow_subfolders: false` |
| `403` | `Vault is locked` | `delete` (decrypted) without a session entry |
| `404` | `Vault not found` / `Vault config missing` | Missing vault directory or `.inbox-age.config` |
| `404` | `File not found` / `Metadata not found` | Missing payload or sidecar |
| `404` | `Vault not unlocked` | `lock` called with nothing to lock |
| `409` | `Vault already exists` | Duplicate `POST /inbox` |
| `413` | `Field '...' exceeds the 64KB limit` | Non-file multipart field too large |
| `415` | `Content-Type must be multipart/form-data` | Upload with a non-multipart body |
| `416` | `Range not satisfiable` (**plain text**) | Unsatisfiable `Range` header |
| `422` | Axum JSON rejection (**plain text**) | Structurally invalid JSON, e.g. unknown field |
| `500` | I/O, crypto or serialization message | Failure reading/writing/decrypting |

Notes:

- Rejections produced by Axum before a handler runs (JSON syntax/type errors, unknown routes,
  method mismatches) do **not** use the `{ "error": ... }` shape; they use Axum's default plain-text
  responses. Trust the status code.
- `416` responses deliberately return a plain-text body plus `Content-Range: bytes */<size>`.
- `413` is only emitted for the 64 KiB non-file-field limit. Requests exceeding
  `MAX_UPLOAD_SIZE_BYTES` are rejected by the body limit and may surface as `400 Invalid multipart`
  because multipart parsing fails while reading the stream.

## Vault management

### `POST /inbox`

Create a vault: derive a keypair from `(password, name)` and write `.inbox-age.config`. The vault
directory is created if the parent exists.

**Request**

```json
{
  "name": "my-vault",
  "password": "super-secret",
  "permissions": {
    "allow_subfolders": false,
    "allow_upload": true,
    "allow_download": true,
    "allow_list": true,
    "allow_delete": true,
    "allow_metadata": true,
    "allow_lock_unlock": true
  }
}
```

- `name` and `password` are required.
- `permissions` is optional; supplied fields override defaults, omitted fields keep defaults.
- Unknown fields (top-level or inside `permissions`) are rejected → `422`.

**Response `200`**

```json
{ "success": true, "public_key": "age1..." }
```

`public_key` is the X25519 recipient that the server uses to encrypt uploads. **This is the only
place it is returned**, and it is **not required to upload**: the upload endpoints never ask for key
material. Store it if you need the vault's recipient for identification. Note that no endpoint
accepts pre-encrypted ciphertext, so "client-side encryption" would mean writing the `.age` file and
its `.meta.age` sidecar into the vault directory yourself.

**Status codes:** `200`, `400` (invalid name), `409` (already exists), `415`/`400`/`422`
(malformed request), `500` (crypto/I/O).

### `GET /inbox/{name}/config`

Return the public policy of a vault. No authentication, and it never returns `public-key`.

**Response `200`**

```json
{
  "permissions": {
    "allow_subfolders": false,
    "allow_upload": true,
    "allow_download": true,
    "allow_list": true,
    "allow_delete": true,
    "allow_metadata": true,
    "allow_lock_unlock": true
  }
}
```

**Status codes:** `200`, `400` (invalid name), `404` (vault/config missing), `500` (config has no
`public-key`).

## Upload

### `POST /inbox/{name}/upload`

Encrypt a multipart file part into the vault root. See
[PROTOCOL §6.2](PROTOCOL.md#62-upload-at-the-vault-root).

**Request:** `multipart/form-data`

| Field | Required | Meaning |
|-------|----------|---------|
| `file` | Yes | Binary payload. Its multipart filename is the fallback filename. |
| `filename` | No | Explicit filename; wins over the file part's filename when non-empty. |
| `origin` | No | Free-form source string stored in metadata. |
| `extended` | No | JSON object (as text) merged into metadata. |
| *(any other)* | No | Stored in metadata as a string field with that name. |

**Response `200`**

```json
{ "message": "File drop-9f2c...f607.age uploaded successfully" }
```

The stored name is **server-generated** (`drop-<32 hex>.age`); the original filename lives in the
encrypted sidecar. Uploads respect `MAX_UPLOAD_SIZE_BYTES` and a 64 KiB cap per non-file field.

The request carries no key material or credential: the server encrypts with the recipient from
`.inbox-age.config`, so `allow_upload` is the only gate on writing to a vault.

**Status codes:** `200`, `400` (invalid name, malformed multipart, missing `file`, missing
filename), `403` (upload disabled), `404` (vault not found), `413` (non-file field > 64 KiB),
`415` (not multipart), `500`.

### `POST /inbox/{name}/upload/{path}`

Same as the root upload, but into a nested subpath. The subpath is created on demand.

**Status codes:** as above, plus `403 Subfolders not allowed by vault config` when
`allow_subfolders` is `false`, and `400 Invalid subfolder path` for a rejected subpath.

## Session

### `POST /inbox/{name}/unlock`

Derive the identity from `password` and start a 1-hour in-memory session. The password is discarded
after derivation and never persisted.

**Request**

```json
{ "password": "super-secret" }
```

**Response `200`**

```json
{ "message": "Vault my-vault unlocked for 1 hour" }
```

Calling unlock again with the correct password refreshes the expiry. The session is shared by all
clients of the process and lost on restart.

**Status codes:** `200`, `400` (invalid name), `401` (wrong password), `403`
(`allow_lock_unlock: false`), `404` (vault missing), `500`. Key derivation runs on a blocking thread
so Argon2 does not stall the async runtime.

### `POST /inbox/{name}/lock`

Remove the vault's session entry immediately.

**Response `200`**

```json
{ "message": "Vault my-vault locked" }
```

**Status codes:** `200`, `400` (invalid name), `403` (`allow_lock_unlock: false`), `404` (vault not
found, or `Vault not unlocked` when there was no session), `500`.

## Read (requires an unlocked vault)

### `GET /inbox/{name}/list`

Recursively list stored payloads with decrypted metadata. Excludes `.meta.age` sidecars.

**Response `200`**

```json
[
  {
    "path": "drop-9f2c...f607.age",
    "filename": "report.pdf",
    "origin": "web-form",
    "size": 35120
  }
]
```

- `size` is the **ciphertext size on disk**.
- `filename` is reduced to its basename as recorded in metadata; `origin` is passed through.
- Files whose sidecar is missing or cannot be decrypted are **silently skipped** (logged server-side).

**Status codes:** `200`, `400` (invalid name), `401` (locked/expired), `403` (`allow_list:
false`), `404` (vault/config missing), `500`.

### `GET /inbox/{name}/metadata/{path}`

Decrypt the sidecar for one payload.

**Response `200`**

```json
{ "filename": "report.pdf", "origin": "web-form", "filesize": 35120, "tag": "monthly" }
```

- `{path}` must end in `.age` and must not end in `.meta.age` (`400` otherwise).
- `filesize` here is the **ciphertext size on disk**, which **overwrites** the plaintext value
  written at upload time. See [PROTOCOL §9](PROTOCOL.md#9-size-and-range-semantics).

**Status codes:** `200`, `400` (invalid path or sidecar path), `401` (locked/expired), `403`
(`allow_metadata: false`), `404` (metadata not found), `500`.

### `GET /inbox/{name}/download/{path}`

Stream decrypted content. Supports a single `Range` request.

**Response `200`** — `application/octet-stream`, `Accept-Ranges: bytes`,
`Content-Disposition: attachment; filename="<resolved name>"`.

**Response `206`** — same headers plus `Content-Range: bytes <start>-<end>/<total>` and
`Content-Length`. The range is resolved against the **plaintext** size from the sidecar. When the
sidecar has no `filesize`, the whole payload is decrypted into memory before slicing.

**Response `416`** — plain-text body plus `Content-Range: bytes */<length>`.

Only `bytes=a-b`, `bytes=a-` and `bytes=-n` are supported; multi-range requests are treated as
unsatisfiable.

**Status codes:** `200`, `206`, `400` (invalid path / not `.age`), `401` (locked/expired), `403`
(`allow_download: false`), `404` (file not found), `416`, `500`.

### `DELETE /inbox/{name}/delete/{path}`

Delete a payload and, if present, its sidecar. Requires a session entry for the vault (presence is
checked, not expiry).

**Response `200`** — empty body.

**Status codes:** `200`, `400` (invalid path), `403` (`allow_delete: false` or vault locked), `404`
(vault or file not found), `500`.

## Raw (no unlock required)

These endpoints operate on ciphertext and never need the password. They are still subject to the
vault's permission flags, and they are **unauthenticated** — anyone who can reach the server can use
them.

### `GET /inbox/{name}/raw/list`

Recursively list payloads with their ciphertext size. Excludes `.meta.age` sidecars and **skips any
payload that has no sidecar on disk**.

**Response `200`**

```json
[ { "path": "drop-9f2c...f607.age", "size": 35120 } ]
```

**Status codes:** `200`, `400` (invalid name), `403` (`allow_list: false`), `404` (vault/config
missing), `500`.

### `GET /inbox/{name}/raw/download/{path}`

Stream the encrypted `.age` file unchanged, seeking on disk for ranges.

**Response `200`** — `application/octet-stream`, `Content-Length`, `Accept-Ranges: bytes`,
`Content-Disposition: attachment; filename="<drop name>"`.

**Response `206`** — `Content-Range: bytes <start>-<end>/<ciphertext size>`, `Content-Length`, body
streamed from the seeked offset.

**Response `416`** — plain-text body plus `Content-Range: bytes */<ciphertext size>`.

**Status codes:** `200`, `206`, `400` (invalid path / not `.age`), `403` (`allow_download: false`),
`404` (vault or file not found), `416`, `500`.

### `DELETE /inbox/{name}/raw/delete/{path}`

Delete a payload and, if present, its sidecar, without requiring an unlock.

**Response `200`** — empty body.

**Status codes:** `200`, `400` (invalid path), `403` (`allow_delete: false`), `404` (vault or file
not found), `500`.

## Related documents

- [`PROTOCOL.md`](PROTOCOL.md) — protocol, session model and use-case flows.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — internal design.
- [`CRYPTO_MODEL.md`](CRYPTO_MODEL.md) — cryptography.
- [`openapi.yaml`](openapi.yaml) — machine-readable contract.
