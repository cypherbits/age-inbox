# API Endpoints

For a fully interactive schema, explore the OpenAPI 3 specification located in `docs/openapi.yaml`.

## Vault Management

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

## Unlocked Vault Operations (require unlock)

- **List Files**
  - `GET /inbox/{name}/list`
  - *Lists encrypted files (excluding `.meta.age`) with decrypted metadata (`filename`, `origin`) and encrypted file `size` in bytes.*

- **Download File (Decrypted)**
  - `GET /inbox/{name}/download/{path}`
  - Supports HTTP `Range` header for partial content (`206 Partial Content`).
  - *Decrypts and streams the file content. Returns `Accept-Ranges: bytes`.*

- **Get File Metadata**
  - `GET /inbox/{name}/metadata/{path}`
  - *Returns decrypted metadata JSON including the encrypted file `filesize` on disk.*

## Raw Operations (no unlock required)

These endpoints work regardless of whether the vault is locked or unlocked. They serve encrypted `.age` files without decryption.

- **Raw List Files**
  - `GET /inbox/{name}/raw/list`
  - *Lists encrypted files with `path` and `size` (no metadata decryption).*

- **Raw Download File (Encrypted)**
  - `GET /inbox/{name}/raw/download/{path}`
  - Supports HTTP `Range` header for efficient partial content (`206 Partial Content`).
  - *Streams the encrypted `.age` file as-is with `Content-Length` and `Accept-Ranges: bytes`.*

