# AGE Inbox Specification

> Related: [`CRYPTO_MODEL.md`](CRYPTO_MODEL.md) · [`ARCHITECTURE.md`](ARCHITECTURE.md) ·
> [`PROTOCOL.md`](PROTOCOL.md) · [`API.md`](API.md)

## 1. Purpose

AGE Inbox is a secure drop-off model built on top of the AGE file encryption format. It is designed
for one-way submission workflows where many parties may upload encrypted data, while only the vault
owner can decrypt it.

The system does not replace AGE or define a new cryptographic format. Instead, it composes AGE
primitives into an inbox-oriented lifecycle with deterministic key reconstruction from user secrets.

The reference implementation is the workspace described in [`ARCHITECTURE.md`](ARCHITECTURE.md):
a core library (`age-inbox-core`) and a REST server (`age-inbox-server`) that wraps it.

## 2. Design goals

- Confidentiality of stored content using modern public-key encryption.
- No plaintext private key persistence on disk.
- Streaming encryption/decryption for bounded memory usage.
- Operational simplicity for inbox sharing: the reference service accepts uploads over HTTP and
  encrypts server-side, so uploaders need no key material.
- Explicit lock/unlock behaviour for controlled read access.

## 3. Layering model: AGE Inbox over AGE

AGE Inbox acts as an application layer over AGE:

- **AGE responsibility:** file format, recipient-based encryption, identity-based decryption, payload
  confidentiality.
- **AGE Inbox responsibility:** vault lifecycle, key derivation policy, storage conventions, unlock
  session behaviour, and metadata handling.

This separation means cryptographic packet handling is delegated to AGE, while inbox semantics are
defined by AGE Inbox.

## 4. Cryptographic components and scope

### 4.1 AGE primitive in use

AGE Inbox uses the AGE Rust implementation with **X25519 recipients/identities** for asymmetric
encryption.

- The upload path encrypts for a vault recipient (public key).
- The download path decrypts with the matching identity (private key).

Passphrase-mode AGE payloads (`scrypt`) are not part of the vault data model and are rejected on
decrypt.

### 4.2 Key derivation primitive

Vault key material is derived from:

- `password` (user secret), and
- `vault_name` (context binding).

Derivation is deterministic and implemented with the Rust `argon2` crate using
`Argon2::default()` — the **Argon2id** variant (version `0x13`, RustCrypto default parameters) — to
produce 32 bytes of key material. Those bytes are encoded into AGE secret-key form
(`AGE-SECRET-KEY-...`, uppercase Bech32) and parsed as an X25519 identity; the corresponding public
recipient is then derived.

### 4.3 Salt and domain separation

A stable **16-byte** salt is deterministically constructed from the vault name:

- the first up-to-16 bytes of the name are copied into the salt;
- remaining bytes are filled with `i ^ 0xAA`, a fixed domain-separation pattern that keeps the salt
  well-defined for short names.

Two consequences are normative for this model:

- The vault name is key-derivation context. Changing it changes the keypair, so stored ciphertext
  becomes undecryptable.
- Only the first 16 bytes of the name contribute entropy to the salt. Names sharing a 16-byte prefix
  derive identical keys for the same password.

## 5. Vault identity model

Each vault has a cryptographic identity defined by `(password, vault_name)`.

Consequences:

- Same password + same vault name → same AGE keypair.
- Changing either input → different keypair.
- The stored public key serves as the verifier during unlock.
- The private identity is reconstructed on demand and never stored as plaintext at rest.
- Changing a vault's password is not a supported operation; it implies a new vault and re-uploading
  the content.

## 6. Data-at-rest model

For each vault, AGE Inbox stores:

- encrypted payload files (`*.age`);
- encrypted metadata sidecars (`*.meta.age`);
- vault configuration including the public recipient and non-secret policy flags
  (`.inbox-age.config`).

AGE Inbox does **not** persist the plaintext private key, nor any password verifier or hash.

## 7. Write path (inbox semantics)

1. Resolve the vault public recipient from vault configuration.
2. Stream incoming content through AGE encryption to disk.
3. Serialize metadata and encrypt it to a sidecar using the same recipient.
4. Commit both files only after they are fully written.

Result: uploaders cannot decrypt what they uploaded. In the reference implementation the recipient
is resolved by the server from vault configuration, so the uploader needs no key material at all.
Publishing the public recipient is what allows an independent writer to encrypt out of band; the
reference API has no endpoint for pre-encrypted payloads, so such a writer must place the `.age`
file and its `.meta.age` sidecar into the vault storage directly.

## 8. Read path (owner semantics)

1. The user provides the password for a vault.
2. The system deterministically reconstructs a candidate identity from `(password, vault_name)`.
3. The system compares the derived public recipient with the stored vault recipient.
4. On match, the vault is considered unlocked for a bounded time window.
5. Encrypted payloads and metadata are decrypted as streams for read operations.

The reference service's default unlock policy is a one-hour in-memory window unless explicitly locked
earlier.

## 9. Secret handling and memory hygiene

AGE Inbox minimises sensitive material lifetime:

- Temporary derived key bytes are zeroized after use.
- Sensitive intermediate key strings use zeroizing wrappers.
- Password buffers are consumed for derivation and not persisted by design.
- Unlock state is volatile and removed on expiration or lock.

This model reduces key exposure in storage and limits secret residency in process memory.

## 10. Security properties and assumptions

### 10.1 Provided by this design

- Confidentiality at rest for payload and metadata under AGE encryption.
- Public upload capability without private-key distribution.
- Reduced key-at-rest risk through on-demand private-key reconstruction.
- Unauthenticated access to ciphertext only (never plaintext) through the raw endpoints.

### 10.2 Required assumptions

- Users choose high-entropy passwords.
- Vault name integrity is preserved (it is part of key derivation context).
- Host runtime and filesystem permissions are appropriately secured.
- Unlock session state in memory is protected by process and OS boundaries.
- Operators configure vault permissions to match their exposure: the defaults allow any network
  client to upload, list, download ciphertext and delete.

## 11. Non-goals

This specification intentionally does not define:

- HTTP endpoint contracts (see [`API.md`](API.md) and [`openapi.yaml`](openapi.yaml));
- Rust function-level API details (see [`../crates/age-inbox-core/API.md`](../crates/age-inbox-core/API.md));
- transport-layer protocol guarantees beyond deployment configuration;
- multi-writer coordination across several server processes sharing a vault directory;
- key rotation, password change or re-encryption workflows.

## 12. Conformance notes

The specification describes the intended model. Where the reference implementation differs today,
the implementation is listed here so integrators are not surprised — see
[`ARCHITECTURE.md` §8](ARCHITECTURE.md#8-known-gaps) for the tracked list:

- `filesize` has different meanings across the sidecar, `/metadata` and `/list` responses
  ([`PROTOCOL.md` §9](PROTOCOL.md#9-size-and-range-semantics)).
- There is no endpoint that returns the public key after vault creation.
- The config parser falls back to permissive defaults when `permissions` is missing or unparseable,
  rather than failing closed.
