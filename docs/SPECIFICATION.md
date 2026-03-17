# AGE Inbox Specification

## 1. Purpose

AGE Inbox is a secure drop-off model built on top of the AGE file encryption format. It is designed for one-way submission workflows where many parties may upload encrypted data, while only the vault owner can decrypt it.

The system does not replace AGE or define a new cryptographic format. Instead, it composes AGE primitives into an inbox-oriented lifecycle with deterministic key reconstruction from user secrets.

## 2. Design Goals

- Confidentiality of stored content using modern public-key encryption.
- No plaintext private key persistence on disk.
- Streaming encryption/decryption for bounded memory usage.
- Operational simplicity for inbox sharing through a public recipient key.
- Explicit lock/unlock behavior for controlled read access.

## 3. Layering Model: AGE Inbox over AGE

AGE Inbox acts as an application layer over AGE:

- **AGE responsibility:** file format, recipient-based encryption, identity-based decryption, payload confidentiality.
- **AGE Inbox responsibility:** vault lifecycle, key derivation policy, storage conventions, unlock session behavior, and metadata handling.

This separation means cryptographic packet handling is delegated to AGE, while inbox semantics are defined by AGE Inbox.

## 4. Cryptographic Components and Scope

### 4.1 AGE Primitive in Use

AGE Inbox uses the AGE Rust implementation with **X25519 recipients/identities** for asymmetric encryption.

- Upload path encrypts for a vault recipient (public key).
- Download path decrypts with the matching identity (private key).

Passphrase-mode AGE payloads are not part of the vault data model.

### 4.2 Key Derivation Primitive

Vault key material is derived from:

- `password` (user secret)
- `vault_name` (context binding)

Derivation is deterministic and currently implemented using the Rust `argon2` crate default Argon2 configuration to produce 32 bytes of key material. That material is encoded into AGE secret-key form and parsed as an X25519 identity; the corresponding public recipient is then derived.

### 4.3 Salt and Domain Separation

A stable 16-byte salt is deterministically constructed from the vault name. Short names are expanded with a fixed pattern so derivation remains deterministic for all valid vault names.

## 5. Vault Identity Model

Each vault has a cryptographic identity defined by `(password, vault_name)`.

Consequences:

- Same password + same vault name -> same AGE keypair.
- Changing either input -> different keypair.
- The stored public key serves as the verifier during unlock.
- Private identity can be reconstructed on demand and is not stored as plaintext at rest.

## 6. Data-at-Rest Model

For each vault, AGE Inbox stores:

- Encrypted payload files (`*.age`)
- Encrypted metadata sidecars (`*.meta.age`)
- Vault configuration including public recipient and non-secret policy flags

AGE Inbox does **not** persist the plaintext private key.

## 7. Write Path (Inbox Semantics)

1. Resolve vault public recipient from vault configuration.
2. Stream incoming content through AGE encryption to disk.
3. Optionally serialize metadata and encrypt it to a sidecar using the same recipient.

Result: uploaders need only recipient information; they cannot decrypt what they uploaded.

## 8. Read Path (Owner Semantics)

1. User provides password for a vault.
2. System deterministically reconstructs a candidate identity from `(password, vault_name)`.
3. System compares derived public recipient with the stored vault recipient.
4. On match, vault is considered unlocked for a bounded time window.
5. Encrypted payloads and metadata are decrypted as streams for read operations.

The default service unlock policy is a one-hour in-memory window unless explicitly locked earlier.

## 9. Secret Handling and Memory Hygiene

AGE Inbox minimizes sensitive material lifetime:

- Temporary derived key bytes are zeroized after use.
- Sensitive intermediate key strings use zeroizing wrappers.
- Password buffers are consumed for derivation and not persisted by design.
- Unlock state is volatile and removed on expiration or lock.

This model reduces key exposure in storage and limits secret residency in process memory.

## 10. Security Properties and Assumptions

### 10.1 Provided by This Design

- Confidentiality at rest for payload and metadata under AGE encryption.
- Public upload capability without private-key distribution.
- Reduced key-at-rest risk through on-demand private-key reconstruction.

### 10.2 Required Assumptions

- Users choose high-entropy passwords.
- Vault name integrity is preserved (it is part of key derivation context).
- Host runtime and filesystem permissions are appropriately secured.
- Unlock session state in memory is protected by process and OS boundaries.

## 11. Non-Goals

This specification intentionally does not define:

- HTTP endpoint contracts
- Rust function-level API details
- Transport-layer protocol guarantees beyond deployment configuration

Those concerns belong to separate API and operations documentation.

