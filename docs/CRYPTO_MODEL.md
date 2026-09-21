# Age Inbox Cryptographic Model

> Related: [`PROTOCOL.md`](PROTOCOL.md) · [`ARCHITECTURE.md`](ARCHITECTURE.md) ·
> [`SPECIFICATION.md`](SPECIFICATION.md) · [`../crates/age-inbox-core/API.md`](../crates/age-inbox-core/API.md)

## What this project does

Age Inbox is a secure drop-off model built on top of `age` encryption. Instead of sharing a private
key with uploaders, each inbox exposes only a public key. Conceptually, anyone holding that public
key can encrypt data for the inbox, while only the owner who knows the password can reconstruct the
matching private key and decrypt content.

This is why it behaves like an inbox: write access can be broad, while read access remains
restricted to whoever can derive the private key from the password.

### How this model maps to the REST service

The reference service encrypts **server-side**. A client uploads plaintext to
`POST /inbox/{name}/upload`; the server loads the recipient from `.inbox-age.config` and encrypts
before writing to disk. Consequences:

- The public key is **not** an upload credential. No REST request sends or requires key material,
  and knowing the recipient grants no read access. Upload access is governed solely by network
  reachability and the vault's `allow_upload` flag.
- The server necessarily handles the plaintext in transit. This is **not** end-to-end encryption:
  use TLS, and treat the host as trusted with respect to file contents.
- The public key is returned once, by `POST /inbox`. It identifies the vault's recipient and
  supports tooling that produces ciphertext out of band. There is **no HTTP endpoint that accepts
  pre-encrypted payloads**, so out-of-band encryption means writing the `.age` file *and* a matching
  `.meta.age` sidecar into the vault directory directly. A payload placed without a sidecar is
  skipped by `list`/`raw/list` and fails to download (`500`).

## Layer on top of age

The project does not replace `age`; it composes around it:

- It uses `age` X25519 recipient encryption for file payloads.
- It stores only public identity material in vault configuration.
- It derives private identity material on demand from a password.
- It refuses passphrase-mode (`scrypt`) `age` payloads, which are not part of the vault data model.

In short, `age` provides the encryption primitives, and Age Inbox adds an inbox-oriented key
lifecycle and storage model.

## Key Derivation Strategy

A vault keypair is deterministically derived from:

- the user password, and
- the vault name.

The derivation process (`crypto::derive_keys`) is:

1. Build a **16-byte salt** from the vault name:
   - bytes `0..min(len, 16)` are the first bytes of the UTF-8 name;
   - any remaining bytes are filled with `i ^ 0xAA` (a fixed domain-separation pattern so short and
     long names both produce a stable 16-byte salt).
2. Run `argon2::Argon2::default()` — **Argon2id** (version `0x13`, the RustCrypto defaults: 19 MiB
   memory, 2 iterations, 1 lane) — over the password and salt to produce **32 bytes**.
3. Encode those 32 bytes as an uppercase `AGE-SECRET-KEY-...` Bech32 string.
4. Parse that string as an `age` X25519 `Identity` (private key).
5. Compute the corresponding `Recipient` (public key) from the identity.
6. Zeroize the raw 32-byte buffer; intermediate secret strings are wrapped in `Zeroizing`.

Because derivation is deterministic, the same password plus vault name always recreates the same
keypair. Nothing secret needs to be stored for that to work.

### Consequences of the salt construction

Two properties follow directly from step 1 and matter operationally:

- **The vault name is key-derivation context, not a label.** Renaming the vault directory (or
  supplying a different name at unlock time) yields a different salt, hence a different keypair, and
  the stored ciphertext becomes permanently undecryptable.
- **Only the first 16 bytes of the name affect the salt.** Names that share their first 16 UTF-8
  bytes collide: for the same password they derive the same keypair. Keep names short and distinct,
  and treat the name as part of the security perimeter.

## Password and secret handling

The implementation minimises secret lifetime in memory:

- Incoming password buffers are consumed for derivation and not persisted by design.
- Temporary key-material bytes are zeroized after use (`zeroize`).
- Intermediate secret strings use zeroizing wrappers so they are wiped on drop.
- The derived identity is held in memory only for the duration of an unlock session (one hour by
  default in the server) and removed on expiry or explicit lock.

No plaintext private key is written to disk, and no password verifier or hash is stored either.

## Unlock and verification

There is no stored password hash. Verification works by re-derivation:

1. Derive a candidate keypair from the supplied password and vault name.
2. Compare the derived **public** recipient with the `public-key` stored in `.inbox-age.config`.
3. If they match, the derived identity is placed in the caller's unlock map with an expiry.
4. If they differ, the password is rejected.

The comparison is over public values, so it does not need to be constant-time. Security rests on the
cost of guessing the password with Argon2id, not on the comparison.

## What is stored at rest

For each inbox vault, the system stores:

- the public key (recipient) in `.inbox-age.config`;
- encrypted payload files (`*.age`);
- encrypted metadata sidecars (`*.meta.age`);
- non-secret vault settings (permission flags).

The private key is never written as a file.

## Encryption flow (inbox write path)

When data is received for a vault:

1. The stored public key is loaded from `.inbox-age.config`.
2. An `age` encryptor is created for that recipient.
3. Content is streamed straight into the encryptor and written to disk as it arrives, without
   buffering the whole payload.
4. Metadata is serialized to JSON and encrypted with the same recipient into a sidecar.

This keeps memory usage stable for large files and avoids buffering full payloads in RAM. The server
handles the plaintext while encrypting, but it cannot decrypt afterwards: it stores neither a
password nor a private key, so stored content is readable only after an unlock.

## Decryption flow (owner read path)

To decrypt content, the owner provides the vault password:

1. The system derives a keypair from password + vault name.
2. It verifies access by checking that the derived public key matches the stored public key.
3. On success, the derived private identity is held in memory for a limited unlock window.
4. Decryption reads the encrypted file and streams plaintext to the caller; range reads decrypt from
   the start of the stream and stop after the requested bytes.

When the unlock window expires or a lock action is triggered, the in-memory unlock state is removed.
Range decryption is a streaming operation, not random access: the server still performs work
proportional to the start offset.

## Security implications

- Public-key encryption allows safe one-way drop-off semantics.
- Confidentiality depends on password strength and Argon2id's resistance to brute force.
- Deterministic derivation means the vault name is part of the key identity (see above).
- Since private keys are reconstructed on demand and not persisted, a disk compromise yields
  encrypted data and public metadata, not decryption keys.
- The `raw/*` endpoints expose ciphertext to anyone with network access; they never expose plaintext,
  but they do allow enumeration and (if `allow_delete` is enabled) deletion.
- An unlocked process holds a live private key in memory. Treat process memory and core dumps as
  sensitive, and prefer locking vaults when done.

## Notes on password generation

This project does not generate random user passwords internally. The user supplies the password, and
the system derives cryptographic key material from it.

Operationally, strong, high-entropy passwords are essential because they are the root secret for
private key reconstruction. Remember that changing the password is not a provided operation: a new
password implies a new keypair, so existing ciphertext must be decrypted with the old password and
re-uploaded under the new one.
