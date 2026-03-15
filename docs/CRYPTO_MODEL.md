# Age Inbox Cryptographic Model

## What This Project Does

Age Inbox is a secure drop-off model built on top of `age` encryption. Instead of sharing a private key with uploaders, each inbox exposes only a public key. Anyone with that public key can encrypt data for the inbox, but only the owner who knows the password can reconstruct the matching private key and decrypt content.

This is why it behaves like an inbox: write access can be broad (encrypt to a public key), while read access remains restricted (private key from password).

## Layer on Top of age

The project does not replace `age`; it composes around it:

- It uses `age` X25519 recipient encryption for files.
- It stores only public identity material in vault configuration.
- It derives private identity material on demand from a password.

In short, `age` provides the encryption primitives, and Age Inbox adds an inbox-oriented key lifecycle and storage model.

## Key Derivation Strategy

A vault keypair is deterministically derived from:

- User password
- Vault name

The derivation process is:

1. Build a 16-byte salt from the vault name.
2. Expand short names with a fixed domain-separation pattern.
3. Run Argon2 to derive 32 bytes.
4. Encode those 32 bytes as an `AGE-SECRET-KEY-...` Bech32 string.
5. Parse as an `age` X25519 identity (private key).
6. Compute the corresponding public recipient key.

Because derivation is deterministic, the same password plus vault name always recreates the same keypair.

## Password and Secret Handling

The implementation minimizes secret lifetime in memory:

- Incoming password buffers are zeroized immediately after derivation.
- Temporary key material bytes are zeroized after use.
- Intermediate secret strings use zeroizing wrappers so they are wiped on drop.

No plaintext private key is persisted to disk.

## What Is Stored At Rest

For each inbox vault, the system stores:

- Public key (recipient)
- Encrypted payload files (`.age`)
- Encrypted metadata sidecars (`.meta.age`)
- Non-secret vault settings

The private key is never written as a file.

## Encryption Flow (Inbox Write Path)

When data is received for a vault:

1. The stored public key is loaded.
2. An `age` encryptor is created for that recipient.
3. Content is streamed directly into the encryptor and written to disk.
4. Optional metadata is serialized and encrypted with the same recipient.

This keeps memory usage stable for large files and avoids buffering full payloads in RAM.

## Decryption Flow (Owner Read Path)

To decrypt content, the owner provides the vault password:

1. The system derives a keypair from password + vault name.
2. It verifies access by checking that the derived public key matches the stored public key.
3. On success, the derived private identity is held in memory for a limited unlock window.
4. Decryption reads encrypted files and streams plaintext to the caller.

When the unlock window expires or a lock action is triggered, the in-memory unlock state is removed.

## Security Implications

- Public-key encryption allows safe one-way drop-off semantics.
- Confidentiality depends on password strength and Argon2 resistance to brute force.
- Deterministic derivation means vault name is part of key identity.
- Since private keys are reconstructed on demand and not persisted, disk compromise yields encrypted data and public metadata, not decryption keys.

## Notes on Password Generation

This project does not generate random user passwords internally. The user supplies the password, and the system derives cryptographic key material from it.

Operationally, strong, high-entropy passwords are essential because they are the root secret for private key reconstruction.
