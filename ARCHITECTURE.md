# GitBox Architecture

## Overview

GitBox is a client-side tool for encrypting secrets in git repositories using GitHub SSH keys as identity. It allows teams to store encrypted secrets directly in version control, with access controlled by GitHub username.

## Design Principles

1. **GitHub as Identity Provider**: GitHub already hosts SSH public keys for all users. By using these keys for encryption, we get identity management for free -- no separate key servers or PKI needed.
2. **Per-Secret Data Encryption Keys**: Each secret gets its own random 256-bit DEK. The DEK is wrapped (encrypted) individually for each authorized recipient. This means adding/removing a user only requires re-wrapping the small DEK, not re-encrypting the (potentially large) payload.
3. **Envelope Encryption**: The pattern of encrypting data with a DEK and then wrapping the DEK with recipient keys is called "envelope encryption." It's the same pattern used by AWS KMS, GCP Cloud KMS, and tools like Keybase/saltpack.
4. **Forward Secrecy on Revocation**: When a user is revoked, the secret is re-encrypted with a fresh DEK. Old ciphertext (from git history) remains encrypted with the old DEK, which the revoked user may still possess -- but any future versions are protected.

## Cryptographic Design

### Key Types Supported

| SSH Key Type | Wrapping Method | Details |
|---|---|---|
| `ssh-rsa` | RSA-OAEP (SHA-256) | Direct asymmetric encryption of the DEK |
| `ssh-ed25519` | Ephemeral ECDH + NaCl secretbox | Ed25519 -> X25519 conversion, ephemeral key agreement |

### How RSA Key Wrapping Works

```
DEK (32 bytes) --[RSA-OAEP-SHA256]--> wrapped_dek (RSA ciphertext)
```

Standard RSA-OAEP encryption with SHA-256 and the label "gitbox-dek" for domain separation. The recipient decrypts with their RSA private key.

### How Ed25519 Key Wrapping Works

Ed25519 is a signing algorithm, not an encryption algorithm. However, Ed25519 and X25519 (Curve25519 Diffie-Hellman) operate on the same underlying curve in different representations (Edwards vs Montgomery form). The conversion is a well-known birational map used by Signal, age, Keybase/saltpack, and others.

```
Step 1: Convert recipient's Ed25519 public key to X25519
   ed25519_pub --[Edwards-to-Montgomery map]--> x25519_pub

Step 2: Generate ephemeral X25519 keypair
   (eph_pub, eph_priv) = random X25519 keypair

Step 3: Compute shared secret via ECDH
   shared_secret = X25519(eph_priv, recipient_x25519_pub)

Step 4: Encrypt DEK with shared secret using NaCl secretbox
   nonce = random 24 bytes
   wrapped_dek = secretbox.Seal(DEK, shared_secret, nonce)

Stored: (wrapped_dek, eph_pub, nonce)
```

To decrypt, the recipient:
1. Converts their Ed25519 private key to X25519 (SHA-512 of seed, clamped)
2. Computes the same shared secret: `X25519(recipient_x25519_priv, eph_pub)`
3. Decrypts: `secretbox.Open(wrapped_dek, shared_secret, nonce)`

### Payload Encryption

All payloads are encrypted with NaCl secretbox (XSalsa20-Poly1305):
- **XSalsa20**: Stream cipher for confidentiality
- **Poly1305**: MAC for authentication/integrity
- **Nonce**: Random 192-bit (24-byte) nonce per encryption

This is an AEAD construction -- any tampering with the ciphertext is detected.

### Paper Key

The paper key is an emergency recovery mechanism:
1. A random 32-byte seed is generated
2. An Ed25519 keypair is deterministically derived from the seed (via SHA-256 with domain separation)
3. The seed is displayed as formatted hex for the user to write down
4. The public key is stored in `.gitbox/paperkey.yaml`
5. All new secrets automatically include the paper key as a recipient

To recover: enter the hex seed -> derive the same keypair -> decrypt.

## Store Format

```
.gitbox/
├── config.yaml              # Version info
├── paperkey.yaml             # Paper key public info (if configured)
├── .tracked                  # Plaintext files tracked by pre-commit hook
├── identities/
│   ├── alice.yaml            # Alice's SSH public keys from GitHub
│   └── bob.yaml              # Bob's SSH public keys from GitHub
└── secrets/
    ├── prod-db.yaml          # Encrypted secret with wrapped DEKs
    └── api-keys.yaml         # Another encrypted secret
```

### Secret Manifest Format (YAML)

```yaml
name: prod-db
encrypted_data: <base64>      # NaCl secretbox ciphertext
nonce: <base64>               # 24-byte nonce
recipients:
  - github_user: alice
    key_type: ssh-ed25519
    key_fingerprint: SHA256:...
    wrapped_key: <base64>     # DEK encrypted for this key
    ephemeral_public: <base64> # Ephemeral X25519 public key
    wrap_nonce: <base64>      # Nonce for DEK wrapping
  - github_user: bob
    key_type: ssh-rsa
    key_fingerprint: SHA256:...
    wrapped_key: <base64>     # DEK encrypted via RSA-OAEP
  - github_user: __paper_key__
    key_type: ssh-ed25519
    key_fingerprint: SHA256:...
    wrapped_key: <base64>
    ephemeral_public: <base64>
    wrap_nonce: <base64>
created_at: 2024-01-01T00:00:00Z
updated_at: 2024-01-01T00:00:00Z
```

The DEK is wrapped for **every** public key of every authorized user. If a user has both an RSA and Ed25519 key on GitHub, both get a wrapped copy. This means they can decrypt with whichever private key they have available.

## Operations

### Encrypt
1. Read plaintext file
2. Generate random DEK
3. Encrypt payload with DEK via NaCl secretbox
4. For each recipient: load their public keys, wrap DEK for each key
5. If paper key exists: also wrap DEK for paper key
6. Write manifest YAML to `.gitbox/secrets/<name>.yaml`
7. Add plaintext file to `.gitignore` and pre-commit tracking

### Decrypt
1. Load manifest
2. Load user's SSH private key (from `~/.ssh/` or `-k` flag)
3. Try each recipient entry until one succeeds
4. Unwrap the DEK
5. Decrypt the payload with the DEK

### Grant Access
1. Decrypt the DEK (requires an existing recipient's private key)
2. Fetch/load the new user's public keys
3. Wrap the DEK for the new user's keys
4. Append new recipient entries to the manifest

### Revoke Access
1. Decrypt the payload (requires an existing recipient's private key)
2. Generate a **new** DEK
3. Re-encrypt the payload with the new DEK
4. Re-wrap the new DEK for all remaining recipients
5. Write the updated manifest (old wrapped keys are gone)

This is a full re-encryption, not just removing recipient entries. The old DEK is effectively destroyed in the manifest, though it may exist in git history.

### Key Refresh (Reboxing)
When a user rotates their SSH keys (e.g., key compromise, hardware change):
1. Re-fetch public keys from GitHub (or accept manual key update)
2. Update the identity file
3. For each secret the user has access to:
   a. Decrypt the DEK using an authorized private key
   b. Remove old wrapped DEK entries for that user
   c. Re-wrap the DEK with the user's new public keys
   d. Update the manifest

The payload is NOT re-encrypted -- only the DEK wrapping changes. This is efficient for key rotation because wrapping is cheap compared to re-encrypting large payloads.

### Groups
Groups are named collections of users (or other groups) stored in `.gitbox/groups.yaml`. They provide a level of indirection so that access policies are expressed in terms of roles rather than individual users.

Resolution is recursive: `@all-devs` can reference `@backend` and `@frontend`, which reference individual users. Cycle detection prevents infinite loops.

Groups are resolved at encrypt/grant/apply time. The secret manifest always stores individual usernames, not group references -- this means group membership changes don't automatically propagate. Use `gitbox apply` to converge.

### Declarative Config (Apply/Export)
The `gitbox.yaml` file describes the desired state of the world:
- Which groups exist and their membership
- Which secrets exist, their source files, and who should have access

`gitbox apply` reads this config and converges:
1. Creates/updates groups
2. For each secret: compares current recipients to desired recipients
3. Grants access to users who should have it but don't
4. Revokes access from users who shouldn't have it (full re-encryption)
5. Creates new secrets from source files
6. Re-encrypts secrets whose source file content has changed

`gitbox export` dumps the current state in the same format. This makes it easy to audit access and manage changes via code review (change the YAML, get it reviewed, apply).

## Security Model

### What GitBox Protects Against
- **Unauthorized access to secrets in the repository**: Only users whose SSH keys are listed as recipients can decrypt
- **Tampering**: NaCl secretbox provides authenticated encryption -- any modification is detected
- **Key compromise of one user**: Each user has their own wrapped DEK; compromising one key doesn't reveal others' wrapped DEKs

### What GitBox Does NOT Protect Against
- **Compromised private SSH keys**: If an attacker has your SSH private key, they can decrypt your secrets
- **Git history after revocation**: Revoking a user re-encrypts going forward, but old git commits still contain the old ciphertext encrypted with a DEK the revoked user possessed
- **Malicious committers**: Someone with write access to the repo could replace the encrypted data or manipulate manifests
- **Side-channel attacks**: This is a CLI tool, not a hardened HSM

### Trust Model
- GitHub is trusted as the source of truth for SSH public keys
- The person running `gitbox add-user` trusts that the keys returned by GitHub belong to the intended user
- Anyone with write access to `.gitbox/identities/` could substitute public keys (TOFU -- Trust On First Use)

## Pre-Commit Hook

The hook prevents plaintext secret files from being accidentally committed:
1. Checks if any staged files are in `.gitbox/.tracked`
2. If so, blocks the commit with a message to encrypt first
3. Encrypted files in `.gitbox/secrets/` pass through normally

## Dependencies

- `golang.org/x/crypto`: SSH key parsing, NaCl secretbox/box, X25519, Ed25519
- `filippo.io/edwards25519`: Ed25519 to X25519 public key conversion (Edwards to Montgomery)
- `gopkg.in/yaml.v3`: YAML serialization for manifests and config

## Inspiration

The cryptographic design draws from:
- **Keybase/saltpack**: Per-recipient key wrapping, Ed25519->X25519 conversion
- **age**: SSH key-based encryption, simple formats
- **NaCl/libsodium**: The secretbox and box constructions
- **PGP**: Concept of per-user key wrapping (but with modern crypto)
