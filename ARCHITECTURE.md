# GitBox Architecture

## Overview

GitBox is a client-side tool for encrypting secrets in git repositories using GitHub (or GitHub Enterprise) SSH keys as identity. It allows teams to store encrypted secrets directly in version control, with access controlled by GitHub username.

## Design Principles

1. **GitHub as Identity Provider**: GitHub already hosts SSH public keys for all users. By using these keys for encryption, we get identity management for free -- no separate key servers or PKI needed. Works with both github.com and GitHub Enterprise.
2. **Per-Secret Data Encryption Keys**: Each secret gets its own random 256-bit DEK. The DEK is wrapped (encrypted) individually for each authorized recipient. This means adding/removing a user only requires re-wrapping the small DEK, not re-encrypting the (potentially large) payload.
3. **Envelope Encryption**: The pattern of encrypting data with a DEK and then wrapping the DEK with recipient keys is called "envelope encryption." It's the same pattern used by AWS KMS, GCP Cloud KMS, and tools like Keybase/saltpack.
4. **Forward Secrecy on Revocation**: When a user is revoked, the secret is re-encrypted with a fresh DEK. Old ciphertext (from git history) remains encrypted with the old DEK, which the revoked user may still possess -- but any future versions are protected.
5. **Automatic Key Discovery**: SSH private keys are auto-discovered from `~/.ssh/`. The GitHub host is auto-detected from the git remote origin. No configuration needed for the common case.

## GitHub Host Detection

On `gitbox init`, the tool inspects the git remote `origin` and extracts the hostname:

| Remote URL | Detected Host |
|---|---|
| `git@github.com:org/repo.git` | `github.com` |
| `git@git.corp.com:org/repo.git` | `git.corp.com` |
| `https://ghes.internal.net/org/repo.git` | `ghes.internal.net` |

The detected host is stored in `.gitbox/config.yaml` and used for all `add-user` and `refresh-keys` operations. Both github.com and GitHub Enterprise expose SSH keys at `https://{host}/{username}.keys`.

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

### Paper Keys

Paper keys are offline emergency recovery keys tied to a specific user identity.

1. A random 32-byte seed is generated
2. An Ed25519 keypair is deterministically derived from the seed (via SHA-256 with domain separation)
3. The seed is displayed as **24 BIP39 mnemonic words** (with SHA-256 checksum) for the user to write down
4. The public key is stored in `.gitbox/paperkeys/<name>.yaml`, signed by the owner's SSH key
5. All new secrets automatically include all paper keys as recipients
6. Each paper key is **owned by the identity** that created it

To recover: enter the 24 words (or hex) -> derive the same keypair -> decrypt.

**Lifecycle**: When a user is revoked, their paper key recipients are stripped from all affected secrets. When a user's keys are refreshed, paper keys whose signatures no longer verify are pruned.

## Store Format

```
.gitbox/
├── config.yaml              # Version and git host
├── groups.yaml              # Named user groups (signed)
├── .tracked                 # Plaintext files tracked by pre-commit hook
├── identities/
│   ├── alice.yaml           # Alice's SSH public keys (from GitHub or manual)
│   └── bob.yaml             # Bob's SSH public keys
├── paperkeys/
│   ├── office-safe.yaml     # Paper key owned by alice (signed)
│   └── ceo-vault.yaml       # Paper key owned by bob (signed)
└── secrets/
    ├── prod-db.yaml         # Encrypted secret with wrapped DEKs
    └── api-keys.yaml        # Another encrypted secret
```

### Config Format

```yaml
version: 1
git_host: git.corp.com       # auto-detected from origin, defaults to github.com
```

### Secret Manifest Format

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
  - github_user: "__paper_key__:alice:office-safe"
    key_type: ssh-ed25519
    key_fingerprint: SHA256:...
    wrapped_key: <base64>
    ephemeral_public: <base64>
    wrap_nonce: <base64>
created_at: 2024-01-01T00:00:00Z
updated_at: 2024-01-01T00:00:00Z
```

The DEK is wrapped for **every** public key of every authorized user. If a user has both an RSA and Ed25519 key on GitHub, both get a wrapped copy. This means they can decrypt with whichever private key they have available.

Paper key recipients are tagged with `__paper_key__:<owner>:<name>` so they can be cleanly removed when the owner is revoked.

## Operations

### Encrypt
1. Read plaintext file
2. Generate random DEK
3. Encrypt payload with DEK via NaCl secretbox
4. Resolve `@group` references to individual usernames
5. For each recipient: verify identity signature, load public keys, wrap DEK for each key
6. For each paper key: verify signature, wrap DEK
7. Write manifest YAML to `.gitbox/secrets/<name>.yaml`
8. Add plaintext file to `.gitignore` and pre-commit tracking

### Decrypt
1. Load manifest
2. Auto-discover SSH private key from `~/.ssh/` (or use `-k` flag)
3. Try each recipient entry until one succeeds
4. Unwrap the DEK
5. Decrypt the payload with the DEK

### Grant Access
1. Decrypt the DEK (using auto-discovered or specified private key)
2. Fetch/load the new user's public keys
3. Wrap the DEK for the new user's keys
4. Append new recipient entries to the manifest

### Revoke Access
1. Decrypt the payload (using auto-discovered or specified private key)
2. Generate a **new** DEK
3. Re-encrypt the payload with the new DEK
4. Remove the revoked user's entries **and their paper key entries**
5. Re-wrap the new DEK for all remaining recipients
6. Write the updated manifest

This is a full re-encryption, not just removing recipient entries. The old DEK is effectively destroyed in the manifest, though it may exist in git history.

### Key Refresh (Reboxing)
When a user rotates their SSH keys (e.g., key compromise, hardware change):
1. Re-fetch public keys from the configured GitHub host
2. Update the identity file
3. Prune paper keys whose signatures no longer verify against the new key set
4. For each secret the user has access to:
   a. Decrypt the DEK using an authorized private key
   b. Remove old wrapped DEK entries for that user
   c. Re-wrap the DEK with the user's new public keys
   d. Update the manifest

The payload is NOT re-encrypted -- only the DEK wrapping changes. This is efficient for key rotation because wrapping is cheap compared to re-encrypting large payloads.

### Groups
Groups are named collections of users (or other groups) stored in `.gitbox/groups.yaml`. They provide a level of indirection so that access policies are expressed in terms of roles rather than individual users.

Resolution is recursive: `@all-devs` can reference `@backend` and `@frontend`, which reference individual users. Cycle detection prevents infinite loops.

Groups are signed with the operator's SSH key. Unsigned groups are rejected at resolution time (except during bootstrap).

Groups are resolved at encrypt/grant/apply time. The secret manifest always stores individual usernames, not group references -- this means group membership changes don't automatically propagate. Use `gitbox apply` to converge.

### Declarative Config (Apply/Export)
The `gitbox.yaml` file describes the desired state of the world:
- Which groups exist and their membership
- Which secrets exist, their source files, and who should have access

`gitbox apply` reads this config and converges:
1. Creates/updates groups (signed)
2. For each secret: compares current recipients to desired recipients
3. Grants access to users who should have it but don't
4. Revokes access from users who shouldn't have it (full re-encryption)
5. Creates new secrets from source files
6. Re-encrypts secrets whose source file content has changed

`gitbox export` dumps the current state in the same format. This makes it easy to audit access and manage changes via code review (change the YAML, get it reviewed, apply).

## Security Model

### Signing and Trust

Sensitive config files are signed with SSH keys to prevent unauthorized modification by rogue committers:

| Resource | Signed? | Trust model |
|---|---|---|
| GitHub identities | No | GitHub/GHE is the trust anchor |
| Manual identities | Optional (TOFU) | First writer wins; signing recommended |
| Paper keys | **Required** | Must be signed by owner's SSH key |
| Groups | **Required** | Must be signed by a known identity or paper key |
| Identity recovery | **Required** | Must be signed by owner's paper key |
| Secret manifests | No (authenticated encryption) | NaCl secretbox provides integrity |

**Paper keys are a root of trust.** The set of valid signers includes both SSH keys from identities AND paper key private keys. This means a paper key can:
- Authorize identity updates (re-keying after SSH key loss)
- Sign group changes
- Sign new paper key additions

Signatures are standard SSH signatures (`ssh.Signer.Sign`), verified against all known public keys (identity SSH keys + paper key Ed25519 keys). Signing only occurs when the signing key matches a known identity -- during bootstrap (no identities yet), signing is skipped.

### What GitBox Protects Against
- **Unauthorized access to secrets in the repository**: Only users whose SSH keys are listed as recipients can decrypt
- **Tampering**: NaCl secretbox provides authenticated encryption -- any modification is detected
- **Key compromise of one user**: Each user has their own wrapped DEK; compromising one key doesn't reveal others' wrapped DEKs
- **Rogue paper key injection**: Paper keys must be signed by the owner's SSH key, verified at encrypt time
- **Rogue group modification**: Groups must be signed, verified at resolution time

### What GitBox Does NOT Protect Against
- **Compromised private SSH keys**: If an attacker has your SSH private key, they can decrypt your secrets
- **Git history after revocation**: Revoking a user re-encrypts going forward, but old git commits still contain the old ciphertext encrypted with a DEK the revoked user possessed
- **Malicious committers replacing secret ciphertext**: Someone could replace the encrypted payload (but not decrypt it or forge it -- NaCl secretbox prevents that)
- **Side-channel attacks**: This is a CLI tool, not a hardened HSM

### Trust Model
- GitHub (or GitHub Enterprise) is trusted as the source of truth for SSH public keys
- The configured `git_host` is auto-detected from the git remote origin
- The person running `gitbox add-user` trusts that the keys returned by the GitHub host belong to the intended user
- Manual identities use TOFU (Trust On First Use) -- signing recommended
- Paper keys and groups require valid SSH signatures from known identities
- Revoking a user strips their direct access AND their paper keys

## Pre-Commit Hook

The hook prevents plaintext secret files from being accidentally committed:
1. Checks if any staged files are in `.gitbox/.tracked`
2. If so, blocks the commit with a message to encrypt first
3. Encrypted files in `.gitbox/secrets/` pass through normally

## Dependencies

- `golang.org/x/crypto`: SSH key parsing, NaCl secretbox/box, X25519, Ed25519, SSH signing
- `filippo.io/edwards25519`: Ed25519 to X25519 public key conversion (Edwards to Montgomery)
- `gopkg.in/yaml.v3`: YAML serialization for manifests and config

## Inspiration

The cryptographic design draws from:
- **Keybase/saltpack**: Per-recipient key wrapping, Ed25519->X25519 conversion
- **age**: SSH key-based encryption, simple formats
- **NaCl/libsodium**: The secretbox and box constructions
- **PGP**: Concept of per-user key wrapping (but with modern crypto)
- **BIP39**: Mnemonic word encoding for paper keys
