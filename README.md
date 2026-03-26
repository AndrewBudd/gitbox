# GitBox

Encrypt secrets in git repositories using GitHub SSH keys as identity.

GitBox lets you store secrets directly in version control, encrypted for specific GitHub users. Recipients are specified by GitHub username -- their SSH public keys are fetched automatically.

## Install

```bash
# From source (requires Go 1.22+)
go install github.com/AndrewBudd/gitbox@latest

# Or clone and build
git clone https://github.com/AndrewBudd/gitbox.git
cd gitbox
go build -o gitbox .

# Move to PATH
sudo mv gitbox /usr/local/bin/
```

## How It Works

1. Each secret is encrypted with a random Data Encryption Key (DEK) using NaCl secretbox
2. The DEK is wrapped (encrypted) for each recipient's SSH public key
3. RSA keys use RSA-OAEP; Ed25519 keys are converted to X25519 for ECDH
4. Encrypted data and wrapped keys are stored as YAML in `.gitbox/`
5. A pre-commit hook prevents plaintext secrets from being committed

Your `~/.ssh/id_ed25519` or `~/.ssh/id_rsa` is used automatically for decryption and signing. The `-k` flag is only needed if your key is in a non-standard location.

## Quick Start

```bash
# Initialize in your git repo
cd your-repo
gitbox init

# Add team members (fetches their SSH keys from GitHub)
gitbox add-user alice
gitbox add-user bob

# Or add keys manually (no GitHub account needed)
gitbox add-key contractor ~/.ssh/contractor_ed25519.pub

# Encrypt a secrets file for specific users
gitbox encrypt .env -n app-secrets -r alice,bob

# Decrypt (uses your ~/.ssh keys automatically)
gitbox decrypt app-secrets

# Decrypt to a file
gitbox decrypt app-secrets -o .env

# Grant access to another user
gitbox grant app-secrets charlie

# Revoke access (re-encrypts with new key)
gitbox revoke app-secrets bob

# List secrets and recipients
gitbox list

# List registered users
gitbox list-users

# Commit the encrypted data
git add .gitbox/ .gitignore
git commit -m "add encrypted secrets"
```

## Groups

Create named groups of users and reference them with `@group` in recipients:

```bash
# Create groups
gitbox group create backend alice,bob,charlie
gitbox group create frontend diana,eve
gitbox group create all-devs @backend,@frontend

# Encrypt for a group
gitbox encrypt .env -n prod-secrets -r @backend

# Mix groups and individual users
gitbox encrypt stripe.env -n payment-secrets -r @frontend,alice

# Manage group membership
gitbox group add backend frank
gitbox group remove backend charlie
gitbox group list
gitbox group delete old-team
```

Groups can reference other groups (nested). Resolution is recursive with cycle detection. Group changes are signed with your SSH key to prevent unauthorized modifications.

## Key Management

```bash
# Fetch keys from GitHub
gitbox add-user octocat

# Add keys manually (from file or inline)
gitbox add-key contractor ~/.ssh/contractor.pub
gitbox add-key contractor "ssh-ed25519 AAAA... user@host"

# Add additional keys to an existing user
gitbox add-key alice ~/.ssh/alice_new_key.pub

# When a user's GitHub keys change, refresh and rebox all their secrets
gitbox refresh-keys alice
gitbox refresh-keys --all
```

`refresh-keys` re-fetches from GitHub and re-wraps the DEK for every secret the user has access to, using the new keys. It also prunes any paper keys whose signatures no longer verify against the updated key set.

## Declarative Config (gitbox.yaml)

Express your entire secrets configuration as YAML:

```yaml
# gitbox.yaml
groups:
  backend:
    - alice
    - bob
  frontend:
    - charlie
    - diana
  all-devs:
    - "@backend"
    - "@frontend"

secrets:
  prod-db:
    file: secrets/prod-db.env
    recipients:
      - "@backend"

  api-keys:
    file: secrets/api-keys.env
    recipients:
      - "@all-devs"

  stripe:
    file: secrets/stripe.env
    recipients:
      - alice
      - bob
```

Apply the config to converge state:

```bash
# Apply config (grants/revokes as needed to match desired state)
gitbox apply gitbox.yaml

# Export current state to gitbox.yaml
gitbox export > gitbox.yaml
```

`apply` is idempotent. It:
- Creates groups that don't exist
- Creates new secrets from their `file` field
- Grants access to users who should have it but don't
- Revokes access from users who shouldn't have it anymore
- Re-encrypts secrets whose source file content has changed

## Paper Key (Emergency Recovery)

Paper keys are offline recovery keys tied to your identity. If you lose all your SSH keys, a paper key lets you decrypt your secrets.

```bash
# Generate a named paper key (displayed as 24 mnemonic words)
gitbox paper-key generate -n office-safe

# Output:
#  1. hundred       2. involve       3. aim           4. neutral
#  5. ketchup       6. summer        7. donkey        8. absorb
#  ...
# 24. heavy

# List all paper keys
gitbox paper-key list

# Recover a secret using the paper key words
gitbox paper-key recover my-secret
# Enter your 24 recovery words (or hex): ...

# Delete a paper key
gitbox paper-key delete office-safe
```

Paper keys are:
- **Your root of trust** -- can sign identity updates, group changes, and new paper keys
- **Owned by your identity** -- you can only create paper keys for yourself
- **Signed with your SSH key** -- unsigned paper keys are rejected at encrypt time
- **Automatically included** in all new secrets as an additional recipient
- **Removed when you're revoked** -- revoking a user also strips their paper keys from secrets
- **Encoded as 24 BIP39 mnemonic words** with a SHA-256 checksum (also accepts hex)

### Identity Recovery (Lost SSH Keys)

If you lose all your SSH keys, your paper key handles everything -- identity update AND reboxing:

```bash
# Generate new SSH keys on your new machine
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519

# Recover: updates identity + reboxes all secrets in one step
gitbox recover-identity alice ~/.ssh/id_ed25519.pub
# Enter your 24 recovery words when prompted
# Output:
#   Identity "alice" updated with new keys, signed by paper key.
#   Reboxed 5 secret(s) for alice's current keys.

# Commit everything
git add .gitbox/
git commit -m "recover alice identity after key loss"
```

The paper key can decrypt the DEKs (it's a recipient on every secret), so it handles the reboxing automatically. No second person needed.

### Key Refresh (GitHub Keys Changed)

If someone rotates their GitHub SSH keys, any team member can refresh and rebox:

```bash
# Fetches new keys from GitHub, then reboxes all their secrets
gitbox refresh-keys alice

# Output:
#   Updated to 2 key(s)
#   Reboxed 5 secret(s) for alice's current keys.
#   Warning: could not rebox 1 secret(s) (no access to decrypt):
#     - infra-creds
#   Another recipient with access to those secrets will need to run refresh-keys.
```

If the operator doesn't have access to all of alice's secrets, it tells you which ones still need reboxing. Another team member who does have access runs the same command to pick up the rest.

The same auto-rebox happens when you `add-key` to an existing user.

The paper key acts as a signing authority: it can authorize changes to your own identity, sign group modifications, and sign new paper keys. This is what makes it safe to write down and store offline -- it's the break-glass root of trust for your gitbox identity.

## Pre-Commit Hook

Install the hook to prevent accidentally committing plaintext secrets:

```bash
gitbox install-hook
```

The hook blocks commits that include tracked plaintext files, ensuring only encrypted data reaches the repository.

## What Gets Committed

| Path | Committed? | Contains |
|---|---|---|
| `.gitbox/config.yaml` | Yes | Version info |
| `.gitbox/identities/*.yaml` | Yes | Public keys (safe) |
| `.gitbox/secrets/*.yaml` | Yes | Encrypted data + wrapped DEKs |
| `.gitbox/groups.yaml` | Yes | Group definitions (signed) |
| `.gitbox/paperkeys/*.yaml` | Yes | Paper key public keys (signed) |
| `gitbox.yaml` | Yes | Declarative config (no secrets) |
| Plaintext secret files | **No** | Auto-added to `.gitignore` |

## Signing and Trust

Sensitive config files are signed with SSH keys to prevent unauthorized modification:

| Resource | Signing | Trust model |
|---|---|---|
| GitHub identities | Not signed | GitHub is the trust anchor |
| Manual identities | Optional (TOFU) | First writer wins; signing recommended |
| Paper keys | **Required** | Must be signed by owner's SSH key |
| Groups | **Required** | Must be signed by a known identity or paper key |
| Identity recovery | **Required** | Must be signed by owner's paper key |

Paper keys are a **root of trust**: they can sign identity updates, group changes, and new paper keys. This means if you lose all your SSH keys, your paper key can authorize the recovery. Paper keys and groups are verified at encrypt time -- an attacker with repo write access cannot inject a backdoor without a valid signature.

## CLI Reference

```
Identity:
  add-user <username>                     Fetch GitHub user's SSH keys
  add-key <user> <key-file-or-string>     Add SSH key manually
  refresh-keys <user|--all>               Re-fetch keys, rebox secrets
  list-users                              List known identities

Groups:
  group create <name> <members>           Create a group (signed)
  group add <name> <user>                 Add member to group
  group remove <name> <user>              Remove member from group
  group list                              List all groups
  group delete <name>                     Delete a group

Secrets:
  encrypt <file> -n <name> -r <recips>    Encrypt (recips: users or @groups)
  decrypt <name> [-o file]                Decrypt a secret
  grant <name> <user>                     Grant access
  revoke <name> <user>                    Revoke access (re-encrypts)
  list                                    List secrets and recipients

Paper Keys & Recovery:
  paper-key generate [-n name]            Generate recovery key (24 words)
  paper-key list                          List all paper keys and owners
  paper-key delete <name>                 Remove a paper key
  paper-key recover <secret>              Decrypt using paper key words
  recover-identity <user> <key.pub>       Re-key identity + rebox using paper key

Config:
  init                                    Initialize .gitbox
  apply [gitbox.yaml]                     Apply declarative config
  export                                  Export state as YAML
  install-hook                            Install pre-commit hook

All commands that need a private key (decrypt, grant, revoke, encrypt, etc.)
automatically use ~/.ssh/id_ed25519 or ~/.ssh/id_rsa. Use -k <path> to
override with a specific key.
```

## Security

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full cryptographic design, threat model, and security considerations.

Key points:
- NaCl secretbox (XSalsa20-Poly1305) for authenticated encryption
- RSA-OAEP with SHA-256 for RSA key wrapping
- Ed25519 to X25519 conversion + ephemeral ECDH for Ed25519 key wrapping
- Per-secret DEKs with envelope encryption
- Revocation generates a new DEK and re-encrypts
- Paper keys provide offline emergency recovery, tied to identity
- SSH signatures on paper keys and groups prevent unauthorized injection
- Key refresh re-wraps DEKs and prunes invalid paper keys

## Requirements

- Go 1.22+
- Git
- SSH keys in `~/.ssh/` (auto-discovered, or specify with `-k`)
- Network access to `github.com` (for fetching public keys, optional with manual keys)
