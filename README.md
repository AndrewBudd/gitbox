# GitBox

Encrypt secrets in git repositories using GitHub SSH keys as identity.

GitBox lets you store secrets directly in version control, encrypted for specific GitHub users. Recipients are specified by GitHub username -- their SSH public keys are fetched automatically.

## How It Works

1. Each secret is encrypted with a random Data Encryption Key (DEK) using NaCl secretbox
2. The DEK is wrapped (encrypted) for each recipient's SSH public key
3. RSA keys use RSA-OAEP; Ed25519 keys are converted to X25519 for ECDH
4. Encrypted data and wrapped keys are stored as YAML in `.gitbox/`
5. A pre-commit hook prevents plaintext secrets from being committed

## Quick Start

```bash
# Build
go build -o gitbox .

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

Groups can reference other groups (nested). Resolution is recursive with cycle detection.

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
gitbox refresh-keys alice -k ~/.ssh/id_ed25519
gitbox refresh-keys --all -k ~/.ssh/id_ed25519
```

`refresh-keys` re-fetches from GitHub and re-wraps the DEK for every secret the user has access to, using the new keys. Old key wrappings are replaced.

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
gitbox apply gitbox.yaml -k ~/.ssh/id_ed25519

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

Generate a paper key for emergency access if you lose your SSH keys:

```bash
gitbox paper-key generate
```

This displays a hex-encoded seed. **Write it down and store it securely** -- it won't be shown again. New secrets are automatically encrypted for the paper key.

To recover a secret using the paper key:

```bash
gitbox paper-key recover <secret-name>
# Enter the hex seed when prompted
```

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
| `.gitbox/groups.yaml` | Yes | Group definitions |
| `.gitbox/paperkey.yaml` | Yes | Paper key public key (safe) |
| `gitbox.yaml` | Yes | Declarative config (no secrets) |
| Plaintext secret files | **No** | Auto-added to `.gitignore` |

## CLI Reference

```
Identity:
  add-user <username>                     Fetch GitHub user's SSH keys
  add-key <user> <key-file-or-string>     Add SSH key manually
  refresh-keys <user|--all> [-k key]      Re-fetch keys, rebox secrets
  list-users                              List known identities

Groups:
  group create <name> <members>           Create a group
  group add <name> <user>                 Add member to group
  group remove <name> <user>              Remove member from group
  group list                              List all groups
  group delete <name>                     Delete a group

Secrets:
  encrypt <file> -n <name> -r <recips>    Encrypt (recips: users or @groups)
  decrypt <name> [-k key] [-o file]       Decrypt a secret
  grant <name> <user> [-k key]            Grant access
  revoke <name> <user> [-k key]           Revoke access (re-encrypts)
  list                                    List secrets and recipients

Config:
  init                                    Initialize .gitbox
  apply [gitbox.yaml] [-k key]            Apply declarative config
  export                                  Export state as YAML
  paper-key generate                      Generate recovery paper key
  paper-key recover <name>                Decrypt with paper key
  install-hook                            Install pre-commit hook
```

## Security

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full cryptographic design, threat model, and security considerations.

Key points:
- Uses NaCl secretbox (XSalsa20-Poly1305) for authenticated encryption
- RSA keys: RSA-OAEP with SHA-256
- Ed25519 keys: Converted to X25519, ephemeral ECDH + NaCl secretbox
- Revocation generates a new DEK and re-encrypts (forward secrecy)
- Paper key provides offline emergency recovery
- Key refresh re-wraps DEKs when SSH keys rotate

## Requirements

- Go 1.22+
- Git
- SSH keys in `~/.ssh/` (or specify with `-k`)
- Network access to `github.com` (for fetching public keys, optional with manual keys)
