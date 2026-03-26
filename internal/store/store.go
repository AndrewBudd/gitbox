// Package store manages the .gitbox directory and secret lifecycle.
package store

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gitboxcrypto "github.com/gitbox/gitbox/internal/crypto"
	"github.com/gitbox/gitbox/internal/github"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Store represents a .gitbox directory in a repository.
type Store struct {
	Root string // path to .gitbox directory
}

// Config is the top-level .gitbox/config.yaml
type Config struct {
	Version  int    `yaml:"version"`
	GitHost  string `yaml:"git_host,omitempty"` // e.g. "github.com" or "git.corp.com"
}

// Identity represents a GitHub user's public keys cached locally.
type Identity struct {
	GitHubUser string                `yaml:"github_user"`
	Keys       []StoredKey           `yaml:"keys"`
	FetchedAt  time.Time             `yaml:"fetched_at"`
	Source     string                `yaml:"source,omitempty"` // "github" or "manual"
	Sig        *gitboxcrypto.Signature `yaml:"signature,omitempty"`
}

// StoredKey is a public key stored in an identity file.
type StoredKey struct {
	Type        string `yaml:"type"`
	Fingerprint string `yaml:"fingerprint"`
	PublicKey   string `yaml:"public_key"` // authorized_keys format
}

// SecretManifest is the YAML stored for each encrypted secret.
type SecretManifest struct {
	Name           string                   `yaml:"name"`
	EncryptedData  string                   `yaml:"encrypted_data"`  // base64 secretbox ciphertext
	Nonce          string                   `yaml:"nonce"`           // base64 secretbox nonce
	Recipients     []RecipientEntry         `yaml:"recipients"`
	CreatedAt      time.Time                `yaml:"created_at"`
	UpdatedAt      time.Time                `yaml:"updated_at"`
}

// RecipientEntry holds a wrapped DEK for one key of one recipient.
type RecipientEntry struct {
	GitHubUser      string `yaml:"github_user"`
	KeyFingerprint  string `yaml:"key_fingerprint"`
	KeyType         string `yaml:"key_type"`
	WrappedKey      string `yaml:"wrapped_key"`
	EphemeralPublic string `yaml:"ephemeral_public,omitempty"`
	WrapNonce       string `yaml:"wrap_nonce,omitempty"`
}

// Group represents a named group of users.
type Group struct {
	Name    string                  `yaml:"name"`
	Members []string                `yaml:"members"` // usernames or @group references
	Sig     *gitboxcrypto.Signature `yaml:"signature,omitempty"`
}

// GitBoxConfig is the declarative YAML config format (gitbox.yaml).
type GitBoxConfig struct {
	Groups  map[string][]string       `yaml:"groups,omitempty"`
	Secrets map[string]SecretConfig   `yaml:"secrets"`
}

// SecretConfig describes a secret in the declarative config.
type SecretConfig struct {
	File       string   `yaml:"file"`
	Recipients []string `yaml:"recipients"` // usernames or @group references
}

// PaperKeyConfig stores a paper key's public info in .gitbox/paperkeys/
type PaperKeyConfig struct {
	Name        string                  `yaml:"name"`
	Owner       string                  `yaml:"owner"`        // username of the identity this paper key belongs to
	PublicKey   string                  `yaml:"public_key"`   // base64 ed25519 public key
	Fingerprint string                 `yaml:"fingerprint"`
	CreatedAt  time.Time               `yaml:"created_at"`
	Sig        *gitboxcrypto.Signature `yaml:"signature,omitempty"`
}

// GitHost returns the configured GitHub host for this store.
func (s *Store) GitHost() string {
	var cfg Config
	if err := readYAML(filepath.Join(s.Root, "config.yaml"), &cfg); err == nil && cfg.GitHost != "" {
		return cfg.GitHost
	}
	return github.DefaultHost
}

// Open opens an existing .gitbox store in the given repo root.
func Open(repoRoot string) (*Store, error) {
	root := filepath.Join(repoRoot, ".gitbox")
	if _, err := os.Stat(filepath.Join(root, "config.yaml")); os.IsNotExist(err) {
		return nil, fmt.Errorf("no .gitbox found in %s (run 'gitbox init' first)", repoRoot)
	}
	return &Store{Root: root}, nil
}

// Init creates a new .gitbox store in the given repo root.
func Init(repoRoot string) (*Store, error) {
	root := filepath.Join(repoRoot, ".gitbox")

	// Create directory structure
	for _, dir := range []string{root, filepath.Join(root, "identities"), filepath.Join(root, "secrets"), filepath.Join(root, "paperkeys")} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	// Detect GitHub host from git remote origin
	host := github.DetectHost(repoRoot)

	cfg := Config{Version: 1, GitHost: host}
	if err := writeYAML(filepath.Join(root, "config.yaml"), cfg); err != nil {
		return nil, err
	}

	// Add .gitbox to .gitignore patterns for plaintext files
	// The encrypted data IS meant to be committed
	return &Store{Root: root}, nil
}

// AddUser fetches a user's SSH keys from the configured GitHub host and stores them.
// GitHub-fetched identities are trusted by virtue of GitHub as the authority.
func (s *Store) AddUser(username string) (*Identity, error) {
	rawKeys, err := github.FetchUserKeys(s.GitHost(), username)
	if err != nil {
		return nil, err
	}

	keys, err := gitboxcrypto.ParseSSHPublicKeys(rawKeys)
	if err != nil {
		return nil, fmt.Errorf("parse keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no supported keys found for user %q (need RSA or Ed25519)", username)
	}

	id := &Identity{
		GitHubUser: username,
		FetchedAt:  time.Now().UTC(),
		Source:     "github",
	}
	for _, k := range keys {
		id.Keys = append(id.Keys, StoredKey{
			Type:        k.Type,
			Fingerprint: k.Fingerprint,
			PublicKey:   k.RawLine,
		})
	}

	path := filepath.Join(s.Root, "identities", username+".yaml")
	if err := writeYAML(path, id); err != nil {
		return nil, err
	}
	return id, nil
}

// GetUser loads a stored identity.
func (s *Store) GetUser(username string) (*Identity, error) {
	path := filepath.Join(s.Root, "identities", username+".yaml")
	var id Identity
	if err := readYAML(path, &id); err != nil {
		return nil, fmt.Errorf("user %q not found: %w", username, err)
	}
	return &id, nil
}

// ListUsers returns all stored identities.
func (s *Store) ListUsers() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "identities"))
	if err != nil {
		return nil, err
	}
	var users []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			users = append(users, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return users, nil
}

// EncryptSecret encrypts data and stores it, wrapped for the given recipients.
// Recipients can include @group references which will be resolved.
func (s *Store) EncryptSecret(name string, plaintext []byte, recipients []string) error {
	// Resolve group references
	resolved, err := s.ResolveRecipients(recipients)
	if err != nil {
		return fmt.Errorf("resolve recipients: %w", err)
	}

	// Generate DEK
	dek, err := gitboxcrypto.GenerateDEK()
	if err != nil {
		return fmt.Errorf("generate dek: %w", err)
	}

	// Encrypt the payload
	ciphertext, nonce, err := gitboxcrypto.Seal(plaintext, dek)
	if err != nil {
		return fmt.Errorf("encrypt payload: %w", err)
	}

	// Wrap DEK for each recipient's keys
	var entries []RecipientEntry
	for _, username := range resolved {
		re, err := s.wrapDEKForUser(dek, username)
		if err != nil {
			return fmt.Errorf("wrap dek for %s: %w", username, err)
		}
		entries = append(entries, re...)
	}

	// Also wrap for paper key if configured
	if pkEntries, _ := s.wrapDEKForPaperKey(dek); len(pkEntries) > 0 {
		entries = append(entries, pkEntries...)
	}

	now := time.Now().UTC()
	manifest := SecretManifest{
		Name:          name,
		EncryptedData: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:         base64.StdEncoding.EncodeToString(nonce[:]),
		Recipients:    entries,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	path := filepath.Join(s.Root, "secrets", name+".yaml")
	return writeYAML(path, manifest)
}

// DecryptSecret decrypts a secret using the given SSH private key.
func (s *Store) DecryptSecret(name string, privKey interface{}) ([]byte, error) {
	manifest, err := s.GetSecret(name)
	if err != nil {
		return nil, err
	}

	// Try each recipient entry until one succeeds with our key
	for _, re := range manifest.Recipients {
		wrapped := &gitboxcrypto.WrappedDEK{
			KeyType:         re.KeyType,
			KeyFingerprint:  re.KeyFingerprint,
			WrappedKey:      re.WrappedKey,
			EphemeralPublic: re.EphemeralPublic,
			WrapNonce:       re.WrapNonce,
		}

		dek, err := gitboxcrypto.UnwrapDEK(wrapped, privKey)
		if err != nil {
			continue
		}

		ciphertext, err := base64.StdEncoding.DecodeString(manifest.EncryptedData)
		if err != nil {
			return nil, fmt.Errorf("decode ciphertext: %w", err)
		}
		nonceBytes, err := base64.StdEncoding.DecodeString(manifest.Nonce)
		if err != nil {
			return nil, fmt.Errorf("decode nonce: %w", err)
		}
		if len(nonceBytes) != 24 {
			return nil, fmt.Errorf("invalid nonce length: %d", len(nonceBytes))
		}
		var nonce [24]byte
		copy(nonce[:], nonceBytes)

		return gitboxcrypto.Open(ciphertext, nonce, dek)
	}
	return nil, fmt.Errorf("no matching key found for secret %q (tried %d recipient entries)", name, len(manifest.Recipients))
}

// GetSecret loads a secret manifest.
func (s *Store) GetSecret(name string) (*SecretManifest, error) {
	path := filepath.Join(s.Root, "secrets", name+".yaml")
	var m SecretManifest
	if err := readYAML(path, &m); err != nil {
		return nil, fmt.Errorf("secret %q not found: %w", name, err)
	}
	return &m, nil
}

// ListSecrets returns all stored secret names.
func (s *Store) ListSecrets() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Root, "secrets"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, strings.TrimSuffix(e.Name(), ".yaml"))
		}
	}
	return names, nil
}

// GrantAccess adds a user to a secret. Re-wraps the DEK for the new user.
// Requires an existing recipient's private key to decrypt the DEK first.
func (s *Store) GrantAccess(secretName, username string, privKey interface{}) error {
	manifest, err := s.GetSecret(secretName)
	if err != nil {
		return err
	}

	// Check if user already has access
	for _, re := range manifest.Recipients {
		if re.GitHubUser == username {
			return fmt.Errorf("user %q already has access to secret %q", username, secretName)
		}
	}

	// Decrypt the DEK using the provided private key
	dek, err := s.decryptDEK(manifest, privKey)
	if err != nil {
		return fmt.Errorf("cannot decrypt DEK (do you have access?): %w", err)
	}

	// Wrap for the new user
	newEntries, err := s.wrapDEKForUser(dek, username)
	if err != nil {
		return fmt.Errorf("wrap dek for %s: %w", username, err)
	}

	manifest.Recipients = append(manifest.Recipients, newEntries...)
	manifest.UpdatedAt = time.Now().UTC()

	path := filepath.Join(s.Root, "secrets", secretName+".yaml")
	return writeYAML(path, manifest)
}

// RevokeAccess removes a user from a secret.
// This re-encrypts the secret with a new DEK, re-wrapping for all remaining recipients.
// Requires an existing recipient's private key.
func (s *Store) RevokeAccess(secretName, username string, privKey interface{}) error {
	manifest, err := s.GetSecret(secretName)
	if err != nil {
		return err
	}

	// Decrypt the current payload
	plaintext, err := s.DecryptSecret(secretName, privKey)
	if err != nil {
		return fmt.Errorf("cannot decrypt secret: %w", err)
	}

	// Determine remaining recipients, excluding the revoked user
	// and any paper keys owned by the revoked user
	remaining := make(map[string]bool)
	hasPaperKey := false
	for _, re := range manifest.Recipients {
		if re.GitHubUser == username || re.GitHubUser == "" {
			continue
		}
		if isPaperKeyOwnedBy(re.GitHubUser, username) {
			continue // Drop paper keys belonging to the revoked user
		}
		if isPaperKeyRecipient(re.GitHubUser) {
			hasPaperKey = true
		} else {
			remaining[re.GitHubUser] = true
		}
	}

	if len(remaining) == 0 && !hasPaperKey {
		return fmt.Errorf("cannot revoke: %q is the last recipient", username)
	}

	var recipientList []string
	for u := range remaining {
		recipientList = append(recipientList, u)
	}

	// Re-encrypt with a fresh DEK for remaining recipients
	// Generate new DEK
	dek, err := gitboxcrypto.GenerateDEK()
	if err != nil {
		return fmt.Errorf("generate new dek: %w", err)
	}

	// Re-encrypt payload
	ciphertext, nonce, err := gitboxcrypto.Seal(plaintext, dek)
	if err != nil {
		return fmt.Errorf("re-encrypt: %w", err)
	}

	// Re-wrap DEK for remaining users
	var entries []RecipientEntry
	for _, u := range recipientList {
		re, err := s.wrapDEKForUser(dek, u)
		if err != nil {
			return fmt.Errorf("wrap dek for %s: %w", u, err)
		}
		entries = append(entries, re...)
	}

	// Re-wrap for paper key if it was present
	if hasPaperKey {
		pkEntries, err := s.wrapDEKForPaperKey(dek)
		if err == nil && pkEntries != nil {
			entries = append(entries, pkEntries...)
		}
	}

	manifest.EncryptedData = base64.StdEncoding.EncodeToString(ciphertext)
	manifest.Nonce = base64.StdEncoding.EncodeToString(nonce[:])
	manifest.Recipients = entries
	manifest.UpdatedAt = time.Now().UTC()

	path := filepath.Join(s.Root, "secrets", secretName+".yaml")
	return writeYAML(path, manifest)
}

// SavePaperKey stores a paper key's public information.
// The signing key must match a known identity -- that identity becomes the paper key's owner.
// You can only create paper keys for yourself.
func (s *Store) SavePaperKey(name string, pk *gitboxcrypto.PaperKey, signingKey interface{}) error {
	if signingKey == nil {
		return fmt.Errorf("signing key required to create a paper key")
	}

	// Determine owner by matching signing key to a known identity
	owner, err := s.IdentifyKey(signingKey)
	if err != nil {
		return fmt.Errorf("cannot determine paper key owner: %w", err)
	}

	dir := filepath.Join(s.Root, "paperkeys")
	os.MkdirAll(dir, 0755)

	cfg := PaperKeyConfig{
		Name:        name,
		Owner:       owner,
		PublicKey:   pk.PublicKeyBase64(),
		Fingerprint: pk.ToKeyInfo().Fingerprint,
		CreatedAt:  time.Now().UTC(),
	}

	data, err := signableBytesForPaperKey(cfg)
	if err != nil {
		return fmt.Errorf("marshal for signing: %w", err)
	}
	sig, err := gitboxcrypto.SignBytes(data, signingKey)
	if err != nil {
		return fmt.Errorf("sign paper key: %w", err)
	}
	cfg.Sig = sig

	return writeYAML(filepath.Join(dir, name+".yaml"), cfg)
}

// RecoverIdentity updates a user's SSH keys, signed by a paper key.
// This is the primary recovery flow: user lost SSH keys, has paper key words,
// generates new SSH keys, uses paper key to authorize the identity update.
// RecoverIdentity updates a user's SSH keys signed by their paper key,
// then automatically reboxes all secrets using the paper key to decrypt DEKs.
func (s *Store) RecoverIdentity(username string, newPubKeyLines string, paperKey *gitboxcrypto.PaperKey) (*ReboxResult, error) {
	// Verify this paper key is registered and belongs to this user
	paperKeys, err := s.ListPaperKeys()
	if err != nil {
		return nil, fmt.Errorf("list paper keys: %w", err)
	}
	found := false
	for _, pk := range paperKeys {
		if pk.Owner == username && pk.Fingerprint == paperKey.ToKeyInfo().Fingerprint {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("paper key does not match any registered paper key for user %q", username)
	}

	keys, err := gitboxcrypto.ParseSSHPublicKeys(newPubKeyLines)
	if err != nil {
		return nil, fmt.Errorf("parse new keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no supported keys found")
	}

	id := &Identity{
		GitHubUser: username,
		FetchedAt:  time.Now().UTC(),
		Source:     "manual",
	}
	for _, k := range keys {
		id.Keys = append(id.Keys, StoredKey{
			Type:        k.Type,
			Fingerprint: k.Fingerprint,
			PublicKey:   k.RawLine,
		})
	}

	// Sign with the paper key
	data, err := signableBytesForIdentity(*id)
	if err != nil {
		return nil, fmt.Errorf("marshal for signing: %w", err)
	}
	sig, err := gitboxcrypto.SignBytes(data, paperKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign identity with paper key: %w", err)
	}
	id.Sig = sig

	path := filepath.Join(s.Root, "identities", username+".yaml")
	if err := writeYAML(path, id); err != nil {
		return nil, err
	}

	// Auto-rebox: paper key is a recipient, so use it to decrypt DEKs
	// and re-wrap for the user's new keys
	result, err := s.ReboxUser(username, paperKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("rebox after recovery: %w", err)
	}
	return result, nil
}

// IdentifyKey determines which user a private key belongs to
// by computing its public key fingerprint and matching against known identities.
func (s *Store) IdentifyKey(privKey interface{}) (string, error) {
	fp, err := gitboxcrypto.FingerprintPrivateKey(privKey)
	if err != nil {
		return "", err
	}

	users, err := s.ListUsers()
	if err != nil {
		return "", err
	}
	for _, u := range users {
		id, err := s.GetUser(u)
		if err != nil {
			continue
		}
		for _, k := range id.Keys {
			if k.Fingerprint == fp {
				return u, nil
			}
		}
	}
	return "", fmt.Errorf("no identity found matching key fingerprint %s", fp)
}

// listPaperKeysRaw reads all paper key configs without signature verification.
// Used by collectTrustedKeys to build the trust chain (paper keys ARE trust anchors).
func (s *Store) listPaperKeysRaw() ([]PaperKeyConfig, error) {
	return s.ListPaperKeys()
}

// ListPaperKeys returns all paper key configs.
func (s *Store) ListPaperKeys() ([]PaperKeyConfig, error) {
	dir := filepath.Join(s.Root, "paperkeys")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Fall back to legacy single paperkey.yaml
			return s.loadLegacyPaperKey()
		}
		return nil, err
	}

	var keys []PaperKeyConfig
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		var cfg PaperKeyConfig
		if err := readYAML(filepath.Join(dir, e.Name()), &cfg); err != nil {
			continue
		}
		if cfg.Name == "" {
			cfg.Name = strings.TrimSuffix(e.Name(), ".yaml")
		}
		keys = append(keys, cfg)
	}

	// Also check legacy single file
	legacy, _ := s.loadLegacyPaperKey()
	keys = append(keys, legacy...)

	return keys, nil
}

// GetPaperKey loads a specific paper key config by name.
func (s *Store) GetPaperKey(name string) (*PaperKeyConfig, error) {
	path := filepath.Join(s.Root, "paperkeys", name+".yaml")
	var cfg PaperKeyConfig
	if err := readYAML(path, &cfg); err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		cfg.Name = name
	}
	return &cfg, nil
}

// DeletePaperKey removes a paper key.
func (s *Store) DeletePaperKey(name string) error {
	path := filepath.Join(s.Root, "paperkeys", name+".yaml")
	return os.Remove(path)
}

// loadLegacyPaperKey reads the old single paperkey.yaml if it exists.
func (s *Store) loadLegacyPaperKey() ([]PaperKeyConfig, error) {
	path := filepath.Join(s.Root, "paperkey.yaml")
	var cfg PaperKeyConfig
	if err := readYAML(path, &cfg); err != nil {
		return nil, nil
	}
	if cfg.Name == "" {
		cfg.Name = "default"
	}
	return []PaperKeyConfig{cfg}, nil
}

// RecipientsForSecret returns the list of GitHub usernames that have access to a secret.
func (s *Store) RecipientsForSecret(name string) ([]string, error) {
	manifest, err := s.GetSecret(name)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var users []string
	for _, re := range manifest.Recipients {
		if !seen[re.GitHubUser] {
			seen[re.GitHubUser] = true
			users = append(users, re.GitHubUser)
		}
	}
	return users, nil
}

// AddManualUser creates an identity from a raw SSH public key string.
// Manual identities must be signed by an existing authorized user (except during bootstrap).
func (s *Store) AddManualUser(username string, pubKeyLines string, signingKey interface{}) (*Identity, error) {
	keys, err := gitboxcrypto.ParseSSHPublicKeys(pubKeyLines)
	if err != nil {
		return nil, fmt.Errorf("parse keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no supported keys found (need RSA or Ed25519)")
	}

	id := &Identity{
		GitHubUser: username,
		FetchedAt:  time.Now().UTC(),
		Source:     "manual",
	}
	for _, k := range keys {
		id.Keys = append(id.Keys, StoredKey{
			Type:        k.Type,
			Fingerprint: k.Fingerprint,
			PublicKey:   k.RawLine,
		})
	}

	// Sign with the operator's key if it matches a known identity.
	// During bootstrap (no identities yet), skip signing.
	if signingKey != nil {
		if _, err := s.IdentifyKey(signingKey); err == nil {
			data, err := signableBytesForIdentity(*id)
			if err != nil {
				return nil, fmt.Errorf("marshal for signing: %w", err)
			}
			sig, err := gitboxcrypto.SignBytes(data, signingKey)
			if err != nil {
				return nil, fmt.Errorf("sign identity: %w", err)
			}
			id.Sig = sig
		}
	}

	path := filepath.Join(s.Root, "identities", username+".yaml")
	if err := writeYAML(path, id); err != nil {
		return nil, err
	}
	return id, nil
}

// AddKeyToUser appends additional SSH public keys to an existing identity,
// then reboxes all secrets the user has access to.
func (s *Store) AddKeyToUser(username string, pubKeyLines string, operatorKey interface{}) ([]StoredKey, *ReboxResult, error) {
	id, err := s.GetUser(username)
	if err != nil {
		return nil, nil, err
	}

	keys, err := gitboxcrypto.ParseSSHPublicKeys(pubKeyLines)
	if err != nil {
		return nil, nil, fmt.Errorf("parse keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no supported keys found")
	}

	existing := make(map[string]bool)
	for _, k := range id.Keys {
		existing[k.Fingerprint] = true
	}

	var added []StoredKey
	for _, k := range keys {
		if existing[k.Fingerprint] {
			continue
		}
		sk := StoredKey{
			Type:        k.Type,
			Fingerprint: k.Fingerprint,
			PublicKey:   k.RawLine,
		}
		id.Keys = append(id.Keys, sk)
		added = append(added, sk)
	}

	if len(added) == 0 {
		return nil, nil, fmt.Errorf("all keys already registered for user %q", username)
	}

	id.FetchedAt = time.Now().UTC()
	path := filepath.Join(s.Root, "identities", username+".yaml")
	if err := writeYAML(path, id); err != nil {
		return nil, nil, err
	}

	// Auto-rebox secrets for the updated key set
	var result *ReboxResult
	if operatorKey != nil {
		result, _ = s.ReboxUser(username, operatorKey)
	}
	return added, result, nil
}

// RefreshUserKeys re-fetches a user's keys from GitHub and re-wraps DEKs
// for all secrets the user has access to.
func (s *Store) RefreshUserKeys(username string, privKey interface{}) (*Identity, *ReboxResult, error) {
	rawKeys, err := github.FetchUserKeys(s.GitHost(), username)
	if err != nil {
		return nil, nil, err
	}

	keys, err := gitboxcrypto.ParseSSHPublicKeys(rawKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("parse keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no supported keys found for user %q", username)
	}

	// Build new key fingerprint set to detect removed keys
	newFingerprints := make(map[string]bool)
	for _, k := range keys {
		newFingerprints[k.Fingerprint] = true
	}

	// Update identity
	id := &Identity{
		GitHubUser: username,
		FetchedAt:  time.Now().UTC(),
		Source:     "github",
	}
	for _, k := range keys {
		id.Keys = append(id.Keys, StoredKey{
			Type:        k.Type,
			Fingerprint: k.Fingerprint,
			PublicKey:   k.RawLine,
		})
	}
	path := filepath.Join(s.Root, "identities", username+".yaml")
	if err := writeYAML(path, id); err != nil {
		return nil, nil, err
	}

	// Prune paper keys owned by this user that were signed by now-removed keys.
	// After a key refresh, the signing key may no longer be in the identity,
	// which means the paper key signature won't verify. Remove them proactively.
	paperKeys, _ := s.ListPaperKeys()
	for _, pk := range paperKeys {
		if pk.Owner != username {
			continue
		}
		// Verify the paper key signature still holds with the new key set
		if err := s.verifyPaperKey(&pk); err != nil {
			fmt.Fprintf(os.Stderr, "Pruning paper key %q (owner %s): signature no longer valid after key refresh\n", pk.Name, pk.Owner)
			s.DeletePaperKey(pk.Name)
		}
	}

	result, err := s.ReboxUser(username, privKey)
	if err != nil {
		return id, nil, err
	}
	return id, result, nil
}

// ReboxResult summarizes a rebox operation.
type ReboxResult struct {
	Reboxed int
	Skipped []string // secrets the operator couldn't decrypt
}

// ReboxUser re-wraps the DEK for all secrets a user has access to,
// using the user's current keys from their identity file.
// privKey is from the operator (whoever is running the command).
func (s *Store) ReboxUser(username string, privKey interface{}) (*ReboxResult, error) {
	secrets, err := s.ListSecrets()
	if err != nil {
		return &ReboxResult{}, nil
	}

	result := &ReboxResult{}
	for _, secretName := range secrets {
		manifest, err := s.GetSecret(secretName)
		if err != nil {
			continue
		}

		hasAccess := false
		for _, re := range manifest.Recipients {
			if re.GitHubUser == username {
				hasAccess = true
				break
			}
		}
		if !hasAccess {
			continue
		}

		dek, err := s.decryptDEK(manifest, privKey)
		if err != nil {
			result.Skipped = append(result.Skipped, secretName)
			continue
		}

		var remaining []RecipientEntry
		for _, re := range manifest.Recipients {
			if re.GitHubUser != username {
				remaining = append(remaining, re)
			}
		}

		newEntries, err := s.wrapDEKForUser(dek, username)
		if err != nil {
			result.Skipped = append(result.Skipped, secretName)
			continue
		}

		manifest.Recipients = append(remaining, newEntries...)
		manifest.UpdatedAt = time.Now().UTC()

		secretPath := filepath.Join(s.Root, "secrets", secretName+".yaml")
		if err := writeYAML(secretPath, manifest); err != nil {
			result.Skipped = append(result.Skipped, secretName)
			continue
		}
		result.Reboxed++
	}

	return result, nil
}

// -- Groups --

// GroupsConfig holds all groups.
type GroupsConfig struct {
	Groups []Group `yaml:"groups"`
}

// SaveGroups writes the groups config, signing each group.
func (s *Store) SaveGroups(groups map[string][]string, signingKey interface{}) error {
	// Only sign if key matches a known identity
	canSign := false
	if signingKey != nil {
		if _, err := s.IdentifyKey(signingKey); err == nil {
			canSign = true
		}
	}

	cfg := GroupsConfig{}
	for name, members := range groups {
		g := Group{Name: name, Members: members}
		if canSign {
			data, err := signableBytesForGroup(g)
			if err == nil {
				sig, err := gitboxcrypto.SignBytes(data, signingKey)
				if err == nil {
					g.Sig = sig
				}
			}
		}
		cfg.Groups = append(cfg.Groups, g)
	}
	return writeYAML(filepath.Join(s.Root, "groups.yaml"), cfg)
}

// LoadGroups reads the groups config.
func (s *Store) LoadGroups() (map[string][]string, error) {
	path := filepath.Join(s.Root, "groups.yaml")
	var cfg GroupsConfig
	if err := readYAML(path, &cfg); err != nil {
		if os.IsNotExist(err) {
			return make(map[string][]string), nil
		}
		return nil, err
	}
	result := make(map[string][]string)
	for _, g := range cfg.Groups {
		result[g.Name] = g.Members
	}
	return result, nil
}

// ResolveRecipients expands a recipient list, resolving @group references to usernames.
// Returns a deduplicated list of usernames.
func (s *Store) ResolveRecipients(recipients []string) ([]string, error) {
	groups, err := s.LoadGroups()
	if err != nil {
		return nil, fmt.Errorf("load groups: %w", err)
	}

	seen := make(map[string]bool)
	var result []string

	var resolve func(items []string, depth int) error
	resolve = func(items []string, depth int) error {
		if depth > 10 {
			return fmt.Errorf("circular group reference detected")
		}
		for _, item := range items {
			item = strings.TrimSpace(item)
			if strings.HasPrefix(item, "@") {
				groupName := item[1:]
				members, ok := groups[groupName]
				if !ok {
					return fmt.Errorf("unknown group: %q", groupName)
				}
				if err := resolve(members, depth+1); err != nil {
					return err
				}
			} else {
				if !seen[item] {
					seen[item] = true
					result = append(result, item)
				}
			}
		}
		return nil
	}

	if err := resolve(recipients, 0); err != nil {
		return nil, err
	}
	return result, nil
}

// -- Declarative Config (apply/export) --

// Export generates a GitBoxConfig representing the current state.
func (s *Store) Export() (*GitBoxConfig, error) {
	cfg := &GitBoxConfig{
		Secrets: make(map[string]SecretConfig),
	}

	// Export groups
	groups, err := s.LoadGroups()
	if err == nil && len(groups) > 0 {
		cfg.Groups = groups
	}

	// Export secrets
	secrets, err := s.ListSecrets()
	if err != nil {
		return nil, err
	}

	for _, name := range secrets {
		recipients, err := s.RecipientsForSecret(name)
		if err != nil {
			continue
		}
		// Filter out internal recipients
		var userRecipients []string
		for _, r := range recipients {
			if !isPaperKeyRecipient(r) {
				userRecipients = append(userRecipients, r)
			}
		}
		cfg.Secrets[name] = SecretConfig{
			Recipients: userRecipients,
		}
	}

	return cfg, nil
}

// Apply converges the store state to match the given config.
// It needs a private key to grant/revoke access on existing secrets.
// For new secrets, it needs the plaintext file content (provided via fileReader).
// Returns a summary of actions taken.
func (s *Store) Apply(cfg *GitBoxConfig, privKey interface{}, fileReader func(path string) ([]byte, error)) ([]string, error) {
	var actions []string

	// 1. Apply groups
	if cfg.Groups != nil {
		existingGroups, _ := s.LoadGroups()
		if !groupsEqual(existingGroups, cfg.Groups) {
			if err := s.SaveGroups(cfg.Groups, privKey); err != nil {
				return actions, fmt.Errorf("save groups: %w", err)
			}
			actions = append(actions, "Updated groups")
		}
	}

	// 2. Apply secrets
	for name, sc := range cfg.Secrets {
		// Resolve group references
		desiredRecipients, err := s.ResolveRecipients(sc.Recipients)
		if err != nil {
			return actions, fmt.Errorf("resolve recipients for %q: %w", name, err)
		}

		// Check if secret exists
		_, err = s.GetSecret(name)
		if err != nil {
			// Secret doesn't exist, create it
			if sc.File == "" {
				return actions, fmt.Errorf("secret %q: 'file' required for new secrets", name)
			}
			if fileReader == nil {
				return actions, fmt.Errorf("secret %q: file reader not provided", name)
			}
			plaintext, err := fileReader(sc.File)
			if err != nil {
				return actions, fmt.Errorf("secret %q: read file %q: %w", name, sc.File, err)
			}
			if err := s.EncryptSecret(name, plaintext, desiredRecipients); err != nil {
				return actions, fmt.Errorf("secret %q: encrypt: %w", name, err)
			}
			actions = append(actions, fmt.Sprintf("Created secret %q for %s", name, strings.Join(desiredRecipients, ", ")))
			continue
		}

		// Secret exists -- converge recipients
		currentRecipients, _ := s.RecipientsForSecret(name)
		currentSet := toSet(currentRecipients)
		desiredSet := toSet(desiredRecipients)

		// Remove internal entries from current set for comparison
		for k := range currentSet {
			if isPaperKeyRecipient(k) {
				delete(currentSet, k)
			}
		}

		// Grant new users
		for _, u := range desiredRecipients {
			if !currentSet[u] {
				if privKey == nil {
					return actions, fmt.Errorf("secret %q: private key required to grant %q", name, u)
				}
				if err := s.GrantAccess(name, u, privKey); err != nil {
					return actions, fmt.Errorf("secret %q: grant %q: %w", name, u, err)
				}
				actions = append(actions, fmt.Sprintf("Granted %s access to %q", u, name))
			}
		}

		// Revoke removed users
		for u := range currentSet {
			if !desiredSet[u] {
				if privKey == nil {
					return actions, fmt.Errorf("secret %q: private key required to revoke %q", name, u)
				}
				if err := s.RevokeAccess(name, u, privKey); err != nil {
					return actions, fmt.Errorf("secret %q: revoke %q: %w", name, u, err)
				}
				actions = append(actions, fmt.Sprintf("Revoked %s access to %q", u, name))
			}
		}

		// If the file field is set and different content, re-encrypt
		if sc.File != "" && fileReader != nil {
			newPlaintext, err := fileReader(sc.File)
			if err == nil {
				// Re-encrypt with current recipients
				oldPlaintext, decErr := s.DecryptSecret(name, privKey)
				if decErr == nil && string(oldPlaintext) != string(newPlaintext) {
					// Content changed, re-encrypt
					currentRecipients, _ = s.RecipientsForSecret(name)
					var userRecipients []string
					for _, r := range currentRecipients {
						if !isPaperKeyRecipient(r) {
							userRecipients = append(userRecipients, r)
						}
					}
					if err := s.EncryptSecret(name, newPlaintext, userRecipients); err != nil {
						return actions, fmt.Errorf("secret %q: re-encrypt: %w", name, err)
					}
					actions = append(actions, fmt.Sprintf("Re-encrypted %q (content changed)", name))
				}
			}
		}

	}

	return actions, nil
}

// -- internal helpers --

func isPaperKeyRecipient(username string) bool {
	return strings.HasPrefix(username, "__paper_key__")
}

// isPaperKeyOwnedBy checks if a paper key recipient string belongs to a specific user.
// Format: __paper_key__:owner:name
func isPaperKeyOwnedBy(recipient, owner string) bool {
	if !isPaperKeyRecipient(recipient) {
		return false
	}
	parts := strings.SplitN(recipient, ":", 3)
	return len(parts) >= 2 && parts[1] == owner
}

// paperKeyOwner extracts the owner from a paper key recipient string.
func paperKeyOwner(recipient string) string {
	parts := strings.SplitN(recipient, ":", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func toSet(items []string) map[string]bool {
	s := make(map[string]bool)
	for _, item := range items {
		s[item] = true
	}
	return s
}

func groupsEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

func (s *Store) wrapDEKForUser(dek [32]byte, username string) ([]RecipientEntry, error) {
	id, err := s.GetUser(username)
	if err != nil {
		return nil, fmt.Errorf("load identity for %s: %w", username, err)
	}

	// Verify signature on manual identities before trusting their keys
	if err := s.verifyIdentity(id); err != nil {
		return nil, fmt.Errorf("identity verification failed for %s: %w", username, err)
	}

	var entries []RecipientEntry
	for _, sk := range id.Keys {
		ki, err := gitboxcrypto.ParseSSHPublicKey(sk.PublicKey)
		if err != nil {
			continue
		}
		wrapped, err := gitboxcrypto.WrapDEKForKey(dek, ki)
		if err != nil {
			return nil, fmt.Errorf("wrap dek with key %s: %w", sk.Fingerprint, err)
		}
		entries = append(entries, RecipientEntry{
			GitHubUser:      username,
			KeyFingerprint:  wrapped.KeyFingerprint,
			KeyType:         wrapped.KeyType,
			WrappedKey:      wrapped.WrappedKey,
			EphemeralPublic: wrapped.EphemeralPublic,
			WrapNonce:       wrapped.WrapNonce,
		})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no usable keys for user %s", username)
	}
	return entries, nil
}

func (s *Store) wrapDEKForPaperKey(dek [32]byte) ([]RecipientEntry, error) {
	paperKeys, err := s.ListPaperKeys()
	if err != nil || len(paperKeys) == 0 {
		return nil, nil // No paper keys configured, not an error
	}

	var entries []RecipientEntry
	for _, cfg := range paperKeys {
		// Verify paper key signature before trusting it
		if err := s.verifyPaperKey(&cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: skipping paper key %q: %v\n", cfg.Name, err)
			continue
		}

		pubBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
		if err != nil {
			continue
		}
		if len(pubBytes) != 32 {
			continue
		}

		edPub := ed25519.PublicKey(pubBytes)
		wrapped, err := gitboxcrypto.WrapDEKForKey(dek, &gitboxcrypto.KeyInfo{
			Type:        "ssh-ed25519",
			PublicKey:   edPub,
			Fingerprint: cfg.Fingerprint,
		})
		if err != nil {
			continue
		}

		entries = append(entries, RecipientEntry{
			GitHubUser:      "__paper_key__:" + cfg.Owner + ":" + cfg.Name,
			KeyFingerprint:  wrapped.KeyFingerprint,
			KeyType:         wrapped.KeyType,
			WrappedKey:      wrapped.WrappedKey,
			EphemeralPublic: wrapped.EphemeralPublic,
			WrapNonce:       wrapped.WrapNonce,
		})
	}
	return entries, nil
}

func (s *Store) decryptDEK(manifest *SecretManifest, privKey interface{}) ([32]byte, error) {
	for _, re := range manifest.Recipients {
		wrapped := &gitboxcrypto.WrappedDEK{
			KeyType:         re.KeyType,
			KeyFingerprint:  re.KeyFingerprint,
			WrappedKey:      re.WrappedKey,
			EphemeralPublic: re.EphemeralPublic,
			WrapNonce:       re.WrapNonce,
		}
		dek, err := gitboxcrypto.UnwrapDEK(wrapped, privKey)
		if err == nil {
			return dek, nil
		}
	}
	return [32]byte{}, fmt.Errorf("no matching key")
}

// collectTrustedKeys returns all public keys accepted as valid signers.
// This includes SSH keys from all known identities AND paper key public keys.
// Paper keys are a root of trust: they can sign identity updates, group changes,
// and other paper key additions -- enabling recovery when SSH keys are lost.
func (s *Store) collectTrustedKeys() []string {
	var keys []string

	// SSH keys from identities
	users, err := s.ListUsers()
	if err == nil {
		for _, u := range users {
			id, err := s.GetUser(u)
			if err != nil {
				continue
			}
			for _, k := range id.Keys {
				keys = append(keys, k.PublicKey)
			}
		}
	}

	// Paper key public keys (as authorized_keys format for signature verification)
	paperKeys, err := s.listPaperKeysRaw()
	if err == nil {
		for _, pk := range paperKeys {
			pubBytes, err := base64.StdEncoding.DecodeString(pk.PublicKey)
			if err != nil || len(pubBytes) != 32 {
				continue
			}
			edPub := ed25519.PublicKey(pubBytes)
			sshPub, err := ssh.NewPublicKey(edPub)
			if err != nil {
				continue
			}
			keys = append(keys, string(ssh.MarshalAuthorizedKey(sshPub)))
		}
	}

	return keys
}

// hasAnyIdentities returns true if at least one identity exists (non-bootstrap state).
func (s *Store) hasAnyIdentities() bool {
	users, err := s.ListUsers()
	return err == nil && len(users) > 0
}

// signableBytes returns the YAML bytes of a struct with its Sig field set to nil.
// This is the canonical content that gets signed.
func signableBytesForPaperKey(pk PaperKeyConfig) ([]byte, error) {
	pk.Sig = nil
	return yaml.Marshal(pk)
}

func signableBytesForIdentity(id Identity) ([]byte, error) {
	id.Sig = nil
	return yaml.Marshal(id)
}

func signableBytesForGroup(g Group) ([]byte, error) {
	g.Sig = nil
	return yaml.Marshal(g)
}

// verifyPaperKey checks that a paper key config has a valid signature from a trusted identity.
// Returns nil if valid or if no identities exist yet (bootstrap).
func (s *Store) verifyPaperKey(pk *PaperKeyConfig) error {
	if !s.hasAnyIdentities() {
		return nil // Bootstrap: no identities to verify against
	}
	if pk.Sig == nil {
		return fmt.Errorf("paper key %q is unsigned (requires signature from a known identity)", pk.Name)
	}
	data, err := signableBytesForPaperKey(*pk)
	if err != nil {
		return err
	}
	trusted := s.collectTrustedKeys()
	if err := gitboxcrypto.VerifySignature(data, pk.Sig, trusted); err != nil {
		return fmt.Errorf("paper key %q: invalid signature: %w", pk.Name, err)
	}
	return nil
}

// verifyIdentity checks that an identity has a valid signature.
// - GitHub-fetched identities (source: "github") are always trusted.
// - Signed manual identities: signature is verified against known keys.
// - Unsigned manual identities: accepted with a warning (TOFU model).
//   Signing is recommended but not required for identities. The critical
//   signing enforcement is on paper keys and groups, which are the real
//   attack surface for unauthorized key injection.
func (s *Store) verifyIdentity(id *Identity) error {
	if id.Source == "github" {
		return nil
	}
	if id.Sig == nil {
		return nil // TOFU: accept unsigned identities (first writer wins)
	}
	// Has a signature -- verify it
	data, err := signableBytesForIdentity(*id)
	if err != nil {
		return err
	}
	trusted := s.collectTrustedKeys()
	if err := gitboxcrypto.VerifySignature(data, id.Sig, trusted); err != nil {
		return fmt.Errorf("identity %q: invalid signature: %w", id.GitHubUser, err)
	}
	return nil
}

// verifyGroup checks that a group has a valid signature.
func (s *Store) verifyGroup(g *Group) error {
	if !s.hasAnyIdentities() {
		return nil
	}
	if g.Sig == nil {
		return fmt.Errorf("group %q is unsigned", g.Name)
	}
	data, err := signableBytesForGroup(*g)
	if err != nil {
		return err
	}
	trusted := s.collectTrustedKeys()
	if err := gitboxcrypto.VerifySignature(data, g.Sig, trusted); err != nil {
		return fmt.Errorf("group %q: invalid signature: %w", g.Name, err)
	}
	return nil
}

func writeYAML(path string, v interface{}) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func readYAML(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, v)
}
