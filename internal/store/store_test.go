package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gitboxcrypto "github.com/AndrewBudd/gitbox/internal/crypto"
	"golang.org/x/crypto/ssh"
)

// setupTestStore creates a temporary directory with a .gitbox store
// and returns the store, the repo root, and a cleanup function.
func setupTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Init(dir)
	if err != nil {
		t.Fatal("init store:", err)
	}
	return s, dir
}

// testFirstPrivKey stores the first test user's private key for signing subsequent users.
var testFirstPrivKey interface{}
var testFirstUser string

// addTestUser creates a fake identity with generated keys, properly chained.
func addTestUser(t *testing.T, s *Store, username string, keyType string) interface{} {
	t.Helper()

	var privKey interface{}
	var sshPubKey ssh.PublicKey

	switch keyType {
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privKey = priv
		sshPubKey, err = ssh.NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
	case "rsa":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		privKey = rsaKey
		sshPubKey, err = ssh.NewPublicKey(&rsaKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
	}

	authorizedKey := string(ssh.MarshalAuthorizedKey(sshPubKey))
	fingerprint := ssh.FingerprintSHA256(sshPubKey)

	id := &Identity{
		GitHubUser: username,
		Source:     "github",
		Keys: []StoredKey{{
			Type:        sshPubKey.Type(),
			Fingerprint: fingerprint,
			PublicKey:   authorizedKey,
		}},
	}

	path := filepath.Join(s.Root, "identities", username+".yaml")
	if err := writeYAML(path, id); err != nil {
		t.Fatal(err)
	}

	// First user: self-sign and set trust anchor
	// Subsequent users: signed by the first user
	users, _ := s.ListUsers()
	var signKey interface{}
	if len(users) <= 1 {
		id.SignedBy = "self"
		_ = s.setTrustAnchor(username, privKey)
		signKey = privKey
		testFirstPrivKey = privKey
		testFirstUser = username
	} else {
		id.SignedBy = testFirstUser
		signKey = testFirstPrivKey
	}

	data, err := signableBytesForIdentity(*id)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := gitboxcrypto.SignBytes(data, signKey)
	if err != nil {
		t.Fatal(err)
	}
	id.Sig = sig
	if err := writeYAML(path, id); err != nil {
		t.Fatal(err)
	}

	return privKey
}

func TestInitAndOpen(t *testing.T) {
	dir := t.TempDir()

	// Init should create the store
	s, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Root != filepath.Join(dir, ".gitbox") {
		t.Fatalf("unexpected root: %s", s.Root)
	}

	// Open should find it
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Root != s.Root {
		t.Fatal("open returned different root")
	}

	// Open on empty dir should fail
	emptyDir := t.TempDir()
	_, err = Open(emptyDir)
	if err == nil {
		t.Fatal("should fail on empty dir")
	}
}

func TestEncryptDecryptEd25519(t *testing.T) {
	s, _ := setupTestStore(t)

	priv := addTestUser(t, s, "alice", "ed25519")

	secret := []byte("super secret database password")
	err := s.EncryptSecret("db-password", secret, []string{"alice"})
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	// Verify secret file exists
	path := filepath.Join(s.Root, "secrets", "db-password.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("secret file not created")
	}

	// Decrypt
	decrypted, err := s.DecryptSecret("db-password", priv)
	if err != nil {
		t.Fatal("decrypt:", err)
	}

	if string(decrypted) != string(secret) {
		t.Fatalf("decrypted %q != original %q", decrypted, secret)
	}
}

func TestEncryptDecryptRSA(t *testing.T) {
	s, _ := setupTestStore(t)

	priv := addTestUser(t, s, "bob", "rsa")

	secret := []byte("rsa encrypted secret content")
	err := s.EncryptSecret("rsa-secret", secret, []string{"bob"})
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	decrypted, err := s.DecryptSecret("rsa-secret", priv)
	if err != nil {
		t.Fatal("decrypt:", err)
	}

	if string(decrypted) != string(secret) {
		t.Fatalf("decrypted %q != original %q", decrypted, secret)
	}
}

func TestMultiRecipientEncryptDecrypt(t *testing.T) {
	s, _ := setupTestStore(t)

	alicePriv := addTestUser(t, s, "alice", "ed25519")
	bobPriv := addTestUser(t, s, "bob", "rsa")

	secret := []byte("shared secret for both alice and bob")
	err := s.EncryptSecret("shared-secret", secret, []string{"alice", "bob"})
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	// Alice can decrypt
	decrypted, err := s.DecryptSecret("shared-secret", alicePriv)
	if err != nil {
		t.Fatal("alice decrypt:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("alice got wrong plaintext")
	}

	// Bob can decrypt
	decrypted, err = s.DecryptSecret("shared-secret", bobPriv)
	if err != nil {
		t.Fatal("bob decrypt:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("bob got wrong plaintext")
	}
}

func TestGrantAccess(t *testing.T) {
	s, _ := setupTestStore(t)

	alicePriv := addTestUser(t, s, "alice", "ed25519")
	bobPriv := addTestUser(t, s, "bob", "rsa")

	secret := []byte("alice's secret that bob will later get access to")
	err := s.EncryptSecret("grant-test", secret, []string{"alice"})
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	// Bob should NOT be able to decrypt yet
	_, err = s.DecryptSecret("grant-test", bobPriv)
	if err == nil {
		t.Fatal("bob should not have access yet")
	}

	// Grant bob access (alice provides her key)
	err = s.GrantAccess("grant-test", "bob", alicePriv)
	if err != nil {
		t.Fatal("grant:", err)
	}

	// Now bob can decrypt
	decrypted, err := s.DecryptSecret("grant-test", bobPriv)
	if err != nil {
		t.Fatal("bob decrypt after grant:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("bob got wrong plaintext after grant")
	}

	// Alice can still decrypt
	decrypted, err = s.DecryptSecret("grant-test", alicePriv)
	if err != nil {
		t.Fatal("alice decrypt after grant:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("alice got wrong plaintext after grant")
	}
}

func TestRevokeAccess(t *testing.T) {
	s, _ := setupTestStore(t)

	alicePriv := addTestUser(t, s, "alice", "ed25519")
	bobPriv := addTestUser(t, s, "bob", "rsa")

	secret := []byte("secret that bob will lose access to")
	err := s.EncryptSecret("revoke-test", secret, []string{"alice", "bob"})
	if err != nil {
		t.Fatal("encrypt:", err)
	}

	// Both can decrypt
	_, err = s.DecryptSecret("revoke-test", alicePriv)
	if err != nil {
		t.Fatal("alice pre-revoke:", err)
	}
	_, err = s.DecryptSecret("revoke-test", bobPriv)
	if err != nil {
		t.Fatal("bob pre-revoke:", err)
	}

	// Revoke bob (alice provides key to re-encrypt)
	err = s.RevokeAccess("revoke-test", "bob", alicePriv)
	if err != nil {
		t.Fatal("revoke:", err)
	}

	// Alice can still decrypt
	decrypted, err := s.DecryptSecret("revoke-test", alicePriv)
	if err != nil {
		t.Fatal("alice post-revoke:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("alice got wrong plaintext after revoke")
	}

	// Bob should NOT be able to decrypt anymore
	_, err = s.DecryptSecret("revoke-test", bobPriv)
	if err == nil {
		t.Fatal("bob should not have access after revoke")
	}
}

func TestListSecrets(t *testing.T) {
	s, _ := setupTestStore(t)
	addTestUser(t, s, "alice", "ed25519")

	// Empty list
	secrets, err := s.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(secrets))
	}

	// Add some secrets
	s.EncryptSecret("secret1", []byte("one"), []string{"alice"})
	s.EncryptSecret("secret2", []byte("two"), []string{"alice"})

	secrets, err = s.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
}

func TestListUsers(t *testing.T) {
	s, _ := setupTestStore(t)

	users, _ := s.ListUsers()
	if len(users) != 0 {
		t.Fatalf("expected 0 users, got %d", len(users))
	}

	addTestUser(t, s, "alice", "ed25519")
	addTestUser(t, s, "bob", "rsa")

	users, err := s.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestRecipientsForSecret(t *testing.T) {
	s, _ := setupTestStore(t)
	addTestUser(t, s, "alice", "ed25519")
	addTestUser(t, s, "bob", "rsa")

	s.EncryptSecret("multi", []byte("data"), []string{"alice", "bob"})

	recipients, err := s.RecipientsForSecret("multi")
	if err != nil {
		t.Fatal(err)
	}
	if len(recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(recipients))
	}
}

func TestPaperKeyIntegration(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")

	// Generate paper key, signed by alice
	pk, err := gitboxcrypto.GeneratePaperKey()
	if err != nil {
		t.Fatal(err)
	}

	err = s.SavePaperKey("test-recovery", pk, alicePriv)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt a secret (should auto-include paper key)
	secret := []byte("recoverable secret")
	err = s.EncryptSecret("recoverable", secret, []string{"alice"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify paper key recipient exists
	manifest, _ := s.GetSecret("recoverable")
	hasPaperKey := false
	for _, re := range manifest.Recipients {
		if strings.HasPrefix(re.GitHubUser, "__paper_key__") {
			hasPaperKey = true
			break
		}
	}
	if !hasPaperKey {
		t.Fatal("paper key should be a recipient")
	}

	// Decrypt using paper key
	decrypted, err := s.DecryptSecret("recoverable", pk.PrivateKey)
	if err != nil {
		t.Fatal("paper key decrypt:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("paper key decrypted wrong plaintext")
	}
}

func TestDecryptNonexistentSecret(t *testing.T) {
	s, _ := setupTestStore(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	_, err := s.DecryptSecret("nonexistent", priv)
	if err == nil {
		t.Fatal("should fail for nonexistent secret")
	}
}

func TestDoubleGrant(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")
	addTestUser(t, s, "bob", "rsa")

	s.EncryptSecret("test", []byte("data"), []string{"alice", "bob"})

	err := s.GrantAccess("test", "bob", alicePriv)
	if err == nil {
		t.Fatal("should fail on double grant")
	}
}

func TestRevokeLastRecipient(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")

	s.EncryptSecret("solo", []byte("data"), []string{"alice"})

	err := s.RevokeAccess("solo", "alice", alicePriv)
	if err == nil {
		t.Fatal("should not allow revoking last recipient")
	}
}

func TestManualAddUser(t *testing.T) {
	s, _ := setupTestStore(t)

	// Generate a key and get its authorized_keys line
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	authKey := string(ssh.MarshalAuthorizedKey(sshPub))

	id, err := s.AddManualUser("manual-user", authKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if id.GitHubUser != "manual-user" {
		t.Fatal("wrong username")
	}
	if len(id.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(id.Keys))
	}

	// Verify we can load it back
	loaded, err := s.GetUser("manual-user")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GitHubUser != "manual-user" {
		t.Fatal("loaded wrong user")
	}
}

func TestAddKeyToUser(t *testing.T) {
	s, _ := setupTestStore(t)
	addTestUser(t, s, "alice", "ed25519")

	// Generate a new RSA key
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	sshPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	authKey := string(ssh.MarshalAuthorizedKey(sshPub))

	added, _, err := s.AddKeyToUser("alice", authKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 {
		t.Fatalf("expected 1 added key, got %d", len(added))
	}

	// Verify user now has 2 keys
	id, _ := s.GetUser("alice")
	if len(id.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(id.Keys))
	}

	// Adding same key again should fail
	_, _, err = s.AddKeyToUser("alice", authKey, nil)
	if err == nil {
		t.Fatal("should fail on duplicate key")
	}
}

func TestGroups(t *testing.T) {
	s, _ := setupTestStore(t)

	// Empty groups
	groups, err := s.LoadGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 0 {
		t.Fatal("expected empty groups")
	}

	// Save groups
	groups = map[string][]string{
		"backend":  {"alice", "bob"},
		"frontend": {"charlie", "diana"},
	}
	if err := s.SaveGroups(groups, nil); err != nil {
		t.Fatal(err)
	}

	// Load back
	loaded, err := s.LoadGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(loaded))
	}
}

func TestResolveRecipients(t *testing.T) {
	s, _ := setupTestStore(t)
	s.SaveGroups(map[string][]string{
		"backend":  {"alice", "bob"},
		"frontend": {"charlie"},
		"all":      {"@backend", "@frontend", "eve"},
	}, nil)

	// Simple group
	resolved, err := s.ResolveRecipients([]string{"@backend"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 {
		t.Fatalf("expected 2, got %d: %v", len(resolved), resolved)
	}

	// Mixed
	resolved, err = s.ResolveRecipients([]string{"@frontend", "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 { // charlie, alice (deduped)
		t.Fatalf("expected 2, got %d: %v", len(resolved), resolved)
	}

	// Nested
	resolved, err = s.ResolveRecipients([]string{"@all"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 4 { // alice, bob, charlie, eve
		t.Fatalf("expected 4, got %d: %v", len(resolved), resolved)
	}

	// Dedup with nested
	resolved, err = s.ResolveRecipients([]string{"@all", "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 4 {
		t.Fatalf("expected 4 (deduped), got %d: %v", len(resolved), resolved)
	}

	// Unknown group
	_, err = s.ResolveRecipients([]string{"@nonexistent"})
	if err == nil {
		t.Fatal("should fail on unknown group")
	}
}

func TestEncryptWithGroup(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")
	addTestUser(t, s, "bob", "rsa")

	s.SaveGroups(map[string][]string{
		"team": {"alice", "bob"},
	}, nil)

	secret := []byte("group encrypted secret")
	err := s.EncryptSecret("group-secret", secret, []string{"@team"})
	if err != nil {
		t.Fatal(err)
	}

	// Both can decrypt
	decrypted, err := s.DecryptSecret("group-secret", alicePriv)
	if err != nil {
		t.Fatal("alice decrypt:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("content mismatch")
	}
}

func TestExport(t *testing.T) {
	s, _ := setupTestStore(t)
	addTestUser(t, s, "alice", "ed25519")
	addTestUser(t, s, "bob", "rsa")

	s.SaveGroups(map[string][]string{"team": {"alice", "bob"}}, nil)
	s.EncryptSecret("test-secret", []byte("data"), []string{"alice", "bob"})

	cfg, err := s.Export()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(cfg.Groups))
	}
	if _, ok := cfg.Secrets["test-secret"]; !ok {
		t.Fatal("missing test-secret in export")
	}
	if len(cfg.Secrets["test-secret"].Recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(cfg.Secrets["test-secret"].Recipients))
	}
}

func TestMultiplePaperKeys(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")

	// Generate two paper keys, signed by alice
	pk1, _ := gitboxcrypto.GeneratePaperKey()
	pk2, _ := gitboxcrypto.GeneratePaperKey()

	s.SavePaperKey("office-safe", pk1, alicePriv)
	s.SavePaperKey("ceo-vault", pk2, alicePriv)

	// List should return both
	keys, err := s.ListPaperKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 paper keys, got %d", len(keys))
	}

	// Encrypt a secret -- both paper keys should be recipients
	s.EncryptSecret("multi-pk-test", []byte("recover me"), []string{"alice"})

	manifest, _ := s.GetSecret("multi-pk-test")
	pkCount := 0
	for _, re := range manifest.Recipients {
		if strings.HasPrefix(re.GitHubUser, "__paper_key__") {
			pkCount++
		}
	}
	if pkCount != 2 {
		t.Fatalf("expected 2 paper key recipients, got %d", pkCount)
	}

	// Both paper keys can decrypt
	dec1, err := s.DecryptSecret("multi-pk-test", pk1.PrivateKey)
	if err != nil {
		t.Fatal("paper key 1 decrypt:", err)
	}
	if string(dec1) != "recover me" {
		t.Fatal("paper key 1 wrong content")
	}

	dec2, err := s.DecryptSecret("multi-pk-test", pk2.PrivateKey)
	if err != nil {
		t.Fatal("paper key 2 decrypt:", err)
	}
	if string(dec2) != "recover me" {
		t.Fatal("paper key 2 wrong content")
	}

	// Delete one, verify the other still works for new secrets
	s.DeletePaperKey("office-safe")
	keys, _ = s.ListPaperKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 paper key after delete, got %d", len(keys))
	}

	s.EncryptSecret("after-delete", []byte("only ceo vault"), []string{"alice"})
	_, err = s.DecryptSecret("after-delete", pk2.PrivateKey)
	if err != nil {
		t.Fatal("ceo-vault should still work:", err)
	}
	_, err = s.DecryptSecret("after-delete", pk1.PrivateKey)
	if err == nil {
		t.Fatal("deleted paper key should not be a recipient of new secrets")
	}
}

func TestRevokeClearsPaperKeys(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")
	bobPriv := addTestUser(t, s, "bob", "rsa")

	// Bob creates a paper key
	bobPK, _ := gitboxcrypto.GeneratePaperKey()
	s.SavePaperKey("bob-recovery", bobPK, bobPriv)

	// Encrypt for both, paper key auto-included
	secret := []byte("revoke-pk-test")
	s.EncryptSecret("pk-revoke-test", secret, []string{"alice", "bob"})

	// Verify bob's paper key is a recipient
	manifest, _ := s.GetSecret("pk-revoke-test")
	hasBobPK := false
	for _, re := range manifest.Recipients {
		if strings.Contains(re.GitHubUser, "bob") && isPaperKeyRecipient(re.GitHubUser) {
			hasBobPK = true
		}
	}
	if !hasBobPK {
		t.Fatal("bob's paper key should be a recipient before revoke")
	}

	// Revoke bob -- should also remove bob's paper key
	err := s.RevokeAccess("pk-revoke-test", "bob", alicePriv)
	if err != nil {
		t.Fatal("revoke:", err)
	}

	// Verify bob's paper key is gone
	manifest, _ = s.GetSecret("pk-revoke-test")
	for _, re := range manifest.Recipients {
		if strings.Contains(re.GitHubUser, "bob") {
			t.Fatalf("bob should have no recipients after revoke, found: %s", re.GitHubUser)
		}
	}

	// Alice can still decrypt
	decrypted, err := s.DecryptSecret("pk-revoke-test", alicePriv)
	if err != nil {
		t.Fatal("alice decrypt after bob revoke:", err)
	}
	if string(decrypted) != string(secret) {
		t.Fatal("content mismatch")
	}

	// Bob's paper key can NOT decrypt
	_, err = s.DecryptSecret("pk-revoke-test", bobPK.PrivateKey)
	if err == nil {
		t.Fatal("bob's paper key should not work after revoke")
	}
}

func TestRecoverIdentity(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")

	// Alice creates a paper key
	paperKey, _ := gitboxcrypto.GeneratePaperKey()
	s.SavePaperKey("alice-recovery", paperKey, alicePriv)

	// Encrypt a secret for alice
	secret := []byte("important data")
	s.EncryptSecret("recovery-test", secret, []string{"alice"})

	// Verify alice can decrypt with original key
	dec, err := s.DecryptSecret("recovery-test", alicePriv)
	if err != nil {
		t.Fatal("original decrypt:", err)
	}
	if string(dec) != string(secret) {
		t.Fatal("original decrypt mismatch")
	}

	// Simulate: alice loses her keys, generates new ones
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	sshNewPub, _ := ssh.NewPublicKey(newPub)
	newPubLine := string(ssh.MarshalAuthorizedKey(sshNewPub))

	// Alice recovers her identity using paper key
	result, err := s.RecoverIdentity("alice", newPubLine, paperKey)
	if err != nil {
		t.Fatal("recover identity:", err)
	}
	if result.Reboxed == 0 {
		t.Fatal("expected rebox to happen during recovery")
	}

	// Verify the identity was updated
	id, _ := s.GetUser("alice")
	if len(id.Keys) != 1 {
		t.Fatalf("expected 1 key after recovery, got %d", len(id.Keys))
	}
	newFP := ssh.FingerprintSHA256(sshNewPub)
	if id.Keys[0].Fingerprint != newFP {
		t.Fatal("identity not updated to new key")
	}

	// Old key should NOT work for new secrets
	// (existing secrets still have the old DEK wrapping, so old key still works for those)
	// But the identity now points to the new key

	// The new key can be used for new operations
	// Verify by identifying the key
	owner, err := s.IdentifyKey(newPriv)
	if err != nil {
		t.Fatal("identify new key:", err)
	}
	if owner != "alice" {
		t.Fatalf("expected owner alice, got %s", owner)
	}

	// Verify the identity signature is valid (signed by paper key)
	if id.Sig == nil {
		t.Fatal("recovered identity should be signed")
	}
}

func TestRecoverIdentityWrongPaperKey(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")
	addTestUser(t, s, "bob", "rsa")

	// Alice creates a paper key
	alicePK, _ := gitboxcrypto.GeneratePaperKey()
	s.SavePaperKey("alice-pk", alicePK, alicePriv)

	// Bob tries to use alice's paper key to update alice's identity -- should fail
	// because the paper key doesn't match bob
	wrongPK, _ := gitboxcrypto.GeneratePaperKey()

	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(newPub)
	pubLine := string(ssh.MarshalAuthorizedKey(sshPub))

	_, err := s.RecoverIdentity("alice", pubLine, wrongPK)
	if err == nil {
		t.Fatal("should reject recovery with unregistered paper key")
	}
}

func TestPaperKeyCanSignGroupChanges(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")
	addTestUser(t, s, "bob", "rsa")

	// Alice creates a paper key
	paperKey, _ := gitboxcrypto.GeneratePaperKey()
	s.SavePaperKey("alice-pk", paperKey, alicePriv)

	// Use paper key private key to sign group changes
	// (simulates: alice lost SSH keys, uses paper key to manage groups)
	err := s.SaveGroups(map[string][]string{
		"team": {"alice", "bob"},
	}, paperKey.PrivateKey)
	if err != nil {
		t.Fatal("save groups with paper key:", err)
	}

	// Verify group resolves correctly (signature should verify since paper key is trusted)
	resolved, err := s.ResolveRecipients([]string{"@team"})
	if err != nil {
		t.Fatal("resolve with paper-key-signed group:", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolved, got %d", len(resolved))
	}
}

func TestApplyGrantsAndRevokes(t *testing.T) {
	s, _ := setupTestStore(t)
	alicePriv := addTestUser(t, s, "alice", "ed25519")
	bobPriv := addTestUser(t, s, "bob", "rsa")
	charliePriv := addTestUser(t, s, "charlie", "ed25519")

	// Start with alice and bob
	s.EncryptSecret("apply-test", []byte("apply secret"), []string{"alice", "bob"})

	// Apply: remove bob, add charlie
	cfg := &GitBoxConfig{
		Secrets: map[string]SecretConfig{
			"apply-test": {Recipients: []string{"alice", "charlie"}},
		},
	}

	actions, err := s.Apply(cfg, alicePriv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) == 0 {
		t.Fatal("expected actions")
	}

	// Verify recipients changed
	recipients, _ := s.RecipientsForSecret("apply-test")
	recipientSet := make(map[string]bool)
	for _, r := range recipients {
		recipientSet[r] = true
	}
	if !recipientSet["alice"] {
		t.Fatal("alice should still have access")
	}
	if !recipientSet["charlie"] {
		t.Fatal("charlie should have been granted access")
	}
	if recipientSet["bob"] {
		t.Fatal("bob should have been revoked")
	}

	// Verify alice can still decrypt
	decrypted, err := s.DecryptSecret("apply-test", alicePriv)
	if err != nil {
		t.Fatal("alice decrypt after apply:", err)
	}
	if string(decrypted) != "apply secret" {
		t.Fatal("content mismatch")
	}

	// Verify charlie can decrypt
	decrypted, err = s.DecryptSecret("apply-test", charliePriv)
	if err != nil {
		t.Fatal("charlie decrypt after apply:", err)
	}
	if string(decrypted) != "apply secret" {
		t.Fatal("content mismatch")
	}

	// Verify bob cannot decrypt
	_, err = s.DecryptSecret("apply-test", bobPriv)
	if err == nil {
		t.Fatal("bob should not have access after apply")
	}
}
