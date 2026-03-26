package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestSecretBoxRoundTrip(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello, gitbox! this is a secret message.")
	ciphertext, nonce, err := Seal(plaintext, dek)
	if err != nil {
		t.Fatal(err)
	}

	if string(ciphertext) == string(plaintext) {
		t.Fatal("ciphertext should not equal plaintext")
	}

	decrypted, err := Open(ciphertext, nonce, dek)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted %q != original %q", decrypted, plaintext)
	}
}

func TestSecretBoxWrongKey(t *testing.T) {
	dek1, _ := GenerateDEK()
	dek2, _ := GenerateDEK()

	plaintext := []byte("secret")
	ciphertext, nonce, _ := Seal(plaintext, dek1)

	_, err := Open(ciphertext, nonce, dek2)
	if err == nil {
		t.Fatal("should fail with wrong key")
	}
}

func TestRSAKeyWrapRoundTrip(t *testing.T) {
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ki := &KeyInfo{
		Type:        "ssh-rsa",
		PublicKey:   &privKey.PublicKey,
		Fingerprint: "test-rsa-fingerprint",
	}

	// Generate and wrap DEK
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := WrapDEKForKey(dek, ki)
	if err != nil {
		t.Fatal(err)
	}

	if wrapped.KeyType != "ssh-rsa" {
		t.Fatalf("expected key type ssh-rsa, got %s", wrapped.KeyType)
	}

	// Unwrap
	unwrapped, err := UnwrapDEK(wrapped, privKey)
	if err != nil {
		t.Fatal(err)
	}

	if unwrapped != dek {
		t.Fatal("unwrapped DEK does not match original")
	}
}

func TestRSAKeyWrapWrongKey(t *testing.T) {
	privKey1, _ := rsa.GenerateKey(rand.Reader, 2048)
	privKey2, _ := rsa.GenerateKey(rand.Reader, 2048)

	ki := &KeyInfo{
		Type:        "ssh-rsa",
		PublicKey:   &privKey1.PublicKey,
		Fingerprint: "test",
	}

	dek, _ := GenerateDEK()
	wrapped, _ := WrapDEKForKey(dek, ki)

	_, err := UnwrapDEK(wrapped, privKey2)
	if err == nil {
		t.Fatal("should fail with wrong RSA key")
	}
}

func TestEd25519KeyWrapRoundTrip(t *testing.T) {
	// Generate Ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ki := &KeyInfo{
		Type:        "ssh-ed25519",
		PublicKey:   pub,
		Fingerprint: "test-ed25519-fingerprint",
	}

	// Generate and wrap DEK
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := WrapDEKForKey(dek, ki)
	if err != nil {
		t.Fatal(err)
	}

	if wrapped.KeyType != "ssh-ed25519" {
		t.Fatalf("expected key type ssh-ed25519, got %s", wrapped.KeyType)
	}
	if wrapped.EphemeralPublic == "" {
		t.Fatal("ed25519 wrap should have ephemeral public key")
	}
	if wrapped.WrapNonce == "" {
		t.Fatal("ed25519 wrap should have nonce")
	}

	// Unwrap
	unwrapped, err := UnwrapDEK(wrapped, priv)
	if err != nil {
		t.Fatal(err)
	}

	if unwrapped != dek {
		t.Fatal("unwrapped DEK does not match original")
	}
}

func TestEd25519KeyWrapWrongKey(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)

	ki := &KeyInfo{
		Type:        "ssh-ed25519",
		PublicKey:   pub1,
		Fingerprint: "test",
	}

	dek, _ := GenerateDEK()
	wrapped, _ := WrapDEKForKey(dek, ki)

	_, err := UnwrapDEK(wrapped, priv2)
	if err == nil {
		t.Fatal("should fail with wrong ed25519 key")
	}
}

func TestEd25519ToX25519RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x25519Pub, err := Ed25519PublicKeyToX25519(pub)
	if err != nil {
		t.Fatal(err)
	}

	x25519Priv := Ed25519PrivateKeyToX25519(priv)

	// Verify the keys are non-zero
	allZero := true
	for _, b := range x25519Pub {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("x25519 public key is all zeros")
	}

	allZero = true
	for _, b := range x25519Priv {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("x25519 private key is all zeros")
	}
}

func TestMultipleRecipientsRoundTrip(t *testing.T) {
	// Simulate encrypting for multiple recipients with different key types
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	rsaKI := &KeyInfo{Type: "ssh-rsa", PublicKey: &rsaPriv.PublicKey, Fingerprint: "rsa-fp"}
	edKI := &KeyInfo{Type: "ssh-ed25519", PublicKey: edPub, Fingerprint: "ed-fp"}

	// Generate DEK and encrypt payload
	dek, _ := GenerateDEK()
	payload := []byte("multi-recipient secret payload with important data")
	ciphertext, nonce, _ := Seal(payload, dek)

	// Wrap DEK for both recipients
	rsaWrapped, err := WrapDEKForKey(dek, rsaKI)
	if err != nil {
		t.Fatal(err)
	}
	edWrapped, err := WrapDEKForKey(dek, edKI)
	if err != nil {
		t.Fatal(err)
	}

	// RSA recipient can decrypt
	rsaDEK, err := UnwrapDEK(rsaWrapped, rsaPriv)
	if err != nil {
		t.Fatal("RSA unwrap failed:", err)
	}
	rsaPlain, err := Open(ciphertext, nonce, rsaDEK)
	if err != nil {
		t.Fatal("RSA decrypt failed:", err)
	}
	if string(rsaPlain) != string(payload) {
		t.Fatal("RSA decrypted payload mismatch")
	}

	// Ed25519 recipient can decrypt
	edDEK, err := UnwrapDEK(edWrapped, edPriv)
	if err != nil {
		t.Fatal("Ed25519 unwrap failed:", err)
	}
	edPlain, err := Open(ciphertext, nonce, edDEK)
	if err != nil {
		t.Fatal("Ed25519 decrypt failed:", err)
	}
	if string(edPlain) != string(payload) {
		t.Fatal("Ed25519 decrypted payload mismatch")
	}
}

func TestPaperKeyMnemonicRoundTrip(t *testing.T) {
	pk, err := GeneratePaperKey()
	if err != nil {
		t.Fatal(err)
	}

	// Get mnemonic words
	words := pk.Words()
	wordList := strings.Fields(words)
	if len(wordList) != 24 {
		t.Fatalf("expected 24 words, got %d", len(wordList))
	}

	// All words should be lowercase alpha
	for i, w := range wordList {
		for _, c := range w {
			if c < 'a' || c > 'z' {
				t.Fatalf("word %d (%q) contains non-alpha char", i+1, w)
			}
		}
	}

	// Recover from words
	recovered, err := PaperKeyFromWords(words)
	if err != nil {
		t.Fatal("recover from words:", err)
	}

	if pk.Seed != recovered.Seed {
		t.Fatal("recovered seed doesn't match")
	}
	if !pk.PublicKey.Equal(recovered.PublicKey) {
		t.Fatal("recovered public key doesn't match")
	}
}

func TestPaperKeyHexRoundTrip(t *testing.T) {
	pk, _ := GeneratePaperKey()
	hexStr := pk.Hex()

	recovered, err := PaperKeyFromHex(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	if pk.Seed != recovered.Seed {
		t.Fatal("hex round-trip seed mismatch")
	}
}

func TestPaperKeyMnemonicChecksumRejectsCorruption(t *testing.T) {
	pk, _ := GeneratePaperKey()
	words := pk.Words()
	wordList := strings.Fields(words)

	// Swap two words -- should fail checksum
	wordList[0], wordList[1] = wordList[1], wordList[0]
	corrupted := strings.Join(wordList, " ")
	_, err := PaperKeyFromWords(corrupted)
	if err == nil {
		t.Fatal("corrupted mnemonic should fail checksum")
	}
}

func TestPaperKeyMnemonicRejectsBadWord(t *testing.T) {
	_, err := PaperKeyFromWords("abandon ability able about above absent absorb abstract absurd abuse access accident accident accident accident accident accident accident accident accident accident accident accident accident")
	// Either wrong number of words or bad checksum
	if err == nil {
		t.Fatal("should reject invalid mnemonic")
	}
}

func TestPaperKeyCryptoRoundTrip(t *testing.T) {
	pk, _ := GeneratePaperKey()

	// Recover from words and verify crypto operations work
	recovered, _ := PaperKeyFromWords(pk.Words())

	ki := pk.ToKeyInfo()
	dek, _ := GenerateDEK()
	wrapped, err := WrapDEKForKey(dek, ki)
	if err != nil {
		t.Fatal("wrap for paper key:", err)
	}

	unwrapped, err := UnwrapDEK(wrapped, recovered.PrivateKey)
	if err != nil {
		t.Fatal("unwrap with recovered paper key:", err)
	}

	if unwrapped != dek {
		t.Fatal("paper key DEK mismatch after mnemonic round-trip")
	}
}

func TestSSHKeyParsing(t *testing.T) {
	// Test parsing an Ed25519 authorized_keys line
	// This is a test key, not a real one
	testRSALine := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7TKCz+FPH0wVN7V7rGMIF5gCPml+hNAa/2o6E5MhmWDJkVJCjI6MkQ+JbgGkz8WhhIX9KGaOEQr1t7GIULYKhPaIRx9eSyHxLwjRBHR2X4GB4fGk4cA+VfR6vXkMFB7lbZOhc+jI3hBT7xoS7Z1b7J6EQWIB4bJNSiIMH7i7nMZFbQPgYdZ6T2QDMTY3F1nJL7G5y7d3JFJ7T3N3Gy0+gBJydjTMBP9qLBf7FcAqLj2P2pMz6Q+PjpKJZbON7G0FkW6N7P3N3Gy0+gBJydjTMBP9qLBf7FcAqLj2P2pMz6Q+PjpKJZbON7G0FkW6N7B9Q0qD2aVY9I0nW7l testkey"

	// We can't easily test with fake RSA keys since they need valid encoding
	// but we can test that parsing doesn't panic on invalid input
	_, err := ParseSSHPublicKey("not a valid key")
	if err == nil {
		t.Fatal("should fail on invalid key")
	}

	_ = testRSALine

	// Test parsing multiple keys with some invalid ones
	keys, err := ParseSSHPublicKeys("invalid line\n\nalso invalid\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 parsed keys from invalid input, got %d", len(keys))
	}
}

func TestLargePayload(t *testing.T) {
	// Test encrypting a larger payload (simulating a real secrets file)
	dek, _ := GenerateDEK()

	payload := make([]byte, 1024*1024) // 1MB
	rand.Read(payload)

	ciphertext, nonce, err := Seal(payload, dek)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := Open(ciphertext, nonce, dek)
	if err != nil {
		t.Fatal(err)
	}

	if len(decrypted) != len(payload) {
		t.Fatalf("length mismatch: %d != %d", len(decrypted), len(payload))
	}

	for i := range payload {
		if decrypted[i] != payload[i] {
			t.Fatalf("byte mismatch at position %d", i)
			break
		}
	}
}
