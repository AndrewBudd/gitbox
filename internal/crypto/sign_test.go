package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSignAndVerifyEd25519(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte("important config data that must not be tampered with")

	sig, err := SignBytes(data, priv)
	if err != nil {
		t.Fatal(err)
	}

	sshPub, _ := ssh.NewPublicKey(pub)
	trustedKey := string(ssh.MarshalAuthorizedKey(sshPub))

	err = VerifySignature(data, sig, []string{trustedKey})
	if err != nil {
		t.Fatal("valid signature rejected:", err)
	}
}

func TestSignAndVerifyRSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := []byte("rsa signed config")

	sig, err := SignBytes(data, rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	sshPub, _ := ssh.NewPublicKey(&rsaKey.PublicKey)
	trustedKey := string(ssh.MarshalAuthorizedKey(sshPub))

	err = VerifySignature(data, sig, []string{trustedKey})
	if err != nil {
		t.Fatal("valid RSA signature rejected:", err)
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	data := []byte("original data")
	sig, _ := SignBytes(data, priv)

	// Tampered data should fail
	err := VerifySignature([]byte("tampered data"), sig, []string{
		string(ssh.MarshalAuthorizedKey(func() ssh.PublicKey {
			k, _ := ssh.NewPublicKey(priv.Public())
			return k
		}())),
	})
	if err == nil {
		t.Fatal("tampered data should fail verification")
	}

	// Wrong key should fail
	sshPub2, _ := ssh.NewPublicKey(pub2)
	err = VerifySignature(data, sig, []string{string(ssh.MarshalAuthorizedKey(sshPub2))})
	if err == nil {
		t.Fatal("wrong key should fail verification")
	}
}

func TestVerifyRejectsNilSignature(t *testing.T) {
	err := VerifySignature([]byte("data"), nil, []string{"key"})
	if err == nil {
		t.Fatal("nil signature should fail")
	}
}

func TestVerifyRejectsEmptyTrustedKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig, _ := SignBytes([]byte("data"), priv)

	err := VerifySignature([]byte("data"), sig, []string{})
	if err == nil {
		t.Fatal("empty trusted keys should fail")
	}
}
