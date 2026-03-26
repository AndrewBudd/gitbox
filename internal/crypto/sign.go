package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Signature holds a detached SSH signature over some content.
type Signature struct {
	SignedBy  string `yaml:"signed_by"`  // username of signer
	Format   string `yaml:"format"`     // signature algorithm (e.g. "ssh-ed25519")
	Blob     string `yaml:"blob"`       // base64-encoded signature blob
}

// SignBytes signs data with an SSH private key.
// Returns the signature and the signer's fingerprint.
func SignBytes(data []byte, privKey interface{}) (*Signature, error) {
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return &Signature{
		Format: sig.Format,
		Blob:   base64.StdEncoding.EncodeToString(sig.Blob),
	}, nil
}

// VerifySignature verifies an SSH signature against a set of trusted public keys.
// Returns nil if the signature is valid and was made by one of the trusted keys.
func VerifySignature(data []byte, sig *Signature, trustedKeys []string) error {
	if sig == nil || sig.Blob == "" {
		return fmt.Errorf("missing signature")
	}

	blob, err := base64.StdEncoding.DecodeString(sig.Blob)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	sshSig := &ssh.Signature{
		Format: sig.Format,
		Blob:   blob,
	}

	// Try each trusted key
	for _, keyLine := range trustedKeys {
		keyLine = strings.TrimSpace(keyLine)
		if keyLine == "" {
			continue
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
		if err != nil {
			continue
		}
		if err := pubKey.Verify(data, sshSig); err == nil {
			return nil // Valid signature from a trusted key
		}
	}

	return fmt.Errorf("signature not valid for any trusted key")
}
