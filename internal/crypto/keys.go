// Package crypto provides cryptographic operations for GitBox.
//
// Key wrapping strategy (inspired by Keybase/saltpack):
//   - Each secret gets a random 256-bit Data Encryption Key (DEK)
//   - The secret payload is encrypted with NaCl secretbox (XSalsa20-Poly1305) using the DEK
//   - The DEK is then "wrapped" (encrypted) separately for each recipient's public key
//   - RSA keys: RSA-OAEP with SHA-256
//   - Ed25519 keys: converted to X25519, then ephemeral ECDH + NaCl secretbox
//
// This means adding/removing a recipient only requires re-wrapping the DEK,
// not re-encrypting the (potentially large) payload.
package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh"
)

// KeyInfo holds a parsed SSH public key with metadata.
type KeyInfo struct {
	Type        string // "ssh-rsa" or "ssh-ed25519"
	PublicKey   crypto.PublicKey
	Fingerprint string
	RawLine    string // original authorized_keys line
}

// ParseSSHPublicKey parses a single line from an authorized_keys-style format.
func ParseSSHPublicKey(line string) (*KeyInfo, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse ssh public key: %w", err)
	}

	fingerprint := ssh.FingerprintSHA256(pubKey)

	cpk, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("key type %s does not implement CryptoPublicKey", pubKey.Type())
	}

	keyType := pubKey.Type()

	return &KeyInfo{
		Type:        keyType,
		PublicKey:   cpk.CryptoPublicKey(),
		Fingerprint: fingerprint,
		RawLine:    strings.TrimSpace(line),
	}, nil
}

// ParseSSHPublicKeys parses multiple lines (GitHub returns one key per line).
func ParseSSHPublicKeys(data string) ([]*KeyInfo, error) {
	var keys []*KeyInfo
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ki, err := ParseSSHPublicKey(line)
		if err != nil {
			// Skip keys we can't parse (e.g., ecdsa-sha2-nistp256)
			continue
		}
		// Only support RSA and Ed25519
		if ki.Type != "ssh-rsa" && ki.Type != "ssh-ed25519" {
			continue
		}
		keys = append(keys, ki)
	}
	return keys, nil
}

// LoadSSHPrivateKeyRaw reads and parses an SSH private key, returning the raw private key.
func LoadSSHPrivateKeyRaw(path string, passphrase []byte) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	var key interface{}
	if len(passphrase) > 0 {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	} else {
		key, err = ssh.ParseRawPrivateKey(data)
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

// Ed25519PublicKeyToX25519 converts an Ed25519 public key to an X25519 public key.
// This uses the birational map from Edwards25519 to Curve25519 (Montgomery form).
func Ed25519PublicKeyToX25519(edPub ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte

	// Parse the Ed25519 public key as an Edwards25519 point
	p, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return out, fmt.Errorf("invalid ed25519 public key: %w", err)
	}

	// Convert to Montgomery form (X25519)
	copy(out[:], p.BytesMontgomery())
	return out, nil
}

// Ed25519PrivateKeyToX25519 converts an Ed25519 private key to an X25519 private key.
// Per RFC 8032, the X25519 private key is derived from SHA-512 of the Ed25519 seed.
func Ed25519PrivateKeyToX25519(edPriv ed25519.PrivateKey) [32]byte {
	var out [32]byte
	h := sha512.Sum512(edPriv.Seed())
	// Clamp (per X25519 spec)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	copy(out[:], h[:32])
	return out
}

// GenerateDEK creates a new random 256-bit Data Encryption Key.
func GenerateDEK() ([32]byte, error) {
	var dek [32]byte
	_, err := rand.Read(dek[:])
	return dek, err
}

// Seal encrypts plaintext using NaCl secretbox with the given key.
// Returns the ciphertext and nonce.
func Seal(plaintext []byte, key [32]byte) (ciphertext []byte, nonce [24]byte, err error) {
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, nonce, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext = secretbox.Seal(nil, plaintext, &nonce, &key)
	return ciphertext, nonce, nil
}

// Open decrypts NaCl secretbox ciphertext with the given key and nonce.
func Open(ciphertext []byte, nonce [24]byte, key [32]byte) ([]byte, error) {
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &key)
	if !ok {
		return nil, fmt.Errorf("secretbox open failed: authentication error")
	}
	return plaintext, nil
}

// WrappedDEK holds a DEK encrypted for a specific recipient.
type WrappedDEK struct {
	KeyType         string `yaml:"key_type"`
	KeyFingerprint  string `yaml:"key_fingerprint"`
	WrappedKey      string `yaml:"wrapped_key"`       // base64
	EphemeralPublic string `yaml:"ephemeral_public,omitempty"` // base64, only for ed25519
	WrapNonce       string `yaml:"wrap_nonce,omitempty"`       // base64, only for ed25519
}

// WrapDEKForKey wraps a DEK for the given public key.
func WrapDEKForKey(dek [32]byte, ki *KeyInfo) (*WrappedDEK, error) {
	switch pub := ki.PublicKey.(type) {
	case *rsa.PublicKey:
		return wrapDEKRSA(dek, pub, ki)
	case ed25519.PublicKey:
		return wrapDEKEd25519(dek, pub, ki)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}
}

// wrapDEKRSA wraps a DEK using RSA-OAEP with SHA-256.
func wrapDEKRSA(dek [32]byte, pub *rsa.PublicKey, ki *KeyInfo) (*WrappedDEK, error) {
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek[:], []byte("gitbox-dek"))
	if err != nil {
		return nil, fmt.Errorf("rsa oaep encrypt: %w", err)
	}
	return &WrappedDEK{
		KeyType:        ki.Type,
		KeyFingerprint: ki.Fingerprint,
		WrappedKey:     base64.StdEncoding.EncodeToString(wrapped),
	}, nil
}

// wrapDEKEd25519 wraps a DEK for an Ed25519 key by converting to X25519
// and using ephemeral ECDH + NaCl secretbox.
func wrapDEKEd25519(dek [32]byte, pub ed25519.PublicKey, ki *KeyInfo) (*WrappedDEK, error) {
	// Convert recipient's Ed25519 public key to X25519
	recipientX25519, err := Ed25519PublicKeyToX25519(pub)
	if err != nil {
		return nil, fmt.Errorf("convert ed25519 to x25519: %w", err)
	}

	// Generate ephemeral X25519 keypair
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Compute shared secret via X25519
	var shared [32]byte
	sharedRaw, err := curve25519.X25519(ephPriv[:], recipientX25519[:])
	if err != nil {
		return nil, fmt.Errorf("x25519 key exchange: %w", err)
	}
	copy(shared[:], sharedRaw)

	// Encrypt the DEK with the shared secret using secretbox
	ciphertext, nonce, err := Seal(dek[:], shared)
	if err != nil {
		return nil, fmt.Errorf("seal dek: %w", err)
	}

	return &WrappedDEK{
		KeyType:         ki.Type,
		KeyFingerprint:  ki.Fingerprint,
		WrappedKey:      base64.StdEncoding.EncodeToString(ciphertext),
		EphemeralPublic: base64.StdEncoding.EncodeToString(ephPub[:]),
		WrapNonce:       base64.StdEncoding.EncodeToString(nonce[:]),
	}, nil
}

// UnwrapDEK decrypts a wrapped DEK using the given private key.
func UnwrapDEK(w *WrappedDEK, privKey interface{}) ([32]byte, error) {
	switch priv := privKey.(type) {
	case *rsa.PrivateKey:
		return unwrapDEKRSA(w, priv)
	case ed25519.PrivateKey:
		return unwrapDEKEd25519(w, priv)
	case *ed25519.PrivateKey:
		return unwrapDEKEd25519(w, *priv)
	default:
		return [32]byte{}, fmt.Errorf("unsupported private key type: %T", priv)
	}
}

func unwrapDEKRSA(w *WrappedDEK, priv *rsa.PrivateKey) ([32]byte, error) {
	var dek [32]byte
	wrapped, err := base64.StdEncoding.DecodeString(w.WrappedKey)
	if err != nil {
		return dek, fmt.Errorf("decode wrapped key: %w", err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, []byte("gitbox-dek"))
	if err != nil {
		return dek, fmt.Errorf("rsa oaep decrypt: %w", err)
	}
	if len(plain) != 32 {
		return dek, fmt.Errorf("unexpected dek length: %d", len(plain))
	}
	copy(dek[:], plain)
	return dek, nil
}

func unwrapDEKEd25519(w *WrappedDEK, priv ed25519.PrivateKey) ([32]byte, error) {
	var dek [32]byte

	wrapped, err := base64.StdEncoding.DecodeString(w.WrappedKey)
	if err != nil {
		return dek, fmt.Errorf("decode wrapped key: %w", err)
	}
	ephPubBytes, err := base64.StdEncoding.DecodeString(w.EphemeralPublic)
	if err != nil {
		return dek, fmt.Errorf("decode ephemeral public: %w", err)
	}
	nonceBytes, err := base64.StdEncoding.DecodeString(w.WrapNonce)
	if err != nil {
		return dek, fmt.Errorf("decode nonce: %w", err)
	}
	if len(ephPubBytes) != 32 {
		return dek, fmt.Errorf("invalid ephemeral public key length: %d", len(ephPubBytes))
	}
	if len(nonceBytes) != 24 {
		return dek, fmt.Errorf("invalid nonce length: %d", len(nonceBytes))
	}

	x25519Priv := Ed25519PrivateKeyToX25519(priv)

	var shared [32]byte
	sharedRaw, err := curve25519.X25519(x25519Priv[:], ephPubBytes)
	if err != nil {
		return dek, fmt.Errorf("x25519 key exchange: %w", err)
	}
	copy(shared[:], sharedRaw)

	var nonce [24]byte
	copy(nonce[:], nonceBytes)
	plain, err := Open(wrapped, nonce, shared)
	if err != nil {
		return dek, fmt.Errorf("open dek: %w", err)
	}
	if len(plain) != 32 {
		return dek, fmt.Errorf("unexpected dek length: %d", len(plain))
	}
	copy(dek[:], plain)
	return dek, nil
}

// FingerprintPublicKey returns the SSH fingerprint for a crypto public key.
func FingerprintPublicKey(pub crypto.PublicKey) (string, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(sshPub), nil
}
