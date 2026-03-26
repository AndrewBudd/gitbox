package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// PaperKey holds a recovery keypair derived from a seed.
// The seed can be printed/written down as 24 mnemonic words for offline backup.
type PaperKey struct {
	Seed       [32]byte
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GeneratePaperKey creates a new paper key with a random seed.
func GeneratePaperKey() (*PaperKey, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("generate seed: %w", err)
	}
	return PaperKeyFromSeed(seed)
}

// PaperKeyFromSeed derives an Ed25519 keypair from a 32-byte seed.
func PaperKeyFromSeed(seed [32]byte) (*PaperKey, error) {
	h := sha256.Sum256(append([]byte("gitbox-paper-key-v1:"), seed[:]...))
	priv := ed25519.NewKeyFromSeed(h[:])
	pub := priv.Public().(ed25519.PublicKey)

	return &PaperKey{
		Seed:       seed,
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// -- Mnemonic encoding (BIP39-style) --
// 256-bit seed + 8-bit checksum = 264 bits -> 24 words (11 bits each)

// Words returns the seed as 24 mnemonic words.
func (pk *PaperKey) Words() string {
	return EncodeMnemonic(pk.Seed[:])
}

// PaperKeyFromWords recovers a paper key from mnemonic words.
func PaperKeyFromWords(words string) (*PaperKey, error) {
	seed, err := DecodeMnemonic(words)
	if err != nil {
		return nil, err
	}
	var seedArr [32]byte
	copy(seedArr[:], seed)
	return PaperKeyFromSeed(seedArr)
}

// EncodeMnemonic encodes 32 bytes as 24 BIP39-style mnemonic words.
// Appends an 8-bit SHA-256 checksum (first byte of hash) to get 264 bits,
// then splits into 24 groups of 11 bits, each mapping to a word.
func EncodeMnemonic(data []byte) string {
	if len(data) != 32 {
		panic("EncodeMnemonic: expected 32 bytes")
	}

	// Compute checksum: first byte of SHA-256(data)
	h := sha256.Sum256(data)
	checksum := h[0]

	// Build 264-bit bitstring: 256 data bits + 8 checksum bits
	// We'll work with the bits as a big-endian byte slice
	bits := make([]byte, 33)
	copy(bits[:32], data)
	bits[32] = checksum

	words := make([]string, 24)
	for i := 0; i < 24; i++ {
		// Extract 11 bits starting at bit position i*11
		idx := extractBits(bits, i*11, 11)
		words[i] = bip39Words[idx]
	}
	return strings.Join(words, " ")
}

// DecodeMnemonic decodes 24 mnemonic words back to 32 bytes.
// Verifies the checksum.
func DecodeMnemonic(mnemonic string) ([]byte, error) {
	wordList := strings.Fields(strings.TrimSpace(mnemonic))
	if len(wordList) != 24 {
		return nil, fmt.Errorf("expected 24 words, got %d", len(wordList))
	}

	// Build word -> index lookup
	wordIndex := make(map[string]int, 2048)
	for i, w := range bip39Words {
		wordIndex[w] = i
	}

	// Convert words to 264 bits
	bits := make([]byte, 33) // 264 bits = 33 bytes
	for i, word := range wordList {
		word = strings.ToLower(word)
		idx, ok := wordIndex[word]
		if !ok {
			return nil, fmt.Errorf("unknown word at position %d: %q", i+1, word)
		}
		setBits(bits, i*11, 11, idx)
	}

	// First 32 bytes = seed, byte 33 = checksum
	seed := bits[:32]
	gotChecksum := bits[32]

	// Verify checksum
	h := sha256.Sum256(seed)
	wantChecksum := h[0]
	if gotChecksum != wantChecksum {
		return nil, fmt.Errorf("invalid checksum (wrong words or wrong order)")
	}

	result := make([]byte, 32)
	copy(result, seed)
	return result, nil
}

// extractBits extracts `count` bits starting at bit position `start` from a byte slice.
// Returns as an int (max 11 bits = 0..2047).
func extractBits(data []byte, start, count int) int {
	val := 0
	for i := 0; i < count; i++ {
		byteIdx := (start + i) / 8
		bitIdx := 7 - ((start + i) % 8)
		if data[byteIdx]&(1<<uint(bitIdx)) != 0 {
			val |= 1 << uint(count-1-i)
		}
	}
	return val
}

// setBits sets `count` bits starting at bit position `start` in a byte slice.
func setBits(data []byte, start, count, val int) {
	for i := 0; i < count; i++ {
		byteIdx := (start + i) / 8
		bitIdx := 7 - ((start + i) % 8)
		if val&(1<<uint(count-1-i)) != 0 {
			data[byteIdx] |= 1 << uint(bitIdx)
		}
	}
}

// -- Hex encoding (still supported for interop) --

// PaperKeyFromHex recovers a paper key from its hex representation.
func PaperKeyFromHex(hexStr string) (*PaperKey, error) {
	hexStr = strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, hexStr)

	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(data))
	}

	var seed [32]byte
	copy(seed[:], data)
	return PaperKeyFromSeed(seed)
}

// Hex returns the seed as a formatted hex string.
func (pk *PaperKey) Hex() string {
	h := hex.EncodeToString(pk.Seed[:])
	var groups []string
	for i := 0; i < len(h); i += 8 {
		end := i + 8
		if end > len(h) {
			end = len(h)
		}
		groups = append(groups, h[i:end])
	}
	return strings.Join(groups, " ")
}

// PublicKeyBase64 returns the public key as base64 for storage.
func (pk *PaperKey) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(pk.PublicKey)
}

// ToKeyInfo converts the paper key's public key to a KeyInfo for use in wrapping.
func (pk *PaperKey) ToKeyInfo() *KeyInfo {
	fp, _ := FingerprintPublicKey(pk.PublicKey)
	return &KeyInfo{
		Type:        "ssh-ed25519",
		PublicKey:   pk.PublicKey,
		Fingerprint: fp,
		RawLine:    fmt.Sprintf("paper-key:%s", pk.PublicKeyBase64()),
	}
}
