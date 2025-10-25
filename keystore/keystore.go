package keystore

import (
	"errors"
	"github.com/go-crypto/crypto/rand"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeAES    KeyType = "aes"
	KeyTypeRSA    KeyType = "rsa"
	KeyTypeHMAC   KeyType = "hmac"
	KeyTypeGeneric KeyType = "generic"
)

// KeyEntry represents a stored key with metadata
type KeyEntry struct {
	ID          string    `json:"id"`
	Type        KeyType   `json:"type"`
	Algorithm   string    `json:"algorithm"`
	KeySize     int       `json:"key_size"`
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	KeyData     []byte    `json:"key_data"`
}

// KeyStore manages cryptographic keys
type KeyStore struct {
	keys        map[string]*KeyEntry
}

// NewKeyStore creates a new key store
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys: make(map[string]*KeyEntry),
	}
}

// GenerateAESKey generates a new AES key
func (ks *KeyStore) GenerateAESKey(id string, keySize int, description string) error {
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return errors.New("invalid AES key size: must be 16, 24, or 32 bytes")
	}
	
	keyData := make([]byte, keySize)
	if _, err := rand.Read(keyData); err != nil {
		return errors.New("failed to generate AES key")
	}
	
	entry := &KeyEntry{
		ID:          id,
		Type:        KeyTypeAES,
		Algorithm:   "AES",
		KeySize:     keySize,
		Description: description,
		KeyData:     keyData,
	}
	
	ks.keys[id] = entry
	return nil
}

// GenerateRSAKey generates a new RSA key pair
func (ks *KeyStore) GenerateRSAKey(id string, keySize int, description string) error {
	// For simplicity, we'll store a placeholder RSA key
	// In a real implementation, this would generate and serialize an actual RSA key
	keyData := make([]byte, 256) // Placeholder key data
	if _, err := rand.Read(keyData); err != nil {
		return errors.New("failed to generate RSA key")
	}
	
	entry := &KeyEntry{
		ID:          id,
		Type:        KeyTypeRSA,
		Algorithm:   "RSA",
		KeySize:     keySize,
		Description: description,
		KeyData:     keyData,
	}
	
	ks.keys[id] = entry
	return nil
}

// GenerateHMACKey generates a new HMAC key
func (ks *KeyStore) GenerateHMACKey(id string, keySize int, description string) error {
	if keySize < 16 {
		return errors.New("HMAC key size must be at least 16 bytes")
	}
	
	keyData := make([]byte, keySize)
	if _, err := rand.Read(keyData); err != nil {
		return errors.New("failed to generate HMAC key")
	}
	
	entry := &KeyEntry{
		ID:          id,
		Type:        KeyTypeHMAC,
		Algorithm:   "HMAC",
		KeySize:     keySize,
		Description: description,
		KeyData:     keyData,
	}
	
	ks.keys[id] = entry
	return nil
}

// GetKey retrieves a key by ID
func (ks *KeyStore) GetKey(id string) (*KeyEntry, error) {
	key, exists := ks.keys[id]
	if !exists {
		return nil, errors.New("key not found")
	}
	return key, nil
}

// DeleteKey removes a key by ID
func (ks *KeyStore) DeleteKey(id string) error {
	if _, exists := ks.keys[id]; !exists {
		return errors.New("key not found")
	}
	delete(ks.keys, id)
	return nil
}

// ListKeys returns all key entries
func (ks *KeyStore) ListKeys() []KeyEntry {
	entries := make([]KeyEntry, 0, len(ks.keys))
	for _, entry := range ks.keys {
		entries = append(entries, *entry)
	}
	return entries
}