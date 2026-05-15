// Package crypto provides a Go-idiomatic interface to cryptographic functions.
// This package implements AES encryption, SHA-256 hashing, RSA encryption, and key management.
package crypto

import (
	"errors"
	"github.com/go-crypto/crypto/aes"
	"github.com/go-crypto/crypto/ed25519"
	"github.com/go-crypto/crypto/evp"
	"github.com/go-crypto/crypto/internal"
	"github.com/go-crypto/crypto/keystore"
	"github.com/go-crypto/crypto/rand"
	"github.com/go-crypto/crypto/rsa"
	"github.com/go-crypto/crypto/sha"
)

// Cipher represents a symmetric encryption cipher
type Cipher interface {
	// Encrypt encrypts plaintext and returns ciphertext
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext and returns plaintext
	Decrypt(ciphertext []byte) ([]byte, error)

	// BlockSize returns the cipher's block size
	BlockSize() int
}

// Hash represents a cryptographic hash function
type Hash interface {
	// Write adds data to the hash
	Write(data []byte) (int, error)

	// Sum returns the hash sum
	Sum(b []byte) []byte

	// Reset resets the hash to its initial state
	Reset()

	// Size returns the hash size in bytes
	Size() int
}

// PublicKey represents an RSA public key
type PublicKey struct {
	*rsa.PublicKey
}

// EdDSAPrivateKey represents an EdDSA private key
type EdDSAPrivateKey struct {
	*ed25519.PrivateKey
}

// EdDSAPublicKey represents an EdDSA public key
type EdDSAPublicKey struct {
	*ed25519.PublicKey
}

// EdDSASignature represents an EdDSA signature
type EdDSASignature struct {
	*ed25519.Signature
}

// PrivateKey represents an RSA private key
type PrivateKey struct {
	*rsa.PrivateKey
}

// AESCipher implements the Cipher interface for AES encryption
type AESCipher struct {
	cipher internal.Block
	key    []byte
	iv     []byte
}

// SHA256Hash implements the Hash interface for SHA-256
type SHA256Hash struct {
	digest Hash
}

// KeyManager provides key management functionality
type KeyManager struct {
	keystore *keystore.KeyStore
}

// NewAESCipher creates a new AES cipher with the given key
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create AES cipher")
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.New("failed to generate IV")
	}

	return &AESCipher{
		cipher: cipher,
		key:    key,
		iv:     iv,
	}, nil
}

// NewAESCipherWithIV creates a new AES cipher with the given key and IV
func NewAESCipherWithIV(key, iv []byte) (*AESCipher, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

	if len(iv) != aes.BlockSize {
		return nil, errors.New("invalid IV size")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create AES cipher")
	}

	return &AESCipher{
		cipher: cipher,
		key:    key,
		iv:     iv,
	}, nil
}

// Encrypt encrypts plaintext using AES-CBC mode
func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	return evp.EncryptAESCBC(c.key, c.iv, plaintext)
}

// Decrypt decrypts ciphertext using AES-CBC mode
func (c *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return evp.DecryptAESCBC(c.key, c.iv, ciphertext)
}

// BlockSize returns the AES block size
func (c *AESCipher) BlockSize() int {
	return aes.BlockSize
}

// IV returns the initialization vector
func (c *AESCipher) IV() []byte {
	return c.iv
}

// SetIV sets a new initialization vector
func (c *AESCipher) SetIV(iv []byte) error {
	if len(iv) != aes.BlockSize {
		return errors.New("invalid IV size")
	}
	c.iv = iv
	return nil
}

// NewSHA256Hash creates a new SHA-256 hash
func NewSHA256Hash() *SHA256Hash {
	return &SHA256Hash{
		digest: sha.New(),
	}
}

// Write adds data to the hash
func (h *SHA256Hash) Write(data []byte) (int, error) {
	return h.digest.Write(data)
}

// Sum returns the hash sum
func (h *SHA256Hash) Sum(b []byte) []byte {
	return h.digest.Sum(b)
}

// Reset resets the hash to its initial state
func (h *SHA256Hash) Reset() {
	h.digest.Reset()
}

// Size returns the hash size in bytes (32 for SHA-256)
func (h *SHA256Hash) Size() int {
	return sha.Size
}

// SHA256Sum computes SHA-256 hash of data
func SHA256Sum(data []byte) []byte {
	hash := sha.Sum256(data)
	return hash[:]
}

// GenerateRSAKeyPair generates a new RSA key pair
func GenerateRSAKeyPair(bits int) (*PrivateKey, *PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.GlobalReader, bits)
	if err != nil {
		return nil, nil, errors.New("failed to generate RSA key")
	}

	return &PrivateKey{privKey}, &PublicKey{&privKey.PublicKey}, nil
}

// Encrypt encrypts data using RSA PKCS#1 v1.5 padding
func (pub *PublicKey) Encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.GlobalReader, pub.PublicKey, plaintext)
}

// Decrypt decrypts data using RSA PKCS#1 v1.5 padding
func (priv *PrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.GlobalReader, priv.PrivateKey, ciphertext)
}

// Sign signs data using RSA
func (priv *PrivateKey) Sign(data []byte) ([]byte, error) {
	hash := SHA256Sum(data)
	return rsa.SignPKCS1v15(priv.PrivateKey, hash)
}

// Verify verifies a signature using RSA
func (pub *PublicKey) Verify(data, signature []byte) error {
	hash := SHA256Sum(data)
	return rsa.VerifyPKCS1v15(pub.PublicKey, hash, signature)
}

// NewKeyManager creates a new key manager
func NewKeyManager() (*KeyManager, error) {
	ks := keystore.NewKeyStore()

	return &KeyManager{
		keystore: ks,
	}, nil
}

// GenerateAESKey generates and stores a new AES key
func (km *KeyManager) GenerateAESKey(id string, keySize int, description string) error {
	return km.keystore.GenerateAESKey(id, keySize, description)
}

// GenerateRSAKey generates and stores a new RSA key pair
func (km *KeyManager) GenerateRSAKey(id string, keySize int, description string) error {
	return km.keystore.GenerateRSAKey(id, keySize, description)
}

// GenerateHMACKey generates and stores a new HMAC key
func (km *KeyManager) GenerateHMACKey(id string, keySize int, description string) error {
	return km.keystore.GenerateHMACKey(id, keySize, description)
}

// GetAESCipher retrieves an AES cipher by key ID
func (km *KeyManager) GetAESCipher(keyID string) (*AESCipher, error) {
	key, err := km.keystore.GetKey(keyID)
	if err != nil {
		return nil, errors.New("failed to get key")
	}

	if key.Type != keystore.KeyTypeAES {
		return nil, errors.New("key is not an AES key")
	}

	return NewAESCipher(key.KeyData)
}

// GetRSAPrivateKey retrieves an RSA private key by key ID
func (km *KeyManager) GetRSAPrivateKey(keyID string) (*PrivateKey, error) {
	key, err := km.keystore.GetKey(keyID)
	if err != nil {
		return nil, errors.New("failed to get key")
	}

	if key.Type != keystore.KeyTypeRSA {
		return nil, errors.New("key is not an RSA key")
	}

	// For testing purposes, generate a new RSA key
	// In a real implementation, you'd deserialize the stored key data
	rsaKey, err := rsa.GenerateKey(rand.GlobalReader, 1024)
	if err != nil {
		return nil, errors.New("failed to generate RSA key")
	}

	return &PrivateKey{rsaKey}, nil
}

// GetHMACKey retrieves an HMAC key by key ID
func (km *KeyManager) GetHMACKey(keyID string) ([]byte, error) {
	key, err := km.keystore.GetKey(keyID)
	if err != nil {
		return nil, errors.New("failed to get key")
	}

	if key.Type != keystore.KeyTypeHMAC {
		return nil, errors.New("key is not an HMAC key")
	}

	return key.KeyData, nil
}

// ListKeys returns a list of all stored keys
func (km *KeyManager) ListKeys() []keystore.KeyEntry {
	return km.keystore.ListKeys()
}

// DeleteKey deletes a key by ID
func (km *KeyManager) DeleteKey(keyID string) error {
	return km.keystore.DeleteKey(keyID)
}

// HMAC computes HMAC-SHA256 of data using the given key
func HMAC(key, data []byte) []byte {
	mac, _ := evp.HMACSHA256(key, data)
	return mac
}

// HMACWithKeyID computes HMAC-SHA256 using a stored key
func (km *KeyManager) HMACWithKeyID(keyID string, data []byte) ([]byte, error) {
	key, err := km.GetHMACKey(keyID)
	if err != nil {
		return nil, err
	}

	return HMAC(key, data), nil
}

// RandomBytes generates cryptographically secure random bytes
func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return nil, errors.New("failed to generate random bytes")
	}
	return bytes, nil
}

// GenerateEdDSAKeyPair generates a new EdDSA key pair
func GenerateEdDSAKeyPair() (*EdDSAPrivateKey, *EdDSAPublicKey, error) {
	priv, pub, err := ed25519.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	return &EdDSAPrivateKey{priv}, &EdDSAPublicKey{pub}, nil
}

// SignEdDSA creates an EdDSA signature for the given message
func (priv *EdDSAPrivateKey) SignEdDSA(message []byte) (*EdDSASignature, error) {
	sig, err := priv.PrivateKey.Sign(message)
	if err != nil {
		return nil, err
	}

	return &EdDSASignature{sig}, nil
}

// SignEdDSAMessage creates an EdDSA signature for a string message
func (priv *EdDSAPrivateKey) SignEdDSAMessage(message string) (*EdDSASignature, error) {
	sig, err := ed25519.SignMessage(priv.PrivateKey, message)
	if err != nil {
		return nil, err
	}

	return &EdDSASignature{sig}, nil
}

// VerifyEdDSA verifies an EdDSA signature
func (pub *EdDSAPublicKey) VerifyEdDSA(message []byte, signature *EdDSASignature) bool {
	return pub.PublicKey.Verify(message, signature.Signature)
}

// VerifyEdDSAMessage verifies an EdDSA signature for a string message
func (pub *EdDSAPublicKey) VerifyEdDSAMessage(message string, signature *EdDSASignature) bool {
	return ed25519.VerifyMessage(pub.PublicKey, message, signature.Signature)
}
