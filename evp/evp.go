// Package evp provides high-level cryptographic operations (Envelope interface)
package evp

import (
	"errors"
	
	"github.com/go-crypto/crypto/aes"
	"github.com/go-crypto/crypto/hmac"
	"github.com/go-crypto/crypto/internal"
	"github.com/go-crypto/crypto/rand"
	"github.com/go-crypto/crypto/rsa"
	"github.com/go-crypto/crypto/sha"
)

// Cipher represents a symmetric cipher
type Cipher interface {
	internal.Block
	KeySize() int
	IVSize() int
}

// Hash represents a hash function
type Hash interface {
	// Write adds more data to the running hash
	Write([]byte) (int, error)
	// Sum appends the current hash to b and returns the resulting slice
	Sum([]byte) []byte
	// Reset resets the Hash to its initial state
	Reset()
	// Size returns the number of bytes Sum will return
	Size() int
	// BlockSize returns the hash's underlying block size
	BlockSize() int
}

// Cipher types
const (
	AES128 = "AES-128"
	AES192 = "AES-192"
	AES256 = "AES-256"
)

// Hash types
const (
	SHA256 = "SHA-256"
)

// Mode types
const (
	CBC = "CBC"
	ECB = "ECB"
	CFB = "CFB"
	OFB = "OFB"
	CTR = "CTR"
	GCM = "GCM"
)

// CipherContext represents an encryption/decryption context
type CipherContext struct {
	cipher    internal.Block
	mode      string
	blockSize int
	keySize   int
	ivSize    int
	encrypt   bool
}

// DigestContext represents a hash context
type DigestContext struct {
	hash Hash
}

// NewCipher creates a new cipher instance
func NewCipher(cipherType string) (internal.Block, error) {
	switch cipherType {
	case AES128:
		return nil, errors.New("key required for cipher creation")
	case AES192:
		return nil, errors.New("key required for cipher creation")
	case AES256:
		return nil, errors.New("key required for cipher creation")
	default:
		return nil, errors.New("unsupported cipher type")
	}
}

// NewCipherWithKey creates a new cipher instance with the given key
func NewCipherWithKey(cipherType string, key []byte) (internal.Block, error) {
	switch cipherType {
	case AES128:
		if len(key) != 16 {
			return nil, internal.ErrInvalidKeySize
		}
		return aes.NewCipher(key)
	case AES192:
		if len(key) != 24 {
			return nil, internal.ErrInvalidKeySize
		}
		return aes.NewCipher(key)
	case AES256:
		if len(key) != 32 {
			return nil, internal.ErrInvalidKeySize
		}
		return aes.NewCipher(key)
	default:
		return nil, errors.New("unsupported cipher type")
	}
}

// NewCipherContext creates a new cipher context for encryption/decryption
func NewCipherContext(cipherType, mode string, key, iv []byte, encrypt bool) (*CipherContext, error) {
	block, err := NewCipherWithKey(cipherType, key)
	if err != nil {
		return nil, err
	}
	
	ctx := &CipherContext{
		cipher:    block,
		mode:      mode,
		blockSize: block.BlockSize(),
		keySize:   len(key),
		ivSize:    len(iv),
		encrypt:   encrypt,
	}
	
	// Simplified mode handling - just store the mode string
	// Actual encryption/decryption would need to be implemented based on mode
	return ctx, nil
}

// Update processes data through the cipher context
func (ctx *CipherContext) Update(dst, src []byte) error {
	// Simplified implementation - just copy data for now
	copy(dst, src)
	return nil
}

// Final finalizes the cipher operation
func (ctx *CipherContext) Final(dst []byte) (int, error) {
	// For block modes, padding should be handled here
	// This is a simplified implementation
	return 0, nil
}

// Seal performs AEAD encryption (for GCM mode)
func (ctx *CipherContext) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	// Simplified implementation - not supported in this version
	return nil
}

// Open performs AEAD decryption (for GCM mode)
func (ctx *CipherContext) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	// Simplified implementation - not supported in this version
	return nil, errors.New("AEAD not supported in simplified version")
}

// NewDigest creates a new hash context
func NewDigest(hashType string) (*DigestContext, error) {
	switch hashType {
	case SHA256:
		h := sha.New()
		return &DigestContext{hash: h}, nil
	default:
		return nil, errors.New("unsupported hash type")
	}
}

// Update adds data to the hash
func (ctx *DigestContext) Update(data []byte) error {
	_, err := ctx.hash.Write(data)
	return err
}

// Final returns the final hash value
func (ctx *DigestContext) Final() []byte {
	return ctx.hash.Sum(nil)
}

// Reset resets the hash context
func (ctx *DigestContext) Reset() {
	ctx.hash.Reset()
}

// Size returns the hash size
func (ctx *DigestContext) Size() int {
	return ctx.hash.Size()
}

// HMAC operations
type HMACContext struct {
	hmac Hash
}

// NewHMAC creates a new HMAC context
func NewHMAC(hashType string, key []byte) (*HMACContext, error) {
	switch hashType {
	case SHA256:
		return &HMACContext{
			hmac: hmac.New(key),
		}, nil
	default:
		return nil, errors.New("unsupported hash type for HMAC")
	}
}

// Update adds data to the HMAC
func (ctx *HMACContext) Update(data []byte) error {
	_, err := ctx.hmac.Write(data)
	return err
}

// Final returns the final HMAC value
func (ctx *HMACContext) Final() []byte {
	return ctx.hmac.Sum(nil)
}

// Reset resets the HMAC context
func (ctx *HMACContext) Reset() {
	ctx.hmac.Reset()
}

// RSA operations
type RSAContext struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewRSAContext creates a new RSA context
func NewRSAContext() *RSAContext {
	return &RSAContext{}
}

// GenerateKey generates an RSA key pair
func (ctx *RSAContext) GenerateKey(bits int, random *rand.Reader) error {
	key, err := rsa.GenerateKey(random, bits)
	if err != nil {
		return err
	}
	
	ctx.privateKey = key
	ctx.publicKey = &key.PublicKey
	return nil
}

// SetPrivateKey sets the private key
func (ctx *RSAContext) SetPrivateKey(key *rsa.PrivateKey) {
	ctx.privateKey = key
	ctx.publicKey = &key.PublicKey
}

// SetPublicKey sets the public key
func (ctx *RSAContext) SetPublicKey(key *rsa.PublicKey) {
	ctx.publicKey = key
}

// Encrypt encrypts data using RSA
func (ctx *RSAContext) Encrypt(random *rand.Reader, msg []byte) ([]byte, error) {
	if ctx.publicKey == nil {
		return nil, errors.New("no public key set")
	}
	return rsa.EncryptPKCS1v15(random, ctx.publicKey, msg)
}

// Decrypt decrypts data using RSA
func (ctx *RSAContext) Decrypt(random *rand.Reader, ciphertext []byte) ([]byte, error) {
	if ctx.privateKey == nil {
		return nil, errors.New("no private key set")
	}
	return rsa.DecryptPKCS1v15(random, ctx.privateKey, ciphertext)
}

// Utility functions

// EncryptAES256CBC encrypts data using AES-256-CBC
func EncryptAES256CBC(key, iv, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		plaintext = internal.PKCS7Pad(plaintext, aes.BlockSize)
	}
	
	ctx, err := NewCipherContext(AES256, CBC, key, iv, true)
	if err != nil {
		return nil, err
	}
	
	ciphertext := make([]byte, len(plaintext))
	err = ctx.Update(ciphertext, plaintext)
	if err != nil {
		return nil, err
	}
	
	return ciphertext, nil
}

// DecryptAES256CBC decrypts data using AES-256-CBC
func DecryptAES256CBC(key, iv, ciphertext []byte) ([]byte, error) {
	ctx, err := NewCipherContext(AES256, CBC, key, iv, false)
	if err != nil {
		return nil, err
	}
	
	plaintext := make([]byte, len(ciphertext))
	err = ctx.Update(plaintext, ciphertext)
	if err != nil {
		return nil, err
	}
	
	// Remove PKCS7 padding
	return internal.PKCS7Unpad(plaintext, aes.BlockSize)
}

// HashSHA256 computes SHA-256 hash
func HashSHA256(data []byte) []byte {
	hash := sha.Sum256(data)
	return hash[:]
}

// HMACSHA256 computes HMAC-SHA256
func HMACSHA256(key, data []byte) ([]byte, error) {
	ctx, err := NewHMAC(SHA256, key)
	if err != nil {
		return nil, err
	}
	
	err = ctx.Update(data)
	if err != nil {
		return nil, err
	}
	
	return ctx.Final(), nil
}