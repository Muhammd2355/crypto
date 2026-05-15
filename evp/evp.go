// Package evp provides high-level cryptographic operations (Envelope interface)
package evp

import (
	stdcipher "crypto/cipher"
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

// CipherContext represents an encryption/decryption context.
type CipherContext struct {
	cipher    internal.Block
	mode      string
	blockSize int
	keySize   int
	iv        []byte
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
	case AES128, AES192, AES256:
		return nil, errors.New("key required for cipher creation")
	default:
		return nil, errors.New("unsupported cipher type")
	}
}

// NewCipherWithKey creates a new cipher instance with the given key
func NewCipherWithKey(cipherType string, key []byte) (internal.Block, error) {
	switch cipherType {
	case AES128:
		if len(key) != aes.KeySize128 {
			return nil, internal.ErrInvalidKeySize
		}
		return aes.NewCipher(key)
	case AES192:
		if len(key) != aes.KeySize192 {
			return nil, internal.ErrInvalidKeySize
		}
		return aes.NewCipher(key)
	case AES256:
		if len(key) != aes.KeySize256 {
			return nil, internal.ErrInvalidKeySize
		}
		return aes.NewCipher(key)
	default:
		return nil, errors.New("unsupported cipher type")
	}
}

// NewCipherContext creates a new cipher context for encryption/decryption.
func NewCipherContext(cipherType, mode string, key, iv []byte, encrypt bool) (*CipherContext, error) {
	block, err := NewCipherWithKey(cipherType, key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	if mode != ECB && mode != GCM && len(iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}
	if mode == GCM && len(iv) == 0 {
		return nil, errors.New("invalid nonce size")
	}

	ctx := &CipherContext{
		cipher:    block,
		mode:      mode,
		blockSize: blockSize,
		keySize:   len(key),
		iv:        append([]byte(nil), iv...),
		ivSize:    len(iv),
		encrypt:   encrypt,
	}

	switch mode {
	case CBC, ECB, CFB, OFB, CTR, GCM:
		return ctx, nil
	default:
		return nil, errors.New("unsupported cipher mode")
	}
}

// Update processes data through the cipher context. Block modes require full blocks;
// use the helper functions for OpenSSL-compatible PKCS#7 padding.
func (ctx *CipherContext) Update(dst, src []byte) error {
	if len(dst) < len(src) {
		return errors.New("output buffer too small")
	}

	switch ctx.mode {
	case CBC:
		if len(src)%ctx.blockSize != 0 {
			return errors.New("input not full blocks")
		}
		if ctx.encrypt {
			stdcipher.NewCBCEncrypter(ctx.cipher, ctx.iv).CryptBlocks(dst[:len(src)], src)
		} else {
			stdcipher.NewCBCDecrypter(ctx.cipher, ctx.iv).CryptBlocks(dst[:len(src)], src)
		}
	case ECB:
		if len(src)%ctx.blockSize != 0 {
			return errors.New("input not full blocks")
		}
		for len(src) > 0 {
			if ctx.encrypt {
				ctx.cipher.Encrypt(dst[:ctx.blockSize], src[:ctx.blockSize])
			} else {
				ctx.cipher.Decrypt(dst[:ctx.blockSize], src[:ctx.blockSize])
			}
			src = src[ctx.blockSize:]
			dst = dst[ctx.blockSize:]
		}
	case CFB:
		stream := stdcipher.NewCFBEncrypter(ctx.cipher, ctx.iv)
		if !ctx.encrypt {
			stream = stdcipher.NewCFBDecrypter(ctx.cipher, ctx.iv)
		}
		stream.XORKeyStream(dst[:len(src)], src)
	case OFB:
		stdcipher.NewOFB(ctx.cipher, ctx.iv).XORKeyStream(dst[:len(src)], src)
	case CTR:
		stdcipher.NewCTR(ctx.cipher, ctx.iv).XORKeyStream(dst[:len(src)], src)
	case GCM:
		return errors.New("use Seal/Open for GCM mode")
	default:
		return errors.New("unsupported cipher mode")
	}

	return nil
}

// Final finalizes the cipher operation.
func (ctx *CipherContext) Final(dst []byte) (int, error) {
	return 0, nil
}

// Seal performs AEAD encryption (for GCM mode).
func (ctx *CipherContext) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if ctx.mode != GCM {
		return nil
	}
	aead, err := stdcipher.NewGCM(ctx.cipher)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil
	}
	return aead.Seal(dst, nonce, plaintext, additionalData)
}

// Open performs AEAD decryption (for GCM mode).
func (ctx *CipherContext) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if ctx.mode != GCM {
		return nil, errors.New("AEAD only supported for GCM mode")
	}
	aead, err := stdcipher.NewGCM(ctx.cipher)
	if err != nil {
		return nil, err
	}
	return aead.Open(dst, nonce, ciphertext, additionalData)
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

// EncryptAESCBC encrypts data with AES-CBC and OpenSSL-compatible PKCS#7 padding.
func EncryptAESCBC(key, iv, plaintext []byte) ([]byte, error) {
	cipherType, err := cipherTypeForKey(key)
	if err != nil {
		return nil, err
	}
	padded := internal.PKCS7Pad(append([]byte(nil), plaintext...), aes.BlockSize)
	ctx, err := NewCipherContext(cipherType, CBC, key, iv, true)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padded))
	if err := ctx.Update(ciphertext, padded); err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// DecryptAESCBC decrypts AES-CBC data and removes OpenSSL-compatible PKCS#7 padding.
func DecryptAESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, internal.ErrInvalidPadding
	}
	cipherType, err := cipherTypeForKey(key)
	if err != nil {
		return nil, err
	}
	ctx, err := NewCipherContext(cipherType, CBC, key, iv, false)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	if err := ctx.Update(plaintext, ciphertext); err != nil {
		return nil, err
	}
	return internal.PKCS7Unpad(plaintext, aes.BlockSize)
}

// EncryptAES256CBC encrypts data using AES-256-CBC.
func EncryptAES256CBC(key, iv, plaintext []byte) ([]byte, error) {
	if len(key) != aes.KeySize256 {
		return nil, internal.ErrInvalidKeySize
	}
	return EncryptAESCBC(key, iv, plaintext)
}

// DecryptAES256CBC decrypts data using AES-256-CBC.
func DecryptAES256CBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != aes.KeySize256 {
		return nil, internal.ErrInvalidKeySize
	}
	return DecryptAESCBC(key, iv, ciphertext)
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

func cipherTypeForKey(key []byte) (string, error) {
	switch len(key) {
	case aes.KeySize128:
		return AES128, nil
	case aes.KeySize192:
		return AES192, nil
	case aes.KeySize256:
		return AES256, nil
	default:
		return "", internal.ErrInvalidKeySize
	}
}
