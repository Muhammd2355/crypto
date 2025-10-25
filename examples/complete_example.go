// Complete example demonstrating the Go crypto library
package main

import (
	"github.com/go-crypto/crypto/aes"
	"github.com/go-crypto/crypto/rand"
	"github.com/go-crypto/crypto/sha"
)

func main() {
	// Simple demonstration of the Go Crypto Library
	
	// AES encryption
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("Hello, Go Crypto Library!")
	
	// Pad to block size
	if len(plaintext)%aes.BlockSize != 0 {
		padding := aes.BlockSize - len(plaintext)%aes.BlockSize
		for i := 0; i < padding; i++ {
			plaintext = append(plaintext, byte(padding))
		}
	}
	
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		cipher.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}
	
	// SHA-256 hashing
	data := []byte("Test data for hashing")
	hash := sha.Sum256(data)
	_ = hash
	
	// Random number generation
	randomData := make([]byte, 32)
	rand.Read(randomData)
}