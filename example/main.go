// Example program demonstrating the Go crypto library port
package main

import (
	"github.com/go-crypto/crypto/aes"
	"github.com/go-crypto/crypto/rand"
	"github.com/go-crypto/crypto/sha"
)

func main() {
	// Simple AES example
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte("Hello, Go Crypto! This is a test message for AES encryption.")
	
	// Pad plaintext to block size
	if len(plaintext)%aes.BlockSize != 0 {
		padding := aes.BlockSize - len(plaintext)%aes.BlockSize
		for i := 0; i < padding; i++ {
			plaintext = append(plaintext, byte(padding))
		}
	}
	
	// Create cipher
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	
	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		cipher.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}
	
	// Simple SHA-256 example
	data := []byte("Hello, Go Crypto! This is a test message for SHA-256 hashing.")
	hash := sha.Sum256(data)
	_ = hash // Use the hash
	
	// Simple random number generation
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
}