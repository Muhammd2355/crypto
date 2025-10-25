package aes

import (
	"bytes"
	"testing"
	
	"github.com/go-crypto/crypto/rand"
)

// Test vectors from NIST SP 800-38A and verified against OpenSSL
var aesTestVectors = []struct {
	key       []byte
	plaintext []byte
	expected  []byte
}{
	{
		// NIST SP 800-38A AES-128 ECB test vector F.1.1 - verified against OpenSSL
		key:       []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		plaintext: []byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
		expected:  []byte{0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97},
	},
	{
		// NIST SP 800-38A AES-128 ECB test vector F.1.2 - verified against OpenSSL
		key:       []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		plaintext: []byte{0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51},
		expected:  []byte{0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf},
	},
	{
		// NIST SP 800-38A AES-128 ECB test vector F.1.3 - verified against OpenSSL
		key:       []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		plaintext: []byte{0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef},
		expected:  []byte{0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88},
	},
	{
		// NIST SP 800-38A AES-128 ECB test vector F.1.4 - verified against OpenSSL
		key:       []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		plaintext: []byte{0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10},
		expected:  []byte{0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4},
	},
}

func TestNewCipher(t *testing.T) {
	// Test valid key sizes
	validKeySizes := []int{16, 24, 32}
	for _, size := range validKeySizes {
		key := make([]byte, size)
		_, err := NewCipher(key)
		if err != nil {
			t.Errorf("NewCipher failed for key size %d: %v", size, err)
		}
	}

	// Test invalid key size
	invalidKey := make([]byte, 15)
	_, err := NewCipher(invalidKey)
	if err == nil {
		t.Error("NewCipher should fail for invalid key size")
	}
}

func TestAESEncryptDecrypt(t *testing.T) {
	for i, tv := range aesTestVectors {
		cipher, err := NewCipher(tv.key)
		if err != nil {
			t.Fatalf("Test vector %d: NewCipher failed: %v", i, err)
		}

		// Test encryption
		encrypted := make([]byte, BlockSize)
		cipher.Encrypt(encrypted, tv.plaintext)
		if !bytes.Equal(encrypted, tv.expected) {
			t.Errorf("Test vector %d: encryption failed\nExpected: %x\nGot:      %x", i, tv.expected, encrypted)
		}

		// Test decryption
		decrypted := make([]byte, BlockSize)
		cipher.Decrypt(decrypted, encrypted)
		if !bytes.Equal(decrypted, tv.plaintext) {
			t.Errorf("Test vector %d: decryption failed\nExpected: %x\nGot:      %x", i, tv.plaintext, decrypted)
		}
	}
}

func TestAESRoundTrip(t *testing.T) {
	keySizes := []int{16, 24, 32}
	
	for _, keySize := range keySizes {
		key := make([]byte, keySize)
		rand.Read(key)
		
		cipher, err := NewCipher(key)
		if err != nil {
			t.Fatalf("NewCipher failed for key size %d: %v", keySize, err)
		}
		
		// Test multiple blocks
		for blocks := 1; blocks <= 10; blocks++ {
			plaintext := make([]byte, blocks*BlockSize)
			rand.Read(plaintext)
			
			// Encrypt
			ciphertext := make([]byte, len(plaintext))
			for i := 0; i < len(plaintext); i += BlockSize {
				cipher.Encrypt(ciphertext[i:i+BlockSize], plaintext[i:i+BlockSize])
			}
			
			// Decrypt
			decrypted := make([]byte, len(ciphertext))
			for i := 0; i < len(ciphertext); i += BlockSize {
				cipher.Decrypt(decrypted[i:i+BlockSize], ciphertext[i:i+BlockSize])
			}
			
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Round trip failed for key size %d, blocks %d", keySize, blocks)
			}
		}
	}
}

func BenchmarkAESEncrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	
	cipher, _ := NewCipher(key)
	plaintext := make([]byte, BlockSize)
	ciphertext := make([]byte, BlockSize)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(ciphertext, plaintext)
	}
}

func BenchmarkAESDecrypt(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	
	cipher, _ := NewCipher(key)
	ciphertext := make([]byte, BlockSize)
	plaintext := make([]byte, BlockSize)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Decrypt(plaintext, ciphertext)
	}
}