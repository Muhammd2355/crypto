package rsa

import (
	"bytes"
	"testing"
	"github.com/go-crypto/crypto/rand"
)

func TestGenerateKey(t *testing.T) {
	keySizes := []int{1024, 2048}
	
	for _, bits := range keySizes {
		key, err := GenerateKey(rand.GlobalReader, bits)
		if err != nil {
			t.Fatalf("GenerateKey(%d) failed: %v", bits, err)
		}
		
		if key.N.BitLen() != bits {
			t.Errorf("Generated key has wrong bit length: expected %d, got %d", bits, key.N.BitLen())
		}
		
		// Verify key components
		if key.E != 65537 {
			t.Errorf("Expected E=65537, got E=%d", key.E)
		}
		
		if key.D == nil {
			t.Error("Private exponent D is nil")
		}
		
		if len(key.Primes) != 2 {
			t.Errorf("Expected 2 primes, got %d", len(key.Primes))
		}
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	key, err := GenerateKey(rand.GlobalReader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	
	testMessages := [][]byte{
		[]byte("Hello, RSA!"),
		[]byte("Short"),
		[]byte("A longer message to test RSA encryption and decryption functionality"),
		make([]byte, 190), // Near maximum size for PKCS#1 v1.5 with 2048-bit key
	}
	
	// Fill the last test message with random data
	rand.Read(testMessages[3])
	
	for i, message := range testMessages {
		// Encrypt
		ciphertext, err := EncryptPKCS1v15(rand.GlobalReader, &key.PublicKey, message)
		if err != nil {
			t.Errorf("Test %d: EncryptPKCS1v15 failed: %v", i, err)
			continue
		}
		
		// Decrypt
		plaintext, err := DecryptPKCS1v15(rand.GlobalReader, key, ciphertext)
		if err != nil {
			t.Errorf("Test %d: DecryptPKCS1v15 failed: %v", i, err)
			continue
		}
		
		if !bytes.Equal(message, plaintext) {
			t.Errorf("Test %d: decrypted message doesn't match original", i)
		}
	}
}

func TestRSAMessageTooLong(t *testing.T) {
	key, err := GenerateKey(rand.GlobalReader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	
	// Message too long for 1024-bit key with PKCS#1 v1.5 padding
	message := make([]byte, 200)
	rand.Read(message)
	
	_, err = EncryptPKCS1v15(rand.GlobalReader, &key.PublicKey, message)
	if err == nil {
		t.Error("EncryptPKCS1v15 should fail for message too long")
	}
}

func TestRSAKeyValidation(t *testing.T) {
	key, err := GenerateKey(rand.GlobalReader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	
	err = key.Validate()
	if err != nil {
		t.Errorf("Key validation failed: %v", err)
	}
	
	// Test with corrupted key
	originalD := key.D
	key.D = nil
	err = key.Validate()
	if err == nil {
		t.Error("Key validation should fail for nil D")
	}
	key.D = originalD
}

func TestMultiPrimeKey(t *testing.T) {
	key, err := GenerateMultiPrimeKey(rand.GlobalReader, 3, 2048)
	if err != nil {
		t.Fatalf("GenerateMultiPrimeKey failed: %v", err)
	}
	
	if len(key.Primes) != 3 {
		t.Errorf("Expected 3 primes, got %d", len(key.Primes))
	}
	
	// Test encryption/decryption with multi-prime key
	message := []byte("Multi-prime RSA test")
	
	ciphertext, err := EncryptPKCS1v15(rand.GlobalReader, &key.PublicKey, message)
	if err != nil {
		t.Fatalf("EncryptPKCS1v15 failed: %v", err)
	}
	
	plaintext, err := DecryptPKCS1v15(rand.GlobalReader, key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptPKCS1v15 failed: %v", err)
	}
	
	if !bytes.Equal(message, plaintext) {
		t.Error("Multi-prime decryption failed")
	}
}

func BenchmarkRSAGenerateKey1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey(rand.GlobalReader, 1024)
	}
}

func BenchmarkRSAGenerateKey2048(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey(rand.GlobalReader, 2048)
	}
}

func BenchmarkRSAEncrypt(b *testing.B) {
	key, _ := GenerateKey(rand.GlobalReader, 2048)
	message := []byte("Benchmark message for RSA encryption")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptPKCS1v15(rand.GlobalReader, &key.PublicKey, message)
	}
}

func BenchmarkRSADecrypt(b *testing.B) {
	key, _ := GenerateKey(rand.GlobalReader, 2048)
	message := []byte("Benchmark message for RSA decryption")
	ciphertext, _ := EncryptPKCS1v15(rand.GlobalReader, &key.PublicKey, message)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptPKCS1v15(rand.GlobalReader, key, ciphertext)
	}
}