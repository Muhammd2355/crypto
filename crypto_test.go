package crypto

import (
	"bytes"
	"testing"

	"github.com/go-crypto/crypto/sha"
)

func TestAESCipher(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes for AES-256
	
	cipher, err := NewAESCipher(key)
	if err != nil {
		t.Fatalf("NewAESCipher failed: %v", err)
	}
	
	plaintext := []byte("Hello, World! This is a test message for AES encryption.")
	
	// Test encryption
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}
	
	// Test decryption
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original. Expected %s, got %s", plaintext, decrypted)
	}
	
	// Test block size
	if cipher.BlockSize() != 16 {
		t.Errorf("Expected block size 16, got %d", cipher.BlockSize())
	}
}

func TestAESCipherWithIV(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	iv := []byte("abcdef0123456789") // 16 bytes
	
	cipher, err := NewAESCipherWithIV(key, iv)
	if err != nil {
		t.Fatalf("NewAESCipherWithIV failed: %v", err)
	}
	
	if !bytes.Equal(cipher.IV(), iv) {
		t.Error("IV doesn't match")
	}
	
	plaintext := []byte("Test message")
	
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original")
	}
}

func TestAESCipherInvalidKey(t *testing.T) {
	// Test invalid key sizes
	invalidKeys := [][]byte{
		make([]byte, 15), // Too short
		make([]byte, 17), // Invalid size
		make([]byte, 33), // Too long
	}
	
	for _, key := range invalidKeys {
		_, err := NewAESCipher(key)
		if err == nil {
			t.Errorf("NewAESCipher should fail for key size %d", len(key))
		}
	}
}

func TestSHA256Hash(t *testing.T) {
	hash := sha.New()
	
	if hash.Size() != 32 {
		t.Errorf("Expected hash size 32, got %d", hash.Size())
	}
	
	data := []byte("Hello, World!")
	
	// Test single write
	hash.Write(data)
	sum1 := hash.Sum(nil)
	
	if len(sum1) != 32 {
		t.Errorf("Expected sum length 32, got %d", len(sum1))
	}
	
	// Test reset and multiple writes
	hash.Reset()
	hash.Write([]byte("Hello, "))
	hash.Write([]byte("World!"))
	sum2 := hash.Sum(nil)
	
	if !bytes.Equal(sum1, sum2) {
		t.Error("Hash sums should be equal")
	}
	
	// Test SHA256Sum function
	sum3 := SHA256Sum(data)
	if !bytes.Equal(sum1, sum3) {
		t.Error("SHA256Sum should match hash result")
	}
}

func TestRSAKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateRSAKeyPair(1024)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair failed: %v", err)
	}
	
	message := []byte("Hello, RSA!")
	
	// Test encryption/decryption
	ciphertext, err := pubKey.Encrypt(message)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	
	if bytes.Equal(message, ciphertext) {
		t.Error("Ciphertext should not equal plaintext")
	}
	
	decrypted, err := privKey.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	
	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted message doesn't match original")
	}
	
	// Test signing/verification
	signature, err := privKey.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	
	err = pubKey.Verify(message, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	
	// Test verification with wrong message
	err = pubKey.Verify([]byte("Wrong message"), signature)
	if err == nil {
		t.Error("Verify should fail for wrong message")
	}
}

func TestKeyManager(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	
	// Test AES key generation and retrieval
	err = km.GenerateAESKey("test-aes", 32, "Test AES key")
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}
	
	aesCipher, err := km.GetAESCipher("test-aes")
	if err != nil {
		t.Fatalf("GetAESCipher failed: %v", err)
	}
	
	// Test encryption with managed key
	plaintext := []byte("Test message")
	ciphertext, err := aesCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	
	decrypted, err := aesCipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Decrypted text doesn't match original")
	}
	
	// Test RSA key generation and retrieval
	err = km.GenerateRSAKey("test-rsa", 1024, "Test RSA key")
	if err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}
	
	rsaPrivKey, err := km.GetRSAPrivateKey("test-rsa")
	if err != nil {
		t.Fatalf("GetRSAPrivateKey failed: %v", err)
	}
	
	// Test RSA operations with managed key
	rsaPubKey := &PublicKey{&rsaPrivKey.PublicKey}
	message := []byte("RSA test")
	
	ciphertext, err = rsaPubKey.Encrypt(message)
	if err != nil {
		t.Fatalf("RSA Encrypt failed: %v", err)
	}
	
	decrypted, err = rsaPrivKey.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("RSA Decrypt failed: %v", err)
	}
	
	if !bytes.Equal(message, decrypted) {
		t.Error("RSA decrypted message doesn't match original")
	}
	
	// Test HMAC key generation and usage
	err = km.GenerateHMACKey("test-hmac", 32, "Test HMAC key")
	if err != nil {
		t.Fatalf("GenerateHMACKey failed: %v", err)
	}
	
	hmacResult, err := km.HMACWithKeyID("test-hmac", message)
	if err != nil {
		t.Fatalf("HMACWithKeyID failed: %v", err)
	}
	
	if len(hmacResult) != 32 {
		t.Errorf("Expected HMAC result length 32, got %d", len(hmacResult))
	}
	
	// Test key listing
	keys := km.ListKeys()
	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}
	
	// Test key deletion
	err = km.DeleteKey("test-aes")
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	
	keys = km.ListKeys()
	if len(keys) != 2 {
		t.Errorf("Expected 2 keys after deletion, got %d", len(keys))
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("secret-key")
	data := []byte("Hello, HMAC!")
	
	result := HMAC(key, data)
	
	if len(result) != 32 {
		t.Errorf("Expected HMAC result length 32, got %d", len(result))
	}
	
	// Test consistency
	result2 := HMAC(key, data)
	if !bytes.Equal(result, result2) {
		t.Error("HMAC results should be consistent")
	}
	
	// Test different key produces different result
	result3 := HMAC([]byte("different-key"), data)
	if bytes.Equal(result, result3) {
		t.Error("Different keys should produce different HMAC results")
	}
}

func TestRandomBytes(t *testing.T) {
	// Test different sizes
	sizes := []int{16, 32, 64, 128}
	
	for _, size := range sizes {
		result, err := RandomBytes(size)
		if err != nil {
			t.Fatalf("RandomBytes failed for size %d: %v", size, err)
		}
		
		if len(result) != size {
			t.Errorf("Expected %d bytes, got %d", size, len(result))
		}
		
		// Test that two calls produce different results
		result2, err := RandomBytes(size)
		if err != nil {
			t.Fatalf("RandomBytes failed for size %d: %v", size, err)
		}
		
		if bytes.Equal(result, result2) {
			t.Error("Two random byte arrays should not be equal")
		}
	}
	
	// Test zero size
	result, err := RandomBytes(0)
	if err != nil {
		t.Fatalf("RandomBytes failed for size 0: %v", err)
	}
	
	if len(result) != 0 {
		t.Errorf("Expected 0 bytes, got %d", len(result))
	}
}

func BenchmarkAESEncrypt(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, _ := NewAESCipher(key)
	plaintext := make([]byte, 1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Encrypt(plaintext)
	}
}

func BenchmarkAESDecrypt(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	cipher, _ := NewAESCipher(key)
	plaintext := make([]byte, 1024)
	ciphertext, _ := cipher.Encrypt(plaintext)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher.Decrypt(ciphertext)
	}
}

func BenchmarkSHA256(b *testing.B) {
	data := make([]byte, 1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SHA256Sum(data)
	}
}

func BenchmarkRSAEncrypt(b *testing.B) {
	_, pubKey, _ := GenerateRSAKeyPair(2048)
	message := make([]byte, 100)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pubKey.Encrypt(message)
	}
}

func BenchmarkRSADecrypt(b *testing.B) {
	privKey, pubKey, _ := GenerateRSAKeyPair(2048)
	message := make([]byte, 100)
	ciphertext, _ := pubKey.Encrypt(message)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		privKey.Decrypt(ciphertext)
	}
}