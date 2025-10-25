package keystore

import (
	"testing"
)

func TestNewKeyStore(t *testing.T) {
	ks := NewKeyStore()
	
	if ks == nil {
		t.Fatal("NewKeyStore returned nil")
	}
	
	if ks.keys == nil {
		t.Error("KeyStore keys map is nil")
	}
}

func TestGenerateAESKey(t *testing.T) {
	ks := NewKeyStore()
	
	// Test valid key sizes
	keySizes := []int{16, 24, 32}
	for _, size := range keySizes {
		keyID := "aes-" + string(rune('0'+size))
		err := ks.GenerateAESKey(keyID, size, "Test AES key")
		if err != nil {
			t.Errorf("GenerateAESKey failed for size %d: %v", size, err)
		}
		
		// Verify key was stored
		key, err := ks.GetKey(keyID)
		if err != nil {
			t.Errorf("GetKey failed for %s: %v", keyID, err)
		}
		
		if key.Type != KeyTypeAES {
			t.Errorf("Expected key type %s, got %s", KeyTypeAES, key.Type)
		}
		
		if len(key.KeyData) != size {
			t.Errorf("Expected key data length %d, got %d", size, len(key.KeyData))
		}
	}
	
	// Test invalid key size
	err := ks.GenerateAESKey("invalid", 15, "Invalid key")
	if err == nil {
		t.Error("GenerateAESKey should fail for invalid key size")
	}
}

func TestGenerateRSAKey(t *testing.T) {
	ks := NewKeyStore()
	
	err := ks.GenerateRSAKey("rsa-test", 2048, "Test RSA key")
	if err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}
	
	// Verify key was stored
	key, err := ks.GetKey("rsa-test")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	
	if key.Type != KeyTypeRSA {
		t.Errorf("Expected key type %s, got %s", KeyTypeRSA, key.Type)
	}
	
	if key.KeySize != 2048 {
		t.Errorf("Expected key size 2048, got %d", key.KeySize)
	}
}

func TestGenerateHMACKey(t *testing.T) {
	ks := NewKeyStore()
	
	err := ks.GenerateHMACKey("hmac-test", 32, "Test HMAC key")
	if err != nil {
		t.Fatalf("GenerateHMACKey failed: %v", err)
	}
	
	// Verify key was stored
	key, err := ks.GetKey("hmac-test")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	
	if key.Type != KeyTypeHMAC {
		t.Errorf("Expected key type %s, got %s", KeyTypeHMAC, key.Type)
	}
	
	if len(key.KeyData) != 32 {
		t.Errorf("Expected key data length 32, got %d", len(key.KeyData))
	}
	
	// Test invalid key size
	err = ks.GenerateHMACKey("invalid", 8, "Invalid key")
	if err == nil {
		t.Error("GenerateHMACKey should fail for key size < 16")
	}
}

func TestGetKey(t *testing.T) {
	ks := NewKeyStore()
	
	// Test getting non-existent key
	_, err := ks.GetKey("non-existent")
	if err == nil {
		t.Error("GetKey should fail for non-existent key")
	}
	
	// Generate and retrieve a key
	err = ks.GenerateAESKey("test-key", 32, "Test key")
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}
	
	key, err := ks.GetKey("test-key")
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	
	if key.ID != "test-key" {
		t.Errorf("Expected key ID 'test-key', got '%s'", key.ID)
	}
}

func TestDeleteKey(t *testing.T) {
	ks := NewKeyStore()
	
	// Test deleting non-existent key
	err := ks.DeleteKey("non-existent")
	if err == nil {
		t.Error("DeleteKey should fail for non-existent key")
	}
	
	// Generate, delete, and verify deletion
	err = ks.GenerateAESKey("delete-me", 32, "Key to delete")
	if err != nil {
		t.Fatalf("GenerateAESKey failed: %v", err)
	}
	
	err = ks.DeleteKey("delete-me")
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	
	_, err = ks.GetKey("delete-me")
	if err == nil {
		t.Error("GetKey should fail after key deletion")
	}
}

func TestListKeys(t *testing.T) {
	ks := NewKeyStore()
	
	// Initially empty
	keys := ks.ListKeys()
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}
	
	// Add some keys
	ks.GenerateAESKey("aes1", 32, "AES key 1")
	ks.GenerateRSAKey("rsa1", 2048, "RSA key 1")
	ks.GenerateHMACKey("hmac1", 32, "HMAC key 1")
	
	keys = ks.ListKeys()
	if len(keys) != 3 {
		t.Errorf("Expected 3 keys, got %d", len(keys))
	}
	
	// Verify key types
	keyTypes := make(map[KeyType]int)
	for _, key := range keys {
		keyTypes[key.Type]++
	}
	
	if keyTypes[KeyTypeAES] != 1 {
		t.Errorf("Expected 1 AES key, got %d", keyTypes[KeyTypeAES])
	}
	if keyTypes[KeyTypeRSA] != 1 {
		t.Errorf("Expected 1 RSA key, got %d", keyTypes[KeyTypeRSA])
	}
	if keyTypes[KeyTypeHMAC] != 1 {
		t.Errorf("Expected 1 HMAC key, got %d", keyTypes[KeyTypeHMAC])
	}
}