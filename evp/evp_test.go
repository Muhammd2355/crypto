package evp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncryptAESCBCMatchesOpenSSL(t *testing.T) {
	key := []byte("0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("Hello OpenSSL compatible AES-CBC!")
	expected, err := hex.DecodeString("9c36cedb20507f27f6bb689f85d0b217b16feb176ea1b1de67d7581ef9df0aa41b55a6866a2dba84107f10ef6517ceca")
	if err != nil {
		t.Fatalf("failed to decode expected ciphertext: %v", err)
	}

	ciphertext, err := EncryptAESCBC(key, iv, plaintext)
	if err != nil {
		t.Fatalf("EncryptAESCBC failed: %v", err)
	}
	if !bytes.Equal(ciphertext, expected) {
		t.Fatalf("ciphertext mismatch\nexpected: %x\ngot:      %x", expected, ciphertext)
	}

	decrypted, err := DecryptAESCBC(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("DecryptAESCBC failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch\nexpected: %q\ngot:      %q", plaintext, decrypted)
	}
}

func TestCipherContextStreamModesRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("abcdef0123456789")
	plaintext := []byte("stream modes do not need block aligned input")

	for _, mode := range []string{CFB, OFB, CTR} {
		encryptCtx, err := NewCipherContext(AES256, mode, key, iv, true)
		if err != nil {
			t.Fatalf("NewCipherContext(%s encrypt) failed: %v", mode, err)
		}
		ciphertext := make([]byte, len(plaintext))
		if err := encryptCtx.Update(ciphertext, plaintext); err != nil {
			t.Fatalf("Update(%s encrypt) failed: %v", mode, err)
		}

		decryptCtx, err := NewCipherContext(AES256, mode, key, iv, false)
		if err != nil {
			t.Fatalf("NewCipherContext(%s decrypt) failed: %v", mode, err)
		}
		decrypted := make([]byte, len(ciphertext))
		if err := decryptCtx.Update(decrypted, ciphertext); err != nil {
			t.Fatalf("Update(%s decrypt) failed: %v", mode, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("%s round trip mismatch", mode)
		}
	}
}

func TestGCMSealOpen(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("123456789012")
	plaintext := []byte("authenticated plaintext")
	aad := []byte("metadata")

	ctx, err := NewCipherContext(AES256, GCM, key, nonce, true)
	if err != nil {
		t.Fatalf("NewCipherContext(GCM) failed: %v", err)
	}
	ciphertext := ctx.Seal(nil, nonce, plaintext, aad)
	if len(ciphertext) == 0 {
		t.Fatal("Seal returned empty ciphertext")
	}
	decrypted, err := ctx.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("GCM plaintext mismatch")
	}
}
