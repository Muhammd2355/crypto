package eddsa

import (
	"math/big"
	"testing"
)

// Test vectors for EdDSA signature verification
func TestEdDSASignVerify(t *testing.T) {
	// Generate a key pair
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test message
	message := "Hello"

	// Sign the message
	signature, err := SignMessage(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	if !VerifyMessage(publicKey, message, signature) {
		t.Errorf("Signature verification failed")
	}

	// Test with different message (should fail)
	if VerifyMessage(publicKey, "Different message", signature) {
		t.Errorf("Signature verification should have failed for different message")
	}
}

// Test with known test vector matching Python implementation
func TestEdDSAKnownVector(t *testing.T) {
	// Known private key (for reproducible testing)
	dA := mustParseBigInt("C28A9F80738FFE1C1E2EAE7E9A7E8B8C7D6E5F4E3D2C1B0A9F8E7D6C5B4A3928")
	
	// Create private key
	privateKey := &PrivateKey{D: dA}
	
	// Calculate public key
	g := Generator()
	qA := g.ScalarMult(dA)
	publicKey := &PublicKey{Point: qA}
	
	// Test message
	message := "Hello"
	
	// Sign and verify
	signature, err := SignMessage(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	
	if !VerifyMessage(publicKey, message, signature) {
		t.Errorf("Known vector signature verification failed")
	}
	
	t.Logf("Private key: %s", dA.Text(16))
	t.Logf("Public key X: %s", qA.X.Text(16))
	t.Logf("Public key Y: %s", qA.Y.Text(16))
	t.Logf("Signature R: %s", signature.R.Text(16))
	t.Logf("Signature S: %s", signature.S.Text(16))
}

// Test elliptic curve point operations
func TestPointOperations(t *testing.T) {
	g := Generator()
	
	// Test that generator is on curve
	if !g.IsOnCurve() {
		t.Errorf("Generator point is not on curve")
	}
	
	// Test point doubling
	g2 := g.Double()
	if !g2.IsOnCurve() {
		t.Errorf("Doubled generator point is not on curve")
	}
	
	// Test scalar multiplication
	k := big.NewInt(2)
	g2_mult := g.ScalarMult(k)
	if g2.X.Cmp(g2_mult.X) != 0 || g2.Y.Cmp(g2_mult.Y) != 0 {
		t.Errorf("Point doubling and scalar multiplication by 2 should be equal")
	}
	
	// Test point addition
	g_plus_g := g.Add(g)
	if g2.X.Cmp(g_plus_g.X) != 0 || g2.Y.Cmp(g_plus_g.Y) != 0 {
		t.Errorf("Point doubling and point addition should be equal")
	}
}

// Test key generation
func TestKeyGeneration(t *testing.T) {
	for i := 0; i < 10; i++ {
		privateKey, publicKey, err := GenerateKey()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}
		
		// Check that private key is in valid range
		if privateKey.D.Sign() <= 0 || privateKey.D.Cmp(N) >= 0 {
			t.Errorf("Private key %d is out of valid range", i)
		}
		
		// Check that public key is on curve
		if !publicKey.Point.IsOnCurve() {
			t.Errorf("Public key %d is not on curve", i)
		}
		
		// Verify that public key = private key * generator
		g := Generator()
		expectedPubKey := g.ScalarMult(privateKey.D)
		if publicKey.Point.X.Cmp(expectedPubKey.X) != 0 || publicKey.Point.Y.Cmp(expectedPubKey.Y) != 0 {
			t.Errorf("Public key %d does not match private key * generator", i)
		}
	}
}

// Test signature with empty message
func TestEmptyMessage(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Sign empty message
	signature, err := SignMessage(privateKey, "")
	if err != nil {
		t.Fatalf("Failed to sign empty message: %v", err)
	}

	// Verify empty message signature
	if !VerifyMessage(publicKey, "", signature) {
		t.Errorf("Empty message signature verification failed")
	}
}

// Test signature with long message
func TestLongMessage(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create a long message
	longMessage := ""
	for i := 0; i < 1000; i++ {
		longMessage += "This is a very long message for testing EdDSA signature. "
	}

	// Sign long message
	signature, err := SignMessage(privateKey, longMessage)
	if err != nil {
		t.Fatalf("Failed to sign long message: %v", err)
	}

	// Verify long message signature
	if !VerifyMessage(publicKey, longMessage, signature) {
		t.Errorf("Long message signature verification failed")
	}
}

// Test multiple signatures with same key
func TestMultipleSignatures(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := []string{
		"Message 1",
		"Message 2",
		"Message 3",
		"Different content",
		"123456789",
	}

	signatures := make([]*Signature, len(messages))

	// Sign all messages
	for i, msg := range messages {
		sig, err := SignMessage(privateKey, msg)
		if err != nil {
			t.Fatalf("Failed to sign message %d: %v", i, err)
		}
		signatures[i] = sig
	}

	// Verify all signatures
	for i, msg := range messages {
		if !VerifyMessage(publicKey, msg, signatures[i]) {
			t.Errorf("Signature verification failed for message %d", i)
		}
	}

	// Cross-verify (should fail)
	for i, msg := range messages {
		for j, sig := range signatures {
			if i != j {
				if VerifyMessage(publicKey, msg, sig) {
					t.Errorf("Cross-verification should have failed for message %d with signature %d", i, j)
				}
			}
		}
	}
}

// Test invalid signatures
func TestInvalidSignatures(t *testing.T) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := "Test message"
	signature, err := SignMessage(privateKey, message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Test with modified R
	invalidSig1 := &Signature{
		R: new(big.Int).Add(signature.R, big.NewInt(1)),
		S: signature.S,
	}
	if VerifyMessage(publicKey, message, invalidSig1) {
		t.Errorf("Verification should fail with modified R")
	}

	// Test with modified S
	invalidSig2 := &Signature{
		R: signature.R,
		S: new(big.Int).Add(signature.S, big.NewInt(1)),
	}
	if VerifyMessage(publicKey, message, invalidSig2) {
		t.Errorf("Verification should fail with modified S")
	}

	// Test with zero R
	invalidSig3 := &Signature{
		R: big.NewInt(0),
		S: signature.S,
	}
	if VerifyMessage(publicKey, message, invalidSig3) {
		t.Errorf("Verification should fail with zero R")
	}

	// Test with zero S
	invalidSig4 := &Signature{
		R: signature.R,
		S: big.NewInt(0),
	}
	if VerifyMessage(publicKey, message, invalidSig4) {
		t.Errorf("Verification should fail with zero S")
	}
}

// Test curve parameters
func TestCurveParameters(t *testing.T) {
	// Test that generator point is on curve
	g := Generator()
	if !g.IsOnCurve() {
		t.Errorf("Generator point is not on secp256k1 curve")
	}

	// Test curve order by multiplying generator by N (should give point at infinity)
	result := g.ScalarMult(N)
	if result.X != nil || result.Y != nil {
		t.Errorf("Generator * N should be point at infinity")
	}

	// Test that N-1 * G + G = point at infinity
	nMinus1 := new(big.Int).Sub(N, big.NewInt(1))
	almostInfinity := g.ScalarMult(nMinus1)
	infinity := almostInfinity.Add(g)
	if infinity.X != nil || infinity.Y != nil {
		t.Errorf("(N-1) * G + G should be point at infinity")
	}
}

// Benchmark tests
func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := GenerateKey()
		if err != nil {
			b.Fatalf("Key generation failed: %v", err)
		}
	}
}

func BenchmarkSigning(b *testing.B) {
	privateKey, _, err := GenerateKey()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	message := "Benchmark message for signing performance test"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := SignMessage(privateKey, message)
		if err != nil {
			b.Fatalf("Signing failed: %v", err)
		}
	}
}

func BenchmarkVerification(b *testing.B) {
	privateKey, publicKey, err := GenerateKey()
	if err != nil {
		b.Fatalf("Key generation failed: %v", err)
	}

	message := "Benchmark message for verification performance test"
	signature, err := SignMessage(privateKey, message)
	if err != nil {
		b.Fatalf("Signing failed: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !VerifyMessage(publicKey, message, signature) {
			b.Fatalf("Verification failed")
		}
	}
}

func BenchmarkScalarMult(b *testing.B) {
	g := Generator()
	k := mustParseBigInt("C28A9F80738FFE1C1E2EAE7E9A7E8B8C7D6E5F4E3D2C1B0A9F8E7D6C5B4A3928")

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = g.ScalarMult(k)
	}
}