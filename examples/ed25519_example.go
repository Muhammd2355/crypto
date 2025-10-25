// Package main demonstrates EdDSA signature generation and verification
// This example shows how to use the EdDSA implementation similar to the Python version
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/go-crypto/crypto"
	"github.com/go-crypto/crypto/ed25519"
)

func main() {
	// Default message
	message := "Hello"
	
	// Check if message is provided as command line argument
	if len(os.Args) > 1 {
		message = os.Args[1]
	}

	fmt.Printf("Message: %s\n\n", message)

	// Generate EdDSA key pair (Alice's keys)
	privateKey, publicKey, err := crypto.GenerateEdDSAKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate EdDSA key pair: %v", err)
	}

	// Display Alice's keys
	fmt.Printf("Alice's private key A: %s\n", privateKey.PrivateKey.A.Text(16))
	fmt.Printf("Alice's public key X: %s\n", publicKey.PublicKey.Point.X.Text(16))
	fmt.Printf("Alice's public key Y: %s\n", publicKey.PublicKey.Point.Y.Text(16))

	// Sign the message
	signature, err := privateKey.SignEdDSAMessage(message)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	fmt.Printf("\nSignature:\n")
	fmt.Printf("r X = %s\n", signature.Signature.R.X.Text(16))
	fmt.Printf("r Y = %s\n", signature.Signature.R.Y.Text(16))
	fmt.Printf("s = %s\n", signature.Signature.S.Text(16))

	// Verify the signature
	isValid := publicKey.VerifyEdDSAMessage(message, signature)
	
	fmt.Printf("\nVerification result: ")
	if isValid {
		fmt.Println("Signature matches!")
	} else {
		fmt.Println("Signature verification failed!")
	}

	// Demonstrate verification with different message (should fail)
	fmt.Printf("\nTesting with different message...")
	differentMessage := "Different message"
	isValidDifferent := publicKey.VerifyEdDSAMessage(differentMessage, signature)
	
	if !isValidDifferent {
		fmt.Println(" Correctly rejected invalid signature")
	} else {
		fmt.Println(" ERROR: Should have rejected invalid signature")
	}

	// Demonstrate direct ed25519 package usage (lower level)
	fmt.Printf("\n--- Direct Ed25519 Package Usage ---\n")

	// Generate key pair using direct package
	directPriv, directPub, err := ed25519.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate direct EdDSA key pair: %v", err)
	}

	// Sign message using direct package
	directSig, err := ed25519.SignMessage(directPriv, message)
	if err != nil {
		log.Fatalf("Failed to sign with direct package: %v", err)
	}

	// Verify using direct package
	directValid := ed25519.VerifyMessage(directPub, message, directSig)
	
	fmt.Printf("Direct package verification: ")
	if directValid {
		fmt.Println("Success!")
	} else {
		fmt.Println("Failed!")
	}

	// Show curve information
	fmt.Printf("\n--- Curve Information ---\n")
	g := ed25519.BasePoint()
	fmt.Printf("Generator point X: %s\n", g.X.Text(16))
	fmt.Printf("Generator point Y: %s\n", g.Y.Text(16))
	fmt.Printf("Curve prime P: %s\n", ed25519.P.Text(16))
	fmt.Printf("Curve order L: %s\n", ed25519.L.Text(16))
	
	// Verify generator is on curve
	if g.IsOnCurve() {
		fmt.Println("Generator point is on Ed25519 curve ✓")
	} else {
		fmt.Println("Generator point is NOT on curve ✗")
	}
}