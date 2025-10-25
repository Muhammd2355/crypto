// Package eddsa implements Edwards-curve Digital Signature Algorithm (EdDSA)
// This implementation provides EdDSA signature generation and verification
// using the secp256k1 elliptic curve for compatibility with the Python version.
package eddsa

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// Secp256k1 curve parameters
var (
	// Prime field modulus
	P = mustParseBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	// Curve order (number of points)
	N = mustParseBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	// Generator point coordinates
	Gx = mustParseBigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	Gy = mustParseBigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
)

// Point represents a point on the elliptic curve
type Point struct {
	X, Y *big.Int
}

// PrivateKey represents an EdDSA private key
type PrivateKey struct {
	D *big.Int // Private scalar
}

// PublicKey represents an EdDSA public key
type PublicKey struct {
	Point *Point // Public key point
}

// Signature represents an EdDSA signature
type Signature struct {
	R, S *big.Int
}

// mustParseBigInt parses a hex string to big.Int, panics on error
func mustParseBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex string: " + s)
	}
	return n
}

// NewPoint creates a new point
func NewPoint(x, y *big.Int) *Point {
	return &Point{
		X: new(big.Int).Set(x),
		Y: new(big.Int).Set(y),
	}
}

// Generator returns the generator point of secp256k1
func Generator() *Point {
	return NewPoint(Gx, Gy)
}

// IsOnCurve checks if a point is on the secp256k1 curve: y² = x³ + 7 (mod p)
func (p *Point) IsOnCurve() bool {
	if p.X == nil || p.Y == nil {
		return false
	}
	
	// y² mod p
	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, P)
	
	// x³ + 7 mod p
	x3 := new(big.Int).Mul(p.X, p.X)
	x3.Mul(x3, p.X)
	x3.Add(x3, big.NewInt(7))
	x3.Mod(x3, P)
	
	return y2.Cmp(x3) == 0
}

// Add performs elliptic curve point addition
func (p *Point) Add(q *Point) *Point {
	if p.X == nil || p.Y == nil {
		return NewPoint(q.X, q.Y)
	}
	if q.X == nil || q.Y == nil {
		return NewPoint(p.X, p.Y)
	}
	
	// Check if points are the same
	if p.X.Cmp(q.X) == 0 {
		if p.Y.Cmp(q.Y) == 0 {
			return p.Double()
		}
		// Points are inverses, return point at infinity
		return &Point{nil, nil}
	}
	
	// λ = (y₂ - y₁) / (x₂ - x₁) mod p
	dy := new(big.Int).Sub(q.Y, p.Y)
	dx := new(big.Int).Sub(q.X, p.X)
	dxInv := new(big.Int).ModInverse(dx, P)
	lambda := new(big.Int).Mul(dy, dxInv)
	lambda.Mod(lambda, P)
	
	// x₃ = λ² - x₁ - x₂ mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, p.X)
	x3.Sub(x3, q.X)
	x3.Mod(x3, P)
	
	// y₃ = λ(x₁ - x₃) - y₁ mod p
	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, P)
	
	return NewPoint(x3, y3)
}

// Double performs elliptic curve point doubling
func (p *Point) Double() *Point {
	if p.X == nil || p.Y == nil {
		return &Point{nil, nil}
	}
	
	// λ = (3x₁² + a) / (2y₁) mod p, where a = 0 for secp256k1
	numerator := new(big.Int).Mul(p.X, p.X)
	numerator.Mul(numerator, big.NewInt(3))
	
	denominator := new(big.Int).Mul(p.Y, big.NewInt(2))
	denominatorInv := new(big.Int).ModInverse(denominator, P)
	
	lambda := new(big.Int).Mul(numerator, denominatorInv)
	lambda.Mod(lambda, P)
	
	// x₃ = λ² - 2x₁ mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Mul(p.X, big.NewInt(2)))
	x3.Mod(x3, P)
	
	// y₃ = λ(x₁ - x₃) - y₁ mod p
	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, P)
	
	return NewPoint(x3, y3)
}

// ScalarMult performs scalar multiplication of a point
func (p *Point) ScalarMult(k *big.Int) *Point {
	if k.Sign() == 0 {
		return &Point{nil, nil} // Point at infinity
	}
	
	// Make a copy of k to avoid modifying the original
	kCopy := new(big.Int).Set(k)
	
	result := &Point{nil, nil}
	addend := NewPoint(p.X, p.Y)
	
	for kCopy.Sign() > 0 {
		if kCopy.Bit(0) == 1 {
			result = result.Add(addend)
		}
		addend = addend.Double()
		kCopy.Rsh(kCopy, 1)
	}
	
	return result
}

// GenerateKey generates a new EdDSA key pair
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	// Generate random private key (ensure it's not zero and less than N)
	for {
		d, err := rand.Int(rand.Reader, new(big.Int).Sub(N, big.NewInt(1)))
		if err != nil {
			return nil, nil, err
		}
		
		// Add 1 to ensure d is in range [1, N-1]
		d.Add(d, big.NewInt(1))
		
		// Calculate public key: Q = d * G
		g := Generator()
		q := g.ScalarMult(d)
		
		// Ensure we got a valid point
		if q.X != nil && q.Y != nil && q.IsOnCurve() {
			privateKey := &PrivateKey{D: d}
			publicKey := &PublicKey{Point: q}
			return privateKey, publicKey, nil
		}
	}
}

// Sign creates an EdDSA signature for the given message
func (priv *PrivateKey) Sign(message []byte) (*Signature, error) {
	// Hash the message
	hash := sha256.Sum256(message)
	h := new(big.Int).SetBytes(hash[:])
	
	// Generate random nonce k in range [1, N-1]
	for {
		k, err := rand.Int(rand.Reader, new(big.Int).Sub(N, big.NewInt(1)))
		if err != nil {
			return nil, err
		}
		
		// Add 1 to ensure k is in range [1, N-1]
		k.Add(k, big.NewInt(1))
		
		// Calculate r = (k * G).x mod n
		g := Generator()
		rPoint := g.ScalarMult(k)
		if rPoint.X == nil {
			continue // Try again with different k
		}
		
		r := new(big.Int).Mod(rPoint.X, N)
		if r.Sign() == 0 {
			continue // r cannot be zero
		}
		
		// Calculate s = k⁻¹(h + r * d) mod n
		kInv := new(big.Int).ModInverse(k, N)
		if kInv == nil {
			continue // Try again with different k
		}
		
		rd := new(big.Int).Mul(r, priv.D)
		hrd := new(big.Int).Add(h, rd)
		s := new(big.Int).Mul(kInv, hrd)
		s.Mod(s, N)
		
		if s.Sign() == 0 {
			continue // s cannot be zero
		}
		
		return &Signature{R: r, S: s}, nil
	}
}

// Verify verifies an EdDSA signature
func (pub *PublicKey) Verify(message []byte, sig *Signature) bool {
	// Hash the message
	hash := sha256.Sum256(message)
	h := new(big.Int).SetBytes(hash[:])
	
	// Calculate s⁻¹ mod n
	sInv := new(big.Int).ModInverse(sig.S, N)
	if sInv == nil {
		return false
	}
	
	// Calculate u1 = h * s⁻¹ mod n
	u1 := new(big.Int).Mul(h, sInv)
	u1.Mod(u1, N)
	
	// Calculate u2 = r * s⁻¹ mod n
	u2 := new(big.Int).Mul(sig.R, sInv)
	u2.Mod(u2, N)
	
	// Calculate P = u1 * G + u2 * Q
	g := Generator()
	p1 := g.ScalarMult(u1)
	p2 := pub.Point.ScalarMult(u2)
	p := p1.Add(p2)
	
	// Verify that P.x mod n == r
	if p.X == nil {
		return false
	}
	
	result := new(big.Int).Mod(p.X, N)
	return result.Cmp(sig.R) == 0
}

// SignMessage is a convenience function that signs a string message
func SignMessage(privateKey *PrivateKey, message string) (*Signature, error) {
	return privateKey.Sign([]byte(message))
}

// VerifyMessage is a convenience function that verifies a signature for a string message
func VerifyMessage(publicKey *PublicKey, message string, signature *Signature) bool {
	return publicKey.Verify([]byte(message), signature)
}