package eddsa

import (
	"github.com/go-crypto/crypto/rand"
	"github.com/go-crypto/crypto/sha"
	"math/big"
)

// Ed25519 curve parameters from the original reference
var (
	// Prime field: p = 2^255 - 19
	P = mustParseBigInt("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
	
	// Order of base point: l = 2^252 + 27742317777372353535851937790883648493
	L = mustParseBigInt("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	
	// Curve parameter: d = -121665/121666 mod p
	D *big.Int
	
	// Square root of -1 mod p: I = 2^((p-1)/4) mod p
	I *big.Int
	
	// Base point coordinates: By = 4/5 mod p
	By *big.Int
	Bx *big.Int
)

func init() {
	// Compute curve parameters exactly as in the original Ed25519 reference
	
	// d = -121665 * inv(121666) mod p
	inv121666 := modInverse(big.NewInt(121666), P)
	D = new(big.Int).Mul(big.NewInt(-121665), inv121666)
	D.Mod(D, P)
	
	// I = 2^((p-1)/4) mod p
	exp := new(big.Int).Sub(P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	I = new(big.Int).Exp(big.NewInt(2), exp, P)
	
	// By = 4 * inv(5) mod p
	inv5 := modInverse(big.NewInt(5), P)
	By = new(big.Int).Mul(big.NewInt(4), inv5)
	By.Mod(By, P)
	
	// Compute Bx from By using curve equation
	Bx = xrecover(By)
}

// Point represents a point on the Ed25519 curve
type Point struct {
	X, Y *big.Int
}

// PrivateKey represents an Ed25519 private key
type PrivateKey struct {
	Seed []byte    // 32-byte seed
	A    *big.Int  // Clamped scalar from first half of H(seed)
	AH   []byte    // Second half of H(seed) for nonce generation
}

// PublicKey represents an Ed25519 public key
type PublicKey struct {
	Point *Point // Public key point A = a*B
}

// Signature represents an Ed25519 signature
type Signature struct {
	R *Point   // R point (32 bytes when encoded)
	S *big.Int // S scalar (32 bytes when encoded)
}

func mustParseBigInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid hex string: " + s)
	}
	return n
}

// xrecover recovers x coordinate from y coordinate
func xrecover(y *big.Int) *big.Int {
	// xx = (y^2 - 1) / (d*y^2 + 1)
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, P)
	
	numerator := new(big.Int).Sub(y2, big.NewInt(1))
	numerator.Mod(numerator, P)
	
	denominator := new(big.Int).Mul(D, y2)
	denominator.Add(denominator, big.NewInt(1))
	denominator.Mod(denominator, P)
	
	xx := new(big.Int).Mul(numerator, modInverse(denominator, P))
	xx.Mod(xx, P)
	
	// x = xx^((p+3)/8) mod p
	exp := new(big.Int).Add(P, big.NewInt(3))
	exp.Div(exp, big.NewInt(8))
	x := new(big.Int).Exp(xx, exp, P)
	
	// If x^2 != xx, then x = x*I
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, P)
	if x2.Cmp(xx) != 0 {
		x.Mul(x, I)
		x.Mod(x, P)
	}
	
	// If x is odd, set x = p - x
	if x.Bit(0) == 1 {
		x.Sub(P, x)
	}
	
	return x
}

// modInverse computes modular inverse using extended Euclidean algorithm
func modInverse(a, m *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, m)
}

// NewPoint creates a new point
func NewPoint(x, y *big.Int) *Point {
	return &Point{
		X: new(big.Int).Set(x),
		Y: new(big.Int).Set(y),
	}
}



// IsOnCurve checks if point is on the Ed25519 curve
func (p *Point) IsOnCurve() bool {
	// -x^2 + y^2 = 1 + d*x^2*y^2
	x2 := new(big.Int).Mul(p.X, p.X)
	x2.Mod(x2, P)
	
	y2 := new(big.Int).Mul(p.Y, p.Y)
	y2.Mod(y2, P)
	
	left := new(big.Int).Sub(y2, x2)
	left.Mod(left, P)
	
	right := new(big.Int).Mul(D, x2)
	right.Mul(right, y2)
	right.Add(right, big.NewInt(1))
	right.Mod(right, P)
	
	return left.Cmp(right) == 0
}

// Add performs Edwards curve point addition using unified formulas
func (p *Point) Add(q *Point) *Point {
	// Edwards addition formulas from Ed25519 reference implementation
	// x3 = (x1*y2 + x2*y1) / (1 + d*x1*x2*y1*y2)
	// y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2)
	
	x1y2 := new(big.Int).Mul(p.X, q.Y)
	x1y2.Mod(x1y2, P)
	
	y1x2 := new(big.Int).Mul(p.Y, q.X)
	y1x2.Mod(y1x2, P)
	
	y1y2 := new(big.Int).Mul(p.Y, q.Y)
	y1y2.Mod(y1y2, P)
	
	x1x2 := new(big.Int).Mul(p.X, q.X)
	x1x2.Mod(x1x2, P)
	
	dxy := new(big.Int).Mul(D, x1x2)
	dxy.Mul(dxy, y1y2)
	dxy.Mod(dxy, P)
	
	// x3 numerator and denominator
	x3num := new(big.Int).Add(x1y2, y1x2)
	x3num.Mod(x3num, P)
	
	x3den := new(big.Int).Add(big.NewInt(1), dxy)
	x3den.Mod(x3den, P)
	
	// y3 numerator and denominator - Reference formula: y1*y2 + x1*x2
	y3num := new(big.Int).Add(y1y2, x1x2)
	y3num.Mod(y3num, P)
	
	y3den := new(big.Int).Sub(big.NewInt(1), dxy)
	y3den.Mod(y3den, P)
	
	// Compute final coordinates
	x3 := new(big.Int).Mul(x3num, modInverse(x3den, P))
	x3.Mod(x3, P)
	
	y3 := new(big.Int).Mul(y3num, modInverse(y3den, P))
	y3.Mod(y3, P)

	return NewPoint(x3, y3)
}

// ScalarMult performs scalar multiplication using double-and-add
func (p *Point) ScalarMult(k *big.Int) *Point {
	if k.Sign() == 0 {
		return NewPoint(big.NewInt(0), big.NewInt(1)) // Identity point
	}
	
	// Use the double-and-add algorithm from the original Ed25519 reference
	result := NewPoint(big.NewInt(0), big.NewInt(1)) // Identity point
	base := NewPoint(p.X, p.Y)
	
	// Process bits from least significant to most significant
	kCopy := new(big.Int).Set(k)
	for kCopy.Sign() > 0 {
		if kCopy.Bit(0) == 1 {
			result = result.Add(base)
		}
		base = base.Add(base) // Double
		kCopy.Rsh(kCopy, 1)   // Shift right by 1 bit
	}
	
	return result
}

// Export functions for debugging
func H(data []byte) []byte {
	hash := sha.Sum512(data)
	return hash[:]
}

func ClampScalar(h []byte) *big.Int {
	return clampScalar(h)
}

func ScalarToBytes(s *big.Int) []byte {
	return scalarToBytes(s)
}

func EncodePoint(p *Point) []byte {
	return encodePoint(p)
}

func BasePoint() *Point {
	return NewPoint(Bx, By)
}

// clampScalar clamps a scalar according to RFC 8032 Ed25519 specification
func clampScalar(h []byte) *big.Int {
	if len(h) < 32 {
		return big.NewInt(0)
	}
	
	// Make a copy of the first 32 bytes for bit manipulation
	clamped := make([]byte, 32)
	copy(clamped, h[:32])
	
	// RFC 8032 bit operations:
	// Clear bits 0, 1, 2 of the first byte
	clamped[0] &= 248  // 248 = 0xF8 = 11111000
	
	// Clear bit 255 (bit 7 of byte 31) and set bit 254 (bit 6 of byte 31)
	clamped[31] &= 127  // 127 = 0x7F = 01111111 (clear bit 7)
	clamped[31] |= 64   // 64  = 0x40 = 01000000 (set bit 6)
	
	// Convert to little-endian integer
	// Ed25519 uses little-endian, but Go's SetBytes expects big-endian
	reversed := make([]byte, 32)
	for i := 0; i < 32; i++ {
		reversed[i] = clamped[31-i]
	}
	
	return new(big.Int).SetBytes(reversed)
}

// bytesToScalar converts little-endian bytes to scalar
func bytesToScalar(b []byte) *big.Int {
	if len(b) == 0 {
		return big.NewInt(0)
	}
	
	// Ensure we have exactly 32 bytes
	bytes := make([]byte, 32)
	if len(b) >= 32 {
		copy(bytes, b[:32])
	} else {
		copy(bytes, b)
	}
	
	// Convert from little-endian to big.Int
	result := new(big.Int)
	for i := 31; i >= 0; i-- {
		result.Lsh(result, 8)
		result.Or(result, big.NewInt(int64(bytes[i])))
	}
	
	return result
}

// scalarToBytes converts scalar to 32-byte little-endian representation
func scalarToBytes(s *big.Int) []byte {
	// Convert scalar to 32-byte little-endian representation
	bytes := make([]byte, 32)
	
	// Get the bytes in big-endian format
	sBytes := s.Bytes()
	
	// Convert to little-endian
	for i := 0; i < len(sBytes) && i < 32; i++ {
		bytes[i] = sBytes[len(sBytes)-1-i]
	}
	
	return bytes
}

// encodePoint encodes a point according to Ed25519 specification
func encodePoint(p *Point) []byte {
	// Encode point according to Ed25519 specification
	// y-coordinate (32 bytes) with x sign bit in MSB
	yBytes := make([]byte, 32)
	
	// Convert y to little-endian bytes
	yBig := new(big.Int).Set(p.Y)
	for i := 0; i < 32; i++ {
		yBytes[i] = byte(yBig.Uint64() & 0xFF)
		yBig.Rsh(yBig, 8)
	}
	
	// Set the sign bit (MSB of last byte) based on x parity
	if p.X.Bit(0) == 1 {
		yBytes[31] |= 0x80
	}
	
	return yBytes
}

// decodePoint decodes a point from Ed25519 encoding
func decodePoint(b []byte) *Point {
	if len(b) != 32 {
		return nil
	}
	
	// Extract y-coordinate from little-endian bytes
	yBytes := make([]byte, 32)
	copy(yBytes, b)
	
	// Extract sign bit and clear it
	xSign := (yBytes[31] & 0x80) != 0
	yBytes[31] &= 0x7F
	
	// Convert y from little-endian to big.Int
	y := new(big.Int)
	for i := 31; i >= 0; i-- {
		y.Lsh(y, 8)
		y.Or(y, big.NewInt(int64(yBytes[i])))
	}
	
	// Recover x-coordinate
	x := xrecover(y)
	if x == nil {
		return nil
	}
	
	// Adjust x sign based on extracted bit
	if (x.Bit(0) == 1) != xSign {
		x.Sub(P, x)
	}
	
	point := NewPoint(x, y)
	if !point.IsOnCurve() {
		return nil
	}
	
	return point
}

// GenerateKey generates a new Ed25519 key pair
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	// Generate 32 random bytes as seed
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	
	// Compute private scalar and nonce from seed using RFC 8032 process
	h := H(seed)
	a := clampScalar(h) // Pass full hash, function will use first 32 bytes
	ah := h[32:]
	
	// Compute public key A = a*B
	B := BasePoint()
	A := B.ScalarMult(a)
	
	privateKey := &PrivateKey{
		Seed: seed,
		A:    a,
		AH:   ah,
	}
	
	publicKey := &PublicKey{
		Point: A,
	}
	
	return privateKey, publicKey, nil
}

// Sign creates an Ed25519 signature
func (priv *PrivateKey) Sign(message []byte) (*Signature, error) {
	// Compute r = H(AH || M) mod L
	rInput := append(priv.AH, message...)
	rHash := H(rInput)
	r := bytesToScalar(rHash)
	r.Mod(r, L)
	
	// Compute R = r * B
	B := BasePoint()
	R := B.ScalarMult(r)
	
	// Encode R and public key A
	RBytes := encodePoint(R)
	A := priv.GetPublicKey()
	ABytes := encodePoint(A.Point)
	
	// Compute k = H(R || A || M) mod L
	kInput := append(RBytes, ABytes...)
	kInput = append(kInput, message...)
	kHash := H(kInput)
	k := bytesToScalar(kHash)
	k.Mod(k, L)
	
	// Compute S = (r + k*a) mod L
	S := new(big.Int).Mul(k, priv.A)
	S.Add(S, r)
	S.Mod(S, L)
	
	return &Signature{R: R, S: S}, nil
}

// GetPublicKey returns the public key corresponding to this private key
func (priv *PrivateKey) GetPublicKey() *PublicKey {
	B := BasePoint()
	A := B.ScalarMult(priv.A)
	return &PublicKey{Point: A}
}

// Verify verifies an Ed25519 signature
func (pub *PublicKey) Verify(message []byte, sig *Signature) bool {
	// Encode points
	RBytes := encodePoint(sig.R)
	ABytes := encodePoint(pub.Point)
	
	// Compute k = H(R || A || M) mod L
	kInput := append(RBytes, ABytes...)
	kInput = append(kInput, message...)
	kHash := H(kInput)
	k := bytesToScalar(kHash)
	k.Mod(k, L)
	
	// Verify: S*B = R + k*A
	B := BasePoint()
	left := B.ScalarMult(sig.S)
	
	right := pub.Point.ScalarMult(k)
	right = sig.R.Add(right)
	
	return left.X.Cmp(right.X) == 0 && left.Y.Cmp(right.Y) == 0
}

// SignMessage signs a string message
func SignMessage(privateKey *PrivateKey, message string) (*Signature, error) {
	return privateKey.Sign([]byte(message))
}

// VerifyMessage verifies a signature for a string message
func VerifyMessage(publicKey *PublicKey, message string, signature *Signature) bool {
	return publicKey.Verify([]byte(message), signature)
}