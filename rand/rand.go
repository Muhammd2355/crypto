// Package rand implements custom random number generation without external dependencies
package rand

import (
	"errors"
	"math/big"
)

// CustomRNG implements a Linear Congruential Generator for random numbers
type CustomRNG struct {
	state uint64
}

// Global instance
var globalRNG = &CustomRNG{state: 1}

// Reader interface implementation
type Reader struct {
	rng *CustomRNG
}

// Global reader instance
var GlobalReader = &Reader{rng: globalRNG}

// Read fills the byte slice with random data
func (r *Reader) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = byte(r.rng.next() >> 24)
	}
	return len(b), nil
}

// Read is a helper function that fills b with random bytes
func Read(b []byte) (n int, err error) {
	return GlobalReader.Read(b)
}

// next generates the next random number using LCG
func (rng *CustomRNG) next() uint64 {
	// LCG parameters (from Numerical Recipes)
	rng.state = rng.state*1664525 + 1013904223
	return rng.state
}

// Seed initializes the random number generator with a seed
func (rng *CustomRNG) Seed(seed uint64) {
	if seed == 0 {
		seed = 1 // Avoid zero state
	}
	rng.state = seed
}

// Seed seeds the global RNG
func Seed(seed uint64) {
	globalRNG.Seed(seed)
}

// Custom big integer implementation for basic operations
type BigInt struct {
	value *big.Int
}

// NewBigInt creates a new BigInt from uint64
func NewBigInt(x uint64) *BigInt {
	return &BigInt{value: big.NewInt(int64(x))}
}

// NewInt creates a new BigInt from int64 (alias for compatibility)
func NewInt(x int64) *BigInt {
	return &BigInt{value: big.NewInt(x)}
}

// Set sets b to the value of other and returns b
func (b *BigInt) Set(other *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Set(other.value)
	return b
}

// SetUint64 sets the BigInt to the given uint64 value
func (b *BigInt) SetUint64(x uint64) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.SetUint64(x)
	return b
}

// SetBytes sets the BigInt from a byte slice (big-endian)
func (b *BigInt) SetBytes(bytes []byte) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.SetBytes(bytes)
	return b
}

// Add sets b to a + other and returns b
func (b *BigInt) Add(a, other *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Add(a.value, other.value)
	return b
}

// Sub sets b to a - other and returns b
func (b *BigInt) Sub(a, other *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Sub(a.value, other.value)
	return b
}

// Mul sets b to a * other and returns b
func (b *BigInt) Mul(a, other *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Mul(a.value, other.value)
	return b
}

// Div sets b to a / other and returns b
func (b *BigInt) Div(a, other *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Div(a.value, other.value)
	return b
}

// Cmp compares b and other and returns:
//   -1 if b < other
//    0 if b == other
//   +1 if b > other
func (b *BigInt) Cmp(other *BigInt) int {
	return b.value.Cmp(other.value)
}

// Bytes returns the absolute value of b as a big-endian byte slice
func (b *BigInt) Bytes() []byte {
	return b.value.Bytes()
}

// BitLen returns the length of the absolute value of b in bits
func (b *BigInt) BitLen() int {
	return b.value.BitLen()
}

// Lsh sets b to a << n and returns b
func (b *BigInt) Lsh(a *BigInt, n uint) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Lsh(a.value, n)
	return b
}

// Rsh sets b to a >> n and returns b
func (b *BigInt) Rsh(a *BigInt, n uint) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Rsh(a.value, n)
	return b
}

// Mod sets b to a mod m and returns b
func (b *BigInt) Mod(a, m *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Mod(a.value, m.value)
	return b
}

// Exp sets b to a^exp mod m and returns b
func (b *BigInt) Exp(a, exp, m *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.Exp(a.value, exp.value, m.value)
	return b
}

// GCD sets b to gcd(a, other) and returns b
func (b *BigInt) GCD(x, y, a, other *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	if x != nil && y != nil {
		b.value.GCD(x.value, y.value, a.value, other.value)
	} else {
		b.value.GCD(nil, nil, a.value, other.value)
	}
	return b
}

// ModInverse sets b to the modular inverse of a modulo m and returns b
func (b *BigInt) ModInverse(a, m *BigInt) *BigInt {
	if b.value == nil {
		b.value = new(big.Int)
	}
	b.value.ModInverse(a.value, m.value)
	return b
}

// ProbablyPrime reports whether b is probably prime
func (b *BigInt) ProbablyPrime(n int) bool {
	return b.value.ProbablyPrime(n)
}

// String returns the decimal representation of b
func (b *BigInt) String() string {
	return b.value.String()
}

// Int64 returns the int64 representation of b
func (b *BigInt) Int64() int64 {
	return b.value.Int64()
}

// Sign returns the sign of b (-1, 0, or 1)
func (b *BigInt) Sign() int {
	return b.value.Sign()
}

// Uint64 returns the uint64 representation of b
func (b *BigInt) Uint64() uint64 {
	return b.value.Uint64()
}

// Prime generates a random prime number with the given bit length
func Prime(random *Reader, bits int) (*BigInt, error) {
	if bits < 2 {
		return nil, errors.New("prime size must be at least 2 bits")
	}
	
	// Generate random bytes for the prime candidate
	byteLen := (bits + 7) / 8
	bytes := make([]byte, byteLen)
	
	for {
		_, err := random.Read(bytes)
		if err != nil {
			return nil, err
		}
		
		// Set the top two bits to ensure the number is large enough
		bytes[0] |= 0xC0
		
		// Set the bottom bit to ensure it's odd
		bytes[byteLen-1] |= 0x01
		
		candidate := &BigInt{value: new(big.Int)}
		candidate.SetBytes(bytes)
		
		// Check if it's probably prime
		if candidate.ProbablyPrime(20) {
			return candidate, nil
		}
	}
}

// Int generates a random number in [0, max)
func Int(random *Reader, max *BigInt) (*BigInt, error) {
	if max.value.Sign() <= 0 {
		return nil, errors.New("max must be positive")
	}
	
	// Get the bit length of max
	bitLen := max.BitLen()
	byteLen := (bitLen + 7) / 8
	
	for {
		bytes := make([]byte, byteLen)
		_, err := random.Read(bytes)
		if err != nil {
			return nil, err
		}
		
		// Clear excess bits
		if bitLen%8 != 0 {
			bytes[0] &= (1 << (bitLen % 8)) - 1
		}
		
		result := &BigInt{value: new(big.Int)}
		result.SetBytes(bytes)
		
		if result.Cmp(max) < 0 {
			return result, nil
		}
	}
}