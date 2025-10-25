// Package rsa implements RSA public key cryptography
package rsa

import (
	"errors"
	
	"github.com/go-crypto/crypto/rand"
)

// Common RSA key sizes
const (
	KeySize1024 = 1024
	KeySize2048 = 2048
	KeySize3072 = 3072
	KeySize4096 = 4096
)

var (
	ErrDecryption      = errors.New("crypto/rsa: decryption error")
	ErrVerification    = errors.New("crypto/rsa: verification error")
	ErrDataToLarge     = errors.New("crypto/rsa: message too long for RSA public key size")
	ErrDataTooSmall    = errors.New("crypto/rsa: message too short")
	ErrInvalidPadding  = errors.New("crypto/rsa: invalid padding")
)

// PublicKey represents an RSA public key
type PublicKey struct {
	N *rand.BigInt // modulus
	E int          // public exponent
}

// PrivateKey represents an RSA private key
type PrivateKey struct {
	PublicKey            // public part
	D         *rand.BigInt   // private exponent
	Primes    []*rand.BigInt // prime factors of N, has >= 2 elements
	
	// Precomputed values for CRT
	Precomputed PrecomputedValues
}

// PrecomputedValues contains precomputed values for CRT
type PrecomputedValues struct {
	Dp, Dq *rand.BigInt      // D mod (P-1), D mod (Q-1)
	Qinv   *rand.BigInt      // Q^-1 mod P
	CRTValues []CRTValue  // additional values for multi-prime RSA
}

// CRTValue contains values for Chinese Remainder Theorem
type CRTValue struct {
	Exp   *rand.BigInt // D mod (prime-1)
	Coeff *rand.BigInt // R·Coeff ≡ 1 mod Prime
	R     *rand.BigInt // product of primes prior to this (inc p and q)
}

// GenerateKey generates an RSA keypair of the given bit size
func GenerateKey(random *rand.Reader, bits int) (*PrivateKey, error) {
	return GenerateMultiPrimeKey(random, 2, bits)
}

// GenerateMultiPrimeKey generates a multi-prime RSA keypair
func GenerateMultiPrimeKey(random *rand.Reader, nprimes int, bits int) (*PrivateKey, error) {
	if nprimes < 2 {
		return nil, errors.New("crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2")
	}
	
	if bits < 64 {
		return nil, errors.New("crypto/rsa: too few bits in RSA key")
	}
	
	primes := make([]*rand.BigInt, nprimes)
	
NextSetOfPrimes:
	for {
		todo := bits
		
		// Generate primes
		for i := 0; i < nprimes; i++ {
			var err error
			primes[i], err = rand.Prime(random, todo/(nprimes-i))
			if err != nil {
				return nil, err
			}
			todo -= primes[i].BitLen()
		}
		
		// Check that the product is of the right bit-length
		n := new(rand.BigInt).Set(primes[0])
		for _, prime := range primes[1:] {
			n.Mul(n, prime)
		}
		if n.BitLen() != bits {
			continue NextSetOfPrimes
		}
		
		// Check that primes are distinct
		for i, prime := range primes {
			for j := i + 1; j < len(primes); j++ {
				if prime.Cmp(primes[j]) == 0 {
					continue NextSetOfPrimes
				}
			}
		}
		
		break
	}
	
	// Sort primes in ascending order as required by validation
	for i := 0; i < len(primes)-1; i++ {
		for j := i + 1; j < len(primes); j++ {
			if primes[i].Cmp(primes[j]) > 0 {
				primes[i], primes[j] = primes[j], primes[i]
			}
		}
	}
	
	// Calculate N = p1 * p2 * ... * pn
	n := new(rand.BigInt).Set(primes[0])
	for _, prime := range primes[1:] {
		n.Mul(n, prime)
	}
	
	// Calculate totient φ(n) = (p1-1) * (p2-1) * ... * (pn-1)
	totient := new(rand.BigInt).Sub(primes[0], rand.NewInt(1))
	for _, prime := range primes[1:] {
		pminus1 := new(rand.BigInt).Sub(prime, rand.NewInt(1))
		totient.Mul(totient, pminus1)
	}
	
	// Choose public exponent e
	e := 65537
	g := new(rand.BigInt)
	
	for {
		g.GCD(nil, nil, rand.NewInt(int64(e)), totient)
		if g.Cmp(rand.NewInt(1)) == 0 {
			break
		}
		e += 2
	}
	
	// Calculate private exponent d = e^-1 mod φ(n)
	d := new(rand.BigInt)
	d.ModInverse(rand.NewInt(int64(e)), totient)
	if d == nil {
		return nil, errors.New("crypto/rsa: unable to find modular inverse")
	}
	
	// Create the private key
	key := &PrivateKey{
		PublicKey: PublicKey{
			N: n,
			E: e,
		},
		D:      d,
		Primes: primes,
	}
	
	// Precompute CRT values
	key.Precompute()
	
	return key, nil
}

// Precompute performs precomputations for CRT
func (priv *PrivateKey) Precompute() {
	if priv.Precomputed.Dp != nil {
		return
	}
	
	priv.Precomputed.Dp = new(rand.BigInt).Sub(priv.Primes[0], rand.NewInt(1))
	priv.Precomputed.Dp.Mod(priv.D, priv.Precomputed.Dp)
	
	priv.Precomputed.Dq = new(rand.BigInt).Sub(priv.Primes[1], rand.NewInt(1))
	priv.Precomputed.Dq.Mod(priv.D, priv.Precomputed.Dq)
	
	priv.Precomputed.Qinv = new(rand.BigInt).ModInverse(priv.Primes[1], priv.Primes[0])
	
	// Multi-prime precomputation
	if len(priv.Primes) > 2 {
		priv.Precomputed.CRTValues = make([]CRTValue, len(priv.Primes)-2)
		
		r := new(rand.BigInt).Mul(priv.Primes[0], priv.Primes[1])
		for i := 2; i < len(priv.Primes); i++ {
			prime := priv.Primes[i]
			values := &priv.Precomputed.CRTValues[i-2]
			
			values.Exp = new(rand.BigInt).Sub(prime, rand.NewInt(1))
			values.Exp.Mod(priv.D, values.Exp)
			
			values.R = new(rand.BigInt).Set(r)
			values.Coeff = new(rand.BigInt).ModInverse(r, prime)
			
			r.Mul(r, prime)
		}
	}
}

// Validate performs basic sanity checks on the key
func (priv *PrivateKey) Validate() error {
	// Check for nil values
	if priv.N == nil {
		return errors.New("crypto/rsa: missing modulus")
	}
	if priv.D == nil {
		return errors.New("crypto/rsa: missing private exponent")
	}
	if len(priv.Primes) < 2 {
		return errors.New("crypto/rsa: missing primes")
	}
	for i, prime := range priv.Primes {
		if prime == nil {
			return errors.New("crypto/rsa: missing prime")
		}
		if i > 0 && prime.Cmp(priv.Primes[i-1]) <= 0 {
			return errors.New("crypto/rsa: primes not in order")
		}
	}
	
	// Check that n = p * q * ...
	n := new(rand.BigInt).Set(priv.Primes[0])
	for _, prime := range priv.Primes[1:] {
		n.Mul(n, prime)
	}
	if n.Cmp(priv.N) != 0 {
		return errors.New("crypto/rsa: invalid modulus")
	}
	
	// Check that e * d ≡ 1 (mod φ(n))
	totient := new(rand.BigInt).Sub(priv.Primes[0], rand.NewInt(1))
	for _, prime := range priv.Primes[1:] {
		pminus1 := new(rand.BigInt).Sub(prime, rand.NewInt(1))
		totient.Mul(totient, pminus1)
	}
	
	de := new(rand.BigInt).Mul(priv.D, rand.NewInt(int64(priv.E)))
	de.Mod(de, totient)
	if de.Cmp(rand.NewInt(1)) != 0 {
		return errors.New("crypto/rsa: invalid exponents")
	}
	
	return nil
}

// Size returns the modulus size in bytes
func (pub *PublicKey) Size() int {
	return (pub.N.BitLen() + 7) / 8
}

// Encrypt encrypts the given message with RSA and PKCS#1 v1.5 padding
func EncryptPKCS1v15(random *rand.Reader, pub *PublicKey, msg []byte) ([]byte, error) {
	k := pub.Size()
	if len(msg) > k-11 {
		return nil, ErrDataToLarge
	}
	
	// EM = 0x00 || 0x02 || PS || 0x00 || M
	em := make([]byte, k)
	em[1] = 2
	ps, mm := em[2:len(em)-len(msg)-1], em[len(em)-len(msg):]
	err := nonZeroRandomBytes(ps, random)
	if err != nil {
		return nil, err
	}
	em[len(em)-len(msg)-1] = 0
	copy(mm, msg)
	
	m := new(rand.BigInt).SetBytes(em)
	c := encrypt(new(rand.BigInt), pub, m)
	
	out := make([]byte, k)
	copyWithLeftPad(out, c.Bytes())
	return out, nil
}

// Decrypt decrypts the given message with RSA and PKCS#1 v1.5 padding
func DecryptPKCS1v15(random *rand.Reader, priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != priv.Size() {
		return nil, ErrDecryption
	}
	
	c := new(rand.BigInt).SetBytes(ciphertext)
	m := decrypt(random, priv, c)
	if m == nil {
		return nil, ErrDecryption
	}
	
	em := leftPad(m.Bytes(), priv.Size())
	
	// EM = 0x00 || 0x02 || PS || 0x00 || M
	if len(em) != priv.Size() {
		return nil, ErrDecryption
	}
	
	if em[0] != 0 {
		return nil, ErrDecryption
	}
	
	if em[1] != 2 {
		return nil, ErrDecryption
	}
	
	// Look for 0x00 separator
	var index int
	for index = 2; index < len(em); index++ {
		if em[index] == 0 {
			break
		}
	}
	
	if index == len(em) || index < 10 {
		return nil, ErrDecryption
	}
	
	return em[index+1:], nil
}

// encrypt performs raw RSA encryption
func encrypt(c *rand.BigInt, pub *PublicKey, m *rand.BigInt) *rand.BigInt {
	e := rand.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// decrypt performs raw RSA decryption using CRT
func decrypt(random *rand.Reader, priv *PrivateKey, c *rand.BigInt) *rand.BigInt {
	if c.Cmp(priv.N) >= 0 {
		return nil
	}
	
	if priv.Precomputed.Dp == nil {
		priv.Precompute()
	}
	
	// Use Chinese Remainder Theorem for faster decryption
	p := priv.Primes[0]
	q := priv.Primes[1]
	
	// m1 = c^dp mod p
	m1 := new(rand.BigInt).Exp(c, priv.Precomputed.Dp, p)
	
	// m2 = c^dq mod q  
	m2 := new(rand.BigInt).Exp(c, priv.Precomputed.Dq, q)
	
	// h = qinv * (m1 - m2) mod p
	h := new(rand.BigInt).Sub(m1, m2)
	if h.Sign() < 0 {
		h.Add(h, p)
	}
	h.Mul(h, priv.Precomputed.Qinv)
	h.Mod(h, p)
	
	// m = m2 + h * q
	m := new(rand.BigInt).Mul(h, q)
	m.Add(m, m2)
	
	// Handle multi-prime case
	if len(priv.Primes) > 2 {
		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			tmp := new(rand.BigInt).Exp(c, values.Exp, prime)
			tmp.Sub(tmp, m)
			tmp.Mul(tmp, values.Coeff)
			tmp.Mod(tmp, prime)
			if tmp.Sign() < 0 {
				tmp.Add(tmp, prime)
			}
			tmp.Mul(tmp, values.R)
			m.Add(m, tmp)
		}
	}
	
	return m
}

// Helper functions
func nonZeroRandomBytes(s []byte, random *rand.Reader) error {
	_, err := random.Read(s)
	if err != nil {
		return err
	}
	
	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = random.Read(s[i:i+1])
			if err != nil {
				return err
			}
		}
	}
	
	return nil
}

func leftPad(input []byte, size int) []byte {
	n := len(input)
	if n == size {
		return input
	}
	if n > size {
		return input[n-size:]
	}
	
	t := make([]byte, size)
	copy(t[size-n:], input)
	return t
}

func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}