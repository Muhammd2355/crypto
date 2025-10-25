// Package sha implements SHA hash functions
package sha

import (
	"github.com/go-crypto/crypto/internal"
)

// SHA-256 constants
const (
	Size      = internal.SHA256Size
	BlockSize = 64
)

// SHA-256 initial hash values
var h0 = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// SHA-256 round constants
var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// digest represents the partial evaluation of a checksum
type digest struct {
	h   [8]uint32
	x   [BlockSize]byte
	nx  int
	len uint64
}

// Hash represents a hash function interface
type Hash interface {
	Write(data []byte) (int, error)
	Sum(b []byte) []byte
	Reset()
	Size() int
	BlockSize() int
}

// New returns a new Hash computing the SHA-256 checksum
func New() Hash {
	d := &digest{}
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state
func (d *digest) Reset() {
	d.h = h0
	d.nx = 0
	d.len = 0
}

// Size returns the number of bytes Sum will return
func (d *digest) Size() int { return Size }

// BlockSize returns the hash's underlying block size
func (d *digest) BlockSize() int { return BlockSize }

// Write adds more data to the running hash
func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			d.processBlock(d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		d.processBlocks(p[:n])
		p = p[n:]
	}
	
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	
	return
}

// Sum appends the current hash to b and returns the resulting slice
func (d *digest) Sum(b []byte) []byte {
	d0 := *d
	hash := d0.checkSum()
	return append(b, hash[:]...)
}

// checkSum returns the final hash
func (d *digest) checkSum() [Size]byte {
	len := d.len
	
	// Padding
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}
	
	// Length in bits
	len <<= 3
	putUint64(tmp[:], len)
	d.Write(tmp[0:8])
	
	if d.nx != 0 {
		panic("d.nx != 0")
	}
	
	var digest [Size]byte
	putUint32(digest[0:], d.h[0])
	putUint32(digest[4:], d.h[1])
	putUint32(digest[8:], d.h[2])
	putUint32(digest[12:], d.h[3])
	putUint32(digest[16:], d.h[4])
	putUint32(digest[20:], d.h[5])
	putUint32(digest[24:], d.h[6])
	putUint32(digest[28:], d.h[7])
	
	return digest
}

// processBlocks processes multiple blocks
func (d *digest) processBlocks(data []byte) {
	for len(data) >= BlockSize {
		d.processBlock(data[:BlockSize])
		data = data[BlockSize:]
	}
}

// processBlock processes a single 512-bit block
func (d *digest) processBlock(data []byte) {
	var w [64]uint32
	
	// Prepare message schedule
	for i := 0; i < 16; i++ {
		w[i] = getUint32(data[4*i:])
	}
	
	for i := 16; i < 64; i++ {
		v1 := w[i-2]
		t1 := (v1>>17 | v1<<15) ^ (v1>>19 | v1<<13) ^ (v1 >> 10)
		v2 := w[i-15]
		t2 := (v2>>7 | v2<<25) ^ (v2>>18 | v2<<14) ^ (v2 >> 3)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}
	
	// Initialize working variables
	a, b, c, d_var, e, f, g, h := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]
	
	// Main loop
	for i := 0; i < 64; i++ {
		t1 := h + ((e>>6 | e<<26) ^ (e>>11 | e<<21) ^ (e>>25 | e<<7)) + ((e & f) ^ (^e & g)) + k[i] + w[i]
		t2 := ((a>>2 | a<<30) ^ (a>>13 | a<<19) ^ (a>>22 | a<<10)) + ((a & b) ^ (a & c) ^ (b & c))
		
		h = g
		g = f
		f = e
		e = d_var + t1
		d_var = c
		c = b
		b = a
		a = t1 + t2
	}
	
	// Add this chunk's hash to result so far
	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += d_var
	d.h[4] += e
	d.h[5] += f
	d.h[6] += g
	d.h[7] += h
}

// Sum256 returns the SHA-256 checksum of the data
func Sum256(data []byte) [Size]byte {
	d := &digest{}
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

// Helper functions for big-endian byte operations
func putUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func putUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func getUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}