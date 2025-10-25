// Package sha implements SHA hash functions
package sha

// SHA-512 constants
const (
	Size512      = 64
	BlockSize512 = 128
)

// SHA-512 initial hash values
var h0_512 = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// SHA-512 round constants
var k512 = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

// digest512 represents the partial evaluation of a SHA-512 checksum
type digest512 struct {
	h   [8]uint64
	x   [BlockSize512]byte
	nx  int
	len uint64
}

// Hash512 represents a SHA-512 hash function interface
type Hash512 interface {
	Write(data []byte) (int, error)
	Sum(b []byte) []byte
	Reset()
	Size() int
	BlockSize() int
}

// New512 returns a new Hash512 computing the SHA-512 checksum
func New512() Hash512 {
	d := &digest512{}
	d.Reset()
	return d
}

// Reset resets the Hash512 to its initial state
func (d *digest512) Reset() {
	d.h = h0_512
	d.nx = 0
	d.len = 0
}

// Size returns the number of bytes Sum will return
func (d *digest512) Size() int { return Size512 }

// BlockSize returns the hash's underlying block size
func (d *digest512) BlockSize() int { return BlockSize512 }

// Write adds more data to the running hash
func (d *digest512) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize512 {
			d.processBlock(d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	
	if len(p) >= BlockSize512 {
		n := len(p) &^ (BlockSize512 - 1)
		d.processBlocks(p[:n])
		p = p[n:]
	}
	
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	
	return
}

// Sum appends the current hash to b and returns the resulting slice
func (d *digest512) Sum(b []byte) []byte {
	d0 := *d
	hash := d0.checkSum()
	return append(b, hash[:]...)
}

// checkSum returns the final hash
func (d *digest512) checkSum() [Size512]byte {
	// Padding
	len := d.len
	var tmp [128]byte
	tmp[0] = 0x80
	if len%128 < 112 {
		d.Write(tmp[0 : 112-len%128])
	} else {
		d.Write(tmp[0 : 128+112-len%128])
	}
	
	// Length in bits
	len <<= 3
	putUint64_512(tmp[:], 0) // High 64 bits are always 0 for our use case
	putUint64_512(tmp[8:], len)
	d.Write(tmp[0:16])
	
	if d.nx != 0 {
		panic("d.nx != 0")
	}
	
	var digest [Size512]byte
	putUint64_512(digest[0:], d.h[0])
	putUint64_512(digest[8:], d.h[1])
	putUint64_512(digest[16:], d.h[2])
	putUint64_512(digest[24:], d.h[3])
	putUint64_512(digest[32:], d.h[4])
	putUint64_512(digest[40:], d.h[5])
	putUint64_512(digest[48:], d.h[6])
	putUint64_512(digest[56:], d.h[7])
	
	return digest
}

// processBlocks processes multiple blocks
func (d *digest512) processBlocks(data []byte) {
	for len(data) >= BlockSize512 {
		d.processBlock(data[:BlockSize512])
		data = data[BlockSize512:]
	}
}

// processBlock processes a single 1024-bit block
func (d *digest512) processBlock(data []byte) {
	var w [80]uint64
	
	// Prepare message schedule
	for i := 0; i < 16; i++ {
		w[i] = getUint64_512(data[8*i:])
	}
	
	for i := 16; i < 80; i++ {
		v1 := w[i-2]
		t1 := (v1>>19 | v1<<45) ^ (v1>>61 | v1<<3) ^ (v1 >> 6)
		v2 := w[i-15]
		t2 := (v2>>1 | v2<<63) ^ (v2>>8 | v2<<56) ^ (v2 >> 7)
		w[i] = t1 + w[i-7] + t2 + w[i-16]
	}
	
	// Initialize working variables
	a, b, c, d_var, e, f, g, h := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]
	
	// Main loop
	for i := 0; i < 80; i++ {
		t1 := h + ((e>>14 | e<<50) ^ (e>>18 | e<<46) ^ (e>>41 | e<<23)) + ((e & f) ^ (^e & g)) + k512[i] + w[i]
		t2 := ((a>>28 | a<<36) ^ (a>>34 | a<<30) ^ (a>>39 | a<<25)) + ((a & b) ^ (a & c) ^ (b & c))
		
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

// Sum512 returns the SHA-512 checksum of the data
func Sum512(data []byte) [Size512]byte {
	d := &digest512{}
	d.Reset()
	d.Write(data)
	return d.checkSum()
}

// Helper functions for big-endian byte operations (64-bit)
func putUint64_512(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func getUint64_512(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}