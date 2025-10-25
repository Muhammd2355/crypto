// Package hmac implements the Keyed-Hash Message Authentication Code (HMAC)
package hmac

import (
	"github.com/go-crypto/crypto/sha"
)

// HMAC represents an HMAC hash
type hmac struct {
	opad, ipad []byte
	outer, inner sha.Hash
}

// New returns a new HMAC hash using SHA-256 and the given key
func New(key []byte) sha.Hash {
	hm := &hmac{
		outer: sha.New(),
		inner: sha.New(),
	}
	
	blocksize := hm.inner.BlockSize()
	hm.ipad = make([]byte, blocksize)
	hm.opad = make([]byte, blocksize)
	
	if len(key) > blocksize {
		// If key is longer than blocksize, hash it
		hm.outer.Write(key)
		key = hm.outer.Sum(nil)
		hm.outer.Reset()
	}
	
	// Pad key to blocksize
	copy(hm.ipad, key)
	copy(hm.opad, key)
	
	// XOR with ipad and opad constants
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
		hm.opad[i] ^= 0x5c
	}
	
	hm.inner.Write(hm.ipad)
	
	return hm
}

func (h *hmac) Sum(in []byte) []byte {
	origLen := len(in)
	in = h.inner.Sum(in)
	
	h.outer.Reset()
	h.outer.Write(h.opad)
	h.outer.Write(in[origLen:])
	return h.outer.Sum(in[:origLen])
}

func (h *hmac) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *hmac) Size() int {
	return h.inner.Size()
}

func (h *hmac) BlockSize() int {
	return h.inner.BlockSize()
}

func (h *hmac) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad)
}

// Equal compares two MACs for equality without leaking timing information
func Equal(mac1, mac2 []byte) bool {
	if len(mac1) != len(mac2) {
		return false
	}
	
	var result byte
	for i := 0; i < len(mac1); i++ {
		result |= mac1[i] ^ mac2[i]
	}
	return result == 0
}