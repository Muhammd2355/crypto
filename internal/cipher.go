// Package internal provides custom cipher interfaces without external dependencies
package internal

// Block represents a block cipher running in a given key
type Block interface {
	// BlockSize returns the cipher's block size
	BlockSize() int

	// Encrypt encrypts the first block in src into dst
	// Dst and src must overlap entirely or not at all
	Encrypt(dst, src []byte)

	// Decrypt decrypts the first block in src into dst
	// Dst and src must overlap entirely or not at all
	Decrypt(dst, src []byte)
}

// Stream represents a stream cipher
type Stream interface {
	// XORKeyStream XORs each byte in the given slice with a byte from the
	// cipher's key stream. Dst and src must overlap entirely or not at all.
	//
	// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
	// to pass a dst bigger than src, and in that case, XORKeyStream will
	// only update dst[:len(src)] and will not touch the rest of dst.
	//
	// Multiple calls to XORKeyStream behave as if the arguments were
	// concatenated and passed in a single run. That is, Stream
	// maintains state and does not reset at each XORKeyStream call.
	XORKeyStream(dst, src []byte)
}

// BlockMode represents a block cipher running in a block-based mode (CBC, ECB etc.)
type BlockMode interface {
	// BlockSize returns the mode's block size
	BlockSize() int

	// CryptBlocks encrypts or decrypts a number of blocks. The length of
	// src must be a multiple of the block size. Dst and src must overlap
	// entirely or not at all.
	//
	// If there isn't sufficient space in dst for src, CryptBlocks will
	// panic. It is acceptable to pass a dst bigger than src, and in that
	// case, CryptBlocks will only update dst[:len(src)] and will not touch
	// the rest of dst.
	CryptBlocks(dst, src []byte)
}

// AEAD is a cipher mode providing authenticated encryption with associated data
type AEAD interface {
	// NonceSize returns the size of the nonce that must be passed to Seal
	// and Open.
	NonceSize() int

	// Overhead returns the maximum difference between the lengths of a
	// plaintext and its ciphertext.
	Overhead() int

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	//
	// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte

	// Open decrypts and authenticates ciphertext, authenticates the
	// additional data and, if successful, appends the resulting plaintext
	// to dst, returning the updated slice. The nonce must be NonceSize()
	// bytes long and both it and the ciphertext must not have been used on
	// any previous call to Open.
	//
	// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
	// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
	//
	// Even if the function fails, the contents of dst, up to its capacity,
	// may be overwritten.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// CBC mode implementation
type cbcEncrypter struct {
	b         Block
	blockSize int
	iv        []byte
}

type cbcDecrypter struct {
	b         Block
	blockSize int
	iv        []byte
}

// NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining mode
func NewCBCEncrypter(b Block, iv []byte) BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher: IV length must equal block size")
	}
	return &cbcEncrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        make([]byte, len(iv)),
	}
}

// NewCBCDecrypter returns a BlockMode which decrypts in cipher block chaining mode
func NewCBCDecrypter(b Block, iv []byte) BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher: IV length must equal block size")
	}
	return &cbcDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        make([]byte, len(iv)),
	}
}

func (x *cbcEncrypter) BlockSize() int { return x.blockSize }

func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}

	iv := x.iv

	for len(src) > 0 {
		// XOR with IV
		for i := 0; i < x.blockSize; i++ {
			dst[i] = src[i] ^ iv[i]
		}

		x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])

		// Update IV to the ciphertext
		copy(iv, dst[:x.blockSize])

		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	copy(x.iv, iv)
}

func (x *cbcDecrypter) BlockSize() int { return x.blockSize }

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("cipher: output smaller than input")
	}

	if len(src) == 0 {
		return
	}

	// For each block, we need to XOR the decrypted output with the previous
	// ciphertext block. The first block is XORed with the IV.
	end := len(src)
	start := end - x.blockSize
	prev := start - x.blockSize

	// Copy the last block of ciphertext in preparation as the new IV.
	copy(x.iv, src[start:end])

	// Loop over all but the first block.
	for start > 0 {
		x.b.Decrypt(dst[start:end], src[start:end])
		for i := 0; i < x.blockSize; i++ {
			dst[start+i] ^= src[prev+i]
		}

		end = start
		start = prev
		prev -= x.blockSize
	}

	// The first block is special because it uses the saved IV.
	x.b.Decrypt(dst[start:end], src[start:end])
	for i := 0; i < x.blockSize; i++ {
		dst[start+i] ^= x.iv[i]
	}
}