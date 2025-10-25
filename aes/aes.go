// Package aes implements the Advanced Encryption Standard (AES) cipher
package aes

import (
	"errors"
)

// AES block size in bytes
const BlockSize = 16

// AES key sizes
const (
	KeySize128 = 16
	KeySize192 = 24
	KeySize256 = 32
)

// Common error messages
var (
	ErrInvalidKeySize = errors.New("crypto: invalid key size")
)

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

// aesCipher represents an AES cipher instance
type aesCipher struct {
	enc []uint32 // encryption key schedule
	dec []uint32 // decryption key schedule
	nr  int      // number of rounds
}

// NewCipher creates and returns a new Block
func NewCipher(key []byte) (Block, error) {
	keySize := len(key)
	switch keySize {
	case KeySize128, KeySize192, KeySize256:
		// Valid key sizes
	default:
		return nil, ErrInvalidKeySize
	}

	c := &aesCipher{}
	c.expandKey(key)
	return c, nil
}

// BlockSize returns the AES block size
func (c *aesCipher) BlockSize() int {
	return BlockSize
}

// Encrypt encrypts the first block in src into dst
func (c *aesCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	c.encrypt(dst, src)
}

// Decrypt decrypts the first block in src into dst
func (c *aesCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	c.decrypt(dst, src)
}

// AES S-box
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// AES inverse S-box
var rsbox = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// Round constants for key expansion
var rcon = [11]uint32{
	0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
}

// expandKey generates the key schedule from the cipher key
func (c *aesCipher) expandKey(key []byte) {
	keySize := len(key)
	var nk, nr int
	
	switch keySize {
	case KeySize128:
		nk, nr = 4, 10
	case KeySize192:
		nk, nr = 6, 12
	case KeySize256:
		nk, nr = 8, 14
	}
	
	c.nr = nr
	c.enc = make([]uint32, 4*(nr+1))
	c.dec = make([]uint32, 4*(nr+1))
	
	// Copy the cipher key to the first nk words of the key schedule
	for i := 0; i < nk; i++ {
		c.enc[i] = uint32(key[4*i])<<24 | uint32(key[4*i+1])<<16 | uint32(key[4*i+2])<<8 | uint32(key[4*i+3])
	}
	
	// Generate the remaining words
	for i := nk; i < 4*(nr+1); i++ {
		temp := c.enc[i-1]
		if i%nk == 0 {
			temp = subWord(rotWord(temp)) ^ rcon[i/nk]
		} else if nk > 6 && i%nk == 4 {
			temp = subWord(temp)
		}
		c.enc[i] = c.enc[i-nk] ^ temp
	}
	
	// Generate decryption key schedule
	copy(c.dec, c.enc)
	for i := 1; i < nr; i++ {
		for j := 0; j < 4; j++ {
			c.dec[4*i+j] = invMixColumn(c.dec[4*i+j])
		}
	}
}

// Helper functions for key expansion
func rotWord(w uint32) uint32 {
	return (w << 8) | (w >> 24)
}

func subWord(w uint32) uint32 {
	return uint32(sbox[w>>24])<<24 | uint32(sbox[(w>>16)&0xff])<<16 | uint32(sbox[(w>>8)&0xff])<<8 | uint32(sbox[w&0xff])
}

func invMixColumn(w uint32) uint32 {
	// Implementation of inverse MixColumns transformation
	b0 := byte(w >> 24)
	b1 := byte(w >> 16)
	b2 := byte(w >> 8)
	b3 := byte(w)
	
	return uint32(mul14(b0)^mul11(b1)^mul13(b2)^mul9(b3))<<24 |
		uint32(mul9(b0)^mul14(b1)^mul11(b2)^mul13(b3))<<16 |
		uint32(mul13(b0)^mul9(b1)^mul14(b2)^mul11(b3))<<8 |
		uint32(mul11(b0)^mul13(b1)^mul9(b2)^mul14(b3))
}

// Galois field multiplication functions
func mul9(b byte) byte  { return mul2(mul2(mul2(b))) ^ b }
func mul11(b byte) byte { return mul2(mul2(mul2(b)) ^ b) ^ b }
func mul13(b byte) byte { return mul2(mul2(mul2(b) ^ b)) ^ b }
func mul14(b byte) byte { return mul2(mul2(mul2(b) ^ b) ^ b) }

func mul2(b byte) byte {
	if b&0x80 != 0 {
		return (b << 1) ^ 0x1b
	}
	return b << 1
}

// encrypt performs AES encryption on a single block
func (c *aesCipher) encrypt(dst, src []byte) {
	// Convert bytes to state matrix
	var state [4][4]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[j][i] = src[i*4+j]
		}
	}
	
	// Initial round key addition
	addRoundKey(&state, c.enc[0:4])
	
	// Main rounds
	for round := 1; round < c.nr; round++ {
		subBytes(&state)
		shiftRows(&state)
		mixColumns(&state)
		addRoundKey(&state, c.enc[round*4:(round+1)*4])
	}
	
	// Final round (no MixColumns)
	subBytes(&state)
	shiftRows(&state)
	addRoundKey(&state, c.enc[c.nr*4:(c.nr+1)*4])
	
	// Convert state matrix back to bytes
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			dst[i*4+j] = state[j][i]
		}
	}
}

// decrypt performs AES decryption on a single block
func (c *aesCipher) decrypt(dst, src []byte) {
	// Convert bytes to state matrix
	var state [4][4]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[j][i] = src[i*4+j]
		}
	}
	
	// Initial round key addition
	addRoundKey(&state, c.enc[c.nr*4:(c.nr+1)*4])
	
	// Main rounds
	for round := c.nr - 1; round > 0; round-- {
		invShiftRows(&state)
		invSubBytes(&state)
		addRoundKey(&state, c.enc[round*4:(round+1)*4])
		invMixColumns(&state)
	}
	
	// Final round (no InvMixColumns)
	invShiftRows(&state)
	invSubBytes(&state)
	addRoundKey(&state, c.enc[0:4])
	
	// Convert state matrix back to bytes
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			dst[i*4+j] = state[j][i]
		}
	}
}

// AES transformation functions
func subBytes(state *[4][4]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = sbox[state[i][j]]
		}
	}
}

func invSubBytes(state *[4][4]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = rsbox[state[i][j]]
		}
	}
}

func shiftRows(state *[4][4]byte) {
	// Row 1: shift left by 1
	temp := state[1][0]
	state[1][0] = state[1][1]
	state[1][1] = state[1][2]
	state[1][2] = state[1][3]
	state[1][3] = temp
	
	// Row 2: shift left by 2
	temp = state[2][0]
	state[2][0] = state[2][2]
	state[2][2] = temp
	temp = state[2][1]
	state[2][1] = state[2][3]
	state[2][3] = temp
	
	// Row 3: shift left by 3 (or right by 1)
	temp = state[3][3]
	state[3][3] = state[3][2]
	state[3][2] = state[3][1]
	state[3][1] = state[3][0]
	state[3][0] = temp
}

func invShiftRows(state *[4][4]byte) {
	// Row 1: shift right by 1
	temp := state[1][3]
	state[1][3] = state[1][2]
	state[1][2] = state[1][1]
	state[1][1] = state[1][0]
	state[1][0] = temp
	
	// Row 2: shift right by 2
	temp = state[2][0]
	state[2][0] = state[2][2]
	state[2][2] = temp
	temp = state[2][1]
	state[2][1] = state[2][3]
	state[2][3] = temp
	
	// Row 3: shift right by 3 (or left by 1)
	temp = state[3][0]
	state[3][0] = state[3][1]
	state[3][1] = state[3][2]
	state[3][2] = state[3][3]
	state[3][3] = temp
}

func mixColumns(state *[4][4]byte) {
	for i := 0; i < 4; i++ {
		s0, s1, s2, s3 := state[0][i], state[1][i], state[2][i], state[3][i]
		state[0][i] = mul2(s0) ^ mul3(s1) ^ s2 ^ s3
		state[1][i] = s0 ^ mul2(s1) ^ mul3(s2) ^ s3
		state[2][i] = s0 ^ s1 ^ mul2(s2) ^ mul3(s3)
		state[3][i] = mul3(s0) ^ s1 ^ s2 ^ mul2(s3)
	}
}

func invMixColumns(state *[4][4]byte) {
	for i := 0; i < 4; i++ {
		s0, s1, s2, s3 := state[0][i], state[1][i], state[2][i], state[3][i]
		state[0][i] = mul14(s0) ^ mul11(s1) ^ mul13(s2) ^ mul9(s3)
		state[1][i] = mul9(s0) ^ mul14(s1) ^ mul11(s2) ^ mul13(s3)
		state[2][i] = mul13(s0) ^ mul9(s1) ^ mul14(s2) ^ mul11(s3)
		state[3][i] = mul11(s0) ^ mul13(s1) ^ mul9(s2) ^ mul14(s3)
	}
}

func mul3(b byte) byte {
	return mul2(b) ^ b
}

func addRoundKey(state *[4][4]byte, roundKey []uint32) {
	for i := 0; i < 4; i++ {
		k := roundKey[i]
		state[0][i] ^= byte(k >> 24)
		state[1][i] ^= byte(k >> 16)
		state[2][i] ^= byte(k >> 8)
		state[3][i] ^= byte(k)
	}
}