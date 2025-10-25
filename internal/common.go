// Package internal provides common utilities and constants for the crypto library
package internal

import (
	"errors"
	"unsafe"
)

// Common error messages
var (
	ErrInvalidKeySize   = errors.New("crypto: invalid key size")
	ErrInvalidBlockSize = errors.New("crypto: invalid block size")
	ErrInvalidPadding   = errors.New("crypto: invalid padding")
	ErrInvalidInput     = errors.New("crypto: invalid input")
	ErrBufferTooSmall   = errors.New("crypto: buffer too small")
)

// Block sizes for various algorithms
const (
	AESBlockSize = 16
	DESBlockSize = 8
	SHA1Size     = 20
	SHA224Size   = 28
	SHA256Size   = 32
	SHA384Size   = 48
	SHA512Size   = 64
)

// Key sizes for various algorithms
const (
	AES128KeySize = 16
	AES192KeySize = 24
	AES256KeySize = 32
	DESKeySize    = 8
	TripleDESKeySize = 24
)

// XORBytes performs XOR operation on two byte slices
func XORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if len(dst) < n {
		n = len(dst)
	}
	
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// SecureZero securely zeros out a byte slice
func SecureZero(b []byte) {
	if len(b) == 0 {
		return
	}
	
	// Use unsafe to prevent compiler optimizations
	ptr := unsafe.Pointer(&b[0])
	for i := 0; i < len(b); i++ {
		*(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))) = 0
	}
}

// ConstantTimeCompare compares two byte slices in constant time
func ConstantTimeCompare(x, y []byte) int {
	if len(x) != len(y) {
		return 0
	}
	
	var v byte
	for i := 0; i < len(x); i++ {
		v |= x[i] ^ y[i]
	}
	
	return int((uint32(v) - 1) >> 31)
}

// PKCS7Pad applies PKCS#7 padding to data
func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// PKCS7Unpad removes PKCS#7 padding from data
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrInvalidPadding
	}
	
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize {
		return nil, ErrInvalidPadding
	}
	
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, ErrInvalidPadding
		}
	}
	
	return data[:len(data)-padding], nil
}