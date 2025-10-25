package sha

import (
	"bytes"
	"testing"
	
	"github.com/go-crypto/crypto/rand"
)

// Test vectors from NIST
var sha256TestVectors = []struct {
	input    string
	expected string
}{
	{
		input:    "",
		expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	},
	{
		input:    "abc",
		expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	},
	{
		input:    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		expected: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	},
	{
		input:    "The quick brown fox jumps over the lazy dog",
		expected: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
	},
}

func TestSHA256(t *testing.T) {
	for i, tv := range sha256TestVectors {
		result := Sum256([]byte(tv.input))
		resultHex := bytesToHex(result[:])
		
		if resultHex != tv.expected {
			t.Errorf("Test vector %d failed\nInput:    %q\nExpected: %s\nGot:      %s", 
				i, tv.input, tv.expected, resultHex)
		}
	}
}

func TestSHA256Digest(t *testing.T) {
	for i, tv := range sha256TestVectors {
		d := New()
		d.Write([]byte(tv.input))
		result := d.Sum(nil)
		resultHex := bytesToHex(result)
		
		if resultHex != tv.expected {
			t.Errorf("Digest test vector %d failed\nInput:    %q\nExpected: %s\nGot:      %s", 
				i, tv.input, tv.expected, resultHex)
		}
	}
}

func TestSHA256MultipleWrites(t *testing.T) {
	// Test writing data in chunks
	expected := "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
	
	d := New()
	
	// Write in chunks
	chunks := []string{"The quick ", "brown fox ", "jumps over ", "the lazy dog"}
	for _, chunk := range chunks {
		d.Write([]byte(chunk))
	}
	
	result := d.Sum(nil)
	resultHex := bytesToHex(result)
	
	if resultHex != expected {
		t.Errorf("Multiple writes test failed\nExpected: %s\nGot:      %s", expected, resultHex)
	}
}

func TestSHA256Reset(t *testing.T) {
	d := New()
	
	// First hash
	d.Write([]byte("test1"))
	result1 := d.Sum(nil)
	
	// Reset and hash again
	d.Reset()
	d.Write([]byte("test2"))
	result2 := d.Sum(nil)
	
	if bytes.Equal(result1, result2) {
		t.Error("Reset test failed: results should be different")
	}
	
	// Verify second result matches direct computation
	expected := Sum256([]byte("test2"))
	if !bytes.Equal(result2, expected[:]) {
		t.Error("Reset test failed: second result doesn't match direct computation")
	}
}

func TestSHA256LargeInput(t *testing.T) {
	// Test with 1MB of random data
	data := make([]byte, 1024*1024)
	rand.Read(data)
	
	// Compute hash using Sum256
	result1 := Sum256(data)
	
	// Compute hash using digest
	d := New()
	d.Write(data)
	result2 := d.Sum(nil)
	
	if !bytes.Equal(result1[:], result2) {
		t.Error("Large input test failed: Sum256 and digest results differ")
	}
}

func BenchmarkSHA256Small(b *testing.B) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

func BenchmarkSHA256Large(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		Sum256(data)
	}
}

func BenchmarkSHA256Digest(b *testing.B) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		d := New()
		d.Write(data)
		d.Sum(nil)
	}
}

// Helper function to convert bytes to hex string
func bytesToHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}