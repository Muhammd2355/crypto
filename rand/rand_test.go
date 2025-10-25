package rand

import (
	"bytes"
	"testing"
)

func TestRead(t *testing.T) {
	// Test different buffer sizes
	sizes := []int{1, 16, 32, 64, 128, 256}
	
	for _, size := range sizes {
		buf := make([]byte, size)
		n, err := Read(buf)
		
		if err != nil {
			t.Errorf("Read failed for size %d: %v", size, err)
		}
		
		if n != size {
			t.Errorf("Expected to read %d bytes, got %d", size, n)
		}
		
		// Test that two reads produce different results
		buf2 := make([]byte, size)
		Read(buf2)
		
		if size > 0 && bytes.Equal(buf, buf2) {
			t.Errorf("Two random reads of size %d should not be equal", size)
		}
	}
}

func TestGlobalReader(t *testing.T) {
	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	
	n1, err1 := GlobalReader.Read(buf1)
	n2, err2 := GlobalReader.Read(buf2)
	
	if err1 != nil || err2 != nil {
		t.Fatalf("GlobalReader.Read failed: %v, %v", err1, err2)
	}
	
	if n1 != 32 || n2 != 32 {
		t.Errorf("Expected 32 bytes, got %d and %d", n1, n2)
	}
	
	if bytes.Equal(buf1, buf2) {
		t.Error("Two GlobalReader reads should not be equal")
	}
}

func TestSeed(t *testing.T) {
	// Test seeding with different values
	seeds := []uint64{1, 12345, 0xDEADBEEF, 0xFFFFFFFFFFFFFFFF}
	
	for _, seed := range seeds {
		Seed(seed)
		
		buf1 := make([]byte, 16)
		buf2 := make([]byte, 16)
		
		Read(buf1)
		
		// Re-seed with same value
		Seed(seed)
		Read(buf2)
		
		if !bytes.Equal(buf1, buf2) {
			t.Errorf("Same seed should produce same sequence")
		}
	}
}

func TestCustomRNG(t *testing.T) {
	rng := &CustomRNG{}
	reader := &Reader{rng: rng}
	
	// Test seeding
	rng.Seed(12345)
	
	buf1 := make([]byte, 32)
	buf2 := make([]byte, 32)
	
	reader.Read(buf1)
	
	// Re-seed with same value
	rng.Seed(12345)
	reader.Read(buf2)
	
	if !bytes.Equal(buf1, buf2) {
		t.Error("Same seed should produce same sequence for CustomRNG")
	}
}

func TestBigIntOperations(t *testing.T) {
	// Test NewBigInt
	b1 := NewBigInt(12345)
	if b1.value.Uint64() != 12345 {
		t.Errorf("NewBigInt failed: expected 12345, got %d", b1.value.Uint64())
	}
	
	// Test NewInt
	b2 := NewInt(67890)
	if b2.value.Int64() != 67890 {
		t.Errorf("NewInt failed: expected 67890, got %d", b2.value.Int64())
	}
	
	// Test Set
	b3 := &BigInt{}
	b3.Set(b1)
	if b3.value.Uint64() != 12345 {
		t.Errorf("Set failed: expected 12345, got %d", b3.value.Uint64())
	}
	
	// Test SetUint64
	b4 := &BigInt{}
	b4.SetUint64(99999)
	if b4.value.Uint64() != 99999 {
		t.Errorf("SetUint64 failed: expected 99999, got %d", b4.value.Uint64())
	}
	
	// Test SetBytes
	bytes := []byte{0x01, 0x23, 0x45, 0x67}
	b5 := &BigInt{}
	b5.SetBytes(bytes)
	expected := uint64(0x01234567)
	if b5.value.Uint64() != expected {
		t.Errorf("SetBytes failed: expected %d, got %d", expected, b5.value.Uint64())
	}
}

func TestRandomDistribution(t *testing.T) {
	// Test that random bytes have reasonable distribution
	buf := make([]byte, 10000)
	Read(buf)
	
	// Count occurrences of each byte value
	counts := make([]int, 256)
	for _, b := range buf {
		counts[b]++
	}
	
	// Check that no byte value is completely missing or overly frequent
	for i, count := range counts {
		if count == 0 {
			t.Errorf("Byte value %d never appeared in 10000 random bytes", i)
		}
		if count > 100 { // Very rough check - should be around 39 on average
			t.Logf("Warning: Byte value %d appeared %d times (may indicate poor distribution)", i, count)
		}
	}
}

func TestZeroSeed(t *testing.T) {
	rng := &CustomRNG{}
	
	// Test that zero seed is handled properly
	rng.Seed(0)
	
	buf := make([]byte, 16)
	reader := &Reader{rng: rng}
	n, err := reader.Read(buf)
	
	if err != nil {
		t.Errorf("Read failed after zero seed: %v", err)
	}
	
	if n != 16 {
		t.Errorf("Expected 16 bytes, got %d", n)
	}
	
	// Should not be all zeros
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	
	if allZero {
		t.Error("Random bytes should not be all zeros even with zero seed")
	}
}

func BenchmarkRead16(b *testing.B) {
	buf := make([]byte, 16)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		Read(buf)
	}
}

func BenchmarkRead256(b *testing.B) {
	buf := make([]byte, 256)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		Read(buf)
	}
}

func BenchmarkRead1024(b *testing.B) {
	buf := make([]byte, 1024)
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		Read(buf)
	}
}