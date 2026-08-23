package pki

import (
	"bytes"
	"testing"
)

// TestDataProtectRoundTrip verifies that DataRestore reverses DataProtect
// for various input lengths (including non-block-aligned ones).
func TestDataProtectRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "short", data: []byte("hi")},
		{name: "exactly one block", data: []byte("12345678")},
		{name: "hello world", data: []byte("Hello World!")},
		{name: "many blocks", data: bytes.Repeat([]byte("abcdefgh"), 5)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restored := DataRestore(DataProtect(tt.data))
			if !bytes.Equal(restored, tt.data) {
				t.Fatalf("DataRestore(DataProtect(%q)) = %q, want %q", tt.data, restored, tt.data)
			}
		})
	}
}

// TestDataProtectChangesOutput ensures the ciphertext actually differs.
func TestDataProtectChangesOutput(t *testing.T) {
	data := []byte("Hello World!")
	protected := DataProtect(data)

	if bytes.Equal(protected, data) {
		t.Fatal("DataProtect returned plaintext unchanged")
	}
}

// TestSplitMerge checks that Split/Merge are lossless round trips.
func TestSplitMerge(t *testing.T) {
	data := bytes.Repeat([]byte("ab"), 7) // 14 bytes -> 8 + 6

	if pieces := Split(data); len(pieces) != 2 {
		t.Fatalf("Split produced %d pieces, want 2", len(pieces))
	}
	if got := Merge(Split(data)); !bytes.Equal(got, data) {
		t.Fatalf("Merge(Split(data)) = %x, want %x", got, data)
	}
}
