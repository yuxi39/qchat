package pki

import (
	"bytes"
	"fmt"
	"testing"
)

// validKey is the 8-byte key required by single-DES.
var validKey = []byte("12345678")

// TestEncRoundTrip verifies that Dec reverses Enc for arbitrary plaintext.
func TestEncRoundTrip(t *testing.T) {
	plaintext := []byte("12345678")
	ciphertext := Enc(validKey, plaintext)
	message := Dec(validKey, ciphertext)
	if !bytes.Equal(plaintext, message) {
		t.Fatalf("plaintext is %s but message is %s", plaintext, message)
	}
	fmt.Printf("Done.")
}
