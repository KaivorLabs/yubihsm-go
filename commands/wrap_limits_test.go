package commands

import "testing"

func TestWrapDataAccountsForResponseOverhead(t *testing.T) {
	// Secure inner payload limit 3116, minus nonce (13), encrypted marker (1)
	// and AES-CCM tag (16): at most 3086 plaintext bytes can be returned.
	if _, err := CreateWrapDataCommand(1, make([]byte, 3086)); err != nil {
		t.Fatalf("maximum WRAP response was rejected locally: %v", err)
	}
	if _, err := CreateWrapDataCommand(1, make([]byte, 3087)); err == nil {
		t.Fatal("WRAP accepted plaintext whose successful response cannot fit in a secure frame")
	}
}

func TestUnwrapHasItsOwnRequestOverhead(t *testing.T) {
	// UNWRAP also sends a two-byte key ID. Its largest original plaintext is
	// therefore 3084 bytes, two bytes less than the one-way WRAP limit.
	nonce := make([]byte, 13)
	if _, err := CreateUnwrapDataCommand(1, nonce, make([]byte, 1+3084+16)); err != nil {
		t.Fatalf("maximum UNWRAP request was rejected: %v", err)
	}
	if _, err := CreateUnwrapDataCommand(1, nonce, make([]byte, 1+3085+16)); err == nil {
		t.Fatal("oversized UNWRAP request was accepted")
	}
}
