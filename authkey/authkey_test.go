package authkey

import (
	"encoding/hex"
	"testing"
)

func TestNewFromPasswordKnownAnswer(t *testing.T) {
	// This is a public, non-secret known-answer vector. A fixed expected value
	// is intentional: it detects accidental changes to the YubiHSM PBKDF2 salt,
	// iteration count, hash function, or output length.
	const (
		testPassword = "yubihsm-go public test vector"
		wantHex      = "d5c788d3642473654ae1436c247afbc3cd7050e8096d7c633c0605281cf103bb"
	)

	key := NewFromPassword(testPassword)
	if got := hex.EncodeToString(key); got != wantHex {
		t.Fatalf("derived key = %s, want %s", got, wantHex)
	}
	if len(key.GetEncKey()) != AuthKeyLength/2 || len(key.GetMacKey()) != AuthKeyLength/2 {
		t.Fatal("derived key was not split into two 16-byte keys")
	}
}

func TestInvalidAuthKeyDoesNotPanic(t *testing.T) {
	key := AuthKey([]byte{1, 2, 3})
	if key.GetEncKey() != nil || key.GetMacKey() != nil {
		t.Fatal("invalid AuthKey returned key material")
	}
}
