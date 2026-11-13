package authkey

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

type (
	// AuthKey is a key to authenticate with the HSM
	AuthKey []byte
)

const (
	// AuthKeyLength is the required length of a YubiHSM authentication key.
	AuthKeyLength     = 32
	authKeyIterations = 10000
	yubicoSeed        = "Yubico"
)

// NewFromPassword derives an AuthKey using PBKDF2 as specified in the HSM documentation.
func NewFromPassword(password string) AuthKey {
	passwordBytes := []byte(password)
	defer func() {
		for i := range passwordBytes {
			passwordBytes[i] = 0
		}
	}()
	return pbkdf2.Key(passwordBytes, []byte(yubicoSeed), authKeyIterations, AuthKeyLength, sha256.New)
}

// GetEncKey returns the EncryptionKey part of the AuthKey
func (k AuthKey) GetEncKey() []byte {
	if len(k) != AuthKeyLength {
		return nil
	}
	return k[:AuthKeyLength/2]
}

// GetMacKey returns the MACKey part of the AuthKey.
func (k AuthKey) GetMacKey() []byte {
	if len(k) != AuthKeyLength {
		return nil
	}
	return k[AuthKeyLength/2 : AuthKeyLength]
}
