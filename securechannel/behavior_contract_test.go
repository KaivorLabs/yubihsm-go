package securechannel

import (
	"bytes"
	"testing"

	"github.com/certusone/yubihsm-go/authkey"
)

func TestAuthenticationKeyOwnershipContract(t *testing.T) {
	// Public test-only credential. Do not substitute any production key here.
	const password = "public key ownership test credential"
	callerKey := authkey.NewFromPassword(password)
	original := append([]byte(nil), callerKey...)
	channel, err := NewSecureChannelWithAuthKey(&emulatedHSMConnector{password: password}, 1, callerKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := channel.Close(); err != nil {
			t.Error(err)
		}
	})
	ownedKey := channel.AuthKey
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	if channel.AuthKey != nil || !bytes.Equal(ownedKey, make([]byte, len(original))) {
		t.Fatal("authentication did not clear the channel-owned backing array")
	}
	if !bytes.Equal(callerKey, original) {
		t.Fatal("authentication modified the caller-owned key")
	}
	if err := channel.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(callerKey, original) {
		t.Fatal("Close modified the caller-owned key")
	}
}
