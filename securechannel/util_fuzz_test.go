//go:build go1.18
// +build go1.18

package securechannel

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func FuzzUnpad(f *testing.F) {
	f.Add(pad(nil))
	f.Add(pad([]byte("test\x80\x00")))
	f.Add(append([]byte{0x80}, make([]byte, 31)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		body, err := unpad(data)
		if err != nil {
			return
		}
		paddingLength := len(data) - len(body)
		if paddingLength < 1 || paddingLength > aes.BlockSize || len(data)%aes.BlockSize != 0 {
			t.Fatal("accepted an invalid padding length")
		}
		if !bytes.Equal(pad(body), data) {
			t.Fatal("accepted noncanonical SCP03 padding")
		}
	})
}
