package securechannel

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestPadAndUnpad(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("a"),
		bytes.Repeat([]byte{0x42}, aes.BlockSize-1),
		bytes.Repeat([]byte{0x42}, aes.BlockSize),
		bytes.Repeat([]byte{0x42}, aes.BlockSize+1),
	}

	for _, input := range cases {
		padded := pad(input)
		if len(padded)%aes.BlockSize != 0 {
			t.Fatalf("padded length %d is not block aligned", len(padded))
		}
		if len(padded) <= len(input) {
			t.Fatalf("padding was not added for input length %d", len(input))
		}
		output, err := unpad(padded)
		if err != nil {
			t.Fatalf("unpad(%x): %v", padded, err)
		}
		if !bytes.Equal(output, input) {
			t.Fatalf("round trip = %x, want %x", output, input)
		}
	}
}

func TestUnpadRejectsMalformedInput(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, aes.BlockSize-1),
		make([]byte, aes.BlockSize),
		bytes.Repeat([]byte{0x01}, aes.BlockSize),
		append([]byte{0x80}, make([]byte, 2*aes.BlockSize-1)...),
	}
	for _, input := range cases {
		if _, err := unpad(input); err == nil {
			t.Fatalf("unpad accepted malformed input %x", input)
		}
	}
}
