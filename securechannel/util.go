package securechannel

import (
	"crypto/aes"
	"errors"
)

var errInvalidPadding = errors.New("invalid SCP03 padding")

// pad applies ISO/IEC 7816-4 padding as required by SCP03. Padding is always
// added, including a full block when src is already block-aligned.
func pad(src []byte) []byte {
	paddingLength := aes.BlockSize - len(src)%aes.BlockSize
	padded := make([]byte, len(src)+paddingLength)
	copy(padded, src)
	padded[len(src)] = 0x80
	return padded
}

// unpad validates and removes ISO/IEC 7816-4 padding. It rejects empty,
// non-block-aligned, and malformed input rather than slicing or accepting it.
func unpad(src []byte) ([]byte, error) {
	if len(src) == 0 || len(src)%aes.BlockSize != 0 {
		return nil, errInvalidPadding
	}

	marker := len(src) - 1
	minimumMarker := len(src) - aes.BlockSize
	for marker >= minimumMarker && src[marker] == 0x00 {
		marker--
	}
	if marker < minimumMarker || src[marker] != 0x80 {
		return nil, errInvalidPadding
	}

	return src[:marker], nil
}
