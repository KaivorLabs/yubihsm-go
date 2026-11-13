//go:build go1.18
// +build go1.18

package commands

import (
	"encoding/binary"
	"testing"
)

func FuzzParseResponse(f *testing.F) {
	f.Add([]byte{0x81, 0, 0})
	f.Add([]byte{0x7f, 0, 1, 0x0b})
	f.Add([]byte{0x85, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xc6, 0, 2, 0x12, 0x34})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseResponse(data)
	})
}

func FuzzParseResponseDeclaredPayload(f *testing.F) {
	f.Add(byte(0xc6), []byte{0x12, 0x34})
	f.Add(byte(0x83), make([]byte, 17))
	f.Add(byte(0x85), make([]byte, 25))
	f.Add(byte(0xce), make([]byte, 66))
	f.Fuzz(func(t *testing.T, responseType byte, payload []byte) {
		if len(payload) > MaxMessageLength {
			return
		}
		frame := make([]byte, 3+len(payload))
		frame[0] = responseType
		binary.BigEndian.PutUint16(frame[1:3], uint16(len(payload)))
		copy(frame[3:], payload)
		_, _ = ParseResponse(frame)
	})
}
