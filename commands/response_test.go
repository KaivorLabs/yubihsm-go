package commands

import "testing"

// Truncated SessionMessage / DeviceInfo responses must return an error, not
// panic with an out-of-range slice. The payload reaching these parsers is not
// yet MAC-verified, so a malformed or hostile connector response must fail
// closed.
func TestParseResponse_TruncatedDoesNotPanic(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"session-message empty payload", []byte{byte(CommandTypeSessionMessage), 0x00, 0x00}},
		{"session-message 8-byte payload", append([]byte{byte(CommandTypeSessionMessage), 0x00, 0x08}, make([]byte, 8)...)},
		{"device-info short payload", append([]byte{byte(CommandTypeDeviceInfo), 0x00, 0x04}, make([]byte, 4)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := ParseResponse(tc.data)
			if err == nil {
				t.Fatalf("expected an error for a truncated payload, got resp=%v", resp)
			}
		})
	}
}
