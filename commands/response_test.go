package commands

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
)

const maxConnectorFrameLengthForTest = 3 + 1 + MaxSessionMessageDataLength + SessionMACLength

func responseFrame(command CommandType, payload []byte) []byte {
	data := make([]byte, 3+len(payload))
	data[0] = byte(uint16(command) + ResponseCommandOffset)
	data[1] = byte(len(payload) >> 8)
	data[2] = byte(len(payload))
	copy(data[3:], payload)
	return data
}

func parseWithoutPanic(data []byte) (resp Response, panicValue interface{}, err error) {
	defer func() {
		panicValue = recover()
	}()
	resp, err = ParseResponse(data)
	return resp, nil, err
}

func TestParseResponseTruncatedDoesNotPanic(t *testing.T) {
	cases := []struct {
		name    string
		command CommandType
		payload []byte
	}{
		{"session-message empty payload", CommandTypeSessionMessage, nil},
		{"session-message 8-byte payload", CommandTypeSessionMessage, make([]byte, 8)},
		{"device-info short payload", CommandTypeDeviceInfo, make([]byte, 4)},
		{"generate-asymmetric short payload", CommandTypeGenerateAsymmetricKey, []byte{0x01}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, panicValue, err := parseWithoutPanic(responseFrame(tc.command, tc.payload))
			if panicValue != nil {
				t.Fatalf("ParseResponse panicked: %v", panicValue)
			}
			if err == nil {
				t.Fatalf("expected an error for a truncated payload, got resp=%v", resp)
			}
		})
	}
}

func TestParseResponseNeverPanicsForDeclaredPayload(t *testing.T) {
	for rawType := 0; rawType <= 0xff; rawType++ {
		for payloadLength := 0; payloadLength <= 96; payloadLength++ {
			data := make([]byte, 3+payloadLength)
			data[0] = byte(rawType)
			data[1] = byte(payloadLength >> 8)
			data[2] = byte(payloadLength)

			_, panicValue, _ := parseWithoutPanic(data)
			if panicValue != nil {
				t.Fatalf("ParseResponse panicked for type=0x%02x length=%d: %v", rawType, payloadLength, panicValue)
			}
		}
	}
}

func TestParseResponseHSMMessageSizeLimits(t *testing.T) {
	if _, err := ParseResponse(responseFrame(CommandTypeEcho, make([]byte, MaxMessageLength-3))); err != nil {
		t.Fatalf("maximum plaintext response was rejected: %v", err)
	}
	if _, err := ParseResponse(responseFrame(CommandTypeEcho, make([]byte, MaxMessageLength-3+1))); err == nil {
		t.Fatal("oversized plaintext response was accepted")
	}

	maximumSessionPayload := make([]byte, 1+MaxSessionMessageDataLength+SessionMACLength)
	if _, err := ParseResponse(responseFrame(CommandTypeSessionMessage, maximumSessionPayload)); err != nil {
		t.Fatalf("maximum session response was rejected: %v", err)
	}
	if _, err := ParseResponse(responseFrame(CommandTypeSessionMessage, append(maximumSessionPayload, 0))); err == nil {
		t.Fatal("oversized session response was accepted")
	}
}

func TestParseResponseRandomInputDoesNotPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		data := make([]byte, rng.Intn(maxConnectorFrameLengthForTest+1))
		if _, err := rng.Read(data); err != nil {
			t.Fatal(err)
		}
		_, panicValue, _ := parseWithoutPanic(data)
		if panicValue != nil {
			t.Fatalf("ParseResponse panicked for %x: %v", data, panicValue)
		}
	}
}

func TestParseResponseOwnsPayloadMemory(t *testing.T) {
	frame := responseFrame(CommandTypeEcho, []byte("echo"))
	resp, err := ParseResponse(frame)
	if err != nil {
		t.Fatal(err)
	}
	echo := resp.(*EchoResponse)
	for i := range frame {
		frame[i] = 0
	}
	if string(echo.Data) != "echo" {
		t.Fatal("parsed response retained the caller's input buffer")
	}
}

func TestParseResponseCommandCodeValidation(t *testing.T) {
	if _, err := ParseResponse([]byte{byte(CommandTypeEcho), 0x00, 0x00}); err == nil {
		t.Fatal("request command code was accepted as a response")
	}

	resp, err := ParseResponse([]byte{0x7f, 0x00, 0x01, byte(ErrorCodeInvalidCommand)})
	if resp != nil {
		t.Fatalf("error response returned resp=%v", resp)
	}
	var cardErr *Error
	if !errors.As(err, &cardErr) || cardErr.Code != ErrorCodeInvalidCommand {
		t.Fatalf("error = %#v", err)
	}
}

func TestErrorFormatting(t *testing.T) {
	if got := (&Error{Code: ErrorCodeAlgorithmDisabled}).Error(); got != "card responded with error: Algorithm disabled" {
		t.Fatalf("algorithm-disabled error = %q", got)
	}
	if got := (&Error{Code: ErrorCode(0x13)}).Error(); got != "card responded with error: Unknown (0x13)" {
		t.Fatalf("unknown error = %q", got)
	}
}

func TestParseSessionIDValidation(t *testing.T) {
	createPayload := make([]byte, 17)
	createPayload[0] = MaxSessionID + 1
	if _, err := ParseResponse(responseFrame(CommandTypeCreateSession, createPayload)); err == nil {
		t.Fatal("invalid create-session ID was accepted")
	}

	sessionPayload := make([]byte, 9)
	sessionPayload[0] = MaxSessionID + 1
	if _, err := ParseResponse(responseFrame(CommandTypeSessionMessage, sessionPayload)); err == nil {
		t.Fatal("invalid session-message ID was accepted")
	}
}

func TestParseCreateAsymmetricKeyResponse(t *testing.T) {
	resp, err := ParseResponse(responseFrame(CommandTypeGenerateAsymmetricKey, []byte{0x12, 0x34}))
	if err != nil {
		t.Fatal(err)
	}
	key, ok := resp.(*CreateAsymmetricKeyResponse)
	if !ok {
		t.Fatalf("response type = %T", resp)
	}
	if key.KeyID != 0x1234 {
		t.Fatalf("key ID = 0x%04x, want 0x1234", key.KeyID)
	}
}

func TestParseEdDSASignatureLength(t *testing.T) {
	if _, err := ParseResponse(responseFrame(CommandTypeSignDataEddsa, make([]byte, 64))); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponse(responseFrame(CommandTypeSignDataEddsa, make([]byte, 63))); err == nil {
		t.Fatal("short Ed25519 signature was accepted")
	}
}

func TestParseGenerateWrapKeyResponse(t *testing.T) {
	resp, err := ParseResponse(responseFrame(CommandTypeGenerateWrapKey, []byte{0xab, 0xcd}))
	if err != nil {
		t.Fatal(err)
	}
	key, ok := resp.(*GenerateWrapKeyResponse)
	if !ok {
		t.Fatalf("response type = %T", resp)
	}
	if key.KeyID != 0xabcd {
		t.Fatalf("key ID = 0x%04x, want 0xabcd", key.KeyID)
	}
}

func TestParseGetOpaqueResponseAllowsEmptyData(t *testing.T) {
	resp, err := ParseResponse(responseFrame(CommandTypeGetOpaque, nil))
	if err != nil {
		t.Fatal(err)
	}
	opaque, ok := resp.(*GetOpaqueResponse)
	if !ok || len(opaque.Data) != 0 {
		t.Fatalf("opaque response = %#v", resp)
	}
}

func TestParseExportWrappedResponseRequiresCompleteOverhead(t *testing.T) {
	payload := make([]byte, WrapNonceLength+WrapIdentifierLength+WrapMACLength)
	if _, err := ParseResponse(responseFrame(CommandTypeExportWrapped, payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseResponse(responseFrame(CommandTypeExportWrapped, payload[:len(payload)-1])); err == nil {
		t.Fatal("expected an error for an export response without complete wrap overhead")
	}
}

func TestParseWrapDataResponse(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x11}, WrapNonceLength)
	wrappedData := bytes.Repeat([]byte{0x22}, WrapDataPrefixLength+WrapMACLength)
	payload := append(append([]byte(nil), nonce...), wrappedData...)

	resp, err := ParseResponse(responseFrame(CommandTypeWrapData, payload))
	if err != nil {
		t.Fatal(err)
	}
	wrapped, ok := resp.(*WrapDataResponse)
	if !ok {
		t.Fatalf("response type = %T", resp)
	}
	if !bytes.Equal(wrapped.Nonce, nonce) || !bytes.Equal(wrapped.Data, wrappedData) {
		t.Fatalf("unexpected wrapped response: %#v", wrapped)
	}

	_, err = ParseResponse(responseFrame(CommandTypeWrapData, payload[:len(payload)-1]))
	if err == nil {
		t.Fatal("expected an error for a wrap response without the complete MAC")
	}
}

func TestParseUnwrapDataAllowsEmptyPlaintext(t *testing.T) {
	resp, err := ParseResponse(responseFrame(CommandTypeUnwrapData, nil))
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, ok := resp.(*UnwrapDataResponse)
	if !ok {
		t.Fatalf("response type = %T", resp)
	}
	if len(unwrapped.Data) != 0 {
		t.Fatalf("unwrapped data length = %d, want 0", len(unwrapped.Data))
	}
}

func TestEmptyResponseCommandsRejectPayload(t *testing.T) {
	commands := []CommandType{
		CommandTypeAuthenticateSession,
		CommandTypeCloseSession,
		CommandTypeDeleteObject,
		CommandTypeReset,
	}
	for _, command := range commands {
		if _, err := ParseResponse(responseFrame(command, []byte{0x00})); err == nil {
			t.Errorf("command 0x%02x accepted a non-empty response", command)
		}
		if _, err := ParseResponse(responseFrame(command, nil)); err != nil {
			t.Errorf("command 0x%02x rejected an empty response: %v", command, err)
		}
	}
}
