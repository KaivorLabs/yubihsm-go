package securechannel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

type testConnector struct{}

func (testConnector) Request(*commands.CommandMessage) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (testConnector) GetStatus() (*connector.StatusResponse, error) {
	return nil, errors.New("not implemented")
}

type mutatingConnector struct{}

func (mutatingConnector) Request(command *commands.CommandMessage) ([]byte, error) {
	*command.SessionID ^= 0xff
	for i := range command.MAC {
		command.MAC[i] ^= 0xff
	}
	return nil, errors.New("mutated command")
}

func (mutatingConnector) GetStatus() (*connector.StatusResponse, error) {
	return nil, errors.New("not implemented")
}

type emulatedHSMConnector struct {
	password                string
	channel                 *SecureChannel
	authenticated           bool
	corruptResponseMAC      bool
	wrongResponseID         bool
	invalidResponsePadding  bool
	invalidCiphertextLength bool
	malformedInnerResponse  bool
	unrelatedInnerResponse  bool
	closeRejected           bool
	innerResponseOverride   func(commands.CommandType, []byte) []byte
}

func responseFrame(command commands.CommandType, payload []byte) []byte {
	frame := make([]byte, 3+len(payload))
	frame[0] = byte(command + commands.ResponseCommandOffset)
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(payload)))
	copy(frame[3:], payload)
	return frame
}

func (h *emulatedHSMConnector) Request(command *commands.CommandMessage) ([]byte, error) {
	switch command.CommandType {
	case commands.CommandTypeCreateSession:
		if len(command.Data) != 2+ChallengeLength {
			return nil, errors.New("invalid create-session command")
		}
		h.channel = &SecureChannel{
			AuthKey:         authkey.NewFromPassword(h.password),
			HostChallenge:   append([]byte(nil), command.Data[2:]...),
			DeviceChallenge: []byte{0, 1, 2, 3, 4, 5, 6, 7},
			ID:              3,
			Counter:         1,
			MACChainValue:   make([]byte, aes.BlockSize),
		}
		if err := h.channel.updateKeychain(); err != nil {
			return nil, err
		}
		cardCryptogram, err := h.channel.deriveKDF(h.channel.keyChain.MACKey, DerivationConstantDeviceCryptogram, CryptogramLength)
		if err != nil {
			return nil, err
		}
		payload := []byte{h.channel.ID}
		payload = append(payload, h.channel.DeviceChallenge...)
		payload = append(payload, cardCryptogram...)
		return responseFrame(commands.CommandTypeCreateSession, payload), nil

	case commands.CommandTypeAuthenticateSession:
		if h.channel == nil || command.SessionID == nil || *command.SessionID != h.channel.ID {
			return nil, errors.New("invalid authenticate-session state")
		}
		hostCryptogram, err := h.channel.deriveKDF(h.channel.keyChain.MACKey, DerivationConstantHostCryptogram, CryptogramLength)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(command.Data, hostCryptogram) {
			return nil, errors.New("invalid host cryptogram")
		}
		expectedMAC, err := h.channel.calculateMAC(command, MessageTypeCommand)
		if err != nil {
			return nil, err
		}
		if len(command.MAC) != MACLength || !bytes.Equal(command.MAC, expectedMAC[:MACLength]) {
			return nil, errors.New("invalid authenticate-session MAC")
		}
		h.channel.MACChainValue = append(h.channel.MACChainValue[:0], expectedMAC...)
		h.authenticated = true
		return responseFrame(commands.CommandTypeAuthenticateSession, nil), nil

	case commands.CommandTypeSessionMessage:
		return h.handleSessionMessage(command)
	default:
		return nil, errors.New("unsupported command")
	}
}

func (h *emulatedHSMConnector) handleSessionMessage(command *commands.CommandMessage) ([]byte, error) {
	if !h.authenticated || command.SessionID == nil || *command.SessionID != h.channel.ID {
		return nil, errors.New("invalid session-message state")
	}
	expectedMAC, err := h.channel.calculateMAC(command, MessageTypeCommand)
	if err != nil {
		return nil, err
	}
	if len(command.MAC) != MACLength || !bytes.Equal(command.MAC, expectedMAC[:MACLength]) {
		return nil, errors.New("invalid session-message MAC")
	}
	h.channel.MACChainValue = append(h.channel.MACChainValue[:0], expectedMAC...)

	block, err := aes.NewCipher(h.channel.keyChain.EncKey)
	if err != nil {
		return nil, err
	}
	icv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(icv[12:], h.channel.Counter)
	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, icv)
	if len(command.Data) == 0 || len(command.Data)%aes.BlockSize != 0 {
		return nil, errors.New("invalid encrypted command length")
	}
	plaintext := make([]byte, len(command.Data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, command.Data)
	plaintext, err = unpad(plaintext)
	if err != nil {
		return nil, err
	}
	if len(plaintext) < 3 || int(binary.BigEndian.Uint16(plaintext[1:3])) != len(plaintext)-3 {
		return nil, errors.New("invalid inner command")
	}

	innerCommand := commands.CommandType(plaintext[0])
	var innerResponse []byte
	switch innerCommand {
	case commands.CommandTypeEcho:
		innerResponse = responseFrame(innerCommand, plaintext[3:])
	case commands.CommandTypeCloseSession, commands.CommandTypeReset:
		innerResponse = responseFrame(innerCommand, nil)
		if h.closeRejected {
			innerResponse = []byte{0x7f, 0, 1, byte(commands.ErrorCodeInvalidPermission)}
		}
	case commands.CommandTypeStorageStatus:
		innerResponse = responseFrame(innerCommand, make([]byte, 10))
	case commands.CommandTypeGetObjectInfo:
		if len(plaintext) != 6 {
			return nil, errors.New("invalid object-info request in emulator")
		}
		payload := make([]byte, 66)
		copy(payload[8:10], plaintext[3:5])
		payload[14] = plaintext[5]
		innerResponse = responseFrame(innerCommand, payload)
	case commands.CommandTypeWrapData:
		if len(plaintext) < 5 {
			return nil, errors.New("invalid wrap request in emulator")
		}
		// Only response shape is simulated, not AES-CCM or key generation.
		innerResponse = responseFrame(innerCommand, make([]byte, len(plaintext)-5+30))
	case commands.CommandTypeUnwrapData:
		if len(plaintext) < 35 {
			return nil, errors.New("invalid unwrap request in emulator")
		}
		innerResponse = responseFrame(innerCommand, make([]byte, len(plaintext)-35))
	case commands.CommandTypeGetPseudoRandom:
		if len(plaintext) != 5 {
			return nil, errors.New("invalid random request in emulator")
		}
		innerResponse = responseFrame(innerCommand, make([]byte, int(binary.BigEndian.Uint16(plaintext[3:]))))
	case commands.CommandTypeGenerateWrapKey:
		id := binary.BigEndian.Uint16(plaintext[3:5])
		if id == 0 {
			id = 0x4321 // Emulate device-assigned IDs, not an ID echo for zero.
		}
		payload := make([]byte, 2)
		binary.BigEndian.PutUint16(payload, id)
		innerResponse = responseFrame(innerCommand, payload)
	case commands.CommandTypeGetOpaque:
		innerResponse = []byte{0x7f, 0, 1, byte(commands.ErrorCodeObjectNotFound)}
	default:
		return nil, errors.New("unsupported inner command")
	}
	if h.innerResponseOverride != nil {
		innerResponse = h.innerResponseOverride(innerCommand, innerResponse)
	}
	if h.unrelatedInnerResponse {
		innerResponse = responseFrame(commands.CommandTypeCloseSession, nil)
		h.unrelatedInnerResponse = false
	}
	if h.malformedInnerResponse {
		innerResponse[2]++
		h.malformedInnerResponse = false
	}
	paddedResponse := pad(innerResponse)
	if h.invalidResponsePadding {
		paddedResponse[len(paddedResponse)-1] = 0x01
		h.invalidResponsePadding = false
	}
	encryptedResponse := make([]byte, len(paddedResponse))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encryptedResponse, paddedResponse)
	if h.invalidCiphertextLength {
		encryptedResponse = encryptedResponse[:len(encryptedResponse)-1]
		h.invalidCiphertextLength = false
	}

	responseID := h.channel.ID
	if h.wrongResponseID {
		responseID = (responseID + 1) % (commands.MaxSessionID + 1)
		h.wrongResponseID = false
	}
	responseMAC, err := h.channel.calculateMAC(&commands.CommandMessage{
		CommandType: commands.CommandTypeSessionMessage + commands.ResponseCommandOffset,
		SessionID:   &responseID,
		Data:        encryptedResponse,
	}, MessageTypeResponse)
	if err != nil {
		return nil, err
	}
	responseMACTag := append([]byte(nil), responseMAC[:MACLength]...)
	if h.corruptResponseMAC {
		responseMACTag[0] ^= 0xff
		h.corruptResponseMAC = false
	}
	outerPayload := []byte{responseID}
	outerPayload = append(outerPayload, encryptedResponse...)
	outerPayload = append(outerPayload, responseMACTag...)
	h.channel.Counter++
	if !h.closeRejected && (innerCommand == commands.CommandTypeCloseSession || innerCommand == commands.CommandTypeReset) {
		h.authenticated = false
	}
	return responseFrame(commands.CommandTypeSessionMessage, outerPayload), nil
}

func (h *emulatedHSMConnector) GetStatus() (*connector.StatusResponse, error) {
	return nil, errors.New("not implemented")
}

func TestSecureChannelEndToEnd(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	if !channel.IsHealthy() {
		t.Fatal("authenticated channel was not healthy")
	}
	if channel.AuthKey != nil {
		t.Fatal("authenticated channel retained its long-term authentication key")
	}
	if _, err := channel.SendEncryptedCommand(&commands.CommandMessage{
		CommandType: commands.CommandTypeEcho,
		Data:        make([]byte, commands.MaxCommandDataLength+1),
	}); err == nil {
		t.Fatal("oversized command was accepted")
	}
	if !channel.IsHealthy() || channel.MessageCount() != 1 {
		t.Fatal("local command validation changed the session state")
	}
	sessionID := uint8(1)
	if _, err := channel.SendEncryptedCommand(&commands.CommandMessage{
		CommandType: commands.CommandTypeEcho,
		SessionID:   &sessionID,
		MAC:         make([]byte, commands.SessionMACLength),
	}); err == nil {
		t.Fatal("nested session framing was accepted as an inner command")
	}
	if !channel.IsHealthy() || channel.MessageCount() != 1 {
		t.Fatal("nested framing validation changed the session state")
	}

	command, err := commands.CreateEchoCommand([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := channel.SendEncryptedCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := resp.(*commands.EchoResponse)
	if !ok || !bytes.Equal(echo.Data, []byte("hello")) {
		t.Fatalf("echo response = %#v", resp)
	}
	if channel.MessageCount() != 2 {
		t.Fatalf("message count = %d, want 2", channel.MessageCount())
	}

	missing, err := commands.CreateGetOpaqueCommand(0xffff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendEncryptedCommand(missing); err == nil {
		t.Fatal("expected card error")
	} else {
		var cardErr *commands.Error
		if !errors.As(err, &cardErr) || cardErr.Code != commands.ErrorCodeObjectNotFound {
			t.Fatalf("card error = %#v", err)
		}
	}
	if !channel.IsHealthy() || channel.MessageCount() != 3 {
		t.Fatal("valid card error desynchronized the secure channel")
	}

	if err := channel.Close(); err != nil {
		t.Fatal(err)
	}
	if channel.SecurityLevel != SecurityLevelClosed || channel.keyChain != nil {
		t.Fatal("Close did not finalize and clear the session")
	}
}

func TestSecureChannelMaximumMessageSize(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, commands.MaxCommandDataLength)
	for i := range data {
		data[i] = byte(i)
	}
	command, err := commands.CreateEchoCommand(data)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := channel.SendEncryptedCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := resp.(*commands.EchoResponse)
	if !ok || !bytes.Equal(echo.Data, data) {
		t.Fatal("maximum-sized echo response did not round-trip")
	}
}

func TestInvalidResponseMACInvalidatesChannel(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	hsm.corruptResponseMAC = true
	command, err := commands.CreateEchoCommand([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendEncryptedCommand(command); err == nil {
		t.Fatal("corrupt response MAC was accepted")
	}
	if channel.SecurityLevel != SecurityLevelInvalid || channel.keyChain != nil {
		t.Fatal("corrupt response MAC did not invalidate and clear the channel")
	}
}

func TestMalformedSecureResponsesInvalidateChannel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*emulatedHSMConnector)
	}{
		{"session ID", func(h *emulatedHSMConnector) { h.wrongResponseID = true }},
		{"padding", func(h *emulatedHSMConnector) { h.invalidResponsePadding = true }},
		{"ciphertext length", func(h *emulatedHSMConnector) { h.invalidCiphertextLength = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hsm := &emulatedHSMConnector{password: "password"}
			channel, err := NewSecureChannel(hsm, 1, "password")
			if err != nil {
				t.Fatal(err)
			}
			if err := channel.Authenticate(); err != nil {
				t.Fatal(err)
			}
			tc.configure(hsm)
			command, err := commands.CreateEchoCommand([]byte("hello"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := channel.SendEncryptedCommand(command); err == nil {
				t.Fatal("malformed secure response was accepted")
			}
			if channel.SecurityLevel != SecurityLevelInvalid || channel.keyChain != nil {
				t.Fatal("malformed secure response did not invalidate and clear the channel")
			}
		})
	}
}

func TestMalformedInnerFrameInvalidatesSession(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	command, err := commands.CreateEchoCommand([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	hsm.malformedInnerResponse = true
	if _, err := channel.SendEncryptedCommand(command); err == nil {
		t.Fatal("expected malformed inner response error")
	}
	if channel.IsHealthy() || channel.keyChain != nil {
		t.Fatal("malformed inner framing did not invalidate and clear the session")
	}
	if _, err := channel.SendEncryptedCommand(command); err == nil {
		t.Fatal("malformed session was reused")
	}
}

func TestNewSecureChannelValidationAndKeyCopy(t *testing.T) {
	if _, err := NewSecureChannel(nil, 1, "password"); err == nil {
		t.Fatal("nil connector was accepted")
	}
	if _, err := NewSecureChannelWithAuthKey(testConnector{}, 1, authkey.AuthKey{1}); err == nil {
		t.Fatal("invalid authentication key was accepted")
	}

	key := authkey.NewFromPassword("password")
	channel, err := NewSecureChannelWithAuthKey(testConnector{}, 1, key)
	if err != nil {
		t.Fatal(err)
	}
	original := channel.AuthKey[0]
	key[0] ^= 0xff
	if channel.AuthKey[0] != original {
		t.Fatal("secure channel retained the caller's authentication key slice")
	}
}

func TestAuthenticateFailureInvalidatesChannel(t *testing.T) {
	channel, err := NewSecureChannel(testConnector{}, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err == nil {
		t.Fatal("expected authentication failure")
	}
	if channel.SecurityLevel != SecurityLevelInvalid {
		t.Fatalf("security level = %d, want invalid", channel.SecurityLevel)
	}
	if channel.AuthKey != nil || channel.keyChain != nil {
		t.Fatal("authentication failure retained key material")
	}
}

func TestSecureChannelStateValidation(t *testing.T) {
	channel, err := NewSecureChannel(testConnector{}, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendEncryptedCommand(&commands.CommandMessage{}); err == nil {
		t.Fatal("unauthenticated encrypted command was accepted")
	}
	if err := channel.Close(); err != nil {
		t.Fatalf("closing an unauthenticated channel: %v", err)
	}
	if channel.SecurityLevel != SecurityLevelClosed {
		t.Fatalf("security level = %d, want closed", channel.SecurityLevel)
	}
	if channel.AuthKey != nil {
		t.Fatal("Close retained the authentication key")
	}
	if got := channel.MessageCount(); got != 0 {
		t.Fatalf("message count = %d, want 0", got)
	}
}

func TestConnectorCannotMutateChannelMACState(t *testing.T) {
	channel := &SecureChannel{
		connector:     mutatingConnector{},
		keyChain:      &KeyChain{EncKey: make([]byte, KeyLength), MACKey: make([]byte, KeyLength), RMACKey: make([]byte, KeyLength)},
		ID:            3,
		MACChainValue: make([]byte, aes.BlockSize),
	}
	command := &commands.CommandMessage{CommandType: commands.CommandTypeAuthenticateSession, Data: make([]byte, 8)}
	if _, err := channel.sendMACCommand(command); err == nil {
		t.Fatal("expected connector error")
	}
	if channel.ID != 3 {
		t.Fatalf("connector changed channel session ID to %d", channel.ID)
	}
	if bytes.Equal(channel.MACChainValue[:MACLength], command.MAC) {
		t.Fatal("connector mutation changed the MAC chain value")
	}
}

func TestTransportFailureInvalidatesSession(t *testing.T) {
	channel := &SecureChannel{
		connector:     testConnector{},
		keyChain:      &KeyChain{EncKey: make([]byte, KeyLength), MACKey: make([]byte, KeyLength), RMACKey: make([]byte, KeyLength)},
		ID:            1,
		Counter:       1,
		SecurityLevel: SecurityLevelAuthenticated,
		MACChainValue: make([]byte, aes.BlockSize),
	}

	if _, err := channel.SendEncryptedCommand(&commands.CommandMessage{CommandType: commands.CommandTypeEcho}); err == nil {
		t.Fatal("expected connector failure")
	}
	if channel.IsHealthy() {
		t.Fatal("channel remained healthy after an uncertain transport failure")
	}
	if channel.SecurityLevel != SecurityLevelInvalid {
		t.Fatalf("security level = %d, want invalid", channel.SecurityLevel)
	}
	if channel.keyChain != nil || channel.MACChainValue != nil {
		t.Fatal("invalidated channel retained session key material")
	}
}

func TestCalculateMACKnownAnswer(t *testing.T) {
	sessionID := uint8(3)
	channel := &SecureChannel{
		keyChain: &KeyChain{
			MACKey:  make([]byte, KeyLength),
			RMACKey: make([]byte, KeyLength),
		},
		MACChainValue: make([]byte, aes.BlockSize),
	}
	command := &commands.CommandMessage{
		CommandType: commands.CommandTypeEcho,
		SessionID:   &sessionID,
		Data:        []byte{0xaa, 0xbb},
	}

	commandMAC, err := channel.calculateMAC(command, MessageTypeCommand)
	if err != nil {
		t.Fatal(err)
	}
	wantCommand := []byte{0x92, 0xe4, 0x62, 0x0f, 0x60, 0xd4, 0x02, 0x81, 0x66, 0x28, 0x49, 0x03, 0x72, 0xdd, 0x36, 0xac}
	if !bytes.Equal(commandMAC, wantCommand) {
		t.Fatalf("command MAC = %x, want %x", commandMAC, wantCommand)
	}

	command.CommandType += commands.ResponseCommandOffset
	responseMAC, err := channel.calculateMAC(command, MessageTypeResponse)
	if err != nil {
		t.Fatal(err)
	}
	wantResponse := []byte{0x4a, 0x91, 0xd3, 0x90, 0x8d, 0x6c, 0x33, 0x96, 0x87, 0x93, 0x86, 0x81, 0x59, 0x77, 0x40, 0x8f}
	if !bytes.Equal(responseMAC, wantResponse) {
		t.Fatalf("response MAC = %x, want %x", responseMAC, wantResponse)
	}
}

func TestDeriveKDFValidation(t *testing.T) {
	channel := &SecureChannel{
		HostChallenge:   make([]byte, ChallengeLength),
		DeviceChallenge: make([]byte, ChallengeLength),
	}
	key := make([]byte, KeyLength)
	derived, err := channel.deriveKDF(key, DerivationConstantEncKey, KeyLength)
	if err != nil {
		t.Fatal(err)
	}
	if len(derived) != KeyLength {
		t.Fatalf("derived key length = %d", len(derived))
	}
	// Public known-answer vector independently generated with AES-CMAC.
	want := []byte{0xd1, 0x19, 0xa7, 0xcc, 0xa7, 0x5f, 0x05, 0x0b, 0x4f, 0x30, 0x6c, 0x8e, 0x1e, 0x5c, 0xc5, 0x54}
	if !bytes.Equal(derived, want) {
		t.Fatalf("derived key = %x, want %x", derived, want)
	}

	if _, err := channel.deriveKDF(key[:len(key)-1], DerivationConstantEncKey, KeyLength); err == nil {
		t.Fatal("short derivation key was accepted")
	}
	if _, err := channel.deriveKDF(key, DerivationConstantEncKey, 0); err == nil {
		t.Fatal("zero derived key length was accepted")
	}
}
