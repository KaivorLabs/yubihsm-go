package securechannel

import (
	"errors"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

func newResponseContractChannel(t *testing.T) (*SecureChannel, *emulatedHSMConnector) {
	t.Helper()
	const password = "public response contract test credential"
	hsm := &emulatedHSMConnector{password: password}
	channel, err := NewSecureChannel(hsm, 1, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := channel.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	return channel, hsm
}

func TestPlainEchoRejectsDifferentPayload(t *testing.T) {
	wire := &transcriptConnector{steps: []transcriptStep{{Request: "010001aa", Response: "810001bb"}}}
	channel, err := NewSecureChannel(wire, 1, "public plaintext test credential")
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	if _, err := channel.SendCommand(&commands.CommandMessage{CommandType: commands.CommandTypeEcho, Data: []byte{0xaa}}); err == nil {
		t.Fatal("different echo payload was accepted as success")
	}
}

func TestEncryptedResponsesMustMatchRequestParameters(t *testing.T) {
	objectInfo := func(idLow, kind byte) []byte {
		// Literal layout from GET OBJECT INFO: capabilities[8], ID[2],
		// length[2], domains[2], type[1], then remaining metadata.
		payload := make([]byte, 66)
		payload[8], payload[9], payload[14] = 0x12, idLow, kind
		return payload
	}
	for _, tc := range []struct {
		name  string
		build func() (*commands.CommandMessage, error)
		reply []byte
	}{
		{"echo contents", func() (*commands.CommandMessage, error) { return commands.CreateEchoCommand([]byte("abc")) }, []byte("abd")},
		{"short random", func() (*commands.CommandMessage, error) { return commands.CreateGetPseudoRandomCommand(32), nil }, make([]byte, 31)},
		{"long random", func() (*commands.CommandMessage, error) { return commands.CreateGetPseudoRandomCommand(32), nil }, make([]byte, 33)},
		{"explicit key ID", func() (*commands.CommandMessage, error) {
			return commands.CreateGenerateWrapKeyCommand(0x1234, nil, commands.Domain1, 0, commands.AlgorithmAES128CCMWrap, 0)
		}, []byte{0x12, 0x35}},
		{"metadata ID", func() (*commands.CommandMessage, error) {
			return commands.CreateGetObjectInfoCommand(0x1234, commands.ObjectTypeAsymmetricKey)
		}, objectInfo(0x35, 3)},
		{"metadata type", func() (*commands.CommandMessage, error) {
			return commands.CreateGetObjectInfoCommand(0x1234, commands.ObjectTypeAsymmetricKey)
		}, objectInfo(0x34, 1)},
		{"short wrap", func() (*commands.CommandMessage, error) { return commands.CreateWrapDataCommand(1, []byte("abc")) }, make([]byte, 32)},
		{"long wrap", func() (*commands.CommandMessage, error) { return commands.CreateWrapDataCommand(1, []byte("abc")) }, make([]byte, 34)},
		{"short unwrap", func() (*commands.CommandMessage, error) {
			return commands.CreateUnwrapDataCommand(1, make([]byte, 13), make([]byte, 20))
		}, make([]byte, 2)},
		{"long unwrap", func() (*commands.CommandMessage, error) {
			return commands.CreateUnwrapDataCommand(1, make([]byte, 13), make([]byte, 20))
		}, make([]byte, 4)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			channel, hsm := newResponseContractChannel(t)
			hsm.innerResponseOverride = func(command commands.CommandType, original []byte) []byte {
				if command == commands.CommandTypeCloseSession {
					return original
				}
				return responseFrame(command, tc.reply) // Valid framing, RMAC and padding, wrong parameters.
			}
			command, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := channel.SendEncryptedCommand(command); err == nil {
				t.Fatal("mismatched successful response parameters were accepted")
			}
			if channel.IsHealthy() || channel.keyChain != nil {
				t.Fatal("inconsistent success left the channel reusable")
			}
		})
	}
}

func TestExplicitObjectIDResponseContracts(t *testing.T) {
	const requestedID = 0x1234
	for _, build := range []func() (*commands.CommandMessage, error){
		func() (*commands.CommandMessage, error) {
			return commands.CreateGenerateAsymmetricKeyCommand(requestedID, nil, commands.Domain1, 0, commands.AlgorithmED25519)
		},
		func() (*commands.CommandMessage, error) {
			return commands.CreatePutAsymmetricKeyCommand(requestedID, nil, commands.Domain1, 0, commands.AlgorithmED25519, make([]byte, 32), nil)
		},
		func() (*commands.CommandMessage, error) {
			return commands.CreateGenerateWrapKeyCommand(requestedID, nil, commands.Domain1, 0, commands.AlgorithmAES128CCMWrap, 0)
		},
		func() (*commands.CommandMessage, error) {
			return commands.CreatePutWrapkeyCommand(requestedID, nil, commands.Domain1, 0, commands.AlgorithmAES128CCMWrap, 0, make([]byte, 16))
		},
		func() (*commands.CommandMessage, error) {
			return commands.CreatePutAuthkeyCommand(requestedID, nil, commands.Domain1, 0, 0, make([]byte, 16), make([]byte, 16))
		},
		func() (*commands.CommandMessage, error) {
			return commands.CreatePutOpaqueCommand(requestedID, nil, commands.Domain1, 0, commands.AlgorithmOpaqueData, nil)
		},
		func() (*commands.CommandMessage, error) {
			return commands.CreateChangeAuthenticationKeyCommand(requestedID, "public response ID test credential")
		},
	} {
		command, err := build()
		if err != nil {
			t.Fatal(err)
		}
		request, err := command.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if err := checkResponseParameters(request, responseFrame(command.CommandType, []byte{0x12, 0x34})); err != nil {
			t.Fatalf("command 0x%02x rejected a matching ID: %v", command.CommandType, err)
		}
		if err := checkResponseParameters(request, responseFrame(command.CommandType, []byte{0x12, 0x35})); err == nil {
			t.Fatalf("command 0x%02x accepted another object's ID", command.CommandType)
		}
	}
}

func TestImpossibleRandomResponseRejectedBeforeSending(t *testing.T) {
	channel, hsm := newResponseContractChannel(t)
	if _, err := channel.SendEncryptedCommand(commands.CreateGetPseudoRandomCommand(3117)); err == nil {
		t.Fatal("impossible random response length was accepted")
	}
	if !channel.IsHealthy() || channel.MessageCount() != 1 || hsm.channel.Counter != 1 {
		t.Fatal("local random-length error advanced or invalidated the session")
	}
}

func TestImpossibleRawWrapResponseRejectedBeforeSending(t *testing.T) {
	channel, hsm := newResponseContractChannel(t)
	command := &commands.CommandMessage{CommandType: commands.CommandTypeWrapData, Data: make([]byte, 2+3087)}
	if _, err := channel.SendEncryptedCommand(command); err == nil {
		t.Fatal("impossible raw WRAP response length was accepted")
	}
	if !channel.IsHealthy() || channel.MessageCount() != 1 || hsm.channel.Counter != 1 {
		t.Fatal("local WRAP response-length error advanced or invalidated the session")
	}
}

func TestResponseContractsAllowMetadataAndWrapShapes(t *testing.T) {
	channel, _ := newResponseContractChannel(t)
	command, err := commands.CreateGetObjectInfoCommand(0x1234, commands.ObjectTypeAsymmetricKey)
	if err != nil {
		t.Fatal(err)
	}
	response, err := channel.SendEncryptedCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	info, ok := response.(*commands.ObjectInfoResponse)
	if !ok || info.ObjectID != 0x1234 || info.Type != 3 {
		t.Fatalf("matching object metadata was not preserved: %#v", response)
	}
	for _, size := range []int{0, 3, 3084, 3086} {
		command, err = commands.CreateWrapDataCommand(1, make([]byte, size))
		if err != nil {
			t.Fatal(err)
		}
		response, err = channel.SendEncryptedCommand(command)
		if err != nil {
			t.Fatal(err)
		}
		wrapped, ok := response.(*commands.WrapDataResponse)
		if !ok || len(wrapped.Nonce) != 13 || len(wrapped.Data) != size+17 {
			t.Fatalf("matching WRAP shape was not preserved: size=%d", size)
		}
		if size > 3084 {
			continue // A valid one-way WRAP need not fit an UNWRAP request.
		}
		command, err = commands.CreateUnwrapDataCommand(1, wrapped.Nonce, wrapped.Data)
		if err != nil {
			t.Fatal(err)
		}
		response, err = channel.SendEncryptedCommand(command)
		if err != nil {
			t.Fatal(err)
		}
		plain, ok := response.(*commands.UnwrapDataResponse)
		if !ok || len(plain.Data) != size {
			t.Fatalf("matching UNWRAP shape was not preserved: size=%d", size)
		}
	}
}

func TestResponseContractsAllowAssignedIDsAndCardErrors(t *testing.T) {
	channel, hsm := newResponseContractChannel(t)
	command, err := commands.CreateGenerateWrapKeyCommand(0, nil, commands.Domain1, 0, commands.AlgorithmAES128CCMWrap, 0)
	if err != nil {
		t.Fatal(err)
	}
	response, err := channel.SendEncryptedCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := response.(*commands.GenerateWrapKeyResponse); !ok || key.KeyID != 0x4321 {
		t.Fatalf("device-assigned key ID was not preserved: %#v", response)
	}
	for _, count := range []uint16{0, 1, 32, 3116} {
		response, err = channel.SendEncryptedCommand(commands.CreateGetPseudoRandomCommand(count))
		data, ok := response.([]byte)
		if err != nil || !ok || len(data) != int(count) {
			t.Fatalf("matching random response for %d bytes failed: %v", count, err)
		}
	}
	hsm.innerResponseOverride = func(command commands.CommandType, original []byte) []byte {
		if command == commands.CommandTypeGetPseudoRandom {
			return []byte{0x7f, 0, 1, byte(commands.ErrorCodeInvalidPermission)}
		}
		return original
	}
	_, err = channel.SendEncryptedCommand(commands.CreateGetPseudoRandomCommand(32))
	var cardErr *commands.Error
	if !errors.As(err, &cardErr) || cardErr.Code != commands.ErrorCodeInvalidPermission || !channel.IsHealthy() {
		t.Fatalf("valid card error was not preserved as a synchronized response: %v", err)
	}
}
