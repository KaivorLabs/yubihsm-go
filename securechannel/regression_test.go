package securechannel

import (
	"errors"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

type responseOverrideConnector struct {
	*emulatedHSMConnector
	override func(commands.CommandType, []byte) []byte
}

func (c *responseOverrideConnector) Request(command *commands.CommandMessage) ([]byte, error) {
	resp, err := c.emulatedHSMConnector.Request(command)
	if err == nil {
		resp = c.override(command.CommandType, resp)
	}
	return resp, err
}

func TestPlainCommandRejectsUnrelatedResponse(t *testing.T) {
	c := &transcriptConnector{steps: []transcriptStep{{Request: "010001aa", Response: "c00000"}}}
	channel, err := NewSecureChannel(c, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendCommand(&commands.CommandMessage{
		CommandType: commands.CommandTypeEcho,
		Data:        []byte{0xaa},
	}); err == nil {
		t.Fatal("unrelated empty ACK was accepted for a plaintext echo")
	}
}

func TestAuthenticateRejectsUnrelatedSuccessResponse(t *testing.T) {
	c := &responseOverrideConnector{
		emulatedHSMConnector: &emulatedHSMConnector{password: "password"},
		override: func(command commands.CommandType, resp []byte) []byte {
			if command == commands.CommandTypeAuthenticateSession {
				return responseFrame(commands.CommandTypeEcho, nil)
			}
			return resp
		},
	}
	channel, err := NewSecureChannel(c, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err == nil {
		t.Fatal("unrelated response was accepted as successful authentication")
	}
	if channel.IsHealthy() || channel.keyChain != nil {
		t.Fatal("failed authentication retained a usable channel")
	}
}

func TestEncryptedCommandRejectsBeyondOfficialFrameLimitLocally(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	// Yubico check_buffer_len limits the ENTIRE frame to 3136 bytes.
	// 12 outer bytes + pad(3 inner header bytes + 3117 data bytes) = 3148.
	_, err = channel.SendEncryptedCommand(&commands.CommandMessage{
		CommandType: commands.CommandTypeEcho,
		Data:        make([]byte, 3117),
	})
	if err == nil {
		t.Fatal("a frame larger than the official HSM limit was accepted")
	}
	if !channel.IsHealthy() || channel.MessageCount() != 1 || hsm.channel.Counter != 1 {
		t.Fatal("local length validation advanced the secure session")
	}
}

func TestUnrelatedEncryptedResponseIsNotSuccess(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	hsm.unrelatedInnerResponse = true
	command, err := commands.CreateEchoCommand([]byte("echo"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendEncryptedCommand(command); err == nil {
		t.Fatal("unrelated empty ACK was accepted as an echo response")
	}
	if channel.IsHealthy() {
		t.Fatal("unrelated authenticated response left channel usable")
	}
}

func TestUnsupportedResponseParserDoesNotInvalidateSession(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendEncryptedCommand(&commands.CommandMessage{CommandType: commands.CommandTypeStorageStatus}); err == nil {
		t.Fatal("expected unimplemented response parser error")
	}
	if !channel.IsHealthy() || channel.MessageCount() != 2 {
		t.Fatal("unimplemented application parser damaged valid SCP03 state")
	}
	command, err := commands.CreateEchoCommand([]byte("echo"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendEncryptedCommand(command); err != nil {
		t.Fatalf("valid next command failed: %v", err)
	}
}

func TestCloseClearsSecretsEvenWhenRejected(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password", closeRejected: true}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	err = channel.Close()
	var cardErr *commands.Error
	if !errors.As(err, &cardErr) || cardErr.Code != commands.ErrorCodeInvalidPermission {
		t.Fatalf("expected close rejection, got %v", err)
	}
	if channel.IsHealthy() || channel.keyChain != nil || channel.SecurityLevel != SecurityLevelClosed {
		t.Fatal("failed Close did not finalize local secrets")
	}
	if err := channel.Close(); err != nil {
		t.Fatalf("repeated Close was not idempotent: %v", err)
	}
}

func TestDirectCloseCommandFinalizesChannel(t *testing.T) {
	hsm := &emulatedHSMConnector{password: "password"}
	channel, err := NewSecureChannel(hsm, 1, "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}
	command, err := commands.CreateCloseSessionCommand()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := channel.SendEncryptedCommand(command); err != nil {
		t.Fatal(err)
	}
	if channel.IsHealthy() || channel.keyChain != nil {
		t.Fatal("direct CLOSE SESSION left a reusable local session")
	}
	if err := channel.Close(); err != nil {
		t.Fatalf("Close after direct close must be idempotent: %v", err)
	}
}
