package commands

import (
	"bytes"
	"testing"
)

func TestCommandSerialize(t *testing.T) {
	sessionID := uint8(7)
	command := &CommandMessage{
		CommandType: CommandTypeEcho,
		SessionID:   &sessionID,
		Data:        []byte{0xaa, 0xbb},
		MAC:         []byte{0xcc, 0xdd},
	}

	serialized, err := command.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{byte(CommandTypeEcho), 0x00, 0x05, 0x07, 0xaa, 0xbb, 0xcc, 0xdd}
	if !bytes.Equal(serialized, want) {
		t.Fatalf("serialized = %x, want %x", serialized, want)
	}
}

func TestCommandSerializeSizeLimits(t *testing.T) {
	if _, err := (&CommandMessage{CommandType: CommandTypeEcho, Data: make([]byte, MaxMessageLength-3)}).Serialize(); err != nil {
		t.Fatalf("maximum plaintext command was rejected: %v", err)
	}
	sessionID := uint8(0)
	if _, err := (&CommandMessage{
		CommandType: CommandTypeSessionMessage,
		SessionID:   &sessionID,
		Data:        make([]byte, MaxSessionMessageDataLength),
		MAC:         make([]byte, SessionMACLength),
	}).Serialize(); err != nil {
		t.Fatalf("maximum session command was rejected: %v", err)
	}
}

func TestCommandSerializeRejectsInvalidInput(t *testing.T) {
	var command *CommandMessage
	if _, err := command.Serialize(); err == nil {
		t.Fatal("nil command was accepted")
	}

	command = &CommandMessage{CommandType: CommandTypeEcho, Data: make([]byte, MaxMessageLength-3+1)}
	if _, err := command.Serialize(); err == nil {
		t.Fatal("oversized HSM command data was accepted")
	}
	command = &CommandMessage{CommandType: CommandTypeSessionMessage, Data: make([]byte, MaxSessionMessageDataLength+1)}
	if _, err := command.Serialize(); err == nil {
		t.Fatal("oversized session message was accepted")
	}
	command = &CommandMessage{
		CommandType: CommandTypeSessionMessage,
		Data:        make([]byte, MaxSessionMessageDataLength),
		MAC:         make([]byte, maxCommandBodyLength-MaxSessionMessageDataLength+1),
	}
	if _, err := command.Serialize(); err == nil {
		t.Fatal("oversized command body was accepted")
	}
	if got := command.BodyLength(); got != uint16(maxCommandBodyLength) {
		t.Fatalf("oversized body length = %d, want saturation at %d", got, maxCommandBodyLength)
	}

	invalidSessionID := uint8(MaxSessionID + 1)
	command = &CommandMessage{SessionID: &invalidSessionID}
	if _, err := command.Serialize(); err == nil {
		t.Fatal("invalid session ID was accepted")
	}
}
