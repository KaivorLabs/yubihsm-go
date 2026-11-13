package commands_test

import (
	"encoding/hex"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

func TestLegacyConstructorWireContracts(t *testing.T) {
	// Literal command codes, lengths and fields from the wire protocol, not
	// calculated from the encoder's constants, offsets or BodyLength method.
	cases := []struct {
		name  string
		build func() (*commands.CommandMessage, error)
		want  string
	}{
		{"device info", commands.CreateDeviceInfoCommand, "060000"},
		{"reset", commands.CreateResetCommand, "080000"},
		{"close", commands.CreateCloseSessionCommand, "400000"},
		{"list all", func() (*commands.CommandMessage, error) { return commands.CreateListObjectsCommand() }, "480000"},
		{"echo", func() (*commands.CommandMessage, error) { return commands.CreateEchoCommand([]byte("abc")) }, "010003616263"},
		{"create session", func() (*commands.CommandMessage, error) {
			return commands.CreateCreateSessionCommand(0x1234, []byte{0, 1, 2, 3, 4, 5, 6, 7})
		}, "03000a12340001020304050607"},
		{"authenticate (unframed)", func() (*commands.CommandMessage, error) {
			return commands.CreateAuthenticateSessionCommand([]byte{0, 1, 2, 3, 4, 5, 6, 7})
		}, "0400080001020304050607"},
		{"public key", func() (*commands.CommandMessage, error) { return commands.CreateGetPubKeyCommand(0x1234) }, "5400021234"},
		{"object info", func() (*commands.CommandMessage, error) { return commands.CreateGetObjectInfoCommand(0x1234, 3) }, "4e0003123403"},
		{"delete", func() (*commands.CommandMessage, error) { return commands.CreateDeleteObjectCommand(0x1234, 3) }, "580003123403"},
		{"sign eddsa", func() (*commands.CommandMessage, error) {
			return commands.CreateSignDataEddsaCommand(0x1234, []byte("abc"))
		}, "6a00051234616263"},
		{"opaque", func() (*commands.CommandMessage, error) { return commands.CreateGetOpaqueCommand(0x1234) }, "4300021234"},
		{"random", func() (*commands.CommandMessage, error) { return commands.CreateGetPseudoRandomCommand(32), nil }, "5100020020"},
		{"attestation", func() (*commands.CommandMessage, error) {
			return commands.CreateSignAttestationCertCommand(0x1234, 0xabcd)
		}, "6400041234abcd"},
		{"export wrapped", func() (*commands.CommandMessage, error) {
			return commands.CreateExportWrappedCommand(0x1234, 3, 0xabcd)
		}, "4a0005123403abcd"},
		{"wrap data", func() (*commands.CommandMessage, error) { return commands.CreateWrapDataCommand(0x1234, []byte("abc")) }, "6800051234616263"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			command, err := tc.build()
			if err != nil {
				t.Fatal(err)
			}
			data, err := command.Serialize()
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(data); got != tc.want {
				t.Fatalf("wire = %s, want %s", got, tc.want)
			}
		})
	}
}
