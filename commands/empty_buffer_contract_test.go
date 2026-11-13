package commands

import (
	"encoding/json"
	"testing"
)

func TestEmptyResponsePreservesLegacyNonNilPayload(t *testing.T) {
	// Before the ownership refactor, data[3:] was non-nil even for an empty
	// successful payload. Copying it must not silently change JSON to null.
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"echo", []byte{0x81, 0, 0}},
		{"random", []byte{0xd1, 0, 0}},
	} {
		response, err := ParseResponse(tc.frame)
		if err != nil {
			t.Fatal(err)
		}
		var data []byte
		switch value := response.(type) {
		case *EchoResponse:
			data = value.Data
		case []byte:
			data = value
		default:
			t.Fatalf("unexpected response type %T", response)
		}
		if data == nil || len(data) != 0 {
			t.Fatalf("%s changed legacy empty payload semantics", tc.name)
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != `""` {
			t.Fatalf("empty byte payload encoded as %s, want an empty base64 string", encoded)
		}
	}
}

func TestEchoConstructorPreservesNilVersusEmpty(t *testing.T) {
	nilCommand, err := CreateEchoCommand(nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyCommand, err := CreateEchoCommand(make([]byte, 0))
	if err != nil {
		t.Fatal(err)
	}
	if nilCommand.Data != nil || emptyCommand.Data == nil {
		t.Fatal("copying changed the constructor's nil-versus-empty contract")
	}
}
