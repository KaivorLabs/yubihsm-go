package commands

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestConstructorsDoNotMutateLabelBackingArray(t *testing.T) {
	backing := bytes.Repeat([]byte{0xaa}, LabelLength)
	copy(backing, []byte("key"))
	label := backing[:3]

	if _, err := CreateGenerateAsymmetricKeyCommand(1, label, Domain1, 0, AlgorithmP256); err != nil {
		t.Fatal(err)
	}
	for i, value := range backing[3:] {
		if value != 0xaa {
			t.Fatalf("label backing array modified at offset %d", i+3)
		}
	}
}

func TestCreateListObjectsCommandOptions(t *testing.T) {
	labelOption, err := NewLabelOption([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	command, err := CreateListObjectsCommand(
		NewObjectTypeOption(ObjectTypeAsymmetricKey),
		NewIDOption(0x1234),
		NewDomainOption(Domain1|Domain2),
		labelOption,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []byte{
		ListObjectParamType, ObjectTypeAsymmetricKey,
		ListObjectParamID, 0x12, 0x34,
		ListObjectParamDomains, 0x00, 0x03,
		ListObjectParamLabel, 'x',
	}
	if len(command.Data) < len(wantPrefix) {
		t.Fatalf("list payload too short: %d", len(command.Data))
	}
	if !bytes.Equal(command.Data[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("list option prefix = %x, want %x", command.Data[:len(wantPrefix)], wantPrefix)
	}
	if len(command.Data) != len(wantPrefix)+LabelLength-1 {
		t.Fatalf("list payload length = %d", len(command.Data))
	}
}

func TestCreateListObjectsCommandRejectsNilOption(t *testing.T) {
	if _, err := CreateListObjectsCommand(nil); err == nil {
		t.Fatal("nil list option was accepted")
	}
}

func TestConstructorsCopyDirectDataInputs(t *testing.T) {
	echoData := []byte("echo")
	echo, err := CreateEchoCommand(echoData)
	if err != nil {
		t.Fatal(err)
	}
	echoData[0] = 'X'
	if string(echo.Data) != "echo" {
		t.Fatal("echo command retained the caller's data slice")
	}

	cryptogram := make([]byte, 8)
	authenticate, err := CreateAuthenticateSessionCommand(cryptogram)
	if err != nil {
		t.Fatal(err)
	}
	cryptogram[0] = 1
	if authenticate.Data[0] != 0 {
		t.Fatal("authenticate command retained the caller's cryptogram slice")
	}
}

func TestSessionConstructorValidation(t *testing.T) {
	if _, err := CreateCreateSessionCommand(1, make([]byte, 7)); err == nil {
		t.Fatal("short host challenge was accepted")
	}
	if _, err := CreateCreateSessionCommand(1, make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateAuthenticateSessionCommand(make([]byte, 7)); err == nil {
		t.Fatal("short host cryptogram was accepted")
	}
	if _, err := CreateAuthenticateSessionCommand(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
}

func TestCreateGenerateWrapKeyCommand(t *testing.T) {
	command, err := CreateGenerateWrapKeyCommand(
		0x1234,
		[]byte("wrap-key"),
		Domain1|Domain2,
		CapabilityWrapData|CapabilityUnwrapData,
		AlgorithmAES256CCMWrap,
		CapabilityExportableUnderWrap,
	)
	if err != nil {
		t.Fatal(err)
	}
	if command.CommandType != CommandTypeGenerateWrapKey {
		t.Fatalf("command type = 0x%02x", command.CommandType)
	}
	if len(command.Data) != 2+LabelLength+2+8+1+8 {
		t.Fatalf("payload length = %d", len(command.Data))
	}
	if got := binary.BigEndian.Uint16(command.Data[:2]); got != 0x1234 {
		t.Fatalf("key ID = 0x%04x", got)
	}
	if !bytes.Equal(command.Data[2:2+len("wrap-key")], []byte("wrap-key")) {
		t.Fatalf("label prefix = %q", command.Data[2:2+len("wrap-key")])
	}
	if command.Data[2+LabelLength+2+8] != byte(AlgorithmAES256CCMWrap) {
		t.Fatal("algorithm was encoded at the wrong offset")
	}
}

func TestCreateGenerateWrapKeyCommandValidation(t *testing.T) {
	if _, err := CreateGenerateWrapKeyCommand(0, make([]byte, LabelLength+1), 0, 0, AlgorithmAES256CCMWrap, 0); err == nil {
		t.Fatal("oversized label was accepted")
	}
	if _, err := CreateGenerateWrapKeyCommand(0, nil, 0, 0, AlgorithmED25519, 0); err == nil {
		t.Fatal("non-wrap algorithm was accepted")
	}
}

func TestCreateImportWrappedCommandValidation(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x11}, WrapNonceLength)
	wrappedData := bytes.Repeat([]byte{0x22}, WrapIdentifierLength+WrapMACLength)
	if _, err := CreateImportWrappedCommand(1, nonce, wrappedData); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateImportWrappedCommand(1, nonce[:len(nonce)-1], wrappedData); err == nil {
		t.Fatal("short nonce was accepted")
	}
	if _, err := CreateImportWrappedCommand(1, nonce, wrappedData[:len(wrappedData)-1]); err == nil {
		t.Fatal("wrapped object without a complete MAC was accepted")
	}
	if _, err := CreateImportWrappedCommand(1, nonce, make([]byte, MaxCommandDataLength-2-len(nonce)+1)); err == nil {
		t.Fatal("oversized wrapped object was accepted")
	}
}

func TestCreatePutRSAWrapKeyCommand(t *testing.T) {
	for _, tc := range []struct {
		algorithm Algorithm
		keyLength int
	}{
		{AlgorithmRSA2048, 256},
		{AlgorithmRSA3072, 384},
		{AlgorithmRSA4096, 512},
	} {
		if _, err := CreatePutWrapkeyCommand(1, nil, Domain1, 0, tc.algorithm, 0, make([]byte, tc.keyLength)); err != nil {
			t.Fatalf("algorithm %d: %v", tc.algorithm, err)
		}
		if _, err := CreatePutWrapkeyCommand(1, nil, Domain1, 0, tc.algorithm, 0, make([]byte, tc.keyLength-1)); err == nil {
			t.Fatalf("algorithm %d accepted an invalid key length", tc.algorithm)
		}
	}
}

func TestCreateWrapAndUnwrapDataCommands(t *testing.T) {
	plaintext := []byte("hello")
	wrap, err := CreateWrapDataCommand(0x0102, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if wrap.CommandType != CommandTypeWrapData || !bytes.Equal(wrap.Data, append([]byte{0x01, 0x02}, plaintext...)) {
		t.Fatalf("unexpected wrap command: %#v", wrap)
	}

	nonce := bytes.Repeat([]byte{0x11}, WrapNonceLength)
	wrappedData := bytes.Repeat([]byte{0x22}, WrapDataPrefixLength+WrapMACLength)
	unwrap, err := CreateUnwrapDataCommand(0x0304, nonce, wrappedData)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0x03, 0x04}, nonce...)
	want = append(want, wrappedData...)
	if unwrap.CommandType != CommandTypeUnwrapData || !bytes.Equal(unwrap.Data, want) {
		t.Fatalf("unexpected unwrap command: %#v", unwrap)
	}

	if _, err := CreateUnwrapDataCommand(1, nonce[:len(nonce)-1], wrappedData); err == nil {
		t.Fatal("short nonce was accepted")
	}
	if _, err := CreateUnwrapDataCommand(1, nonce, wrappedData[:len(wrappedData)-1]); err == nil {
		t.Fatal("wrapped data without a complete MAC was accepted")
	}
	if _, err := CreateWrapDataCommand(1, make([]byte, MaxCommandDataLength-1)); err == nil {
		t.Fatal("oversized plaintext was accepted")
	}
	if _, err := CreateUnwrapDataCommand(1, nonce, make([]byte, MaxCommandDataLength-2-len(nonce)+1)); err == nil {
		t.Fatal("oversized wrapped data was accepted")
	}
}
