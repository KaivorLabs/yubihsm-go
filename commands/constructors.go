package commands

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/certusone/yubihsm-go/authkey"
)

// Constructor encodings below use binary.Write only with fixed-size values
// and bytes.Buffer, whose Write method cannot fail.
func padLabel(label []byte) ([]byte, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	padded := make([]byte, LabelLength)
	copy(padded, label)
	return padded, nil
}

func CreateDeviceInfoCommand() (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeDeviceInfo,
	}

	return command, nil
}

func CreateCreateSessionCommand(keySetID uint16, hostChallenge []byte) (*CommandMessage, error) {
	if len(hostChallenge) != 8 {
		return nil, errors.New("host challenge must be 8 bytes")
	}

	command := &CommandMessage{
		CommandType: CommandTypeCreateSession,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keySetID)
	payload.Write(hostChallenge)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateAuthenticateSessionCommand(hostCryptogram []byte) (*CommandMessage, error) {
	if len(hostCryptogram) != 8 {
		return nil, errors.New("host cryptogram must be 8 bytes")
	}

	command := &CommandMessage{
		CommandType: CommandTypeAuthenticateSession,
		Data:        append([]byte(nil), hostCryptogram...),
	}

	return command, nil
}

// Authenticated

func CreateResetCommand() (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeReset,
	}

	return command, nil
}

func CreateGenerateAsymmetricKeyCommand(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm) (*CommandMessage, error) {
	label, err := padLabel(label)
	if err != nil {
		return nil, err
	}

	command := &CommandMessage{
		CommandType: CommandTypeGenerateAsymmetricKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateSignDataEddsaCommand(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataEddsa,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateSignDataEcdsaCommand(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataEcdsa,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateSignDataPkcs1Command(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataPkcs1,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutAsymmetricKeyCommand(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, keyPart1 []byte, keyPart2 []byte) (*CommandMessage, error) {
	label, err := padLabel(label)
	if err != nil {
		return nil, err
	}
	command := &CommandMessage{
		CommandType: CommandTypePutAsymmetric,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	payload.Write(keyPart1)
	if keyPart2 != nil {
		payload.Write(keyPart2)
	}

	command.Data = payload.Bytes()

	return command, nil
}

// ListCommandOption writes a list filter. The historical signature cannot
// report writer errors; built-in options are consumed by CreateListObjectsCommand
// with a bytes.Buffer, which cannot fail writes.
type ListCommandOption func(w io.Writer)

func NewObjectTypeOption(objectType uint8) ListCommandOption {
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamType)
		binary.Write(w, binary.BigEndian, objectType)
	}
}

func NewIDOption(id uint16) ListCommandOption {
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamID)
		binary.Write(w, binary.BigEndian, id)
	}
}

func NewDomainOption(domain uint16) ListCommandOption {
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamDomains)
		binary.Write(w, binary.BigEndian, domain)
	}
}

func NewLabelOption(label []byte) (ListCommandOption, error) {
	label, err := padLabel(label)
	if err != nil {
		return nil, err
	}
	return func(w io.Writer) {
		binary.Write(w, binary.BigEndian, ListObjectParamLabel)
		binary.Write(w, binary.BigEndian, label)
	}, nil
}

func CreateListObjectsCommand(options ...ListCommandOption) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeListObjects,
	}

	payload := bytes.NewBuffer(nil)
	for _, opt := range options {
		if opt == nil {
			return nil, errors.New("list object option must not be nil")
		}
		opt(payload)
	}

	command.Data = payload.Bytes()

	return command, nil
}

func CreateGetObjectInfoCommand(keyID uint16, objectType uint8) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeGetObjectInfo,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	binary.Write(payload, binary.BigEndian, objectType)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateCloseSessionCommand() (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeCloseSession,
	}

	return command, nil
}

func CreateGetPubKeyCommand(keyID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeGetPubKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateDeleteObjectCommand(objID uint16, objType uint8) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeDeleteObject,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	binary.Write(payload, binary.BigEndian, objType)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateEchoCommand(data []byte) (*CommandMessage, error) {
	var ownedData []byte
	if data != nil {
		ownedData = make([]byte, len(data))
		copy(ownedData, data)
	}
	command := &CommandMessage{
		CommandType: CommandTypeEcho,
		Data:        ownedData,
	}

	return command, nil
}

func CreateDeriveEcdhCommand(objID uint16, pubkey []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeDeriveEcdh,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(pubkey)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateChangeAuthenticationKeyCommand(objID uint16, newPassword string) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeChangeAuthenticationKey,
	}

	authKey := authkey.NewFromPassword(newPassword)
	defer func() {
		for i := range authKey {
			authKey[i] = 0
		}
	}()
	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	binary.Write(payload, binary.BigEndian, AlgorithmYubicoAESAuthentication)
	payload.Write(authKey.GetEncKey())
	payload.Write(authKey.GetMacKey())
	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutOpaqueCommand(objID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, data []byte) (*CommandMessage, error) {
	label, err := padLabel(label)
	if err != nil {
		return nil, err
	}

	command := &CommandMessage{
		CommandType: CommandTypePutOpaque,
	}

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateGetOpaqueCommand(objID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeGetOpaque,
	}

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, objID)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateGetPseudoRandomCommand(numBytes uint16) *CommandMessage {
	command := &CommandMessage{
		CommandType: CommandTypeGetPseudoRandom,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, numBytes)
	command.Data = payload.Bytes()

	return command
}

func CreatePutWrapkeyCommand(objID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, delegated uint64, wrapkey []byte) (*CommandMessage, error) {
	label, err := padLabel(label)
	if err != nil {
		return nil, err
	}
	switch algorithm {
	case AlgorithmAES128CCMWrap:
		if keyLen := len(wrapkey); keyLen != 16 {
			return nil, errors.New("wrapkey is wrong length")
		}
	case AlgorithmAES192CCMWrap:
		if keyLen := len(wrapkey); keyLen != 24 {
			return nil, errors.New("wrapkey is wrong length")
		}
	case AlgorithmAES256CCMWrap:
		if keyLen := len(wrapkey); keyLen != 32 {
			return nil, errors.New("wrapkey is wrong length")
		}
	case AlgorithmRSA2048:
		if keyLen := len(wrapkey); keyLen != 256 {
			return nil, errors.New("wrapkey is wrong length")
		}
	case AlgorithmRSA3072:
		if keyLen := len(wrapkey); keyLen != 384 {
			return nil, errors.New("wrapkey is wrong length")
		}
	case AlgorithmRSA4096:
		if keyLen := len(wrapkey); keyLen != 512 {
			return nil, errors.New("wrapkey is wrong length")
		}
	default:
		return nil, errors.New("invalid algorithm")
	}

	command := &CommandMessage{
		CommandType: CommandTypePutWrapKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	binary.Write(payload, binary.BigEndian, delegated)
	payload.Write(wrapkey)

	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutAuthkeyCommand(objID uint16, label []byte, domains uint16, capabilities, delegated uint64, encKey, macKey []byte) (*CommandMessage, error) {
	label, err := padLabel(label)
	if err != nil {
		return nil, err
	}
	algorithm := AlgorithmYubicoAESAuthentication
	// TODO: support P256 Authentication when it is released
	// https://github.com/Yubico/yubihsm-shell/blob/1c8e254603e72f3f39cf1c3910996dbfcdba2b12/lib/yubihsm.c#L3110
	if len(encKey) != 16 {
		return nil, errors.New("invalid encryption key length")
	}
	if len(macKey) != 16 {
		return nil, errors.New("invalid mac key length")
	}

	command := &CommandMessage{
		CommandType: CommandTypePutAuthKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	binary.Write(payload, binary.BigEndian, delegated)
	payload.Write(encKey)
	payload.Write(macKey)

	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutDerivedAuthenticationKeyCommand(objID uint16, label []byte, domains uint16, capabilities uint64, delegated uint64, password string) (*CommandMessage, error) {
	authKey := authkey.NewFromPassword(password)
	defer func() {
		for i := range authKey {
			authKey[i] = 0
		}
	}()
	return CreatePutAuthkeyCommand(objID, label, domains, capabilities, delegated, authKey.GetEncKey(), authKey.GetMacKey())
}

func CreateSignAttestationCertCommand(keyObjID, attestationObjID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeAttestAsymmetric,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyObjID)
	binary.Write(payload, binary.BigEndian, attestationObjID)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateExportWrappedCommand(wrapObjID uint16, objType uint8, objID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeExportWrapped,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, wrapObjID)
	binary.Write(payload, binary.BigEndian, objType)
	binary.Write(payload, binary.BigEndian, objID)
	command.Data = payload.Bytes()

	return command, nil
}

// CreateImportWrappedCommand will import a wrapped/encrypted Object that was
// previously exported by an YubiHSM2 device. The imported object will retain
// its metadata (Object ID, Domains, Capabilities …etc), however, the object’s
// origin will be marked as imported instead of generated.
func CreateImportWrappedCommand(wrapObjID uint16, nonce, data []byte) (*CommandMessage, error) {
	if len(nonce) != WrapNonceLength {
		return nil, errors.New("invalid nonce length")
	}
	if len(data) < WrapIdentifierLength+WrapMACLength {
		return nil, errors.New("wrapped data is too short")
	}
	if len(nonce)+len(data) > MaxCommandDataLength-2 {
		return nil, errors.New("wrapped data exceeds the HSM message length limit")
	}

	command := &CommandMessage{CommandType: CommandTypeImportWrapped}
	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, wrapObjID)
	payload.Write(nonce)
	payload.Write(data)
	command.Data = payload.Bytes()

	return command, nil
}

// CreateGenerateWrapKeyCommand creates a command that generates a Wrap Key.
func CreateGenerateWrapKeyCommand(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, delegated uint64) (*CommandMessage, error) {
	paddedLabel, err := padLabel(label)
	if err != nil {
		return nil, err
	}
	if !isWrapKeyAlgorithm(algorithm) {
		return nil, errors.New("invalid wrap key algorithm")
	}

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(paddedLabel)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	payload.WriteByte(byte(algorithm))
	binary.Write(payload, binary.BigEndian, delegated)

	return &CommandMessage{
		CommandType: CommandTypeGenerateWrapKey,
		Data:        payload.Bytes(),
	}, nil
}

// CreateWrapDataCommand creates a command that encrypts data with a Wrap Key.
// The successful response must also fit: it adds a nonce, encrypted prefix,
// and MAC. UNWRAP DATA has an additional two-byte key ID in its request, so
// its plaintext capacity is two bytes smaller than this one-way WRAP limit.
func CreateWrapDataCommand(keyID uint16, data []byte) (*CommandMessage, error) {
	responseOverhead := WrapNonceLength + WrapDataPrefixLength + WrapMACLength
	if len(data) > MaxCommandDataLength-responseOverhead {
		return nil, errors.New("wrapped response would exceed the HSM message length limit")
	}

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	return &CommandMessage{
		CommandType: CommandTypeWrapData,
		Data:        payload.Bytes(),
	}, nil
}

// CreateUnwrapDataCommand creates a command that decrypts data produced by
// WRAP DATA. data must contain the encrypted leading zero byte, ciphertext,
// and the trailing AES-CCM MAC.
func CreateUnwrapDataCommand(keyID uint16, nonce, data []byte) (*CommandMessage, error) {
	if len(nonce) != WrapNonceLength {
		return nil, errors.New("invalid nonce length")
	}
	if len(data) < WrapDataPrefixLength+WrapMACLength {
		return nil, errors.New("wrapped data is too short")
	}
	if len(nonce)+len(data) > MaxCommandDataLength-2 {
		return nil, errors.New("wrapped data exceeds the HSM message length limit")
	}

	payload := bytes.NewBuffer(nil)
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(nonce)
	payload.Write(data)

	return &CommandMessage{
		CommandType: CommandTypeUnwrapData,
		Data:        payload.Bytes(),
	}, nil
}

func isWrapKeyAlgorithm(algorithm Algorithm) bool {
	switch algorithm {
	case AlgorithmAES128CCMWrap, AlgorithmAES192CCMWrap, AlgorithmAES256CCMWrap,
		AlgorithmRSA2048, AlgorithmRSA3072, AlgorithmRSA4096:
		return true
	default:
		return false
	}
}
