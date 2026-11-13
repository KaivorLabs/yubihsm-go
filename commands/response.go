package commands

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type (
	Response interface {
	}

	Error struct {
		Code ErrorCode
	}

	DeviceInfoResponse struct {
		MajorVersion        uint8
		MinorVersion        uint8
		BuildVersion        uint8
		SerialNumber        uint32
		LogTotal            uint8
		LogUsed             uint8
		SupportedAlgorithms []Algorithm
	}

	CreateSessionResponse struct {
		SessionID      uint8
		CardChallenge  []byte
		CardCryptogram []byte
	}

	SessionMessageResponse struct {
		SessionID     uint8
		EncryptedData []byte
		MAC           []byte
	}

	CreateAsymmetricKeyResponse struct {
		KeyID uint16
	}

	PutAsymmetricKeyResponse struct {
		KeyID uint16
	}

	ObjectInfoResponse struct {
		Capabilities         uint64
		ObjectID             uint16
		Length               uint16
		Domains              uint16
		Type                 uint8
		Algorithm            Algorithm
		Sequence             uint8
		Origin               uint8
		Label                [40]byte
		DelegatedCapabilites uint64
	}

	Object struct {
		ObjectID   uint16
		ObjectType uint8
		Sequence   uint8
	}

	ListObjectsResponse struct {
		Objects []Object
	}

	SignDataEddsaResponse struct {
		Signature []byte
	}

	SignDataPkcs1Response struct {
		Signature []byte
	}

	SignDataEcdsaResponse struct {
		Signature []byte
	}

	GetPubKeyResponse struct {
		Algorithm Algorithm
		// KeyData can contain different formats depending on the algorithm according to the YubiHSM2 documentation.
		KeyData []byte
	}

	EchoResponse struct {
		Data []byte
	}

	DeriveEcdhResponse struct {
		XCoordinate []byte
	}

	ChangeAuthenticationKeyResponse struct {
		ObjectID uint16
	}

	PutWrapkeyResponse struct {
		ObjectID uint16
	}

	PutAuthkeyResponse struct {
		ObjectID uint16
	}

	PutOpaqueResponse struct {
		ObjectID uint16
	}

	GetOpaqueResponse struct {
		Data []byte
	}

	SignAttestationCertResponse struct {
		Cert []byte
	}

	ExportWrappedResponse struct {
		Nonce []byte
		Data  []byte
	}

	ImportWrappedResponse struct {
		ObjectType uint8
		ObjectID   uint16
	}

	GenerateWrapKeyResponse struct {
		KeyID uint16
	}

	WrapDataResponse struct {
		Nonce []byte
		// Data contains the encrypted leading zero byte, wrapped plaintext,
		// and the trailing AES-CCM MAC. It can be passed unchanged to
		// CreateUnwrapDataCommand together with Nonce.
		Data []byte
	}

	UnwrapDataResponse struct {
		Data []byte
	}
)

// ParseResponse parses a binary response into the corresponding response type.
// Card error responses are returned as *Error.
func ParseResponse(data []byte) (Response, error) {
	if len(data) < 3 {
		return nil, errors.New("invalid response")
	}
	if len(data) > MaxMessageLength {
		return nil, errors.New("response frame exceeds the HSM message length limit")
	}

	var transactionType CommandType
	switch responseType := data[0]; {
	case responseType == byte(ErrorResponseCode-ResponseCommandOffset):
		transactionType = ErrorResponseCode
	case responseType >= ResponseCommandOffset:
		transactionType = CommandType(responseType - ResponseCommandOffset)
	default:
		return nil, errors.New("invalid response command code")
	}

	var payloadLength uint16
	err := binary.Read(bytes.NewReader(data[1:3]), binary.BigEndian, &payloadLength)
	if err != nil {
		return nil, err
	}

	payload := data[3:]
	if len(payload) != int(payloadLength) {
		return nil, errors.New("response payload length does not equal the given length")
	}
	if transactionType == CommandTypeSessionMessage {
		if len(payload) > 1+MaxSessionMessageDataLength+SessionMACLength {
			return nil, errors.New("session response exceeds the HSM message length limit")
		}
	}
	// Response values may retain payload slices. Copy only after validating the
	// declared length so malformed oversized input is rejected without a large
	// allocation, while valid parsed responses own their payload memory.
	// Preserve the historical non-nil empty payload (including its JSON
	// representation) while detaching it from the caller's input buffer.
	ownedPayload := make([]byte, len(payload))
	copy(ownedPayload, payload)
	payload = ownedPayload

	switch transactionType {
	case CommandTypeDeviceInfo:
		return parseDeviceInfoResponse(payload)
	case CommandTypeCreateSession:
		return parseCreateSessionResponse(payload)
	case CommandTypeAuthenticateSession, CommandTypeCloseSession, CommandTypeDeleteObject, CommandTypeReset:
		return parseEmptyResponse(payload)
	case CommandTypeSessionMessage:
		return parseSessionMessage(payload)
	case CommandTypeGenerateAsymmetricKey:
		return parseCreateAsymmetricKeyResponse(payload)
	case CommandTypeSignDataEddsa:
		return parseSignDataEddsaResponse(payload)
	case CommandTypeSignDataEcdsa:
		return parseSignDataEcdsaResponse(payload)
	case CommandTypeSignDataPkcs1:
		return parseSignDataPkcs1Response(payload)
	case CommandTypePutAsymmetric:
		return parsePutAsymmetricKeyResponse(payload)
	case CommandTypeListObjects:
		return parseListObjectsResponse(payload)
	case CommandTypeGetObjectInfo:
		return parseGetObjectInfoResponse(payload)
	case CommandTypeGetPubKey:
		return parseGetPubKeyResponse(payload)
	case CommandTypeEcho:
		return parseEchoResponse(payload)
	case CommandTypeDeriveEcdh:
		return parseDeriveEcdhResponse(payload)
	case CommandTypeChangeAuthenticationKey:
		return parseChangeAuthenticationKeyResponse(payload)
	case CommandTypeGetPseudoRandom:
		return parseGetPseudoRandomResponse(payload), nil
	case CommandTypePutWrapKey:
		return parsePutWrapkeyResponse(payload)
	case CommandTypePutAuthKey:
		return parsePutAuthkeyResponse(payload)
	case CommandTypePutOpaque:
		return parsePutOpaqueResponse(payload)
	case CommandTypeGetOpaque:
		return parseGetOpaqueResponse(payload)
	case CommandTypeAttestAsymmetric:
		return parseAttestationCertResponse(payload)
	case CommandTypeExportWrapped:
		return parseExportWrappedResponse(payload)
	case CommandTypeImportWrapped:
		return parseImportWrappedResponse(payload)
	case CommandTypeGenerateWrapKey:
		return parseGenerateWrapKeyResponse(payload)
	case CommandTypeWrapData:
		return parseWrapDataResponse(payload)
	case CommandTypeUnwrapData:
		return parseUnwrapDataResponse(payload)
	case ErrorResponseCode:
		return nil, parseErrorResponse(payload)
	default:
		return nil, errors.New("response type unknown / not implemented")
	}
}

func parseEmptyResponse(payload []byte) (Response, error) {
	if len(payload) != 0 {
		return nil, errors.New("invalid response payload length")
	}
	return nil, nil
}

func parseErrorResponse(payload []byte) error {
	if len(payload) != 1 {
		return errors.New("invalid response payload length")
	}

	return &Error{
		Code: ErrorCode(payload[0]),
	}
}

func parseSessionMessage(payload []byte) (Response, error) {
	// SessionID (1) + MAC (8); EncryptedData may be empty. Guard before
	// slicing so a malformed or truncated connector response returns an error
	// instead of panicking with an out-of-range slice (the payload is not yet
	// MAC-verified at this point).
	if len(payload) < 1+SessionMACLength {
		return nil, errors.New("invalid session message payload length")
	}
	if payload[0] > MaxSessionID {
		return nil, errors.New("invalid session ID")
	}
	return &SessionMessageResponse{
		SessionID:     payload[0],
		EncryptedData: payload[1 : len(payload)-SessionMACLength],
		MAC:           payload[len(payload)-SessionMACLength:],
	}, nil
}

func parseDeviceInfoResponse(payload []byte) (Response, error) {
	// Reads payload[3:7] and payload[9:]; guard before slicing.
	if len(payload) < 9 {
		return nil, errors.New("invalid device info payload length")
	}
	var serialNumber uint32
	err := binary.Read(bytes.NewReader(payload[3:7]), binary.BigEndian, &serialNumber)
	if err != nil {
		return nil, err
	}

	var supportedAlgorithms []Algorithm
	for _, alg := range payload[9:] {
		supportedAlgorithms = append(supportedAlgorithms, Algorithm(alg))
	}

	return &DeviceInfoResponse{
		MajorVersion:        payload[0],
		MinorVersion:        payload[1],
		BuildVersion:        payload[2],
		SerialNumber:        serialNumber,
		LogTotal:            payload[7],
		LogUsed:             payload[8],
		SupportedAlgorithms: supportedAlgorithms,
	}, nil
}

func parseCreateSessionResponse(payload []byte) (Response, error) {
	if len(payload) != 17 {
		return nil, errors.New("invalid response payload length")
	}
	if payload[0] > MaxSessionID {
		return nil, errors.New("invalid session ID")
	}

	return &CreateSessionResponse{
		SessionID:      uint8(payload[0]),
		CardChallenge:  payload[1:9],
		CardCryptogram: payload[9:],
	}, nil
}

func parseCreateAsymmetricKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var keyID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &keyID)
	if err != nil {
		return nil, err
	}

	return &CreateAsymmetricKeyResponse{
		KeyID: keyID,
	}, nil
}

func parseSignDataEddsaResponse(payload []byte) (Response, error) {
	const ed25519SignatureLength = 64
	if len(payload) != ed25519SignatureLength {
		return nil, errors.New("invalid response payload length")
	}
	return &SignDataEddsaResponse{
		Signature: payload,
	}, nil
}

func parseSignDataPkcs1Response(payload []byte) (Response, error) {
	if len(payload) < 1 {
		return nil, errors.New("invalid response payload length")
	}

	return &SignDataPkcs1Response{
		Signature: payload,
	}, nil
}

func parseSignDataEcdsaResponse(payload []byte) (Response, error) {
	if len(payload) == 0 {
		return nil, errors.New("invalid response payload length")
	}
	return &SignDataEcdsaResponse{
		Signature: payload,
	}, nil
}

func parsePutAsymmetricKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var keyID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &keyID)
	if err != nil {
		return nil, err
	}

	return &PutAsymmetricKeyResponse{
		KeyID: keyID,
	}, nil
}

func parseListObjectsResponse(payload []byte) (Response, error) {
	if len(payload)%4 != 0 {
		return nil, errors.New("invalid response payload length")
	}

	response := ListObjectsResponse{
		Objects: make([]Object, len(payload)/4),
	}

	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &response.Objects)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func parseGetObjectInfoResponse(payload []byte) (Response, error) {
	response := ObjectInfoResponse{}
	if len(payload) != binary.Size(response) {
		return nil, errors.New("invalid response payload length")
	}

	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func parseGetPubKeyResponse(payload []byte) (Response, error) {
	if len(payload) < 2 {
		return nil, errors.New("invalid response payload length")
	}
	return &GetPubKeyResponse{
		Algorithm: Algorithm(payload[0]),
		KeyData:   payload[1:],
	}, nil
}

func parseEchoResponse(payload []byte) (Response, error) {
	return &EchoResponse{
		Data: payload,
	}, nil
}

func parseDeriveEcdhResponse(payload []byte) (Response, error) {
	if len(payload) == 0 {
		return nil, errors.New("invalid response payload length")
	}
	return &DeriveEcdhResponse{
		XCoordinate: payload,
	}, nil
}

func parseChangeAuthenticationKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}

	return &ChangeAuthenticationKeyResponse{ObjectID: objectID}, nil
}

func parseGetPseudoRandomResponse(payload []byte) Response {
	return payload
}

func parsePutWrapkeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}
	return &PutWrapkeyResponse{ObjectID: objectID}, nil
}

func parsePutAuthkeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}

	return &PutAuthkeyResponse{ObjectID: objectID}, nil
}

func parsePutOpaqueResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var objectID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &objectID)
	if err != nil {
		return nil, err
	}

	return &PutOpaqueResponse{
		ObjectID: objectID,
	}, nil
}

func parseGetOpaqueResponse(payload []byte) (Response, error) {
	return &GetOpaqueResponse{
		Data: payload,
	}, nil
}

func parseAttestationCertResponse(payload []byte) (Response, error) {
	if len(payload) < 1 {
		return nil, errors.New("invalid response payload length")
	}

	return &SignAttestationCertResponse{
		Cert: payload,
	}, nil
}

func parseExportWrappedResponse(payload []byte) (Response, error) {
	if len(payload) < WrapNonceLength+WrapIdentifierLength+WrapMACLength {
		return nil, errors.New("invalid response payload length")
	}

	return &ExportWrappedResponse{
		Nonce: payload[:WrapNonceLength],
		Data:  payload[WrapNonceLength:],
	}, nil
}

func parseImportWrappedResponse(payload []byte) (Response, error) {
	if len(payload) != 3 {
		return nil, errors.New("invalid response payload length")
	}

	var objID uint16
	err := binary.Read(bytes.NewReader(payload[1:3]), binary.BigEndian, &objID)
	if err != nil {
		return nil, err
	}

	return &ImportWrappedResponse{
		ObjectType: uint8(payload[0]),
		ObjectID:   objID,
	}, nil
}

func parseGenerateWrapKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var keyID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &keyID)
	if err != nil {
		return nil, err
	}
	return &GenerateWrapKeyResponse{KeyID: keyID}, nil
}

func parseWrapDataResponse(payload []byte) (Response, error) {
	minimumLength := WrapNonceLength + WrapDataPrefixLength + WrapMACLength
	if len(payload) < minimumLength {
		return nil, errors.New("invalid response payload length")
	}

	return &WrapDataResponse{
		Nonce: payload[:WrapNonceLength],
		Data:  payload[WrapNonceLength:],
	}, nil
}

func parseUnwrapDataResponse(payload []byte) (Response, error) {
	return &UnwrapDataResponse{
		Data: payload,
	}, nil
}

// Error formats a card error message into a human readable format
func (e *Error) Error() string {
	message := ""
	switch e.Code {
	case ErrorCodeOK:
		message = "OK"
	case ErrorCodeInvalidCommand:
		message = "Invalid command"
	case ErrorCodeInvalidData:
		message = "Invalid data"
	case ErrorCodeInvalidSession:
		message = "Invalid session"
	case ErrorCodeAuthFail:
		message = "Auth fail"
	case ErrorCodeSessionFull:
		message = "Session full"
	case ErrorCodeSessionFailed:
		message = "Session failed"
	case ErrorCodeStorageFailed:
		message = "Storage failed"
	case ErrorCodeWrongLength:
		message = "Wrong length"
	case ErrorCodeInvalidPermission:
		message = "Invalid permission"
	case ErrorCodeLogFull:
		message = "Log full"
	case ErrorCodeObjectNotFound:
		message = "Object not found"
	case ErrorCodeInvalidID:
		message = "Invalid ID"
	case ErrorCodeCommandUnexecuted:
		message = "Command unexecuted"
	case ErrorCodeSSHCAConstraintViolation:
		message = "SSH CA constraint violation"
	case ErrorCodeInvalidOTP:
		message = "Invalid OTP"
	case ErrorCodeDemoMode:
		message = "Demo mode"
	case ErrorCodeObjectExists:
		message = "Object exists"
	case ErrorCodeAlgorithmDisabled:
		message = "Algorithm disabled"
	default:
		message = fmt.Sprintf("Unknown (0x%02x)", uint8(e.Code))
	}

	return fmt.Sprintf("card responded with error: %s", message)
}
