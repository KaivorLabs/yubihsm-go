package securechannel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/enceve/crypto/cmac"
)

type (
	// SecureChannel implements YubiHSM2's SCP03 channel. Methods serialize
	// communication internally. Legacy exported state fields must not be
	// mutated during use or read concurrently; use MessageCount and IsHealthy
	// for synchronized state access. A SecureChannel must not be copied.
	SecureChannel struct {
		// connector is used to communicate with the card
		connector connector.Connector
		// authKeySlot is the slot of the used authKey on the HSM
		authKeySlot uint16
		// keyChain holds the keys generated in the authentication ceremony
		keyChain *KeyChain
		// channelLock is used to lock encrypted communications to prevent race conditions
		channelLock sync.Mutex

		// ID is the ID of the session with the HSM
		ID uint8
		// Counter of commands performed on the session
		Counter uint32
		// SecurityLevel is the authentication state of the session
		SecurityLevel SecurityLevel

		// HostChallenge is the auth challenge of the host
		HostChallenge []byte
		// DeviceChallenge is the auth challenge of the device
		DeviceChallenge []byte

		// AuthKey authenticates against authKeySlot and is cleared after
		// Authenticate finishes, on invalidation, and on Close.
		AuthKey authkey.AuthKey

		// MACChainValue is the last MAC to allow MAC chaining
		MACChainValue []byte
	}

	// KeyDerivationConstant used to derive keys using KDF
	KeyDerivationConstant byte

	// SecurityLevel indicates an auth state of a session/channel
	SecurityLevel byte

	// KeyChain holds session keys
	KeyChain struct {
		EncKey  []byte
		MACKey  []byte
		RMACKey []byte
	}

	// MessageType indicates whether a message is a command or response
	MessageType byte
)

const (
	MACLength        = commands.SessionMACLength
	ChallengeLength  = 8
	CryptogramLength = 8
	KeyLength        = 16

	DerivationConstantEncKey  KeyDerivationConstant = 0x04
	DerivationConstantMACKey  KeyDerivationConstant = 0x06
	DerivationConstantRMACKey KeyDerivationConstant = 0x07

	DerivationConstantDeviceCryptogram KeyDerivationConstant = 0x00
	DerivationConstantHostCryptogram   KeyDerivationConstant = 0x01

	SecurityLevelUnauthenticated SecurityLevel = 0
	SecurityLevelAuthenticated   SecurityLevel = 1
	// SecurityLevelInvalid indicates that transport or protocol state was lost
	// and the session must be replaced rather than reused.
	SecurityLevelInvalid SecurityLevel = 2
	// SecurityLevelClosed indicates that Close has finalized the channel.
	SecurityLevelClosed SecurityLevel = 3

	MessageTypeCommand  MessageType = 0
	MessageTypeResponse MessageType = 1

	MaxMessagesPerSession = 10000
)

var ErrAuthCryptogram = errors.New("authentication failed: device sent wrong cryptogram")

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func (s *SecureChannel) clearAuthKeyLocked() {
	wipeBytes(s.AuthKey)
	s.AuthKey = nil
}

func (s *SecureChannel) clearSessionSecretsLocked() {
	s.clearAuthKeyLocked()
	if s.keyChain != nil {
		wipeBytes(s.keyChain.EncKey)
		wipeBytes(s.keyChain.MACKey)
		wipeBytes(s.keyChain.RMACKey)
		s.keyChain = nil
	}
	wipeBytes(s.MACChainValue)
	s.MACChainValue = nil
}

// NewSecureChannel initiates a new secure channel using a password-derived
// authentication key. Call Authenticate next to establish a session.
func NewSecureChannel(connector connector.Connector, authKeySlot uint16, password string) (*SecureChannel, error) {
	if connector == nil {
		return nil, errors.New("connector must not be nil")
	}
	key := authkey.NewFromPassword(password)
	defer wipeBytes(key)
	return NewSecureChannelWithAuthKey(connector, authKeySlot, key)
}

// NewSecureChannelWithAuthKey initiates a secure channel using an already
// derived YubiHSM authentication key. The key is copied before it is stored
// and cleared when Authenticate finishes.
func NewSecureChannelWithAuthKey(connector connector.Connector, authKeySlot uint16, key authkey.AuthKey) (*SecureChannel, error) {
	if connector == nil {
		return nil, errors.New("connector must not be nil")
	}
	if len(key.GetEncKey()) != KeyLength || len(key.GetMacKey()) != KeyLength {
		return nil, errors.New("authentication key must be 32 bytes")
	}

	keyCopy := make(authkey.AuthKey, len(key))
	copy(keyCopy, key)
	channel := &SecureChannel{
		ID:            0,
		AuthKey:       keyCopy,
		MACChainValue: make([]byte, aes.BlockSize),
		SecurityLevel: SecurityLevelUnauthenticated,
		authKeySlot:   authKeySlot,
		connector:     connector,
	}

	hostChallenge := make([]byte, ChallengeLength)
	_, err := rand.Read(hostChallenge)
	if err != nil {
		channel.clearSessionSecretsLocked()
		return nil, err
	}
	channel.HostChallenge = hostChallenge

	return channel, nil
}

// Authenticate establishes an authenticated session with the HSM
func (s *SecureChannel) Authenticate() (err error) {
	s.channelLock.Lock()
	defer s.channelLock.Unlock()

	if s.SecurityLevel != SecurityLevelUnauthenticated {
		return errors.New("the session is already authenticated")
	}

	command, err := commands.CreateCreateSessionCommand(s.authKeySlot, s.HostChallenge)
	if err != nil {
		return err
	}

	// Once CREATE SESSION may have reached the HSM, retrying with the same
	// challenge can leak a device session and reuse authentication material.
	// Any failure therefore makes this channel one-shot and non-reusable.
	defer func() {
		if err != nil {
			s.SecurityLevel = SecurityLevelInvalid
			s.clearSessionSecretsLocked()
			return
		}
		// The long-term authentication key is no longer needed after the
		// session keys and cryptograms have been established.
		s.clearAuthKeyLocked()
	}()

	response, err := s.sendCommandLocked(command)
	if err != nil {
		return err
	}

	createSessionResp, match := response.(*commands.CreateSessionResponse)
	if !match {
		return errors.New("invalid response type")
	}

	s.ID = createSessionResp.SessionID
	s.DeviceChallenge = createSessionResp.CardChallenge

	// Update keychain
	err = s.updateKeychain()
	if err != nil {
		return err
	}

	// Validate device cryptogram
	deviceCryptogram, err := s.deriveKDF(s.keyChain.MACKey, DerivationConstantDeviceCryptogram, CryptogramLength)
	if err != nil {
		return err
	}
	defer wipeBytes(deviceCryptogram)

	if len(createSessionResp.CardCryptogram) != len(deviceCryptogram) ||
		subtle.ConstantTimeCompare(deviceCryptogram, createSessionResp.CardCryptogram) != 1 {
		return ErrAuthCryptogram
	}

	// Create host cryptogram
	hostCryptogram, err := s.deriveKDF(s.keyChain.MACKey, DerivationConstantHostCryptogram, CryptogramLength)
	if err != nil {
		return err
	}
	defer wipeBytes(hostCryptogram)

	// Authenticate session
	authenticateCommand, err := commands.CreateAuthenticateSessionCommand(hostCryptogram)
	if err != nil {
		return err
	}
	_, err = s.sendMACCommand(authenticateCommand)
	if err != nil {
		return err
	}

	// Set counter to 1 as specified by the protocol
	s.Counter = 1

	s.SecurityLevel = SecurityLevelAuthenticated

	return nil
}

// SendCommand sends an unauthenticated command to the HSM and returns the parsed response.
func (s *SecureChannel) SendCommand(c *commands.CommandMessage) (commands.Response, error) {
	s.channelLock.Lock()
	defer s.channelLock.Unlock()

	return s.sendCommandLocked(c)
}

func (s *SecureChannel) sendCommandLocked(c *commands.CommandMessage) (commands.Response, error) {
	if c == nil {
		return nil, errors.New("command must not be nil")
	}
	if s.connector == nil {
		return nil, errors.New("connector is not configured")
	}

	// Snapshot the actual outgoing body before calling user-supplied transport
	// code. This private serialized copy is never passed to the transport.
	requestData, err := c.Serialize()
	if err != nil {
		return nil, err
	}
	defer wipeBytes(requestData)
	if err := checkRequestParameters(requestData); err != nil {
		return nil, err
	}
	resp, err := s.connector.Request(c)
	if err != nil {
		return nil, err
	}
	if err := checkResponseCommand(commands.CommandType(requestData[0]), resp); err != nil {
		return nil, err
	}
	if err := checkResponseParameters(requestData, resp); err != nil {
		return nil, err
	}
	return commands.ParseResponse(resp)
}

func checkResponseCommand(command commands.CommandType, data []byte) error {
	if len(data) < 3 {
		return errors.New("invalid response header")
	}
	if int(binary.BigEndian.Uint16(data[1:3])) != len(data)-3 {
		return errors.New("response payload length does not match its header")
	}
	// A card error is valid for every command, but a success must correspond
	// to the request. In particular, another empty response is not an ACK.
	if data[0] != byte(commands.ErrorResponseCode-commands.ResponseCommandOffset) &&
		data[0] != (byte(command)|commands.ResponseCommandOffset) {
		return fmt.Errorf("response command 0x%02x does not match request 0x%02x", data[0], byte(command))
	}
	return nil
}

// These helpers receive serialized frames with validated headers. Parameter
// checks deliberately cover only relationships defined by supported commands,
// not unknown algorithms or firmware extensions.
func checkRequestParameters(request []byte) error {
	if commands.CommandType(request[0]) == commands.CommandTypeGetPseudoRandom && len(request) == 5 &&
		int(binary.BigEndian.Uint16(request[3:])) > commands.MaxCommandDataLength {
		return errors.New("requested random response exceeds the secure message length limit")
	}
	wrapOverhead := commands.WrapNonceLength + commands.WrapDataPrefixLength + commands.WrapMACLength
	if commands.CommandType(request[0]) == commands.CommandTypeWrapData && len(request) >= 5 &&
		len(request)-5 > commands.MaxCommandDataLength-wrapOverhead {
		return errors.New("requested wrapped response exceeds the secure message length limit")
	}
	return nil
}

func checkResponseParameters(request, response []byte) error {
	if response[0] == byte(commands.ErrorResponseCode-commands.ResponseCommandOffset) {
		return nil // Card errors are not successful short/random/key responses.
	}
	requestBody, responseBody := request[3:], response[3:]
	switch commands.CommandType(request[0]) {
	case commands.CommandTypeEcho:
		if !bytes.Equal(requestBody, responseBody) {
			return errors.New("echo response does not match the requested data")
		}
	case commands.CommandTypeGetPseudoRandom:
		if len(requestBody) == 2 && len(responseBody) != int(binary.BigEndian.Uint16(requestBody)) {
			return errors.New("random response length does not match the requested count")
		}
	case commands.CommandTypeGetObjectInfo:
		if len(requestBody) == 3 && len(responseBody) == binary.Size(commands.ObjectInfoResponse{}) {
			if binary.BigEndian.Uint16(requestBody[:2]) != binary.BigEndian.Uint16(responseBody[8:10]) {
				return errors.New("object metadata ID does not match the requested ID")
			}
			// Do not guess how firmware-specific pseudo/public types map to
			// descriptors; exact type binding covers the supported native types.
			kind := requestBody[2]
			if kind >= commands.ObjectTypeOpaque && kind <= commands.ObjectTypeOtpAeadKey && responseBody[14] != kind {
				return errors.New("object metadata type does not match the requested type")
			}
		}
	case commands.CommandTypeWrapData:
		overhead := commands.WrapNonceLength + commands.WrapDataPrefixLength + commands.WrapMACLength
		if len(requestBody) >= 2 && len(responseBody) != len(requestBody)-2+overhead {
			return errors.New("wrapped response length does not match the requested data")
		}
	case commands.CommandTypeUnwrapData:
		overhead := 2 + commands.WrapNonceLength + commands.WrapDataPrefixLength + commands.WrapMACLength
		if len(requestBody) >= overhead && len(responseBody) != len(requestBody)-overhead {
			return errors.New("unwrapped response length does not match the requested data")
		}
	case commands.CommandTypeGenerateAsymmetricKey, commands.CommandTypePutAsymmetric,
		commands.CommandTypeGenerateWrapKey, commands.CommandTypePutWrapKey,
		commands.CommandTypePutAuthKey, commands.CommandTypePutOpaque,
		commands.CommandTypeChangeAuthenticationKey:
		if len(requestBody) >= 2 && len(responseBody) == 2 {
			requestedID := binary.BigEndian.Uint16(requestBody[:2])
			if requestedID != 0 && binary.BigEndian.Uint16(responseBody) != requestedID {
				return errors.New("response object ID does not match the requested ID")
			}
		}
	}
	return nil
}

// SendEncryptedCommand sends an encrypted and authenticated command to the HSM
// and returns the decrypted, parsed response.
func (s *SecureChannel) SendEncryptedCommand(c *commands.CommandMessage) (commands.Response, error) {
	s.channelLock.Lock()
	defer s.channelLock.Unlock()

	return s.sendEncryptedCommandLocked(c)
}

func (s *SecureChannel) failSessionLocked(err error) (commands.Response, error) {
	s.SecurityLevel = SecurityLevelInvalid
	s.clearSessionSecretsLocked()
	return nil, err
}

func (s *SecureChannel) sendEncryptedCommandLocked(c *commands.CommandMessage) (commands.Response, error) {
	if c == nil {
		return nil, errors.New("command must not be nil")
	}
	if s.SecurityLevel != SecurityLevelAuthenticated {
		return nil, errors.New("the session is not authenticated")
	}
	if c.SessionID != nil || len(c.MAC) != 0 {
		return nil, errors.New("encrypted inner command must not contain session framing")
	}
	if len(c.Data) > commands.MaxCommandDataLength {
		return nil, errors.New("command data exceeds the HSM message length limit")
	}
	if s.Counter >= MaxMessagesPerSession {
		return s.failSessionLocked(errors.New("channel has reached its message limit; please recreate"))
	}
	if s.keyChain == nil {
		return s.failSessionLocked(errors.New("session key chain is not initialized"))
	}

	block, err := aes.NewCipher(s.keyChain.EncKey)
	if err != nil {
		return s.failSessionLocked(err)
	}

	// Encrypt the padded counter to generate the IV.
	icv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint32(icv[12:], s.Counter)
	iv := make([]byte, aes.BlockSize)
	block.Encrypt(iv, icv)

	commandData, err := c.Serialize()
	if err != nil {
		return nil, err
	}
	defer wipeBytes(commandData)
	if err := checkRequestParameters(commandData); err != nil {
		return nil, err
	}
	paddedCommand := pad(commandData)
	defer wipeBytes(paddedCommand)
	if len(paddedCommand) > commands.MaxSessionMessageDataLength {
		return nil, errors.New("encrypted command exceeds the HSM message length limit")
	}
	encryptedCommand := make([]byte, len(paddedCommand))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encryptedCommand, paddedCommand)

	resp, err := s.sendMACCommand(&commands.CommandMessage{
		CommandType: commands.CommandTypeSessionMessage,
		Data:        encryptedCommand,
	})
	if err != nil {
		return s.failSessionLocked(err)
	}

	sessionMessage, ok := resp.(*commands.SessionMessageResponse)
	if !ok || sessionMessage == nil {
		return s.failSessionLocked(errors.New("invalid session message response type"))
	}

	expectedMAC, err := s.calculateMAC(&commands.CommandMessage{
		CommandType: commands.CommandTypeSessionMessage + commands.ResponseCommandOffset,
		SessionID:   &sessionMessage.SessionID,
		Data:        sessionMessage.EncryptedData,
	}, MessageTypeResponse)
	if err != nil {
		return s.failSessionLocked(err)
	}
	if len(expectedMAC) < MACLength || len(sessionMessage.MAC) != MACLength ||
		subtle.ConstantTimeCompare(expectedMAC[:MACLength], sessionMessage.MAC) != 1 {
		return s.failSessionLocked(errors.New("invalid response MAC"))
	}
	if sessionMessage.SessionID != s.ID {
		return s.failSessionLocked(errors.New("response session ID does not match the active session"))
	}
	if len(sessionMessage.EncryptedData) == 0 || len(sessionMessage.EncryptedData)%aes.BlockSize != 0 {
		return s.failSessionLocked(errors.New("invalid encrypted response length"))
	}

	decryptedBuffer := make([]byte, len(sessionMessage.EncryptedData))
	defer wipeBytes(decryptedBuffer)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decryptedBuffer, sessionMessage.EncryptedData)
	decryptedResponse, err := unpad(decryptedBuffer)
	if err != nil {
		return s.failSessionLocked(err)
	}

	// Once a response has a valid RMAC, block length, and padding, the HSM has
	// consumed this counter even when the inner command reports an error.
	s.Counter++
	if err := checkResponseCommand(commands.CommandType(commandData[0]), decryptedResponse); err != nil {
		return s.failSessionLocked(err)
	}
	if err := checkResponseParameters(commandData, decryptedResponse); err != nil {
		return s.failSessionLocked(err)
	}
	resp, err = commands.ParseResponse(decryptedResponse)
	commandType := commands.CommandType(commandData[0])
	if commandType == commands.CommandTypeCloseSession || commandType == commands.CommandTypeReset {
		if err == nil {
			s.SecurityLevel = SecurityLevelClosed
			s.clearSessionSecretsLocked()
		} else {
			var cardErr *commands.Error
			if !errors.As(err, &cardErr) {
				return s.failSessionLocked(err)
			}
		}
	}
	return resp, err
}

// MessageCount returns the current SCP03 message counter. It starts at one
// after authentication and advances after each authenticated response.
func (s *SecureChannel) MessageCount() uint32 {
	s.channelLock.Lock()
	defer s.channelLock.Unlock()
	return s.Counter
}

// IsHealthy reports whether the channel is authenticated and safe to reuse.
func (s *SecureChannel) IsHealthy() bool {
	s.channelLock.Lock()
	defer s.channelLock.Unlock()
	return s.SecurityLevel == SecurityLevelAuthenticated
}

// Close closes an authenticated HSM session. It is safe to call more than once.
func (s *SecureChannel) Close() error {
	s.channelLock.Lock()
	defer s.channelLock.Unlock()

	if s.SecurityLevel == SecurityLevelClosed {
		return nil
	}
	if s.SecurityLevel != SecurityLevelAuthenticated {
		s.SecurityLevel = SecurityLevelClosed
		s.clearSessionSecretsLocked()
		return nil
	}

	// Close always finalizes local secrets, even if the device rejects CLOSE
	// or the transport cannot confirm that it arrived. Never retry an
	// uncertain CLOSE using the same secure-channel state.
	defer func() {
		s.SecurityLevel = SecurityLevelClosed
		s.clearSessionSecretsLocked()
	}()
	command, err := commands.CreateCloseSessionCommand()
	if err != nil {
		return err
	}
	_, err = s.sendEncryptedCommandLocked(command)
	return err
}

// sendMACCommand sends a MAC authenticated command to the HSM and returns a parsed response
func (s *SecureChannel) sendMACCommand(c *commands.CommandMessage) (commands.Response, error) {
	if c == nil {
		return nil, errors.New("command must not be nil")
	}

	// Use detached values so a custom connector cannot mutate the channel's
	// session ID or MAC chaining state through the command it receives.
	sessionID := s.ID
	c.SessionID = &sessionID

	// Calculate MAC for the command
	sum, err := s.calculateMAC(c, MessageTypeCommand)
	if err != nil {
		return nil, err
	}

	// Update chain value and command MAC using independent backing arrays.
	s.MACChainValue = append(s.MACChainValue[:0], sum...)
	c.MAC = append([]byte(nil), sum[:MACLength]...)

	return s.sendCommandLocked(c)
}

// calculateMAC calculates the authenticated MAC for a command or response.
// This is stateful since it uses the MACChainValue.
func (s *SecureChannel) calculateMAC(c *commands.CommandMessage, messageType MessageType) ([]byte, error) {
	if c == nil {
		return nil, errors.New("command must not be nil")
	}
	if c.SessionID == nil {
		return nil, errors.New("command session ID must not be nil")
	}
	if *c.SessionID > commands.MaxSessionID {
		return nil, errors.New("invalid session ID")
	}
	if len(s.MACChainValue) != aes.BlockSize {
		return nil, errors.New("invalid MAC chain value length")
	}
	if s.keyChain == nil {
		return nil, errors.New("session key chain is not initialized")
	}
	macBodyLength := 1 + len(c.Data) + MACLength
	if macBodyLength > int(^uint16(0)) {
		return nil, errors.New("command data is too large for MAC framing")
	}

	// Select the right key
	var key []byte
	switch messageType {
	case MessageTypeCommand:
		key = s.keyChain.MACKey
	case MessageTypeResponse:
		key = s.keyChain.RMACKey
	default:
		return nil, errors.New("invalid messageType")
	}

	// Setup CMAC using aes
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, err
	}

	// Setup a buffer for the cmac data
	buffer := new(bytes.Buffer)

	// Write the MacChainValue
	buffer.Write(s.MACChainValue)

	// bytes.Buffer writes cannot fail, and all values below have fixed size.
	buffer.WriteByte(byte(c.CommandType))

	// Write length
	if err := binary.Write(buffer, binary.BigEndian, uint16(macBodyLength)); err != nil { // #nosec G115 -- bounded above.
		return nil, err
	}

	// Write sessionID
	buffer.WriteByte(*c.SessionID)

	// Write data
	buffer.Write(c.Data)

	// Write buffer to MAC.
	if _, err := mac.Write(buffer.Bytes()); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// updateKeychain derives and stores the session keys.
func (s *SecureChannel) updateKeychain() error {
	keyChain := &KeyChain{}

	encKey, err := s.deriveKDF(s.AuthKey.GetEncKey(), DerivationConstantEncKey, KeyLength)
	if err != nil {
		return err
	}
	keyChain.EncKey = encKey

	macKey, err := s.deriveKDF(s.AuthKey.GetMacKey(), DerivationConstantMACKey, KeyLength)
	if err != nil {
		return err
	}
	keyChain.MACKey = macKey

	rmacKey, err := s.deriveKDF(s.AuthKey.GetMacKey(), DerivationConstantRMACKey, KeyLength)
	if err != nil {
		return err
	}
	keyChain.RMACKey = rmacKey

	s.keyChain = keyChain
	return nil
}

// deriveKDF derives a key using SCP03's KDF.
// derivationConstant and keyLen define which key to derive.
func (s *SecureChannel) deriveKDF(key []byte, derivationConstant KeyDerivationConstant, keyLen uint8) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, errors.New("invalid derivation key length; should be 16")
	}
	if keyLen == 0 || keyLen > aes.BlockSize {
		return nil, errors.New("invalid derived key length")
	}

	if len(s.HostChallenge) != ChallengeLength {
		return nil, errors.New("invalid HostChallenge length; should be 8")
	}

	if len(s.DeviceChallenge) != ChallengeLength {
		return nil, errors.New("invalid DeviceChallenge length; should be 8")
	}

	derivationData := new(bytes.Buffer)
	derivationData.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(derivationConstant)})

	derivationData.WriteByte(0x00)

	if err := binary.Write(derivationData, binary.BigEndian, uint16(keyLen*8)); err != nil {
		return nil, err
	}

	derivationData.WriteByte(0x01)
	derivationData.Write(s.HostChallenge)
	derivationData.Write(s.DeviceChallenge)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, err
	}

	if _, err := mac.Write(derivationData.Bytes()); err != nil {
		return nil, err
	}
	kdf := mac.Sum(nil)
	derived := make([]byte, int(keyLen))
	copy(derived, kdf)
	wipeBytes(kdf)
	return derived, nil
}
