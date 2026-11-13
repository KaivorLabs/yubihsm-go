package commands

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type (
	CommandMessage struct {
		UUID        uint8
		CommandType CommandType
		SessionID   *uint8
		Data        []byte
		MAC         []byte
	}
)

const (
	maxCommandBodyLength = 1<<16 - 1
	// MaxSessionMessageDataLength is the maximum AES-block-aligned ciphertext
	// after subtracting the outer header, session ID, and truncated MAC.
	MaxSessionMessageDataLength = (MaxMessageLength - 3 - 1 - SessionMACLength) / 16 * 16
)

// BodyLength returns the encoded command body length. For an invalid command
// whose body cannot fit in the protocol's uint16 length field, it returns the
// largest representable value; Serialize returns the corresponding error.
func (c *CommandMessage) BodyLength() uint16 {
	if c == nil {
		return 0
	}

	length := len(c.Data) + len(c.MAC)
	if c.SessionID != nil {
		length++
	}
	if length > maxCommandBodyLength {
		return uint16(maxCommandBodyLength)
	}

	return uint16(length) // #nosec G115 -- length is bounded above.
}

func (c *CommandMessage) Serialize() ([]byte, error) {
	if c == nil {
		return nil, errors.New("command must not be nil")
	}
	if c.SessionID != nil && *c.SessionID > MaxSessionID {
		return nil, errors.New("invalid session ID")
	}
	if c.CommandType == CommandTypeSessionMessage {
		if len(c.Data) > MaxSessionMessageDataLength {
			return nil, errors.New("session message exceeds the HSM message length limit")
		}
	} else if len(c.Data) > MaxMessageLength-3 {
		return nil, errors.New("command data exceeds the HSM message length limit")
	}

	bodyLength := len(c.Data) + len(c.MAC)
	if c.SessionID != nil {
		bodyLength++
	}
	if bodyLength > MaxMessageLength-3 {
		return nil, errors.New("command frame exceeds the HSM message length limit")
	}

	buffer := bytes.NewBuffer(make([]byte, 0, 3+bodyLength))
	buffer.WriteByte(byte(c.CommandType))
	if err := binary.Write(buffer, binary.BigEndian, uint16(bodyLength)); err != nil {
		return nil, err
	}
	if c.SessionID != nil {
		buffer.WriteByte(*c.SessionID)
	}
	buffer.Write(c.Data)
	buffer.Write(c.MAC)

	return buffer.Bytes(), nil
}
