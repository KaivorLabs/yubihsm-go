package securechannel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

type transcriptStep struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

type transcriptConnector struct {
	steps []transcriptStep
	index int
}

func (c *transcriptConnector) Request(command *commands.CommandMessage) ([]byte, error) {
	if c.index >= len(c.steps) {
		return nil, errors.New("unexpected request after transcript ended")
	}
	request, err := command.Serialize()
	if err != nil {
		return nil, err
	}
	step := c.steps[c.index]
	if got := hex.EncodeToString(request); got != step.Request {
		return nil, fmt.Errorf("transcript step %d: request %s, want %s", c.index, got, step.Request)
	}
	c.index++
	return hex.DecodeString(step.Response)
}

func (*transcriptConnector) GetStatus() (*connector.StatusResponse, error) {
	return nil, errors.New("transcript has no status endpoint")
}

func TestIndependentSCP03Transcript(t *testing.T) {
	// Unlike the emulator tests, this connector does not calculate any MAC,
	// KDF, IV, padding, or ciphertext using the implementation under test.
	data, err := os.ReadFile("testdata/scp03.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		AuthKey       string           `json:"auth_key"`
		HostChallenge string           `json:"host_challenge"`
		Steps         []transcriptStep `json:"steps"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(fixture.AuthKey)
	if err != nil {
		t.Fatal(err)
	}
	hostChallenge, err := hex.DecodeString(fixture.HostChallenge)
	if err != nil {
		t.Fatal(err)
	}
	c := &transcriptConnector{steps: fixture.Steps}
	channel, err := NewSecureChannelWithAuthKey(c, 1, authkey.AuthKey(key))
	if err != nil {
		t.Fatal(err)
	}
	channel.HostChallenge = hostChallenge
	if err := channel.Authenticate(); err != nil {
		t.Fatal(err)
	}

	message := []byte("independent transcript")
	command, err := commands.CreateEchoCommand(message)
	if err != nil {
		t.Fatal(err)
	}
	response, err := channel.SendEncryptedCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := response.(*commands.EchoResponse)
	if !ok || !bytes.Equal(echo.Data, message) {
		t.Fatalf("unexpected echo: %#v", response)
	}
	command, err = commands.CreateGetOpaqueCommand(0xffff)
	if err != nil {
		t.Fatal(err)
	}
	_, err = channel.SendEncryptedCommand(command)
	var cardErr *commands.Error
	if !errors.As(err, &cardErr) || cardErr.Code != commands.ErrorCodeObjectNotFound {
		t.Fatalf("unexpected card error: %v", err)
	}
	if !channel.IsHealthy() || channel.MessageCount() != 3 {
		t.Fatal("valid card error damaged channel synchronization")
	}
	if err := channel.Close(); err != nil {
		t.Fatal(err)
	}
	if c.index != len(c.steps) || channel.IsHealthy() || channel.keyChain != nil {
		t.Fatal("transcript did not finish with a closed, cleared session")
	}
}
