package yubihsm_test

import (
	"testing"

	yubihsm "github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/certusone/yubihsm-go/securechannel"
)

// Compile-time source contracts from 3b1fcb9. These do NOT assert unchanged
// runtime semantics; intentional differences are listed in docs/compatibility.md.
var (
	_ func(connector.Connector, uint16, string) (*yubihsm.SessionManager, error)         = yubihsm.NewSessionManager
	_ func(connector.Connector, uint16, string) (*securechannel.SecureChannel, error)    = securechannel.NewSecureChannel
	_ func(string) *connector.HTTPConnector                                              = connector.NewHTTPConnector
	_ func(*yubihsm.SessionManager, *commands.CommandMessage) (commands.Response, error) = (*yubihsm.SessionManager).SendEncryptedCommand
	_ connector.Connector                                                                = (*connector.HTTPConnector)(nil)
	_                                                                                    = map[yubihsm.SessionManager]struct{}{} // Historical comparability, without copying a used mutex.
)

func TestLegacyHTTPConnectorShape(t *testing.T) {
	// Exact struct conversion verifies the old one-field layout, including
	// compatibility with downstream unkeyed literals, without vet warnings.
	type legacyHTTPConnector struct{ URL string }
	oldShape := legacyHTTPConnector(connector.HTTPConnector{URL: "localhost:1234"})
	if oldShape.URL != "localhost:1234" {
		t.Fatal("legacy URL field changed")
	}
}
