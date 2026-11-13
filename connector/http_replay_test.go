package connector

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

// Exercise the real local net/http transport, not a RoundTripper stub. The
// second POST is fully consumed on a reused connection before its response is
// lost: it must never be replayed as if the HSM had not executed the command.
func TestHTTPTransportDoesNotReplayConsumedCommand(t *testing.T) {
	var lock sync.Mutex
	var addresses []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if r.Method != http.MethodPost || !bytes.Equal(body, []byte{0x01, 0, 1, 0xaa}) {
			t.Errorf("unexpected command method/body: %s %x", r.Method, body)
		}
		lock.Lock()
		addresses = append(addresses, r.RemoteAddr)
		n := len(addresses)
		lock.Unlock()
		if n == 2 {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
			return
		}
		if _, err := w.Write([]byte{0x81, 0, 1, 0xaa}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	c := NewHTTPConnector(server.URL)
	command := &commands.CommandMessage{CommandType: commands.CommandTypeEcho, Data: []byte{0xaa}}
	if _, err := c.Request(command); err != nil {
		t.Fatalf("warmup command: %v", err)
	}
	if _, err := c.Request(command); err == nil {
		t.Fatal("lost command response was replayed or reported as success")
	}
	lock.Lock()
	defer lock.Unlock()
	if len(addresses) != 2 {
		t.Fatalf("server received %d POSTs, want exactly two including warmup", len(addresses))
	}
	if addresses[0] != addresses[1] {
		t.Fatal("test did not exercise a reused connection")
	}
}
