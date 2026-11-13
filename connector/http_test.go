package connector

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

func TestDefaultHTTPClientSecurityPolicy(t *testing.T) {
	transport, ok := defaultHTTPClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("default connector has no TLS policy")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = 0x%x", transport.TLSClientConfig.MinVersion)
	}
	if transport.MaxResponseHeaderBytes != maxConnectorResponseHeaderSize {
		t.Fatalf("maximum response header size = %d", transport.MaxResponseHeaderBytes)
	}
	if defaultHTTPClient.CheckRedirect == nil {
		t.Fatal("default connector has no redirect policy")
	}
}

func TestConnectorEndpoint(t *testing.T) {
	endpoint, err := connectorEndpoint("localhost:1234/base/?ignored=true", "/connector/api")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "http://localhost:1234/base/connector/api?ignored=true" {
		t.Fatalf("endpoint = %q", endpoint)
	}
	if _, err := connectorEndpoint("ftp://localhost/device", "/connector/api"); err == nil {
		t.Fatal("unsupported URL scheme was accepted")
	}
}

func TestHTTPConnectorRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connector/api" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("content type = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
			return
		}
		want := []byte{byte(commands.CommandTypeEcho), 0x00, 0x02, 0xaa, 0xbb}
		if !bytes.Equal(body, want) {
			t.Errorf("request body = %x, want %x", body, want)
		}
		w.Write([]byte{0x81, 0x00, 0x00})
	}))
	defer server.Close()

	connector := NewHTTPConnectorWithClient(server.URL+"/", server.Client())
	response, err := connector.Request(&commands.CommandMessage{
		CommandType: commands.CommandTypeEcho,
		Data:        []byte{0xaa, 0xbb},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, []byte{0x81, 0x00, 0x00}) {
		t.Fatalf("response = %x", response)
	}
}

func TestHTTPClientConnectorSupportsHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte{0x81, 0x00, 0x00})
	}))
	defer server.Close()

	connector := NewHTTPConnectorWithClient(server.URL, server.Client())
	if _, err := connector.Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho}); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultHTTPConnectorRejectsRedirects(t *testing.T) {
	targetHit := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHit <- struct{}{}
	}))
	defer target.Close()

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	connector := NewHTTPConnector(redirect.URL)
	if _, err := connector.Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho}); err == nil {
		t.Fatal("redirect response was accepted")
	}
	select {
	case <-targetHit:
		t.Fatal("default connector followed a redirect")
	default:
	}
}

func TestHTTPConnectorGetStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connector/status" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Write([]byte("version=3.0.0\nstatus=OK\nport=12345\nserial=123456\naddress=127.0.0.1\npid=42\n"))
	}))
	defer server.Close()

	connector := NewHTTPConnectorWithClient(server.URL, server.Client())
	status, err := connector.GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != "OK" || status.Serial != "123456" || status.Version != "3.0.0" ||
		status.Pid != "42" || status.Address != "127.0.0.1" || status.Port != "12345" {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestHTTPConnectorAcceptsMaximumResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, maxConnectorResponseSize))
	}))
	defer server.Close()

	connector := NewHTTPConnectorWithClient(server.URL, server.Client())
	response, err := connector.Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho})
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != maxConnectorResponseSize {
		t.Fatalf("response length = %d", len(response))
	}
}

func TestHTTPConnectorRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, maxConnectorResponseSize+1))
	}))
	defer server.Close()

	connector := NewHTTPConnectorWithClient(server.URL, server.Client())
	if _, err := connector.Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho}); err == nil {
		t.Fatal("oversized connector response was accepted")
	}
}

func TestHTTPConnectorRejectsBadResponses(t *testing.T) {
	t.Run("HTTP status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		connector := NewHTTPConnectorWithClient(server.URL, server.Client())
		if _, err := connector.GetStatus(); err == nil {
			t.Fatal("non-OK status was accepted")
		}
	})

	t.Run("oversized status body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write(make([]byte, maxConnectorStatusSize+1))
		}))
		defer server.Close()

		connector := NewHTTPConnectorWithClient(server.URL, server.Client())
		if _, err := connector.GetStatus(); err == nil {
			t.Fatal("oversized status response was accepted")
		}
	})

	t.Run("duplicate status field", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("status=OK\nstatus=NO_DEVICE\nserial=*\nversion=1\npid=1\naddress=127.0.0.1\nport=1234\n"))
		}))
		defer server.Close()

		connector := NewHTTPConnectorWithClient(server.URL, server.Client())
		if _, err := connector.GetStatus(); err != ErrInvalidResponseValueLength {
			t.Fatalf("error = %v, want %v", err, ErrInvalidResponseValueLength)
		}
	})

	t.Run("empty status field", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("status=\nserial=*\nversion=1\npid=1\naddress=127.0.0.1\nport=1234\n"))
		}))
		defer server.Close()

		connector := NewHTTPConnectorWithClient(server.URL, server.Client())
		if _, err := connector.GetStatus(); err != ErrInvalidResponseValueLength {
			t.Fatalf("error = %v, want %v", err, ErrInvalidResponseValueLength)
		}
	})

	t.Run("missing status fields", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("status=OK\nserial=123\n"))
		}))
		defer server.Close()

		connector := NewHTTPConnectorWithClient(server.URL, server.Client())
		if _, err := connector.GetStatus(); err != ErrInvalidResponseValueLength {
			t.Fatalf("error = %v, want %v", err, ErrInvalidResponseValueLength)
		}
	})
}
