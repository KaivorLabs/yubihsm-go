package connector

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRequestBodyRemainsValidUntilTransportClosesIt(t *testing.T) {
	// RoundTripper may read/close the request body asynchronously, even after
	// the response has been consumed. Delay the read to make this deterministic.
	var request *http.Request
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		request = r
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("\x81\x00\x00")),
		}, nil
	})}
	command, err := commands.CreateEchoCommand([]byte("late read"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := command.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPConnectorWithClient("http://localhost", client).Request(command); err != nil {
		t.Fatal(err)
	}
	defer request.Body.Close()
	got, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("transport saw corrupted request body: %x, want %x", got, want)
	}
}

func TestGetStatusAllowsWildcardListenAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("status=NO_DEVICE\nserial=*\nversion=3.0.0\npid=42\naddress=\nport=1234\n"))
	}))
	defer server.Close()
	status, err := NewHTTPConnectorWithClient(server.URL, server.Client()).GetStatus()
	if err != nil {
		t.Fatal(err)
	}
	if status.Address != "" || status.Status != "NO_DEVICE" {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestEndpointPreservesEscapingAndQuery(t *testing.T) {
	got, err := connectorEndpoint("https://localhost:1234/proxy%2Fhsm/?token=example#fragment", "/connector/api")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://localhost:1234/proxy%2Fhsm/connector/api?token=example"
	if got != want {
		t.Fatalf("endpoint = %q, want %q", got, want)
	}
	if _, err := connectorEndpoint("http://:1234", "/connector/api"); err == nil {
		t.Fatal("URL without a hostname was accepted")
	}
}

func TestEndpointPreservesEncodedTrailingSlash(t *testing.T) {
	for _, base := range []string{
		"https://localhost/proxy%2F",
		"https://localhost/proxy%2F/",
	} {
		got, err := connectorEndpoint(base, "/connector/api")
		if err != nil {
			t.Fatal(err)
		}
		want := "https://localhost/proxy%2F/connector/api"
		if got != want {
			t.Fatalf("endpoint for %q = %q, want %q", base, got, want)
		}
	}
}

func TestEncodedEndpointReachesServerWithoutRewriting(t *testing.T) {
	uri := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uri <- r.RequestURI
		_, _ = w.Write([]byte{0x81, 0, 0})
	}))
	defer server.Close()
	c := NewHTTPConnectorWithClient(server.URL+"/proxy%2F?token=public-test-token", server.Client())
	if _, err := c.Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho}); err != nil {
		t.Fatal(err)
	}
	want := "/proxy%2F/connector/api?token=public-test-token"
	if got := <-uri; got != want {
		t.Fatalf("wire request URI = %q, want %q", got, want)
	}
}

func TestDefaultClientDoesNotDependOnGlobalTransportType(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("global transport must not be used")
		return nil, nil
	})
	client := newDefaultHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify ||
		transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatal("default client must own a verifying TLS transport")
	}
	transport.CloseIdleConnections()
}
