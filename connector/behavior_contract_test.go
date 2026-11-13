package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/certusone/yubihsm-go/commands"
)

func TestDefaultConnectorDoesNotInheritGlobalClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte{0x81, 0, 0})
	}))
	defer server.Close()
	original := http.DefaultClient
	defer func() { http.DefaultClient = original }()
	globalCalled := false
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		globalCalled = true
		return nil, nil
	})}
	if _, err := NewHTTPConnector(server.URL).Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho}); err != nil {
		t.Fatal(err)
	}
	if globalCalled {
		t.Fatal("default connector inherited global HTTP client configuration")
	}
}

func TestCustomClientRetainsItsExplicitPolicies(t *testing.T) {
	requests := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests <- struct{}{}
		_, _ = w.Write([]byte{0x81, 0, 0})
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client := redirect.Client()
	client.Timeout = 5 * time.Second
	transport := client.Transport
	// nil CheckRedirect deliberately uses Go's normal redirect policy.
	c := NewHTTPConnectorWithClient(redirect.URL, client)
	if _, err := c.Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-requests:
	default:
		t.Fatal("custom client's explicit redirect policy was overridden")
	}
	if client.Timeout != 5*time.Second || client.Transport != transport || client.CheckRedirect != nil {
		t.Fatal("connector changed caller-owned client policies")
	}
}
