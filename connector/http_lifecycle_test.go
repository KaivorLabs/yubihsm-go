package connector

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/certusone/yubihsm-go/commands"
)

type lifecycleBody struct {
	reader    io.Reader
	readErr   error
	closeErr  error
	readCalls int
	closes    int
}

func (b *lifecycleBody) Read(data []byte) (int, error) {
	b.readCalls++
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.reader.Read(data)
}

func (b *lifecycleBody) Close() error {
	b.closes++
	return b.closeErr
}

func TestHTTPResponseBodyLifecycle(t *testing.T) {
	readErr := errors.New("test body read failure")
	closeErr := errors.New("test body close failure")
	for _, endpoint := range []string{"command", "status"} {
		for _, tc := range []struct {
			name       string
			statusCode int
			readErr    error
			closeErr   error
			wantErr    error
		}{
			{"success", http.StatusOK, nil, nil, nil},
			{"read failure", http.StatusOK, readErr, closeErr, readErr},
			{"close failure", http.StatusOK, nil, closeErr, closeErr},
			{"HTTP status failure", http.StatusServiceUnavailable, nil, closeErr, nil},
		} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				payload := []byte{0x81, 0, 0}
				if endpoint == "status" {
					payload = []byte("status=OK\nserial=*\nversion=1\npid=1\naddress=\nport=1234\n")
				}
				body := &lifecycleBody{reader: bytes.NewReader(payload), readErr: tc.readErr, closeErr: tc.closeErr}
				client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					// A RoundTripper owns closing its request body, independently of
					// the response body whose lifecycle is under test here.
					if req.Body != nil {
						if err := req.Body.Close(); err != nil {
							return nil, err
						}
					}
					return &http.Response{StatusCode: tc.statusCode, Header: make(http.Header), Body: body}, nil
				})}
				c := NewHTTPConnectorWithClient("http://localhost", client)
				var err error
				if endpoint == "command" {
					_, err = c.Request(&commands.CommandMessage{CommandType: commands.CommandTypeEcho})
				} else {
					_, err = c.GetStatus()
				}
				if tc.statusCode != http.StatusOK {
					if err == nil || errors.Is(err, closeErr) || body.readCalls != 0 {
						t.Fatalf("HTTP failure was lost or its body read unexpectedly: %v", err)
					}
				} else if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				if body.closes != 1 {
					t.Fatalf("response body close count = %d, want one", body.closes)
				}
			})
		}
	}
}
