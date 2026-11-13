package connector

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/certusone/yubihsm-go/commands"
)

// ErrInvalidResponseValueLength indicates a malformed connector status response.
var ErrInvalidResponseValueLength = errors.New("invalid response value length")

const (
	// DefaultHTTPTimeout bounds connector requests made by NewHTTPConnector.
	DefaultHTTPTimeout             = 30 * time.Second
	maxConnectorResponseSize       = commands.MaxMessageLength
	maxConnectorStatusSize         = 4 << 10
	maxConnectorResponseHeaderSize = 64 << 10
)

var defaultHTTPClient = newDefaultHTTPClient()

func newDefaultHTTPClient() *http.Client {
	// Do not type-assert or inherit http.DefaultTransport: applications can
	// replace it with a custom RoundTripper or disable its TLS verification.
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxConnectorResponseHeaderSize,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   DefaultHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type (
	// HTTPConnector implements the HTTP based connection with the YubiHSM2 connector.
	// Its shape is kept compatible with earlier releases; use
	// NewHTTPConnectorWithClient when a custom HTTP client is required.
	HTTPConnector struct {
		URL string
	}

	// HTTPClientConnector is an HTTP connector with a caller-supplied client.
	HTTPClientConnector struct {
		URL    string
		Client *http.Client
	}
)

// NewHTTPConnector creates a new HTTPConnector. url may be either host:port or
// a complete http/https base URL. The default client enforces a timeout,
// requires TLS 1.2 or newer for HTTPS, and does not follow redirects.
func NewHTTPConnector(url string) *HTTPConnector {
	return &HTTPConnector{URL: url}
}

// NewHTTPConnectorWithClient creates a connector using the supplied HTTP client.
func NewHTTPConnectorWithClient(url string, client *http.Client) *HTTPClientConnector {
	return &HTTPClientConnector{URL: url, Client: client}
}

func connectorEndpoint(baseURL, path string) (string, error) {
	base := strings.TrimSpace(baseURL)
	if base == "" {
		return "", errors.New("connector URL must not be empty")
	}
	lowerBase := strings.ToLower(base)
	if !strings.HasPrefix(lowerBase, "http://") && !strings.HasPrefix(lowerBase, "https://") {
		if strings.Contains(base, "://") {
			return "", errors.New("connector URL must use http or https")
		}
		base = "http://" + base
	}

	parsed, err := url.Parse(base)
	if err != nil || parsed.Hostname() == "" {
		return "", errors.New("invalid connector URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("connector URL must use http or https")
	}
	// Append in escaped form: an encoded trailing slash belongs to the base
	// path component, unlike a literal separator. Derive Path from RawPath so
	// url.URL.String cannot silently discard a now-inconsistent escape form.
	escapedPath := strings.TrimRight(parsed.EscapedPath(), "/") + path
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return "", errors.New("invalid connector URL path")
	}
	parsed.Path = decodedPath
	parsed.RawPath = escapedPath
	parsed.Fragment = ""
	return parsed.String(), nil
}

func connectorHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return defaultHTTPClient
}

// Request encodes and executes a command on the HSM and returns the binary response.
func (c *HTTPConnector) Request(command *commands.CommandMessage) ([]byte, error) {
	if c == nil {
		return nil, errors.New("connector must not be nil")
	}
	return request(c.URL, defaultHTTPClient, command)
}

// GetStatus requests and parses /connector/status.
func (c *HTTPConnector) GetStatus() (*StatusResponse, error) {
	if c == nil {
		return nil, errors.New("connector must not be nil")
	}
	return getStatus(c.URL, defaultHTTPClient)
}

// Request encodes and executes a command using the configured HTTP client.
func (c *HTTPClientConnector) Request(command *commands.CommandMessage) ([]byte, error) {
	if c == nil {
		return nil, errors.New("connector must not be nil")
	}
	return request(c.URL, connectorHTTPClient(c.Client), command)
}

// GetStatus requests and parses /connector/status using the configured client.
func (c *HTTPClientConnector) GetStatus() (*StatusResponse, error) {
	if c == nil {
		return nil, errors.New("connector must not be nil")
	}
	return getStatus(c.URL, connectorHTTPClient(c.Client))
}

func request(baseURL string, client *http.Client, command *commands.CommandMessage) (data []byte, err error) {
	if command == nil {
		return nil, errors.New("command must not be nil")
	}

	requestData, err := command.Serialize()
	if err != nil {
		return nil, err
	}
	// The transport owns the request body's lifetime and may read it after Do
	// returns. Do not wipe or reuse requestData when the response is closed.
	endpoint, err := connectorEndpoint(baseURL, "/connector/api")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := res.Body.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-OK status code %d", res.StatusCode)
	}

	data, err = io.ReadAll(io.LimitReader(res.Body, maxConnectorResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConnectorResponseSize {
		return nil, errors.New("connector response exceeds the protocol length limit")
	}
	return data, nil
}

func getStatus(baseURL string, client *http.Client) (status *StatusResponse, err error) {
	endpoint, err := connectorEndpoint(baseURL, "/connector/status")
	if err != nil {
		return nil, err
	}

	res, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := res.Body.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-OK status code %d", res.StatusCode)
	}

	statusBody, err := io.ReadAll(io.LimitReader(res.Body, maxConnectorStatusSize+1))
	if err != nil {
		return nil, err
	}
	if len(statusBody) > maxConnectorStatusSize {
		return nil, errors.New("connector status response is too large")
	}

	values := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(statusBody))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		pair := strings.SplitN(line, "=", 2)
		if len(pair) != 2 {
			return nil, ErrInvalidResponseValueLength
		}
		key := strings.ToLower(strings.TrimSpace(pair[0]))
		if key == "" {
			return nil, ErrInvalidResponseValueLength
		}
		if _, exists := values[key]; exists {
			return nil, ErrInvalidResponseValueLength
		}
		values[key] = strings.TrimSpace(pair[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	required := []string{"status", "serial", "version", "pid", "address", "port"}
	for _, key := range required {
		// An empty address is valid when the connector listens on :port.
		if value, ok := values[key]; !ok || (value == "" && key != "address") {
			return nil, ErrInvalidResponseValueLength
		}
	}

	return &StatusResponse{
		Status:  Status(values["status"]),
		Serial:  values["serial"],
		Version: values["version"],
		Pid:     values["pid"],
		Address: values["address"],
		Port:    values["port"],
	}, nil
}
