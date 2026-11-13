package yubihsm

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/connector"
)

type sessionLogSink chan string

func (s sessionLogSink) Write(data []byte) (int, error) {
	select {
	case s <- string(data):
	default:
	}
	return len(data), nil
}

func TestBackgroundSwapLogDoesNotExposeConnectorCredentials(t *testing.T) {
	const secret = "public-test-query-credential"
	sink := make(sessionLogSink, 10)
	original := log.Writer()
	log.SetOutput(sink)
	defer log.SetOutput(original)
	session := &fakeManagedSession{}
	originalError := &url.Error{
		Op:  "Post",
		URL: "https://user:password@example.invalid/private/" + secret + "?token=" + secret,
		Err: errors.New("public test connection failure"),
	}
	// Include a sensitive outer wrapper too: recognizing the URL error must
	// omit the entire formatted chain from process-global background logs.
	reportedError := fmt.Errorf("public wrapper %s: %w", secret, originalError)
	manager := &SessionManager{
		session: session,
		done:    make(chan struct{}),
		newSession: &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
			return nil, reportedError
		}},
	}
	defer manager.Destroy()
	manager.startProactiveSwap(session)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case entry := <-sink:
			if !strings.Contains(entry, "proactive session swap failed") {
				continue
			}
			if strings.Contains(entry, secret) || strings.Contains(entry, "user:password") {
				t.Fatal("background error logging exposed connector URL credentials")
			}
			if err := manager.swapSession(); err != reportedError || !errors.Is(err, originalError) {
				t.Fatal("logging protection changed the error returned to the caller")
			}
			if !strings.Contains(originalError.URL, secret) {
				t.Fatal("logging protection mutated the caller-visible URL error")
			}
			return
		case <-deadline.C:
			t.Fatal("background swap failure was not logged")
		}
	}
}
