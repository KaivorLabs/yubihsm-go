package yubihsm

import (
	"bytes"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/certusone/yubihsm-go/securechannel"
)

type (
	// SessionManager manages a pool of authenticated secure sessions with a YubiHSM2
	SessionManager struct {
		session   *securechannel.SecureChannel
		lock      sync.Mutex
		connector connector.Connector
		authKeyID uint16
		password  string

		creationWait sync.WaitGroup
		destroyed    bool
		keepAlive    *time.Timer
		done         chan struct{}
		// swapping is 1 while swapSession runs; it is read and written
		// only through sync/atomic, by the keep-alive goroutine and by
		// the goroutine checkSessionHealth starts.
		swapping int32
	}
)

var (
	echoPayload = []byte("keepalive")
)

const (
	pingInterval = 15 * time.Second
)

// NewSessionManager creates a new instance of the SessionManager with poolSize connections.
// Wait on channel Connected with a timeout to wait for active connections to be ready.
func NewSessionManager(connector connector.Connector, authKeyID uint16, password string) (*SessionManager, error) {
	manager := &SessionManager{
		connector: connector,
		authKeyID: authKeyID,
		password:  password,
		destroyed: false,
		done:      make(chan struct{}),
	}

	err := manager.swapSession()
	if err != nil {
		return nil, err
	}

	manager.keepAlive = time.NewTimer(pingInterval)
	go manager.pingRoutine()

	return manager, err
}

func (s *SessionManager) pingRoutine() {
	// Exit when Destroy closes s.done. time.Timer.Stop alone does not
	// close keepAlive.C, so a bare `for range s.keepAlive.C` would
	// block forever after Destroy.
	for {
		select {
		case <-s.done:
			return
		case <-s.keepAlive.C:
		}

		command, _ := commands.CreateEchoCommand(echoPayload)

		resp, err := s.SendEncryptedCommand(command)
		if err == nil {
			err = checkEcho(resp)
		}
		if err != nil {
			// The session is dead or answered with something other than
			// the echo: reconnect and swap.
			if err := s.swapSession(); err != nil {
				log.Printf("swapping dead session failed; err=%v", err)
			}
		}

		s.keepAlive.Reset(pingInterval)
	}
}

// checkEcho reports whether resp is the keep-alive echo. A response of
// any other type, nil included, is an error, never a dereference.
func checkEcho(resp commands.Response) error {
	echo, ok := resp.(*commands.EchoResponse)
	if !ok || echo == nil {
		return errors.New("invalid response type")
	}
	if !bytes.Equal(echo.Data, echoPayload) {
		return errors.New("echoed data is invalid")
	}
	return nil
}

// swapSession opens and authenticates a new session and replaces the
// current one with it. One swap runs at a time: a call made while
// another is running returns nil and leaves the replacement to it.
func (s *SessionManager) swapSession() error {
	if !atomic.CompareAndSwapInt32(&s.swapping, 0, 1) {
		return nil
	}
	defer atomic.StoreInt32(&s.swapping, 0)

	newSession, err := securechannel.NewSecureChannel(s.connector, s.authKeyID, s.password)
	if err != nil {
		return err
	}

	err = newSession.Authenticate()
	if err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	// Close old session
	if s.session != nil {
		go s.session.Close()
	}

	// Replace primary session
	s.session = newSession

	return nil
}

func (s *SessionManager) checkSessionHealth() {
	if s.session.Counter >= securechannel.MaxMessagesPerSession*0.9 && atomic.LoadInt32(&s.swapping) == 0 {
		go s.swapSession()
	}
}

// SendEncryptedCommand sends an encrypted & authenticated command to the HSM
// and returns the decrypted and parsed response.
func (s *SessionManager) SendEncryptedCommand(c *commands.CommandMessage) (commands.Response, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check session health after executing the command
	defer s.checkSessionHealth()

	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if s.session == nil {
		return nil, errors.New("no session available")
	}

	return s.session.SendEncryptedCommand(c)
}

// SendCommand sends an unauthenticated command to the HSM and returns the parsed response
func (s *SessionManager) SendCommand(c *commands.CommandMessage) (commands.Response, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if s.session == nil {
		return nil, errors.New("no session available")
	}

	return s.session.SendCommand(c)
}

// Destroy closes all connections in the pool and terminates the
// keep-alive goroutine. SessionManager instances can't be reused.
// Calling Destroy more than once is a no-op.
func (s *SessionManager) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.destroyed {
		return
	}
	close(s.done)
	s.keepAlive.Stop()
	s.session.Close()
	s.destroyed = true
}
