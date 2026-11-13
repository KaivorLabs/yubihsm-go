package yubihsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/certusone/yubihsm-go/securechannel"
)

type (
	managedSession interface {
		Authenticate() error
		SendEncryptedCommand(*commands.CommandMessage) (commands.Response, error)
		SendCommand(*commands.CommandMessage) (commands.Response, error)
		Close() error
		MessageCount() uint32
		IsHealthy() bool
	}

	sessionFactory struct {
		create func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error)
	}

	// SessionManager manages an authenticated secure session with a YubiHSM2.
	// It must not be copied after first use.
	SessionManager struct {
		session    managedSession
		lock       sync.Mutex
		connector  connector.Connector
		authKeyID  uint16
		authKey    *[authkey.AuthKeyLength]byte
		newSession *sessionFactory

		destroyed       bool
		destroyComplete chan struct{}
		keepAlive       *time.Timer
		done            chan struct{}
		pingWG          sync.WaitGroup
		swapWG          sync.WaitGroup

		// swapping is 1 while swapSession runs. It is accessed only through
		// sync/atomic because health checks and keep-alive run in goroutines.
		swapping int32
	}
)

var (
	echoPayload = []byte("keepalive")

	// ErrSessionManagerDestroyed is returned when an operation is attempted
	// after Destroy has begun.
	ErrSessionManagerDestroyed = errors.New("sessionmanager has already been destroyed")
	// ErrNoSession is returned when no authenticated session is available.
	ErrNoSession = errors.New("no session available")
)

const (
	pingInterval = 15 * time.Second
)

var defaultSessionFactory = &sessionFactory{
	create: func(c connector.Connector, authKeyID uint16, key authkey.AuthKey) (managedSession, error) {
		return securechannel.NewSecureChannelWithAuthKey(c, authKeyID, key)
	},
}

// Transport errors commonly include complete URLs (including userinfo, path
// tokens and query credentials). Never send that text to the process logger.
// The original error is still returned unchanged to the operation's caller.
func logSessionError(message string, err error) {
	var transportErr *url.Error
	if errors.As(err, &transportErr) {
		log.Printf("%s; HTTP transport error (URL and details omitted)", message)
		return
	}
	log.Printf("%s; err=%v", message, err)
}

func clearAuthKey(key *[authkey.AuthKeyLength]byte) {
	if key == nil {
		return
	}
	for i := range key {
		key[i] = 0
	}
}

// NewSessionManager creates a SessionManager using a password-derived
// authentication key and establishes its initial authenticated session.
func NewSessionManager(c connector.Connector, authKeyID uint16, password string) (*SessionManager, error) {
	if c == nil {
		return nil, errors.New("connector must not be nil")
	}
	key := authkey.NewFromPassword(password)
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	return NewSessionManagerWithAuthKey(c, authKeyID, key)
}

// NewSessionManagerWithAuthKey creates a SessionManager using an already
// derived authentication key. The key is copied before it is stored.
func NewSessionManagerWithAuthKey(c connector.Connector, authKeyID uint16, key authkey.AuthKey) (*SessionManager, error) {
	if c == nil {
		return nil, errors.New("connector must not be nil")
	}
	if len(key.GetEncKey()) != authkey.AuthKeyLength/2 || len(key.GetMacKey()) != authkey.AuthKeyLength/2 {
		return nil, errors.New("authentication key must be 32 bytes")
	}

	manager := &SessionManager{
		connector:  c,
		authKeyID:  authKeyID,
		authKey:    new([authkey.AuthKeyLength]byte),
		newSession: defaultSessionFactory,
		done:       make(chan struct{}),
	}
	copy(manager.authKey[:], key)

	if err := manager.swapSession(); err != nil {
		clearAuthKey(manager.authKey)
		manager.authKey = nil
		return nil, err
	}

	manager.keepAlive = time.NewTimer(pingInterval)
	manager.pingWG.Add(1)
	go func() {
		defer manager.pingWG.Done()
		manager.pingRoutine()
	}()

	return manager, nil
}

func (s *SessionManager) pingRoutine() {
	for {
		select {
		case <-s.done:
			return
		case <-s.keepAlive.C:
		}

		command, _ := commands.CreateEchoCommand(echoPayload)
		if _, err := s.sendEncryptedCommand(command, true); errors.Is(err, ErrSessionManagerDestroyed) {
			return
		}

		if !s.resetKeepAlive() {
			return
		}
	}
}

func (s *SessionManager) resetKeepAlive() bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.destroyed || s.keepAlive == nil {
		return false
	}
	s.keepAlive.Reset(pingInterval)
	return true
}

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

// swapSession opens and authenticates a replacement session. Only one swap is
// allowed to run at a time. A session authenticated concurrently with Destroy
// is closed instead of being installed.
func (s *SessionManager) swapSession() error {
	s.lock.Lock()
	if s.destroyed {
		s.lock.Unlock()
		return ErrSessionManagerDestroyed
	}
	if !atomic.CompareAndSwapInt32(&s.swapping, 0, 1) {
		s.lock.Unlock()
		return nil
	}
	s.swapWG.Add(1)
	s.lock.Unlock()
	return s.runSessionSwap()
}

// runSessionSwap owns the reservation and WaitGroup entry made under lock by
// swapSession or startProactiveSwap, including time before goroutine startup.
func (s *SessionManager) runSessionSwap() error {
	defer s.swapWG.Done()
	defer atomic.StoreInt32(&s.swapping, 0)

	s.lock.Lock()
	if s.destroyed {
		s.lock.Unlock()
		return ErrSessionManagerDestroyed
	}
	factory := s.newSession
	if factory == nil {
		factory = defaultSessionFactory
	}
	c, authKeyID := s.connector, s.authKeyID
	key := make(authkey.AuthKey, authkey.AuthKeyLength)
	if s.authKey != nil {
		copy(key, s.authKey[:])
	}
	s.lock.Unlock()
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	newSession, err := factory.create(c, authKeyID, key)
	if err != nil {
		return err
	}
	if newSession == nil {
		return errors.New("session factory returned a nil session")
	}
	if err := newSession.Authenticate(); err != nil {
		if closeErr := newSession.Close(); closeErr != nil {
			logSessionError("closing session after failed authentication failed", closeErr)
		}
		return err
	}

	s.lock.Lock()
	if s.destroyed {
		s.lock.Unlock()
		if err := newSession.Close(); err != nil {
			logSessionError("closing session created during destroy failed", err)
		}
		return ErrSessionManagerDestroyed
	}
	oldSession := s.session
	s.session = newSession
	s.lock.Unlock()

	if oldSession != nil {
		if err := oldSession.Close(); err != nil {
			logSessionError("closing replaced session failed", err)
		}
	}

	return nil
}

// SendEncryptedCommand sends an encrypted and authenticated command to the HSM
// and returns the decrypted, parsed response. Failures are never automatically
// retried: the HSM may already have executed a command whose response was lost.
func (s *SessionManager) SendEncryptedCommand(c *commands.CommandMessage) (commands.Response, error) {
	return s.sendEncryptedCommand(c, false)
}

// Keepalive validation belongs to the same operation/health snapshot as the
// send. Schedule recovery once, and only for the session that was inspected;
// a delayed keepalive result must not replace a newly recovered session.
func (s *SessionManager) sendEncryptedCommand(c *commands.CommandMessage, keepAlive bool) (commands.Response, error) {
	s.lock.Lock()
	if s.destroyed {
		s.lock.Unlock()
		return nil, ErrSessionManagerDestroyed
	}
	if s.session == nil {
		s.lock.Unlock()
		return nil, ErrNoSession
	}

	session := s.session
	resp, err := session.SendEncryptedCommand(c)
	if err == nil {
		s.updateAuthenticationKeyLocked(c, resp)
		if keepAlive {
			err = checkEcho(resp)
		}
	}
	unhealthy := !session.IsHealthy()
	nearLimit := !unhealthy && session.MessageCount() >= securechannel.MaxMessagesPerSession*9/10
	needsSwap := (unhealthy || nearLimit || (keepAlive && err != nil)) && atomic.LoadInt32(&s.swapping) == 0
	s.lock.Unlock()

	if needsSwap {
		s.startProactiveSwap(session)
	}

	return resp, err
}

// updateAuthenticationKeyLocked keeps future session creation in sync when
// the caller successfully rotates the key used by this manager. Existing
// sessions continue using their already-derived session keys.
func (s *SessionManager) updateAuthenticationKeyLocked(c *commands.CommandMessage, resp commands.Response) {
	if c == nil || c.CommandType != commands.CommandTypeChangeAuthenticationKey ||
		len(c.Data) != 3+authkey.AuthKeyLength ||
		binary.BigEndian.Uint16(c.Data[:2]) != s.authKeyID ||
		commands.Algorithm(c.Data[2]) != commands.AlgorithmYubicoAESAuthentication {
		return
	}
	changed, ok := resp.(*commands.ChangeAuthenticationKeyResponse)
	if !ok || changed == nil || changed.ObjectID != s.authKeyID {
		return
	}
	if s.authKey == nil {
		s.authKey = new([authkey.AuthKeyLength]byte)
	}
	copy(s.authKey[:], c.Data[3:])
}

func (s *SessionManager) startProactiveSwap(expected managedSession) {
	s.lock.Lock()
	// Reserve before spawning, and ignore a stale health check if another
	// swap has already replaced the session. This bounds background tasks.
	if s.destroyed || s.session != expected || !atomic.CompareAndSwapInt32(&s.swapping, 0, 1) {
		s.lock.Unlock()
		return
	}
	s.swapWG.Add(1)
	s.lock.Unlock()

	go func() {
		if err := s.runSessionSwap(); err != nil && !errors.Is(err, ErrSessionManagerDestroyed) {
			logSessionError("proactive session swap failed", err)
		}
	}()
}

// SendCommand sends an unauthenticated command to the HSM and returns the
// parsed response.
func (s *SessionManager) SendCommand(c *commands.CommandMessage) (commands.Response, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.destroyed {
		return nil, ErrSessionManagerDestroyed
	}
	if s.session == nil {
		return nil, ErrNoSession
	}

	return s.session.SendCommand(c)
}

// Destroy prevents new operations, terminates keep-alive, detaches the active
// session, and closes it. It waits for session swaps and keep-alive to finish;
// concurrent calls wait for the same shutdown. Connector operations must have
// bounded timeouts if shutdown needs to complete within a bounded time.
func (s *SessionManager) Destroy() {
	s.lock.Lock()
	if s.destroyed {
		complete := s.destroyComplete
		s.lock.Unlock()
		if complete != nil {
			<-complete
		}
		return
	}

	s.destroyComplete = make(chan struct{})
	complete := s.destroyComplete
	// Mark destroyed before releasing the lock so an in-flight swap cannot
	// install a newly authenticated session afterwards.
	s.destroyed = true
	if s.done != nil {
		close(s.done)
	}
	if s.keepAlive != nil {
		s.keepAlive.Stop()
	}
	session := s.session
	s.session = nil
	clearAuthKey(s.authKey)
	s.authKey = nil
	s.lock.Unlock()

	if session != nil {
		if err := session.Close(); err != nil {
			logSessionError("closing session during destroy failed", err)
		}
	}
	// A swap that registered before destroyed was set will observe the flag,
	// close its authenticated candidate, and call Done before this returns.
	s.swapWG.Wait()
	s.pingWG.Wait()
	close(complete)
}
