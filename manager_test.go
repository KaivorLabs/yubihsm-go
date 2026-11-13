package yubihsm

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/certusone/yubihsm-go/securechannel"
)

func testManagerAuthKey() *[authkey.AuthKeyLength]byte {
	key := new([authkey.AuthKeyLength]byte)
	derived := authkey.NewFromPassword("password")
	copy(key[:], derived)
	for i := range derived {
		derived[i] = 0
	}
	return key
}

func TestSessionManagerRemainsComparable(t *testing.T) {
	var left, right SessionManager
	if left != right {
		t.Fatal("zero-value session managers should compare equal")
	}
}

func TestNewSessionManagerValidation(t *testing.T) {
	if _, err := NewSessionManager(nil, 1, "password"); err == nil {
		t.Fatal("nil connector was accepted")
	}
	if _, err := NewSessionManagerWithAuthKey(structConnector{}, 1, authkey.AuthKey{1}); err == nil {
		t.Fatal("invalid authentication key was accepted")
	}

	key := authkey.NewFromPassword("password")
	original := append([]byte(nil), key...)
	if _, err := NewSessionManagerWithAuthKey(structConnector{}, 1, key); err == nil {
		t.Fatal("expected initial session failure")
	}
	if !bytes.Equal(key, original) {
		t.Fatal("session manager modified the caller's authentication key")
	}
}

func TestPingRoutineExitsOnDoneClose(t *testing.T) {
	s := &SessionManager{
		keepAlive: time.NewTimer(time.Hour),
		done:      make(chan struct{}),
	}

	exited := make(chan struct{})
	go func() {
		s.pingRoutine()
		close(exited)
	}()

	close(s.done)
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("pingRoutine did not exit after done was closed")
	}
}

func TestResetKeepAliveAfterDestroy(t *testing.T) {
	s := &SessionManager{
		keepAlive: time.NewTimer(time.Hour),
		done:      make(chan struct{}),
	}
	s.Destroy()
	if s.resetKeepAlive() {
		t.Fatal("keep-alive timer was reset after Destroy")
	}
}

func TestDestroyIsIdempotent(t *testing.T) {
	key := testManagerAuthKey()
	s := &SessionManager{
		authKey:   key,
		keepAlive: time.NewTimer(time.Hour),
		done:      make(chan struct{}),
	}

	s.Destroy()
	s.Destroy()

	if !s.destroyed {
		t.Fatal("manager was not marked destroyed")
	}
	for i, value := range key[:] {
		if value != 0 {
			t.Fatalf("authentication key byte %d was not cleared", i)
		}
	}
}

func TestConcurrentDestroyWaitsForSessionClose(t *testing.T) {
	session := &fakeManagedSession{
		healthy:      1,
		closeStarted: make(chan struct{}),
		closeRelease: make(chan struct{}),
	}
	s := &SessionManager{
		session: session,
		done:    make(chan struct{}),
	}

	firstReturned := make(chan struct{})
	go func() {
		s.Destroy()
		close(firstReturned)
	}()
	<-session.closeStarted

	secondStarted := make(chan struct{})
	secondReturned := make(chan struct{})
	go func() {
		close(secondStarted)
		s.Destroy()
		close(secondReturned)
	}()
	<-secondStarted
	select {
	case <-secondReturned:
		t.Fatal("concurrent Destroy returned before session close completed")
	case <-time.After(20 * time.Millisecond):
	}

	close(session.closeRelease)
	for name, returned := range map[string]<-chan struct{}{
		"first":  firstReturned,
		"second": secondReturned,
	} {
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Fatalf("%s Destroy call did not return", name)
		}
	}
	if got := atomic.LoadInt32(&session.closed); got != 1 {
		t.Fatalf("session close count = %d, want 1", got)
	}
}

func TestCheckEcho(t *testing.T) {
	cases := []struct {
		name string
		resp commands.Response
		ok   bool
	}{
		{"the echo", &commands.EchoResponse{Data: echoPayload}, true},
		{"other data", &commands.EchoResponse{Data: []byte("other")}, false},
		{"nil", nil, false},
		{"a nil echo", (*commands.EchoResponse)(nil), false},
		{"another type", &commands.CreateSessionResponse{}, false},
	}
	for _, c := range cases {
		err := checkEcho(c.resp)
		if (err == nil) != c.ok {
			t.Errorf("%s: checkEcho = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// blockingConnector blocks every Request until release is closed, then fails
// it, and counts the requests.
type blockingConnector struct {
	requests int32
	first    chan struct{}
	once     sync.Once
	release  chan struct{}
}

func (c *blockingConnector) Request(*commands.CommandMessage) ([]byte, error) {
	atomic.AddInt32(&c.requests, 1)
	c.once.Do(func() { close(c.first) })
	<-c.release
	return nil, errors.New("connector closed")
}

func (c *blockingConnector) GetStatus() (*connector.StatusResponse, error) {
	return nil, errors.New("not implemented")
}

func TestSwapSessionOneAtATime(t *testing.T) {
	conn := &blockingConnector{first: make(chan struct{}), release: make(chan struct{})}
	s := &SessionManager{
		connector: conn,
		authKey:   testManagerAuthKey(),
		done:      make(chan struct{}),
	}

	firstReturned := make(chan struct{})
	go func() {
		_ = s.swapSession()
		close(firstReturned)
	}()
	select {
	case <-conn.first:
	case <-time.After(5 * time.Second):
		t.Fatal("the first swap did not reach the connector")
	}

	const others = 8
	var returned sync.WaitGroup
	returned.Add(others)
	for i := 0; i < others; i++ {
		go func() {
			defer returned.Done()
			if err := s.swapSession(); err != nil {
				t.Errorf("a swap during a swap returned %v, want nil", err)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		returned.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(conn.release)
		t.Fatal("swaps made during a running swap did not return")
	}
	if n := atomic.LoadInt32(&conn.requests); n != 1 {
		t.Errorf("connector requests = %d, want 1", n)
	}
	close(conn.release)
	<-firstReturned
}

type fakeManagedSession struct {
	authStarted  chan struct{}
	authRelease  chan struct{}
	authOnce     sync.Once
	authErr      error
	closeStarted chan struct{}
	closeRelease chan struct{}
	closeOnce    sync.Once
	closed       int32
	healthy      int32
	messages     uint32
	sendErr      error
	sendResponse commands.Response
}

func (s *fakeManagedSession) Authenticate() error {
	if s.authStarted != nil {
		s.authOnce.Do(func() { close(s.authStarted) })
	}
	if s.authRelease != nil {
		<-s.authRelease
	}
	if s.authErr != nil {
		return s.authErr
	}
	atomic.StoreInt32(&s.healthy, 1)
	return nil
}

func (s *fakeManagedSession) SendEncryptedCommand(*commands.CommandMessage) (commands.Response, error) {
	atomic.AddUint32(&s.messages, 1)
	if s.sendErr != nil {
		return nil, s.sendErr
	}
	if s.sendResponse != nil {
		return s.sendResponse, nil
	}
	return &commands.EchoResponse{Data: echoPayload}, nil
}

func (s *fakeManagedSession) SendCommand(*commands.CommandMessage) (commands.Response, error) {
	return nil, nil
}

func (s *fakeManagedSession) Close() error {
	atomic.StoreInt32(&s.healthy, 0)
	atomic.AddInt32(&s.closed, 1)
	if s.closeStarted != nil {
		s.closeOnce.Do(func() { close(s.closeStarted) })
	}
	if s.closeRelease != nil {
		<-s.closeRelease
	}
	return nil
}

func (s *fakeManagedSession) MessageCount() uint32 {
	return atomic.LoadUint32(&s.messages)
}

func (s *fakeManagedSession) IsHealthy() bool {
	return atomic.LoadInt32(&s.healthy) == 1
}

func TestSendEncryptedCommandKeepsHealthySessionAfterCommandError(t *testing.T) {
	session := &fakeManagedSession{
		healthy: 1,
		sendErr: &commands.Error{Code: commands.ErrorCodeInvalidData},
	}
	var factoryCalls int32
	s := &SessionManager{
		session:   session,
		connector: structConnector{},
		done:      make(chan struct{}),
		newSession: &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
			atomic.AddInt32(&factoryCalls, 1)
			return nil, errors.New("unexpected factory call")
		}},
	}

	if _, err := s.SendEncryptedCommand(&commands.CommandMessage{}); err == nil {
		t.Fatal("expected command error")
	}
	if got := atomic.LoadInt32(&factoryCalls); got != 0 {
		t.Fatalf("session factory calls = %d, want 0", got)
	}
}

func TestCommandErrorNearLimitStillReplacesSession(t *testing.T) {
	session := &fakeManagedSession{
		healthy:  1,
		messages: securechannel.MaxMessagesPerSession*9/10 - 1,
		sendErr:  &commands.Error{Code: commands.ErrorCodeInvalidData},
	}
	replacement := &fakeManagedSession{authStarted: make(chan struct{})}
	s := &SessionManager{
		session:   session,
		connector: structConnector{},
		done:      make(chan struct{}),
		newSession: &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
			return replacement, nil
		}},
	}

	if _, err := s.SendEncryptedCommand(&commands.CommandMessage{}); err == nil {
		t.Fatal("expected command error")
	}
	select {
	case <-replacement.authStarted:
	case <-time.After(time.Second):
		t.Fatal("near-limit command error did not start session replacement")
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.lock.Lock()
		installed := s.session == replacement
		s.lock.Unlock()
		if installed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement session was not installed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSendEncryptedCommandReplacesUnhealthySession(t *testing.T) {
	broken := &fakeManagedSession{
		healthy: 0,
		sendErr: errors.New("transport failed"),
	}
	replacement := &fakeManagedSession{authStarted: make(chan struct{})}
	s := &SessionManager{
		session:   broken,
		connector: structConnector{},
		done:      make(chan struct{}),
		newSession: &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
			return replacement, nil
		}},
	}

	if _, err := s.SendEncryptedCommand(&commands.CommandMessage{}); err == nil {
		t.Fatal("expected the transport error")
	}

	select {
	case <-replacement.authStarted:
	case <-time.After(time.Second):
		t.Fatal("replacement session authentication did not start")
	}

	deadline := time.Now().Add(time.Second)
	for {
		s.lock.Lock()
		installed := s.session == replacement
		s.lock.Unlock()
		closed := atomic.LoadInt32(&broken.closed) == 1
		if installed && closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("replacement installed=%v, old session closed=%v", installed, closed)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSwapDoesNotInstallSessionAfterDestroy(t *testing.T) {
	candidate := &fakeManagedSession{
		authStarted: make(chan struct{}),
		authRelease: make(chan struct{}),
	}
	s := &SessionManager{
		connector: structConnector{},
		done:      make(chan struct{}),
		newSession: &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
			return candidate, nil
		}},
	}

	swapResult := make(chan error, 1)
	go func() { swapResult <- s.swapSession() }()
	<-candidate.authStarted

	destroyReturned := make(chan struct{})
	go func() {
		s.Destroy()
		close(destroyReturned)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		s.lock.Lock()
		destroyed := s.destroyed
		s.lock.Unlock()
		if destroyed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Destroy did not mark the manager destroyed")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-destroyReturned:
		t.Fatal("Destroy returned before the in-flight session was finalized")
	default:
	}

	close(candidate.authRelease)
	select {
	case <-destroyReturned:
	case <-time.After(time.Second):
		t.Fatal("Destroy did not wait for the in-flight session")
	}

	if err := <-swapResult; !errors.Is(err, ErrSessionManagerDestroyed) {
		t.Fatalf("swap error = %v, want %v", err, ErrSessionManagerDestroyed)
	}
	if got := atomic.LoadInt32(&candidate.closed); got != 1 {
		t.Fatalf("candidate close count = %d, want 1", got)
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	if s.session != nil {
		t.Fatal("a session was installed after Destroy")
	}
}

func TestProactiveSwapIgnoresStaleHealthCheck(t *testing.T) {
	old := &fakeManagedSession{}
	current := &fakeManagedSession{healthy: 1}
	var calls int32
	s := &SessionManager{
		session: current,
		done:    make(chan struct{}),
		newSession: &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
			atomic.AddInt32(&calls, 1)
			return &fakeManagedSession{}, nil
		}},
	}
	s.startProactiveSwap(old)
	s.Destroy()
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("stale health check created %d sessions", got)
	}
}

func TestProactiveSwapReservesBeforeGoroutineStart(t *testing.T) {
	old := &fakeManagedSession{}
	candidate := &fakeManagedSession{authStarted: make(chan struct{}), authRelease: make(chan struct{})}
	var calls int32
	s := &SessionManager{
		session: old,
		done:    make(chan struct{}),
		newSession: &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
			atomic.AddInt32(&calls, 1)
			return candidate, nil
		}},
	}
	for i := 0; i < 100; i++ {
		s.startProactiveSwap(old)
	}
	if got := atomic.LoadInt32(&s.swapping); got != 1 {
		t.Fatal("proactive swap was not reserved synchronously")
	}
	select {
	case <-candidate.authStarted:
	case <-time.After(time.Second):
		close(candidate.authRelease)
		t.Fatal("authentication did not start")
	}
	close(candidate.authRelease)
	s.Destroy()
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("factory calls = %d, want one", got)
	}
	if got := atomic.LoadInt32(&s.swapping); got != 0 {
		t.Fatal("Destroy returned before the swap reservation was released")
	}
}

func TestSendEncryptedCommandWithoutSession(t *testing.T) {
	s := &SessionManager{done: make(chan struct{})}
	if _, err := s.SendEncryptedCommand(&commands.CommandMessage{}); !errors.Is(err, ErrNoSession) {
		t.Fatalf("error = %v, want %v", err, ErrNoSession)
	}
}

// structConnector is a non-nil connector used by tests whose session factory
// does not access the connector.
type structConnector struct{}

func (structConnector) Request(*commands.CommandMessage) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (structConnector) GetStatus() (*connector.StatusResponse, error) {
	return nil, errors.New("not implemented")
}
