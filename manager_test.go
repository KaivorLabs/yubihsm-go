package yubihsm

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

// TestPingRoutine_ExitsOnDoneClose proves that closing s.done terminates
// the keep-alive goroutine. Before this fix, pingRoutine used `for range
// s.keepAlive.C` and could not exit at all: time.Timer.Stop does not
// close the channel, so the goroutine leaked for the lifetime of the
// process. The test sets keepAlive to a far-future timer so the only
// reachable exit is the new s.done case in the select.
func TestPingRoutine_ExitsOnDoneClose(t *testing.T) {
	s := &SessionManager{
		keepAlive: time.NewTimer(time.Hour),
		done:      make(chan struct{}),
	}

	exited := make(chan struct{})
	go func() {
		s.pingRoutine()
		close(exited)
	}()

	// Give pingRoutine time to enter its select.
	time.Sleep(10 * time.Millisecond)
	close(s.done)

	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("pingRoutine did not exit after s.done was closed")
	}
}

// TestDestroy_Idempotent guards the new early-return guard in Destroy.
// A second Destroy must not panic; before the guard, close(s.done) on
// the already-closed channel would have. We construct a SessionManager
// with no real session by stubbing session.Close via a SessionManager
// state that skips the call: destroyed=true forces the early return on
// the first Destroy too, so this test exercises only the guard.
func TestDestroy_Idempotent(t *testing.T) {
	s := &SessionManager{
		keepAlive: time.NewTimer(time.Hour),
		done:      make(chan struct{}),
		destroyed: true, // pretend Destroy has already run
	}

	// Should hit the guard and return without touching done/session.
	s.Destroy()
	s.Destroy()
}

// TestCheckEcho: the keep-alive accepts only the echo of its payload. A
// response of another type, nil included, is an error; before checkEcho,
// pingRoutine read the echo's data without checking the type and
// panicked on a nil pointer, which ended the process.
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

// blockingConnector blocks every Request until release is closed, then
// fails it, and counts the requests.
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

// TestSwapSession_OneAtATime: while one swap is opening a session, every
// other swap returns without opening one. Before the atomic flag, each
// call set and read swapping unsynchronized (a data race under -race),
// and concurrent calls each opened a session, which can fill the
// device's 16 session slots.
func TestSwapSession_OneAtATime(t *testing.T) {
	conn := &blockingConnector{first: make(chan struct{}), release: make(chan struct{})}
	s := &SessionManager{connector: conn, done: make(chan struct{})}

	go s.swapSession()
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
	go func() { returned.Wait(); close(done) }()
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
}
