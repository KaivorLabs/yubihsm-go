package yubihsm

import (
	"testing"
	"time"
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
