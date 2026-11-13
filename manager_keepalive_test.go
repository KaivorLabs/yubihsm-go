package yubihsm

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

// errors.Is is called by pingRoutine after SendEncryptedCommand returns. Wait
// for its already-registered proactive recovery so the stale-result schedule
// is deterministic, rather than hoping the scheduler produces this race.
type completedRecoveryError struct {
	manager  *SessionManager
	compared chan struct{}
}

func (*completedRecoveryError) Error() string { return "public injected transport failure" }
func (e *completedRecoveryError) Is(error) bool {
	e.manager.swapWG.Wait()
	close(e.compared)
	return false
}

func TestKeepAliveDoesNotReplaceRecoveredSessionAgain(t *testing.T) {
	manager := &SessionManager{
		done:      make(chan struct{}),
		keepAlive: time.NewTimer(0),
		authKey:   testManagerAuthKey(),
	}
	compared := make(chan struct{})
	manager.session = &fakeManagedSession{sendErr: &completedRecoveryError{manager: manager, compared: compared}}
	var calls int32
	manager.newSession = &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
		atomic.AddInt32(&calls, 1)
		return &fakeManagedSession{}, nil
	}}
	defer manager.Destroy()
	manager.pingWG.Add(1)
	go func() {
		defer manager.pingWG.Done()
		manager.pingRoutine()
	}()

	select {
	case <-compared:
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive did not observe the transport failure")
	}
	// Stop returns true only once the fired/consumed timer has been reset at
	// the end of this ping iteration. No fifteen-second wall-clock delay.
	deadline := time.Now().Add(5 * time.Second)
	for {
		manager.lock.Lock()
		iterationFinished := manager.keepAlive.Stop()
		manager.lock.Unlock()
		if iterationFinished {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("keepalive iteration did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	manager.swapWG.Wait()
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("stale keepalive failure created %d replacement sessions, want one", got)
	}
}

func TestKeepAliveStillReplacesInvalidEchoAndCardErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp commands.Response
		err  error
	}{
		{"different data", &commands.EchoResponse{Data: []byte("wrong")}, nil},
		{"wrong type", []byte("keepalive"), nil},
		{"card error", nil, &commands.Error{Code: commands.ErrorCodeInvalidPermission}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := &SessionManager{
				done:      make(chan struct{}),
				keepAlive: time.NewTimer(time.Millisecond),
				authKey:   testManagerAuthKey(),
				session:   &fakeManagedSession{healthy: 1, sendResponse: tc.resp, sendErr: tc.err},
			}
			created := make(chan struct{}, 1)
			manager.newSession = &sessionFactory{create: func(connector.Connector, uint16, authkey.AuthKey) (managedSession, error) {
				select {
				case created <- struct{}{}:
				default:
					return nil, errors.New("duplicate keepalive replacement")
				}
				return &fakeManagedSession{}, nil
			}}
			defer manager.Destroy()
			manager.pingWG.Add(1)
			go func() {
				defer manager.pingWG.Done()
				manager.pingRoutine()
			}()
			select {
			case <-created:
			case <-time.After(5 * time.Second):
				t.Fatal("failed keepalive did not start replacement")
			}
		})
	}
}
