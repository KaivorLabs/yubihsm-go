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
)

func TestCredentialRotationDuringReplacementAuthentication(t *testing.T) {
	for _, candidateSucceeds := range []bool{false, true} {
		name := "old credential rejected"
		if candidateSucceeds {
			name = "already established session accepted"
		}
		t.Run(name, func(t *testing.T) {
			originalKey := testManagerAuthKey()
			originalSession := &fakeManagedSession{
				healthy:      1,
				sendResponse: &commands.ChangeAuthenticationKeyResponse{ObjectID: 1},
			}
			candidate := &fakeManagedSession{authStarted: make(chan struct{}), authRelease: make(chan struct{})}
			if !candidateSucceeds {
				candidate.authErr = errors.New("old credential rejected during authentication")
			}
			finalSession := &fakeManagedSession{}
			manager := &SessionManager{
				authKeyID: 1,
				authKey:   new([authkey.AuthKeyLength]byte),
				session:   originalSession,
				done:      make(chan struct{}),
			}
			copy(manager.authKey[:], originalKey[:])
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(candidate.authRelease) }) }
			t.Cleanup(func() {
				release()
				manager.Destroy()
			})
			command, err := commands.CreateChangeAuthenticationKeyCommand(1, "public interleaving test credential")
			if err != nil {
				t.Fatal(err)
			}
			rotatedKey := append([]byte(nil), command.Data[3:]...)
			calls := 0
			manager.newSession = &sessionFactory{create: func(_ connector.Connector, _ uint16, key authkey.AuthKey) (managedSession, error) {
				calls++
				if calls == 1 {
					if !bytes.Equal(key, originalKey[:]) {
						return nil, errors.New("initial swap did not snapshot the original credential")
					}
					return candidate, nil
				}
				if !bytes.Equal(key, rotatedKey) {
					return nil, errors.New("next swap used a stale credential")
				}
				return finalSession, nil
			}}

			result := make(chan error, 1)
			go func() { result <- manager.swapSession() }()
			select {
			case <-candidate.authStarted:
			case err := <-result:
				t.Fatalf("swap returned before authenticating: %v", err)
			case <-time.After(time.Second):
				t.Fatal("replacement authentication did not start")
			}
			// Rotation is confirmed on the still-active session while replacement
			// authentication is suspended outside the manager lock.
			if _, err := manager.SendEncryptedCommand(command); err != nil {
				t.Fatal(err)
			}
			release()
			select {
			case err := <-result:
				if !errors.Is(err, candidate.authErr) {
					t.Fatalf("swap error = %v, want %v", err, candidate.authErr)
				}
			case <-time.After(time.Second):
				t.Fatal("replacement did not finish")
			}
			manager.lock.Lock()
			active := manager.session
			keyCorrect := bytes.Equal(manager.authKey[:], rotatedKey)
			manager.lock.Unlock()
			if !keyCorrect {
				t.Fatal("concurrent replacement rolled back the retained credential")
			}
			if candidateSucceeds {
				if active != candidate {
					t.Fatal("authenticated candidate was not installed")
				}
			} else if active != originalSession || atomic.LoadInt32(&candidate.closed) != 1 {
				t.Fatal("failed candidate replaced the active session or was not closed")
			}
			// A fresh authentication attempt uses the rotated long-term key in
			// both cases. No business command has been automatically replayed.
			if err := manager.swapSession(); err != nil {
				t.Fatal(err)
			}
			if got := atomic.LoadUint32(&originalSession.messages); got != 1 {
				t.Fatalf("rotation send count = %d, want one", got)
			}
		})
	}
}
