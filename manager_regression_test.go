package yubihsm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/certusone/yubihsm-go/authkey"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

func TestAuthenticationKeyRotationUpdatesReplacementCredential(t *testing.T) {
	for _, tc := range []struct {
		name    string
		slot    uint16
		sendErr error
		rotated bool
	}{
		{"own key", 1, nil, true},
		{"other key", 2, nil, false},
		{"failed change", 1, &commands.Error{Code: commands.ErrorCodeInvalidPermission}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := testManagerAuthKey()
			s := &SessionManager{
				authKeyID: 1,
				authKey:   new([authkey.AuthKeyLength]byte),
				done:      make(chan struct{}),
				session: &fakeManagedSession{
					healthy:      1,
					sendErr:      tc.sendErr,
					sendResponse: &commands.ChangeAuthenticationKeyResponse{ObjectID: tc.slot},
				},
			}
			copy(s.authKey[:], original[:])
			defer s.Destroy()
			command, err := commands.CreateChangeAuthenticationKeyCommand(tc.slot, "public rotated test credential")
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.SendEncryptedCommand(command)
			if !errors.Is(err, tc.sendErr) {
				t.Fatalf("change error = %v, want %v", err, tc.sendErr)
			}
			want := original[:]
			if tc.rotated {
				want = append([]byte(nil), command.Data[3:]...)
			}
			if !bytes.Equal(s.authKey[:], want) {
				t.Fatal("replacement authentication credential was not updated correctly")
			}
			s.newSession = &sessionFactory{create: func(_ connector.Connector, _ uint16, key authkey.AuthKey) (managedSession, error) {
				if !bytes.Equal(key, want) {
					t.Fatal("replacement session received a stale authentication key")
				}
				return &fakeManagedSession{}, nil
			}}
			if err := s.swapSession(); err != nil {
				t.Fatal(err)
			}
			if tc.rotated && !bytes.Equal(command.Data[3:], want) {
				t.Fatal("session replacement modified the caller's command data")
			}
		})
	}
}
