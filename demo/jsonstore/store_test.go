package jsonstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	auth "github.com/dreego-stack/plugin-auth"
)

func TestStorePersistsUsersCredentialsAndSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.CreatePasswordUser(context.Background(), auth.NewUser{
		ID: "user-1", Identifier: "user@example.com", DisplayName: "User", WebAuthnID: []byte("webauthn-user-1"),
	}, auth.PasswordCredential{Hash: "hash", UpdatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	session := auth.Session{ID: "session-1", UserID: user.ID, Level: auth.LevelPassword, ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.CreateSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.UserByIdentifier(context.Background(), "user@example.com")
	if err != nil || got.ID != user.ID {
		t.Fatalf("user = %+v, %v", got, err)
	}
	credential, err := reopened.Password(context.Background(), user.ID)
	if err != nil || credential.Hash != "hash" {
		t.Fatalf("password = %+v, %v", credential, err)
	}
	gotSession, err := reopened.SessionByID(context.Background(), session.ID, time.Now())
	if err != nil || gotSession.UserID != user.ID {
		t.Fatalf("session = %+v, %v", gotSession, err)
	}
}

var _ auth.Store = (*Store)(nil)
