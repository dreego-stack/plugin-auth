package jsonstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	auth "github.com/dreego-stack/plugin-auth"
)

type state struct {
	Users       map[string]auth.User                `json:"users"`
	Identifiers map[string]string                   `json:"identifiers"`
	WebAuthnIDs map[string]string                   `json:"webAuthnIds"`
	Passwords   map[string]auth.PasswordCredential  `json:"passwords"`
	Passkeys    map[string][]auth.PasskeyCredential `json:"passkeys"`
	TOTP        map[string]auth.TOTPCredential      `json:"totp"`
	Recovery    map[string][]auth.RecoveryCode      `json:"recovery"`
	Codes       map[string]auth.OneTimeCode         `json:"codes"`
	Sessions    map[string]auth.Session             `json:"sessions"`
}

type Store struct {
	mu    sync.Mutex
	path  string
	state state
}

func Open(path string) (*Store, error) {
	store := &Store{path: path, state: emptyState()}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, store.persistLocked()
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, err
	}
	store.fillMissingMaps()
	return store, nil
}

func emptyState() state {
	return state{
		Users: map[string]auth.User{}, Identifiers: map[string]string{}, WebAuthnIDs: map[string]string{},
		Passwords: map[string]auth.PasswordCredential{}, Passkeys: map[string][]auth.PasskeyCredential{},
		TOTP: map[string]auth.TOTPCredential{}, Recovery: map[string][]auth.RecoveryCode{},
		Codes: map[string]auth.OneTimeCode{}, Sessions: map[string]auth.Session{},
	}
}

func (s *Store) fillMissingMaps() {
	empty := emptyState()
	if s.state.Users == nil {
		s.state.Users = empty.Users
	}
	if s.state.Identifiers == nil {
		s.state.Identifiers = empty.Identifiers
	}
	if s.state.WebAuthnIDs == nil {
		s.state.WebAuthnIDs = empty.WebAuthnIDs
	}
	if s.state.Passwords == nil {
		s.state.Passwords = empty.Passwords
	}
	if s.state.Passkeys == nil {
		s.state.Passkeys = empty.Passkeys
	}
	if s.state.TOTP == nil {
		s.state.TOTP = empty.TOTP
	}
	if s.state.Recovery == nil {
		s.state.Recovery = empty.Recovery
	}
	if s.state.Codes == nil {
		s.state.Codes = empty.Codes
	}
	if s.state.Sessions == nil {
		s.state.Sessions = empty.Sessions
	}
}

func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".auth-*.json")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path)
}

func webAuthnKey(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func clone[T any](value T) T {
	data, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(data, &result)
	return result
}
