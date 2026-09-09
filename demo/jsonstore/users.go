package jsonstore

import (
	"context"
	"time"

	auth "github.com/dreego-stack/plugin-auth"
)

func (s *Store) CreateUser(_ context.Context, input auth.NewUser) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createUserLocked(input, nil)
}

func (s *Store) CreatePasswordUser(_ context.Context, input auth.NewUser, password auth.PasswordCredential) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createUserLocked(input, &password)
}

func (s *Store) createUserLocked(input auth.NewUser, password *auth.PasswordCredential) (auth.User, error) {
	if input.ID == "" || input.Identifier == "" || len(input.WebAuthnID) == 0 {
		return auth.User{}, auth.ErrConflict
	}
	if _, exists := s.state.Users[input.ID]; exists {
		return auth.User{}, auth.ErrConflict
	}
	if _, exists := s.state.Identifiers[input.Identifier]; exists {
		return auth.User{}, auth.ErrConflict
	}
	key := webAuthnKey(input.WebAuthnID)
	if _, exists := s.state.WebAuthnIDs[key]; exists {
		return auth.User{}, auth.ErrConflict
	}
	user := auth.User{ID: input.ID, Identifier: input.Identifier, DisplayName: input.DisplayName, WebAuthnID: clone(input.WebAuthnID), CreatedAt: time.Now().UTC()}
	s.state.Users[user.ID] = user
	s.state.Identifiers[user.Identifier] = user.ID
	s.state.WebAuthnIDs[key] = user.ID
	if password != nil {
		s.state.Passwords[user.ID] = *password
	}
	if err := s.persistLocked(); err != nil {
		delete(s.state.Users, user.ID)
		delete(s.state.Identifiers, user.Identifier)
		delete(s.state.WebAuthnIDs, key)
		delete(s.state.Passwords, user.ID)
		return auth.User{}, err
	}
	return clone(user), nil
}

func (s *Store) UserByID(_ context.Context, id string) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.state.Users[id]
	if !ok {
		return auth.User{}, auth.ErrNotFound
	}
	return clone(user), nil
}

func (s *Store) UserByIdentifier(_ context.Context, identifier string) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.state.Identifiers[identifier]
	if !ok {
		return auth.User{}, auth.ErrNotFound
	}
	return clone(s.state.Users[id]), nil
}

func (s *Store) UserByWebAuthnID(_ context.Context, webAuthnID []byte) (auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.state.WebAuthnIDs[webAuthnKey(webAuthnID)]
	if !ok {
		return auth.User{}, auth.ErrNotFound
	}
	return clone(s.state.Users[id]), nil
}

func (s *Store) SetUserVerified(_ context.Context, userID string, verified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.state.Users[userID]
	if !ok {
		return auth.ErrNotFound
	}
	user.Verified = verified
	s.state.Users[userID] = user
	return s.persistLocked()
}

func (s *Store) SetPassword(_ context.Context, userID string, credential auth.PasswordCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Users[userID]; !ok {
		return auth.ErrNotFound
	}
	s.state.Passwords[userID] = credential
	return s.persistLocked()
}

func (s *Store) Password(_ context.Context, userID string) (auth.PasswordCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.state.Passwords[userID]
	if !ok {
		return auth.PasswordCredential{}, auth.ErrNotFound
	}
	return credential, nil
}
