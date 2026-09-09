package jsonstore

import (
	"context"
	"time"

	auth "github.com/dreego-stack/plugin-auth"
)

func (s *Store) CreateSession(_ context.Context, session auth.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Sessions[session.ID]; exists {
		return auth.ErrConflict
	}
	s.state.Sessions[session.ID] = session
	return s.persistLocked()
}

func (s *Store) SessionByID(_ context.Context, id string, now time.Time) (auth.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.state.Sessions[id]
	if !ok {
		return auth.Session{}, auth.ErrNotFound
	}
	if !session.ExpiresAt.After(now) {
		delete(s.state.Sessions, id)
		_ = s.persistLocked()
		return auth.Session{}, auth.ErrExpired
	}
	return session, nil
}

func (s *Store) RevokeSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Sessions, id)
	return s.persistLocked()
}

func (s *Store) RevokeUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.state.Sessions {
		if session.UserID == userID {
			delete(s.state.Sessions, id)
		}
	}
	return s.persistLocked()
}
