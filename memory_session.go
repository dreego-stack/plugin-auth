package auth

import (
	"context"
	"time"
)

func (s *MemoryStore) CreateSession(_ context.Context, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[session.ID]; exists {
		return ErrConflict
	}
	s.sessions[session.ID] = session
	return nil
}

func (s *MemoryStore) SessionByID(_ context.Context, id string, now time.Time) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}
	if !session.ExpiresAt.After(now) {
		delete(s.sessions, id)
		return Session{}, ErrExpired
	}
	return session, nil
}

func (s *MemoryStore) RevokeSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *MemoryStore) RevokeUserSessions(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, id)
		}
	}
	return nil
}
