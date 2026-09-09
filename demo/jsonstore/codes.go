package jsonstore

import (
	"context"
	"crypto/subtle"
	"time"

	auth "github.com/dreego-stack/plugin-auth"
)

func (s *Store) SaveCode(_ context.Context, code auth.OneTimeCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Codes[code.ID]; exists {
		return auth.ErrConflict
	}
	s.state.Codes[code.ID] = clone(code)
	return s.persistLocked()
}

func (s *Store) AttemptCode(_ context.Context, id string, proof []byte, now time.Time) (auth.OneTimeCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.state.Codes[id]
	if !ok {
		return auth.OneTimeCode{}, false, auth.ErrNotFound
	}
	if !code.ExpiresAt.After(now) {
		delete(s.state.Codes, id)
		_ = s.persistLocked()
		return auth.OneTimeCode{}, false, auth.ErrExpired
	}
	code.Attempts++
	matched := subtle.ConstantTimeCompare(code.Proof, proof) == 1
	if matched || code.Attempts >= code.MaxAttempts {
		delete(s.state.Codes, id)
	} else {
		s.state.Codes[id] = code
	}
	if err := s.persistLocked(); err != nil {
		return auth.OneTimeCode{}, false, err
	}
	if !matched && code.Attempts >= code.MaxAttempts {
		return code, false, auth.ErrAttemptsExceeded
	}
	return clone(code), matched, nil
}

func (s *Store) DeleteCode(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.Codes, id)
	return s.persistLocked()
}
