package jsonstore

import (
	"context"
	"crypto/subtle"
	"time"

	auth "github.com/dreego-stack/plugin-auth"
)

func (s *Store) SavePasskey(_ context.Context, userID string, credential auth.PasskeyCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Users[userID]; !ok {
		return auth.ErrNotFound
	}
	for _, credentials := range s.state.Passkeys {
		for _, current := range credentials {
			if subtle.ConstantTimeCompare(current.ID, credential.ID) == 1 {
				return auth.ErrConflict
			}
		}
	}
	s.state.Passkeys[userID] = append(s.state.Passkeys[userID], clone(credential))
	return s.persistLocked()
}

func (s *Store) Passkeys(_ context.Context, userID string) ([]auth.PasskeyCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clone(s.state.Passkeys[userID]), nil
}

func (s *Store) UpdatePasskey(_ context.Context, userID string, credential auth.PasskeyCredential, previous uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index, current := range s.state.Passkeys[userID] {
		if subtle.ConstantTimeCompare(current.ID, credential.ID) != 1 {
			continue
		}
		if current.SignCount != previous {
			return auth.ErrConflict
		}
		s.state.Passkeys[userID][index] = clone(credential)
		return s.persistLocked()
	}
	return auth.ErrNotFound
}

func (s *Store) DeletePasskey(_ context.Context, userID string, id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index, credential := range s.state.Passkeys[userID] {
		if subtle.ConstantTimeCompare(credential.ID, id) == 1 {
			s.state.Passkeys[userID] = append(s.state.Passkeys[userID][:index], s.state.Passkeys[userID][index+1:]...)
			return s.persistLocked()
		}
	}
	return auth.ErrNotFound
}

func (s *Store) SetTOTP(_ context.Context, userID string, credential auth.TOTPCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Users[userID]; !ok {
		return auth.ErrNotFound
	}
	s.state.TOTP[userID] = clone(credential)
	return s.persistLocked()
}

func (s *Store) TOTP(_ context.Context, userID string) (auth.TOTPCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.state.TOTP[userID]
	if !ok {
		return auth.TOTPCredential{}, auth.ErrNotFound
	}
	return clone(credential), nil
}

func (s *Store) DeleteTOTP(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.state.TOTP, userID)
	return s.persistLocked()
}

func (s *Store) SetRecoveryCodes(_ context.Context, userID string, codes []auth.RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Users[userID]; !ok {
		return auth.ErrNotFound
	}
	s.state.Recovery[userID] = clone(codes)
	return s.persistLocked()
}

func (s *Store) ConsumeRecoveryCode(_ context.Context, userID string, proof []byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index := range s.state.Recovery[userID] {
		code := &s.state.Recovery[userID][index]
		if code.UsedAt.IsZero() && subtle.ConstantTimeCompare(code.Proof, proof) == 1 {
			code.UsedAt = now
			return true, s.persistLocked()
		}
	}
	return false, nil
}
