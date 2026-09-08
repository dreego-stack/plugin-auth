package auth

import (
	"context"
	"sync"
	"time"
)

type MemoryChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]Challenge
}

func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{challenges: map[string]Challenge{}}
}

func (s *MemoryChallengeStore) Put(_ context.Context, challenge Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.challenges[challenge.ID]; exists {
		return ErrConflict
	}
	challenge.Payload = append([]byte(nil), challenge.Payload...)
	s.challenges[challenge.ID] = challenge
	return nil
}

func (s *MemoryChallengeStore) Take(_ context.Context, id string, now time.Time) (Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, exists := s.challenges[id]
	if !exists {
		return Challenge{}, ErrNotFound
	}
	delete(s.challenges, id)
	if !challenge.ExpiresAt.After(now) {
		return Challenge{}, ErrExpired
	}
	challenge.Payload = append([]byte(nil), challenge.Payload...)
	return challenge, nil
}
