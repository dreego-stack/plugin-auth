package auth

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"
)

type MemoryStore struct {
	mu          sync.Mutex
	users       map[string]User
	identifiers map[string]string
	webAuthnIDs map[string]string
	passwords   map[string]PasswordCredential
	passkeys    map[string][]PasskeyCredential
	totp        map[string]TOTPCredential
	recovery    map[string][]RecoveryCode
	codes       map[string]OneTimeCode
	sessions    map[string]Session
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		users: map[string]User{}, identifiers: map[string]string{}, webAuthnIDs: map[string]string{}, passwords: map[string]PasswordCredential{},
		passkeys: map[string][]PasskeyCredential{}, totp: map[string]TOTPCredential{}, recovery: map[string][]RecoveryCode{},
		codes: map[string]OneTimeCode{}, sessions: map[string]Session{},
	}
}

func (s *MemoryStore) CreateUser(_ context.Context, input NewUser) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createUser(input)
}

func (s *MemoryStore) CreatePasswordUser(_ context.Context, input NewUser, password PasswordCredential) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, err := s.createUser(input)
	if err != nil {
		return User{}, err
	}
	s.passwords[user.ID] = password
	return cloneUser(user), nil
}

func (s *MemoryStore) createUser(input NewUser) (User, error) {
	if _, exists := s.identifiers[input.Identifier]; exists {
		return User{}, ErrConflict
	}
	if _, exists := s.users[input.ID]; exists || input.ID == "" || input.Identifier == "" || len(input.WebAuthnID) == 0 {
		return User{}, ErrConflict
	}
	if _, exists := s.webAuthnIDs[string(input.WebAuthnID)]; exists {
		return User{}, ErrConflict
	}
	user := User{ID: input.ID, Identifier: input.Identifier, DisplayName: input.DisplayName, WebAuthnID: append([]byte(nil), input.WebAuthnID...), CreatedAt: time.Now().UTC()}
	s.users[user.ID] = user
	s.identifiers[user.Identifier] = user.ID
	s.webAuthnIDs[string(user.WebAuthnID)] = user.ID
	return cloneUser(user), nil
}

func (s *MemoryStore) UserByID(_ context.Context, id string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return cloneUser(user), nil
}

func (s *MemoryStore) UserByIdentifier(_ context.Context, identifier string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.identifiers[identifier]
	if !ok {
		return User{}, ErrNotFound
	}
	return cloneUser(s.users[id]), nil
}

func (s *MemoryStore) UserByWebAuthnID(_ context.Context, webAuthnID []byte) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.webAuthnIDs[string(webAuthnID)]
	if !ok {
		return User{}, ErrNotFound
	}
	return cloneUser(s.users[id]), nil
}

func (s *MemoryStore) SetUserVerified(_ context.Context, userID string, verified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return ErrNotFound
	}
	user.Verified = verified
	s.users[userID] = user
	return nil
}

func (s *MemoryStore) SetPassword(_ context.Context, userID string, credential PasswordCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound
	}
	s.passwords[userID] = credential
	return nil
}

func (s *MemoryStore) Password(_ context.Context, userID string) (PasswordCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.passwords[userID]
	if !ok {
		return PasswordCredential{}, ErrNotFound
	}
	return credential, nil
}

func (s *MemoryStore) SavePasskey(_ context.Context, userID string, credential PasskeyCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound
	}
	for _, credentials := range s.passkeys {
		for _, current := range credentials {
			if subtle.ConstantTimeCompare(current.ID, credential.ID) == 1 {
				return ErrConflict
			}
		}
	}
	s.passkeys[userID] = append(s.passkeys[userID], clonePasskey(credential))
	return nil
}

func (s *MemoryStore) Passkeys(_ context.Context, userID string) ([]PasskeyCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.passkeys[userID]
	result := make([]PasskeyCredential, len(items))
	for i := range items {
		result[i] = clonePasskey(items[i])
	}
	return result, nil
}

func (s *MemoryStore) UpdatePasskey(_ context.Context, userID string, credential PasskeyCredential, previous uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, current := range s.passkeys[userID] {
		if subtle.ConstantTimeCompare(current.ID, credential.ID) == 1 {
			if current.SignCount != previous {
				return ErrConflict
			}
			s.passkeys[userID][i] = clonePasskey(credential)
			return nil
		}
	}
	return ErrNotFound
}

func (s *MemoryStore) DeletePasskey(_ context.Context, userID string, id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, current := range s.passkeys[userID] {
		if subtle.ConstantTimeCompare(current.ID, id) == 1 {
			s.passkeys[userID] = append(s.passkeys[userID][:i], s.passkeys[userID][i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

func (s *MemoryStore) SetTOTP(_ context.Context, userID string, credential TOTPCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound
	}
	credential.EncryptedSecret = append([]byte(nil), credential.EncryptedSecret...)
	s.totp[userID] = credential
	return nil
}

func (s *MemoryStore) TOTP(_ context.Context, userID string) (TOTPCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.totp[userID]
	if !ok {
		return TOTPCredential{}, ErrNotFound
	}
	credential.EncryptedSecret = append([]byte(nil), credential.EncryptedSecret...)
	return credential, nil
}

func (s *MemoryStore) DeleteTOTP(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.totp, userID)
	return nil
}

func (s *MemoryStore) SetRecoveryCodes(_ context.Context, userID string, codes []RecoveryCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound
	}
	s.recovery[userID] = cloneRecovery(codes)
	return nil
}

func (s *MemoryStore) ConsumeRecoveryCode(_ context.Context, userID string, proof []byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.recovery[userID] {
		code := &s.recovery[userID][i]
		if code.UsedAt.IsZero() && subtle.ConstantTimeCompare(code.Proof, proof) == 1 {
			code.UsedAt = now
			return true, nil
		}
	}
	return false, nil
}

func (s *MemoryStore) SaveCode(_ context.Context, code OneTimeCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.codes[code.ID]; exists {
		return ErrConflict
	}
	code.Proof = append([]byte(nil), code.Proof...)
	s.codes[code.ID] = code
	return nil
}

func (s *MemoryStore) AttemptCode(_ context.Context, id string, proof []byte, now time.Time) (OneTimeCode, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.codes[id]
	if !ok {
		return OneTimeCode{}, false, ErrNotFound
	}
	if !code.ExpiresAt.After(now) {
		delete(s.codes, id)
		return OneTimeCode{}, false, ErrExpired
	}
	code.Attempts++
	matched := subtle.ConstantTimeCompare(code.Proof, proof) == 1
	if matched || code.Attempts >= code.MaxAttempts {
		delete(s.codes, id)
	} else {
		s.codes[id] = code
	}
	if !matched && code.Attempts >= code.MaxAttempts {
		return code, false, ErrAttemptsExceeded
	}
	return code, matched, nil
}

func (s *MemoryStore) DeleteCode(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, id)
	return nil
}
