package auth

import (
	"context"
	"time"
)

type Store interface {
	CreateUser(context.Context, NewUser) (User, error)
	CreatePasswordUser(context.Context, NewUser, PasswordCredential) (User, error)
	UserByID(context.Context, string) (User, error)
	UserByIdentifier(context.Context, string) (User, error)
	UserByWebAuthnID(context.Context, []byte) (User, error)
	SetPassword(context.Context, string, PasswordCredential) error
	Password(context.Context, string) (PasswordCredential, error)
	SavePasskey(context.Context, string, PasskeyCredential) error
	Passkeys(context.Context, string) ([]PasskeyCredential, error)
	UpdatePasskey(context.Context, string, PasskeyCredential, uint32) error
	DeletePasskey(context.Context, string, []byte) error
	SetTOTP(context.Context, string, TOTPCredential) error
	TOTP(context.Context, string) (TOTPCredential, error)
	DeleteTOTP(context.Context, string) error
	SetRecoveryCodes(context.Context, string, []RecoveryCode) error
	ConsumeRecoveryCode(context.Context, string, []byte, time.Time) (bool, error)
	SaveCode(context.Context, OneTimeCode) error
	AttemptCode(context.Context, string, []byte, time.Time) (OneTimeCode, bool, error)
	DeleteCode(context.Context, string) error
	CreateSession(context.Context, Session) error
	SessionByID(context.Context, string, time.Time) (Session, error)
	RevokeSession(context.Context, string) error
	RevokeUserSessions(context.Context, string) error
}

type Challenge struct {
	ID        string
	Kind      string
	UserID    string
	Payload   []byte
	ExpiresAt time.Time
}

type ChallengeStore interface {
	Put(context.Context, Challenge) error
	Take(context.Context, string, time.Time) (Challenge, error)
}

type Messenger interface {
	Send(context.Context, Message) error
}

type Message struct {
	Purpose   Purpose
	Recipient string
	Code      string
	ExpiresAt time.Time
}

type RateLimiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}

type Observer interface {
	Record(context.Context, Event)
}
