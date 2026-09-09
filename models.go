package auth

import "time"

type User struct {
	ID          string    `json:"id"`
	Identifier  string    `json:"identifier"`
	DisplayName string    `json:"displayName"`
	WebAuthnID  []byte    `json:"-"`
	Verified    bool      `json:"verified"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"createdAt"`
}

type NewUser struct {
	ID          string
	Identifier  string
	DisplayName string
	WebAuthnID  []byte
}

type PasswordCredential struct {
	Hash      string
	UpdatedAt time.Time
}

type PasskeyCredential struct {
	ID              []byte
	PublicKey       []byte
	AttestationType string
	Transports      []string
	UserPresent     bool
	UserVerified    bool
	BackupEligible  bool
	BackupState     bool
	AAGUID          []byte
	SignCount       uint32
	Attachment      string
	CloneWarning    bool
	Name            string
	CreatedAt       time.Time
}

type TOTPCredential struct {
	EncryptedSecret []byte
	Confirmed       bool
	CreatedAt       time.Time
}

type RecoveryCode struct {
	Proof  []byte
	UsedAt time.Time
}

type Purpose string

const (
	PurposeLoginCode     Purpose = "login_code"
	PurposeVerifyAccount Purpose = "verify_account"
	PurposePasswordReset Purpose = "password_reset"
)

type OneTimeCode struct {
	ID          string
	UserID      string
	Recipient   string
	Purpose     Purpose
	Proof       []byte
	ExpiresAt   time.Time
	Attempts    int
	MaxAttempts int
}

type AuthLevel string

const (
	LevelPassword AuthLevel = "password"
	LevelMFA      AuthLevel = "mfa"
	LevelPasskey  AuthLevel = "passkey"
	LevelCode     AuthLevel = "code"
)

type Session struct {
	ID              string
	UserID          string
	Level           AuthLevel
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	LastSeenAt      time.Time
	UserAgent       string
	RemoteAddr      string
}

type Event struct {
	Type       string
	UserID     string
	Identifier string
	RemoteAddr string
	UserAgent  string
	At         time.Time
}
