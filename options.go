package auth

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	dreego "github.com/dreego-stack/dreego/core"
)

type Options struct {
	BasePath        string
	Store           Store
	SessionStore    dreego.Store
	Challenges      ChallengeStore
	Messenger       Messenger
	Secret          []byte
	Password        PasswordOptions
	Passkeys        PasskeyOptions
	TOTP            TOTPOptions
	Codes           CodeOptions
	SessionLifetime time.Duration
	RateLimiter     RateLimiter
	Observer        Observer
	Normalize       func(string) (string, error)
}

type PasswordOptions struct {
	Enabled       bool
	Hasher        PasswordHasher
	MinimumLength int
}

type PasskeyOptions struct {
	Enabled   bool
	RPName    string
	RPID      string
	RPOrigins []string
}

type TOTPOptions struct {
	Enabled bool
	Issuer  string
	Digits  int
	Period  time.Duration
}

type CodeOptions struct {
	Enabled     bool
	Lifetime    time.Duration
	MaxAttempts int
}

func normalizeOptions(app *dreego.App, options Options) (Options, error) {
	if app == nil {
		return Options{}, errors.New("auth: app is required")
	}
	if options.Store == nil {
		return Options{}, errors.New("auth: store is required")
	}
	if len(options.Secret) < 32 {
		return Options{}, errors.New("auth: secret must be at least 32 bytes")
	}
	if options.SessionStore == nil {
		options.SessionStore = app.SessionStore()
	}
	if options.SessionStore == nil {
		return Options{}, errors.New("auth: session store is required")
	}
	if !options.Password.Enabled && !options.Passkeys.Enabled && !options.Codes.Enabled {
		return Options{}, errors.New("auth: at least one login method must be enabled")
	}
	if options.BasePath == "" {
		options.BasePath = "/auth"
	}
	if !validBasePath(options.BasePath) {
		return Options{}, errors.New("auth: base path must be a clean absolute path")
	}
	if options.SessionLifetime == 0 {
		options.SessionLifetime = 24 * time.Hour
	}
	if options.SessionLifetime < time.Minute || options.SessionLifetime > 365*24*time.Hour {
		return Options{}, errors.New("auth: invalid session lifetime")
	}
	if options.Password.Enabled {
		if options.Password.Hasher == nil {
			var err error
			options.Password.Hasher, err = NewArgon2idHasher(DefaultArgon2idParams())
			if err != nil {
				return Options{}, err
			}
		}
		if options.Password.MinimumLength == 0 {
			options.Password.MinimumLength = 12
		}
		if options.Password.MinimumLength < 8 || options.Password.MinimumLength > 128 {
			return Options{}, errors.New("auth: invalid minimum password length")
		}
	}
	if options.Passkeys.Enabled {
		if strings.TrimSpace(options.Passkeys.RPName) == "" || strings.TrimSpace(options.Passkeys.RPID) == "" || len(options.Passkeys.RPOrigins) == 0 {
			return Options{}, errors.New("auth: passkey RP name, ID, and origins are required")
		}
		for _, origin := range options.Passkeys.RPOrigins {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return Options{}, errors.New("auth: invalid passkey RP origin")
			}
		}
	}
	if options.TOTP.Enabled {
		if options.TOTP.Issuer == "" {
			return Options{}, errors.New("auth: TOTP issuer is required")
		}
		if options.TOTP.Digits == 0 {
			options.TOTP.Digits = 6
		}
		if options.TOTP.Digits != 6 && options.TOTP.Digits != 8 {
			return Options{}, errors.New("auth: TOTP digits must be 6 or 8")
		}
		if options.TOTP.Period == 0 {
			options.TOTP.Period = 30 * time.Second
		}
		if options.TOTP.Period < 15*time.Second || options.TOTP.Period > time.Minute {
			return Options{}, errors.New("auth: invalid TOTP period")
		}
	}
	if options.Challenges == nil {
		options.Challenges = NewMemoryChallengeStore()
	}
	if options.RateLimiter == nil {
		options.RateLimiter = NewMemoryRateLimiter()
	}
	if options.Normalize == nil {
		options.Normalize = defaultNormalizeIdentifier
	}
	return options, nil
}

func validBasePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/") && !strings.ContainsAny(value, "\\?#") && path.Clean(value) == value
}

func defaultNormalizeIdentifier(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 254 || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("invalid identifier")
	}
	return value, nil
}

func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
