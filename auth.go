package auth

import (
	"fmt"
	"net/http"
	"time"

	dreego "github.com/dreego-stack/dreego/core"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

const ClientURL = "/_dreego/plugin-auth.js"

type Auth struct {
	options   Options
	dummyHash string
	now       func() time.Time
	webAuthn  *webauthnlib.WebAuthn
}

func Register(app *dreego.App, options Options) (*Auth, error) {
	normalized, err := normalizeOptions(app, options)
	if err != nil {
		return nil, err
	}
	auth := &Auth{options: normalized, now: time.Now}
	if normalized.Password.Enabled {
		auth.dummyHash, err = normalized.Password.Hasher.Hash("dreego-auth-dummy-password")
		if err != nil {
			return nil, fmt.Errorf("auth: prepare password verifier: %w", err)
		}
	}
	if normalized.Passkeys.Enabled {
		auth.webAuthn, err = webauthnlib.New(&webauthnlib.Config{RPDisplayName: normalized.Passkeys.RPName, RPID: normalized.Passkeys.RPID, RPOrigins: normalized.Passkeys.RPOrigins})
		if err != nil {
			return nil, fmt.Errorf("auth: configure passkeys: %w", err)
		}
	}
	if err := auth.register(app); err != nil {
		return nil, err
	}
	return auth, nil
}

func (a *Auth) register(app *dreego.App) error {
	routes := []struct {
		enabled bool
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{a.options.Password.Enabled, http.MethodPost, "/register", a.registerPassword},
		{a.options.Password.Enabled, http.MethodPost, "/login/password", a.loginPassword},
		{a.options.TOTP.Enabled, http.MethodPost, "/totp/setup", a.setupTOTP},
		{a.options.TOTP.Enabled, http.MethodPost, "/totp/confirm", a.confirmTOTP},
		{a.options.TOTP.Enabled, http.MethodPost, "/login/totp", a.loginTOTP},
		{a.options.TOTP.Enabled, http.MethodPost, "/login/recovery", a.loginRecovery},
		{a.options.Passkeys.Enabled, http.MethodPost, "/passkeys/register/begin", a.beginPasskeyRegistration},
		{a.options.Passkeys.Enabled, http.MethodPost, "/passkeys/register/finish", a.finishPasskeyRegistration},
		{a.options.Passkeys.Enabled, http.MethodPost, "/login/passkey/begin", a.beginPasskeyLogin},
		{a.options.Passkeys.Enabled, http.MethodPost, "/login/passkey/finish", a.finishPasskeyLogin},
		{a.options.Codes.Enabled, http.MethodPost, "/codes/request", a.requestCode},
		{a.options.Codes.Enabled, http.MethodPost, "/codes/verify", a.verifyCode},
		{true, http.MethodPost, "/logout", a.logout},
	}
	for _, route := range routes {
		if !route.enabled {
			continue
		}
		if err := app.Register(route.method, a.options.BasePath+route.path, route.handler); err != nil {
			return fmt.Errorf("auth: register %s %s: %w", route.method, route.path, err)
		}
	}
	return nil
}

func (a *Auth) record(r *http.Request, kind, userID, identifier string) {
	if a.options.Observer == nil {
		return
	}
	a.options.Observer.Record(r.Context(), Event{Type: kind, UserID: userID, Identifier: identifier, RemoteAddr: requestIP(r), UserAgent: r.UserAgent(), At: a.now().UTC()})
}
