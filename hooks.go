package auth

import (
	"context"
	"net/http"
)

type Action string

const (
	ActionRegister        Action = "register"
	ActionLoginPassword   Action = "login.password"
	ActionLoginPasskey    Action = "login.passkey"
	ActionLoginTOTP       Action = "login.totp"
	ActionLoginRecovery   Action = "login.recovery"
	ActionRequestCode     Action = "code.request"
	ActionVerifyCode      Action = "code.verify"
	ActionRegisterPasskey Action = "passkey.register"
	ActionConfigureTOTP   Action = "totp.configure"
)

type Attempt struct {
	Action     Action
	User       User
	Identifier string
	RemoteAddr string
	UserAgent  string
	Attributes map[string]string
}

type Policy interface {
	Authorize(context.Context, Attempt) error
}

type PolicyFunc func(context.Context, Attempt) error

func (f PolicyFunc) Authorize(ctx context.Context, attempt Attempt) error {
	return f(ctx, attempt)
}

func (a *Auth) authorize(w http.ResponseWriter, r *http.Request, attempt Attempt) bool {
	attempt.RemoteAddr = requestIP(r)
	attempt.UserAgent = r.UserAgent()
	for _, policy := range a.options.Policies {
		if policy == nil {
			continue
		}
		if err := policy.Authorize(r.Context(), attempt); err != nil {
			a.record(r, "policy.denied", attempt.User.ID, attempt.Identifier)
			writeAPIError(w, http.StatusForbidden, "AUTH_DENIED", "authentication request denied")
			return false
		}
	}
	return true
}
