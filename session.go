package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	dreego "github.com/dreego-stack/dreego/core"
)

const sessionIDKey = "auth.session_id"

func (a *Auth) createSession(w http.ResponseWriter, r *http.Request, user User, level AuthLevel) error {
	id, err := randomID(32)
	if err != nil {
		return err
	}
	now := a.now().UTC()
	session := Session{
		ID: id, UserID: user.ID, Level: level, AuthenticatedAt: now, LastSeenAt: now,
		ExpiresAt: now.Add(a.options.SessionLifetime), UserAgent: r.UserAgent(), RemoteAddr: requestIP(r),
	}
	if current, _ := a.options.SessionStore.Get(r, sessionIDKey); current != "" {
		_ = a.options.Store.RevokeSession(r.Context(), current)
	}
	if err := a.options.Store.CreateSession(r.Context(), session); err != nil {
		return err
	}
	cookie := &dreego.Options{MaxAge: int(a.options.SessionLifetime.Seconds()), HttpOnly: true, Secure: r.TLS != nil, Encrypt: true}
	if err := a.options.SessionStore.Set(w, r, sessionIDKey, id, cookie); err != nil {
		_ = a.options.Store.RevokeSession(r.Context(), id)
		return err
	}
	return nil
}

func (a *Auth) User(r *http.Request) (User, bool, error) {
	id, err := a.options.SessionStore.Get(r, sessionIDKey)
	if err != nil || id == "" {
		return User{}, false, err
	}
	session, err := a.options.Store.SessionByID(r.Context(), id, a.now().UTC())
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	user, err := a.options.Store.UserByID(r.Context(), session.UserID)
	if errors.Is(err, ErrNotFound) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	if user.Disabled {
		_ = a.options.Store.RevokeSession(r.Context(), id)
		return User{}, false, nil
	}
	if !a.sessionCompletesAuthentication(r, user, session) {
		return User{}, false, nil
	}
	return user, true, nil
}

func (a *Auth) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, authenticated, err := a.User(r)
		if err != nil || !authenticated {
			writeAPIError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *Auth) sessionCompletesAuthentication(r *http.Request, user User, session Session) bool {
	if session.Level != LevelPassword || !a.options.TOTP.Enabled {
		return true
	}
	credential, err := a.options.Store.TOTP(r.Context(), user.ID)
	return errors.Is(err, ErrNotFound) || err == nil && !credential.Confirmed
}

func (a *Auth) RequireLevel(level AuthLevel) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := a.options.SessionStore.Get(r, sessionIDKey)
			if err != nil || id == "" {
				writeAPIError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "authentication required")
				return
			}
			session, err := a.options.Store.SessionByID(r.Context(), id, a.now().UTC())
			if err != nil || level != "" && session.Level != level && session.Level != LevelMFA {
				writeAPIError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "authentication required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *Auth) logout(w http.ResponseWriter, r *http.Request) {
	if id, _ := a.options.SessionStore.Get(r, sessionIDKey); id != "" {
		_ = a.options.Store.RevokeSession(r.Context(), id)
	}
	if err := a.options.SessionStore.Delete(w, r, sessionIDKey); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) Session(r *http.Request) (Session, bool, error) {
	id, err := a.options.SessionStore.Get(r, sessionIDKey)
	if err != nil || id == "" {
		return Session{}, false, err
	}
	session, err := a.options.Store.SessionByID(r.Context(), id, a.now().UTC())
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) {
		return Session{}, false, nil
	}
	return session, err == nil, err
}

func (a *Auth) RevokeAll(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("auth: user id is required")
	}
	return a.options.Store.RevokeUserSessions(ctx, userID)
}
