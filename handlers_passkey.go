package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

const passkeyChallengeLifetime = 5 * time.Minute

func (a *Auth) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.authenticatedSessionUser(w, r)
	if !ok {
		return
	}
	webUser, err := a.passkeyUser(r, user)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	creation, session, err := a.webAuthn.BeginRegistration(webUser)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "PASSKEY_FAILED", "passkey request failed")
		return
	}
	challengeID, err := a.savePasskeyChallenge(r, "passkey.registration", user.ID, session)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challengeId": challengeID, "options": creation})
}

func (a *Auth) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.authenticatedSessionUser(w, r)
	if !ok {
		return
	}
	session, ok := a.takePasskeyChallenge(w, r, "passkey.registration", user.ID)
	if !ok {
		return
	}
	webUser, err := a.passkeyUser(r, user)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	credential, err := a.webAuthn.FinishRegistration(webUser, session, r)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "INVALID_PASSKEY", "invalid passkey response")
		return
	}
	stored := fromWebAuthnCredential(credential)
	stored.CreatedAt = a.now().UTC()
	if err := a.options.Store.SavePasskey(r.Context(), user.ID, stored); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	a.record(r, "passkey.registered", user.ID, user.Identifier)
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := a.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "PASSKEY_FAILED", "passkey request failed")
		return
	}
	challengeID, err := a.savePasskeyChallenge(r, "passkey.login", "", session)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challengeId": challengeID, "options": assertion})
}

func (a *Auth) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	session, ok := a.takePasskeyChallenge(w, r, "passkey.login", "")
	if !ok {
		return
	}
	var found User
	credential, err := a.webAuthn.FinishDiscoverableLogin(func(_, userHandle []byte) (webauthnlib.User, error) {
		user, lookupErr := a.options.Store.UserByWebAuthnID(r.Context(), userHandle)
		if lookupErr != nil || user.Disabled {
			return nil, ErrInvalidCredential
		}
		found = user
		return a.passkeyUser(r, user)
	}, session, r)
	if err != nil || found.ID == "" {
		a.record(r, "login.passkey.failed", "", "")
		writeAPIError(w, http.StatusUnauthorized, "INVALID_PASSKEY", "invalid passkey response")
		return
	}
	updated := fromWebAuthnCredential(credential)
	stored, err := a.findPasskey(r, found.ID, updated.ID)
	if err != nil {
		writeAPIError(w, http.StatusUnauthorized, "INVALID_PASSKEY", "invalid passkey response")
		return
	}
	updated.Name = stored.Name
	updated.CreatedAt = stored.CreatedAt
	if err := a.options.Store.UpdatePasskey(r.Context(), found.ID, updated, stored.SignCount); err != nil {
		writeAPIError(w, http.StatusConflict, "PASSKEY_CONFLICT", "passkey state changed")
		return
	}
	if err := a.createSession(w, r, found, LevelPasskey); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	a.record(r, "login.passkey.succeeded", found.ID, found.Identifier)
	writeJSON(w, http.StatusOK, map[string]any{"user": found})
}

func (a *Auth) passkeyUser(r *http.Request, user User) (passkeyUser, error) {
	credentials, err := a.options.Store.Passkeys(r.Context(), user.ID)
	return passkeyUser{user: user, credentials: credentials}, err
}

func (a *Auth) savePasskeyChallenge(r *http.Request, kind, userID string, session *webauthnlib.SessionData) (string, error) {
	payload, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	id, err := randomID(24)
	if err != nil {
		return "", err
	}
	expires := a.now().UTC().Add(passkeyChallengeLifetime)
	if !session.Expires.IsZero() && session.Expires.Before(expires) {
		expires = session.Expires
	}
	return id, a.options.Challenges.Put(r.Context(), Challenge{ID: id, Kind: kind, UserID: userID, Payload: payload, ExpiresAt: expires})
}

func (a *Auth) takePasskeyChallenge(w http.ResponseWriter, r *http.Request, kind, userID string) (webauthnlib.SessionData, bool) {
	id := r.URL.Query().Get("challenge")
	challenge, err := a.options.Challenges.Take(r.Context(), id, a.now().UTC())
	if err != nil || challenge.Kind != kind || challenge.UserID != userID {
		writeAPIError(w, http.StatusUnauthorized, "INVALID_CHALLENGE", "invalid or expired challenge")
		return webauthnlib.SessionData{}, false
	}
	var session webauthnlib.SessionData
	if json.Unmarshal(challenge.Payload, &session) != nil {
		writeAPIError(w, http.StatusUnauthorized, "INVALID_CHALLENGE", "invalid or expired challenge")
		return webauthnlib.SessionData{}, false
	}
	return session, true
}

func (a *Auth) findPasskey(r *http.Request, userID string, id []byte) (PasskeyCredential, error) {
	credentials, err := a.options.Store.Passkeys(r.Context(), userID)
	if err != nil {
		return PasskeyCredential{}, err
	}
	for _, credential := range credentials {
		if string(credential.ID) == string(id) {
			return credential, nil
		}
	}
	return PasskeyCredential{}, errors.New("passkey not found")
}
