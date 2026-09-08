package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"
)

type credentialsInput struct {
	Identifier  string `json:"identifier"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
	Next        string `json:"next"`
}

func (a *Auth) registerPassword(w http.ResponseWriter, r *http.Request) {
	var input credentialsInput
	if err := decodeRequest(w, r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	identifier, err := a.options.Normalize(input.Identifier)
	if err != nil || utf8.RuneCountInString(input.Password) < a.options.Password.MinimumLength || len(input.Password) > 1024 {
		writeAPIError(w, http.StatusUnprocessableEntity, "INVALID_REGISTRATION", "registration details are invalid")
		return
	}
	hash, err := a.options.Password.Hasher.Hash(input.Password)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	userID, err := randomID(24)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	webAuthnID, err := randomBytes(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	user, err := a.options.Store.CreatePasswordUser(r.Context(), NewUser{ID: userID, Identifier: identifier, DisplayName: input.DisplayName, WebAuthnID: webAuthnID}, PasswordCredential{Hash: hash, UpdatedAt: a.now().UTC()})
	if errors.Is(err, ErrConflict) {
		writeAPIError(w, http.StatusConflict, "REGISTRATION_FAILED", "registration failed")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	a.record(r, "user.registered", user.ID, user.Identifier)
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (a *Auth) loginPassword(w http.ResponseWriter, r *http.Request) {
	var input credentialsInput
	if err := decodeRequest(w, r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	identifier, err := a.options.Normalize(input.Identifier)
	if err != nil || len(input.Password) > 1024 {
		a.invalidLogin(w, r, input.Identifier)
		return
	}
	allowed, err := a.options.RateLimiter.Allow(r.Context(), "password:"+requestIP(r)+":"+identifier, 10, 15*time.Minute)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	if !allowed {
		writeAPIError(w, http.StatusTooManyRequests, "RATE_LIMITED", "try again later")
		return
	}
	user, userErr := a.options.Store.UserByIdentifier(r.Context(), identifier)
	hash := a.dummyHash
	if userErr == nil {
		credential, passwordErr := a.options.Store.Password(r.Context(), user.ID)
		if passwordErr == nil {
			hash = credential.Hash
		} else if !errors.Is(passwordErr, ErrNotFound) {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
			return
		}
	} else if !errors.Is(userErr, ErrNotFound) {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	valid, verifyErr := a.options.Password.Hasher.Verify(hash, input.Password)
	if verifyErr != nil || userErr != nil || !valid || user.Disabled {
		a.invalidLogin(w, r, identifier)
		return
	}
	credential, _ := a.options.Store.Password(r.Context(), user.ID)
	if a.options.Password.Hasher.NeedsRehash(credential.Hash) {
		if updated, hashErr := a.options.Password.Hasher.Hash(input.Password); hashErr == nil {
			_ = a.options.Store.SetPassword(r.Context(), user.ID, PasswordCredential{Hash: updated, UpdatedAt: a.now().UTC()})
		}
	}
	if err := a.createSession(w, r, user, LevelPassword); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	a.record(r, "login.password.succeeded", user.ID, identifier)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "next": safeNext(input.Next)})
}

func (a *Auth) invalidLogin(w http.ResponseWriter, r *http.Request, identifier string) {
	a.record(r, "login.password.failed", "", identifier)
	writeAPIError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	_, err := rand.Read(value)
	return value, err
}

func randomID(size int) (string, error) {
	value, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
