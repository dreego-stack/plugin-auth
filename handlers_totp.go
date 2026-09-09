package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type codeInput struct {
	Code string `json:"code"`
}

func (a *Auth) setupTOTP(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.authenticatedSessionUser(w, r)
	if !ok {
		return
	}
	secret, err := randomBase32(20)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	encrypted, err := encryptValue(a.options.Secret, "totp:"+user.ID, []byte(secret))
	if err != nil || a.options.Store.SetTOTP(r.Context(), user.ID, TOTPCredential{EncryptedSecret: encrypted, CreatedAt: a.now().UTC()}) != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	label := url.PathEscape(a.options.TOTP.Issuer + ":" + user.Identifier)
	query := url.Values{"secret": {secret}, "issuer": {a.options.TOTP.Issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(a.options.TOTP.Digits)}, "period": {fmt.Sprint(int(a.options.TOTP.Period.Seconds()))}}
	writeJSON(w, http.StatusOK, map[string]any{"secret": secret, "uri": "otpauth://totp/" + label + "?" + query.Encode()})
}

func (a *Auth) confirmTOTP(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	var input codeInput
	if decodeRequest(w, r, &input) != nil {
		writeAPIError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	credential, secret, ok := a.totpCredential(w, r, user.ID, false)
	if !ok {
		return
	}
	if !verifyTOTP(secret, input.Code, a.now(), a.options.TOTP) {
		writeAPIError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid code")
		return
	}
	credential.Confirmed = true
	if err := a.options.Store.SetTOTP(r.Context(), user.ID, credential); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	codes, stored, err := a.newRecoveryCodes(user.ID, 10)
	if err != nil || a.options.Store.SetRecoveryCodes(r.Context(), user.ID, stored) != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	a.record(r, "totp.enabled", user.ID, user.Identifier)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
}

func (a *Auth) loginTOTP(w http.ResponseWriter, r *http.Request) {
	user, session, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	if session.Level != LevelPassword {
		writeAPIError(w, http.StatusConflict, "INVALID_AUTH_STATE", "authentication state is invalid")
		return
	}
	if !a.allowSecondFactor(w, r, user.ID) {
		return
	}
	var input codeInput
	if decodeRequest(w, r, &input) != nil {
		writeAPIError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	_, secret, ok := a.totpCredential(w, r, user.ID, true)
	if !ok {
		return
	}
	if !verifyTOTP(secret, input.Code, a.now(), a.options.TOTP) {
		a.invalidSecondFactor(w, r, user, "totp")
		return
	}
	if err := a.createSession(w, r, user, LevelMFA); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	a.record(r, "login.totp.succeeded", user.ID, user.Identifier)
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (a *Auth) loginRecovery(w http.ResponseWriter, r *http.Request) {
	user, session, ok := a.sessionUser(w, r)
	if !ok {
		return
	}
	if session.Level != LevelPassword {
		writeAPIError(w, http.StatusConflict, "INVALID_AUTH_STATE", "authentication state is invalid")
		return
	}
	if !a.allowSecondFactor(w, r, user.ID) {
		return
	}
	var input codeInput
	if decodeRequest(w, r, &input) != nil {
		writeAPIError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	proof := codeProof(a.options.Secret, "recovery:"+user.ID, input.Code)
	matched, err := a.options.Store.ConsumeRecoveryCode(r.Context(), user.ID, proof, a.now().UTC())
	if err != nil || !matched {
		a.invalidSecondFactor(w, r, user, "recovery")
		return
	}
	if err := a.createSession(w, r, user, LevelMFA); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	a.record(r, "login.recovery.succeeded", user.ID, user.Identifier)
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (a *Auth) sessionUser(w http.ResponseWriter, r *http.Request) (User, Session, bool) {
	session, ok, err := a.Session(r)
	if err != nil || !ok {
		writeAPIError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "authentication required")
		return User{}, Session{}, false
	}
	user, err := a.options.Store.UserByID(r.Context(), session.UserID)
	if err != nil || user.Disabled {
		writeAPIError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "authentication required")
		return User{}, Session{}, false
	}
	return user, session, true
}

func (a *Auth) authenticatedSessionUser(w http.ResponseWriter, r *http.Request) (User, Session, bool) {
	user, session, ok := a.sessionUser(w, r)
	if !ok {
		return User{}, Session{}, false
	}
	if !a.sessionCompletesAuthentication(r, user, session) {
		writeAPIError(w, http.StatusUnauthorized, "SECOND_FACTOR_REQUIRED", "second factor required")
		return User{}, Session{}, false
	}
	return user, session, true
}

func (a *Auth) totpCredential(w http.ResponseWriter, r *http.Request, userID string, confirmed bool) (TOTPCredential, string, bool) {
	credential, err := a.options.Store.TOTP(r.Context(), userID)
	if err != nil || credential.Confirmed != confirmed {
		status := http.StatusConflict
		if !errors.Is(err, ErrNotFound) && err != nil {
			status = http.StatusInternalServerError
		}
		writeAPIError(w, status, "TOTP_UNAVAILABLE", "TOTP is unavailable")
		return TOTPCredential{}, "", false
	}
	plaintext, err := decryptValue(a.options.Secret, "totp:"+userID, credential.EncryptedSecret)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return TOTPCredential{}, "", false
	}
	return credential, string(plaintext), true
}

func (a *Auth) newRecoveryCodes(userID string, count int) ([]string, []RecoveryCode, error) {
	plain := make([]string, count)
	stored := make([]RecoveryCode, count)
	for i := range plain {
		raw, err := randomBase32(10)
		if err != nil {
			return nil, nil, err
		}
		raw = strings.ToUpper(raw)
		plain[i] = raw[:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:]
		stored[i] = RecoveryCode{Proof: codeProof(a.options.Secret, "recovery:"+userID, plain[i])}
	}
	return plain, stored, nil
}

func (a *Auth) invalidSecondFactor(w http.ResponseWriter, r *http.Request, user User, method string) {
	a.record(r, "login."+method+".failed", user.ID, user.Identifier)
	writeAPIError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid code")
}

func (a *Auth) allowSecondFactor(w http.ResponseWriter, r *http.Request, userID string) bool {
	allowed, err := a.options.RateLimiter.Allow(r.Context(), "second-factor:"+requestIP(r)+":"+userID, 10, 5*time.Minute)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return false
	}
	if !allowed {
		writeAPIError(w, http.StatusTooManyRequests, "RATE_LIMITED", "try again later")
		return false
	}
	return true
}
