package auth

import (
	"errors"
	"net/http"
	"unicode/utf8"
)

type requestCodeInput struct {
	Identifier string  `json:"identifier"`
	Purpose    Purpose `json:"purpose"`
}

type verifyCodeInput struct {
	ID       string  `json:"id"`
	Code     string  `json:"code"`
	Purpose  Purpose `json:"purpose"`
	Password string  `json:"password"`
}

func (a *Auth) requestCode(w http.ResponseWriter, r *http.Request) {
	var input requestCodeInput
	if decodeRequest(w, r, &input) != nil || !validCodePurpose(input.Purpose) {
		writeAPIError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	identifier, normalizeErr := a.options.Normalize(input.Identifier)
	if normalizeErr != nil {
		identifier = "invalid"
	}
	allowed, err := a.options.RateLimiter.Allow(r.Context(), "code:"+requestIP(r)+":"+identifier+":"+string(input.Purpose), 5, a.options.Codes.Lifetime)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	if !allowed {
		writeAPIError(w, http.StatusTooManyRequests, "RATE_LIMITED", "try again later")
		return
	}
	id, err := randomID(24)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	plain, err := randomNumericCode(8)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	user, lookupErr := a.options.Store.UserByIdentifier(r.Context(), identifier)
	userID := ""
	if lookupErr == nil && !user.Disabled {
		userID = user.ID
	} else if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	expires := a.now().UTC().Add(a.options.Codes.Lifetime)
	code := OneTimeCode{ID: id, UserID: userID, Recipient: identifier, Purpose: input.Purpose, Proof: codeProof(a.options.Secret, codeLabel(id, input.Purpose), plain), ExpiresAt: expires, MaxAttempts: a.options.Codes.MaxAttempts}
	if err := a.options.Store.SaveCode(r.Context(), code); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
		return
	}
	if userID != "" {
		if err := a.options.Messenger.Send(r.Context(), Message{Purpose: input.Purpose, Recipient: identifier, Code: plain, ExpiresAt: expires}); err != nil {
			_ = a.options.Store.DeleteCode(r.Context(), id)
			a.record(r, "code.delivery_failed", userID, identifier)
			writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "expiresAt": expires})
			return
		}
	}
	a.record(r, "code.requested", userID, identifier)
	writeJSON(w, http.StatusAccepted, map[string]any{"id": id, "expiresAt": expires})
}

func (a *Auth) verifyCode(w http.ResponseWriter, r *http.Request) {
	var input verifyCodeInput
	if decodeRequest(w, r, &input) != nil || input.ID == "" || !validCodePurpose(input.Purpose) {
		writeAPIError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	proof := codeProof(a.options.Secret, codeLabel(input.ID, input.Purpose), input.Code)
	code, matched, err := a.options.Store.AttemptCode(r.Context(), input.ID, proof, a.now().UTC())
	if err != nil || !matched || code.UserID == "" || code.Purpose != input.Purpose {
		writeAPIError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid or expired code")
		return
	}
	user, err := a.options.Store.UserByID(r.Context(), code.UserID)
	if err != nil || user.Disabled {
		writeAPIError(w, http.StatusUnauthorized, "INVALID_CODE", "invalid or expired code")
		return
	}
	if !a.applyVerifiedCode(w, r, user, input) {
		return
	}
	a.record(r, "code.verified", user.ID, user.Identifier)
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (a *Auth) applyVerifiedCode(w http.ResponseWriter, r *http.Request, user User, input verifyCodeInput) bool {
	switch input.Purpose {
	case PurposeLoginCode:
		if err := a.createSession(w, r, user, LevelCode); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
			return false
		}
	case PurposeVerifyAccount:
		if err := a.options.Store.SetUserVerified(r.Context(), user.ID, true); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
			return false
		}
		user.Verified = true
	case PurposePasswordReset:
		if !a.options.Password.Enabled || utf8.RuneCountInString(input.Password) < a.options.Password.MinimumLength || len(input.Password) > 1024 {
			writeAPIError(w, http.StatusUnprocessableEntity, "INVALID_PASSWORD", "password is invalid")
			return false
		}
		hash, err := a.options.Password.Hasher.Hash(input.Password)
		if err != nil || a.options.Store.SetPassword(r.Context(), user.ID, PasswordCredential{Hash: hash, UpdatedAt: a.now().UTC()}) != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "request failed")
			return false
		}
		_ = a.options.Store.RevokeUserSessions(r.Context(), user.ID)
	}
	return true
}

func validCodePurpose(purpose Purpose) bool {
	return purpose == PurposeLoginCode || purpose == PurposeVerifyAccount || purpose == PurposePasswordReset
}

func codeLabel(id string, purpose Purpose) string {
	return "one-time:" + id + ":" + string(purpose)
}
