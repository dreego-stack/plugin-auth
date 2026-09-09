package auth

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestTOTPSetupConfirmAndRecoveryLogin(t *testing.T) {
	auth, app, _ := testAuthWithTOTP(t)
	registerAndLogin := registerAndLoginUser(t, app)

	setup := requestJSON(t, app, http.MethodPost, "/auth/totp/setup", nil, registerAndLogin)
	if setup.Code != http.StatusOK {
		t.Fatalf("setup status = %d, body = %s", setup.Code, setup.Body.String())
	}
	var setupBody struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupBody); err != nil || setupBody.Secret == "" {
		t.Fatalf("setup response = %q, %v", setup.Body.String(), err)
	}
	code, err := generateTOTP(setupBody.Secret, auth.now(), auth.options.TOTP)
	if err != nil {
		t.Fatal(err)
	}
	confirm := requestJSON(t, app, http.MethodPost, "/auth/totp/confirm", map[string]string{"code": code}, registerAndLogin)
	if confirm.Code != http.StatusOK {
		t.Fatalf("confirm status = %d, body = %s", confirm.Code, confirm.Body.String())
	}
	var confirmBody struct {
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	if err := json.Unmarshal(confirm.Body.Bytes(), &confirmBody); err != nil || len(confirmBody.RecoveryCodes) != 10 {
		t.Fatalf("confirm response = %q, %v", confirm.Body.String(), err)
	}

	passwordSession := registerAndLogin
	secondFactor := requestJSON(t, app, http.MethodPost, "/auth/login/totp", map[string]string{"code": code}, passwordSession)
	if secondFactor.Code != http.StatusOK {
		t.Fatalf("TOTP login status = %d, body = %s", secondFactor.Code, secondFactor.Body.String())
	}
	if session, ok, err := auth.Session(requestWithCookies(http.MethodGet, "/", secondFactor.Result().Cookies())); err != nil || !ok || session.Level != LevelMFA {
		t.Fatalf("TOTP session = %+v, %v, %v", session, ok, err)
	}

	relogin := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{
		"identifier": "mfa@example.com", "password": "correct horse battery staple",
	}, nil)
	if relogin.Code != http.StatusOK {
		t.Fatalf("second password login status = %d, body = %s", relogin.Code, relogin.Body.String())
	}
	passwordSession = relogin.Result().Cookies()
	recovery := requestJSON(t, app, http.MethodPost, "/auth/login/recovery", map[string]string{"code": confirmBody.RecoveryCodes[0]}, passwordSession)
	if recovery.Code != http.StatusOK {
		t.Fatalf("recovery login status = %d, body = %s", recovery.Code, recovery.Body.String())
	}
	relogin = requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{
		"identifier": "mfa@example.com", "password": "correct horse battery staple",
	}, nil)
	reused := requestJSON(t, app, http.MethodPost, "/auth/login/recovery", map[string]string{"code": confirmBody.RecoveryCodes[0]}, relogin.Result().Cookies())
	if reused.Code != http.StatusUnauthorized {
		t.Fatalf("reused recovery status = %d, body = %s", reused.Code, reused.Body.String())
	}
}

func testAuthWithTOTP(t *testing.T) (*Auth, http.Handler, *MemoryStore) {
	t.Helper()
	auth, app, store := testAuthOptions(t, func(options *Options) {
		options.TOTP = TOTPOptions{Enabled: true, Issuer: "Dreego Test", Digits: 6, Period: 30 * time.Second}
	})
	return auth, app, store
}

func registerAndLoginUser(t *testing.T, app http.Handler) []*http.Cookie {
	t.Helper()
	register := requestJSON(t, app, http.MethodPost, "/auth/register", map[string]string{
		"identifier": "mfa@example.com", "displayName": "MFA User", "password": "correct horse battery staple",
	}, nil)
	if register.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", register.Code, register.Body.String())
	}
	login := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{
		"identifier": "mfa@example.com", "password": "correct horse battery staple",
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", login.Code, login.Body.String())
	}
	return login.Result().Cookies()
}
