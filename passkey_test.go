package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestPasskeyBeginCreatesSingleUseBoundChallenges(t *testing.T) {
	challenges := NewMemoryChallengeStore()
	_, app, _ := testAuthOptions(t, func(options *Options) {
		options.Challenges = challenges
		options.Passkeys = PasskeyOptions{Enabled: true, RPName: "Dreego Test", RPID: "example.com", RPOrigins: []string{"https://example.com"}}
	})
	cookies := registerAndLoginUser(t, app)

	registration := requestJSON(t, app, http.MethodPost, "/auth/passkeys/register/begin", nil, cookies)
	challengeID := responseChallengeID(t, registration)
	challenge, err := challenges.Take(context.Background(), challengeID, time.Now())
	if err != nil || challenge.Kind != "passkey.registration" || challenge.UserID == "" {
		t.Fatalf("registration challenge = %+v, %v", challenge, err)
	}
	if _, err := challenges.Take(context.Background(), challengeID, time.Now()); err == nil {
		t.Fatal("registration challenge was reusable")
	}

	login := requestJSON(t, app, http.MethodPost, "/auth/login/passkey/begin", nil, nil)
	loginID := responseChallengeID(t, login)
	challenge, err = challenges.Take(context.Background(), loginID, time.Now())
	if err != nil || challenge.Kind != "passkey.login" || challenge.UserID != "" {
		t.Fatalf("login challenge = %+v, %v", challenge, err)
	}
}

func TestPasskeyConfigurationRejectsUntrustedOrigins(t *testing.T) {
	app := newTestApp(t)
	_, err := Register(app, Options{
		Store: NewMemoryStore(), Secret: []byte("01234567890123456789012345678901"),
		Passkeys: PasskeyOptions{Enabled: true, RPName: "Test", RPID: "example.com", RPOrigins: []string{"https://example.com/path"}},
	})
	if err == nil {
		t.Fatal("Register accepted an origin with a path")
	}
}

func TestPasskeyRegistrationCanRequireExternalSecurityKey(t *testing.T) {
	_, app, _ := testAuthOptions(t, func(options *Options) {
		options.Passkeys = PasskeyOptions{Enabled: true, RPName: "Dreego Test", RPID: "example.com", RPOrigins: []string{"https://example.com"}}
	})
	cookies := registerAndLoginUser(t, app)
	response := requestJSON(t, app, http.MethodPost, "/auth/passkeys/register/begin", map[string]string{"attachment": "cross-platform"}, cookies)
	if response.Code != http.StatusOK {
		t.Fatalf("security-key begin = %d %q", response.Code, response.Body.String())
	}
	var body struct {
		Options struct {
			PublicKey struct {
				AuthenticatorSelection struct {
					Attachment  string `json:"authenticatorAttachment"`
					ResidentKey string `json:"residentKey"`
				} `json:"authenticatorSelection"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	selection := body.Options.PublicKey.AuthenticatorSelection
	if selection.Attachment != "cross-platform" || selection.ResidentKey != "required" {
		t.Fatalf("authenticator selection = %+v", selection)
	}
	invalid := requestJSON(t, app, http.MethodPost, "/auth/passkeys/register/begin", map[string]string{"attachment": "yubikey"}, cookies)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid attachment status = %d", invalid.Code)
	}
}

func responseChallengeID(t *testing.T, response interface {
	Result() *http.Response
}) string {
	t.Helper()
	result := response.Result()
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		t.Fatalf("begin status = %d", result.StatusCode)
	}
	var body struct {
		ChallengeID string          `json:"challengeId"`
		Options     json.RawMessage `json:"options"`
	}
	if err := json.NewDecoder(result.Body).Decode(&body); err != nil || body.ChallengeID == "" || len(body.Options) == 0 {
		t.Fatalf("begin response = %+v, %v", body, err)
	}
	return body.ChallengeID
}
