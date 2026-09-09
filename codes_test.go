package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

type memoryMessenger struct {
	mu       sync.Mutex
	messages []Message
}

func (m *memoryMessenger) Send(_ context.Context, message Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, message)
	return nil
}

func (m *memoryMessenger) last() Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.messages[len(m.messages)-1]
}

func TestCodeLoginIsSingleUseAndDoesNotExposeUnknownUsers(t *testing.T) {
	messenger := &memoryMessenger{}
	auth, app, _ := testAuthOptions(t, func(options *Options) {
		options.Codes = CodeOptions{Enabled: true}
		options.Messenger = messenger
	})
	registerAndLoginUser(t, app)

	request := requestJSON(t, app, http.MethodPost, "/auth/codes/request", map[string]string{"identifier": "mfa@example.com", "purpose": string(PurposeLoginCode)}, nil)
	if request.Code != http.StatusAccepted {
		t.Fatalf("request status = %d, body = %s", request.Code, request.Body.String())
	}
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(request.Body.Bytes(), &response); err != nil || response.ID == "" {
		t.Fatalf("request response = %q, %v", request.Body.String(), err)
	}
	message := messenger.last()
	verify := requestJSON(t, app, http.MethodPost, "/auth/codes/verify", map[string]string{"id": response.ID, "code": message.Code, "purpose": string(PurposeLoginCode)}, nil)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body = %s", verify.Code, verify.Body.String())
	}
	if session, ok, err := auth.Session(requestWithCookies(http.MethodGet, "/", verify.Result().Cookies())); err != nil || !ok || session.Level != LevelCode {
		t.Fatalf("code session = %+v, %v, %v", session, ok, err)
	}
	reused := requestJSON(t, app, http.MethodPost, "/auth/codes/verify", map[string]string{"id": response.ID, "code": message.Code, "purpose": string(PurposeLoginCode)}, nil)
	if reused.Code != http.StatusUnauthorized {
		t.Fatalf("reused status = %d", reused.Code)
	}
	unknown := requestJSON(t, app, http.MethodPost, "/auth/codes/request", map[string]string{"identifier": "unknown@example.com", "purpose": string(PurposeLoginCode)}, nil)
	if unknown.Code != http.StatusAccepted {
		t.Fatalf("unknown status = %d, body = %s", unknown.Code, unknown.Body.String())
	}
	if len(messenger.messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(messenger.messages))
	}
}

func TestVerificationAndPasswordResetCodesApplyPurpose(t *testing.T) {
	messenger := &memoryMessenger{}
	_, app, store := testAuthOptions(t, func(options *Options) {
		options.Codes = CodeOptions{Enabled: true}
		options.Messenger = messenger
	})
	registerAndLoginUser(t, app)

	requestAndVerifyCode(t, app, messenger, PurposeVerifyAccount, "")
	user, err := store.UserByIdentifier(context.Background(), "mfa@example.com")
	if err != nil || !user.Verified {
		t.Fatalf("verified user = %+v, %v", user, err)
	}
	requestAndVerifyCode(t, app, messenger, PurposePasswordReset, "new correct horse battery staple")
	oldLogin := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{"identifier": "mfa@example.com", "password": "correct horse battery staple"}, nil)
	newLogin := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{"identifier": "mfa@example.com", "password": "new correct horse battery staple"}, nil)
	if oldLogin.Code != http.StatusUnauthorized || newLogin.Code != http.StatusOK {
		t.Fatalf("old login = %d, new login = %d", oldLogin.Code, newLogin.Code)
	}
}

func requestAndVerifyCode(t *testing.T, app http.Handler, messenger *memoryMessenger, purpose Purpose, password string) {
	t.Helper()
	request := requestJSON(t, app, http.MethodPost, "/auth/codes/request", map[string]string{"identifier": "mfa@example.com", "purpose": string(purpose)}, nil)
	var response struct {
		ID string `json:"id"`
	}
	if request.Code != http.StatusAccepted || json.Unmarshal(request.Body.Bytes(), &response) != nil {
		t.Fatalf("request %s = %d %q", purpose, request.Code, request.Body.String())
	}
	message := messenger.last()
	verify := requestJSON(t, app, http.MethodPost, "/auth/codes/verify", map[string]string{"id": response.ID, "code": message.Code, "purpose": string(purpose), "password": password}, nil)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify %s = %d %q", purpose, verify.Code, verify.Body.String())
	}
}
