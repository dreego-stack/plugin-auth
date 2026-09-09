package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dreego "github.com/dreego-stack/dreego/core"
)

func TestPasswordRegistrationLoginSessionAndLogout(t *testing.T) {
	auth, app, store := testAuth(t)

	register := requestJSON(t, app, http.MethodPost, "/auth/register", map[string]string{
		"identifier": "User@example.com", "displayName": "Example User", "password": "correct horse battery staple",
	}, nil)
	if register.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", register.Code, register.Body.String())
	}
	user, err := store.UserByIdentifier(context.Background(), "user@example.com")
	if err != nil || user.DisplayName != "Example User" {
		t.Fatalf("stored user = %+v, %v", user, err)
	}

	login := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{
		"identifier": "USER@example.com", "password": "correct horse battery staple",
	}, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	meRequest := httptest.NewRequest(http.MethodGet, "/me", nil)
	for _, cookie := range cookies {
		meRequest.AddCookie(cookie)
	}
	got, authenticated, err := auth.User(meRequest)
	if err != nil || !authenticated || got.ID != user.ID {
		t.Fatalf("User() = %+v, %v, %v", got, authenticated, err)
	}

	logout := requestJSON(t, app, http.MethodPost, "/auth/logout", nil, cookies)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, body = %s", logout.Code, logout.Body.String())
	}
	if _, authenticated, err := auth.User(requestWithCookies(http.MethodGet, "/me", cookies)); err != nil || authenticated {
		t.Fatalf("User() after logout = authenticated %v, error %v", authenticated, err)
	}
}

func TestPasswordLoginUsesGenericFailureForUnknownAndWrongPassword(t *testing.T) {
	_, app, _ := testAuth(t)
	requestJSON(t, app, http.MethodPost, "/auth/register", map[string]string{
		"identifier": "user@example.com", "displayName": "User", "password": "another correct password",
	}, nil)
	unknown := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{"identifier": "unknown", "password": "wrong password value"}, nil)
	wrong := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{"identifier": "user@example.com", "password": "wrong password value"}, nil)
	if unknown.Code != http.StatusUnauthorized || wrong.Code != http.StatusUnauthorized || unknown.Body.String() != wrong.Body.String() {
		t.Fatalf("unknown = %d %q, wrong = %d %q", unknown.Code, unknown.Body.String(), wrong.Code, wrong.Body.String())
	}
}

func TestRegisterRejectsUnsafeConfigurationBeforeAddingRoutes(t *testing.T) {
	app := dreego.New()
	if _, err := Register(app, Options{Store: NewMemoryStore(), Secret: []byte("short"), Password: PasswordOptions{Enabled: true}}); err == nil {
		t.Fatal("Register accepted a short secret")
	}
	if err := app.Register(http.MethodGet, "/auth/login/password", func(http.ResponseWriter, *http.Request) {}); err != nil {
		t.Fatalf("failed Register must not leave routes behind: %v", err)
	}
}

func testAuth(t *testing.T) (*Auth, *dreego.App, *MemoryStore) {
	return testAuthOptions(t, nil)
}

func testAuthOptions(t *testing.T, configure func(*Options)) (*Auth, *dreego.App, *MemoryStore) {
	t.Helper()
	app := newTestApp(t)
	store := NewMemoryStore()
	hasher, err := NewArgon2idHasher(Argon2idParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	if err != nil {
		t.Fatal(err)
	}
	options := Options{
		Store: store, Secret: bytes.Repeat([]byte{9}, 32), Password: PasswordOptions{Enabled: true, Hasher: hasher, MinimumLength: 12},
		SessionLifetime: time.Hour,
	}
	if configure != nil {
		configure(&options)
	}
	auth, err := Register(app, options)
	if err != nil {
		t.Fatal(err)
	}
	return auth, app, store
}

func newTestApp(t *testing.T) *dreego.App {
	t.Helper()
	app := dreego.New()
	app.SetCSRF(false)
	cookies := dreego.NewCookieStore(bytes.Repeat([]byte{7}, 32))
	cookies.SetCookiePolicy(dreego.CookiePolicy{HttpOnly: true, Path: "/", Encrypt: true})
	if err := app.SetSessionStore(cookies); err != nil {
		t.Fatal(err)
	}
	return app
}

func requestJSON(t *testing.T, handler http.Handler, method, path string, body any, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func requestWithCookies(method, path string, cookies []*http.Cookie) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}
