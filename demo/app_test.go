package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestDemoServesStyledPageBundleAndWorkingRegistration(t *testing.T) {
	app, err := newApp(bytes.Repeat([]byte{7}, 32), filepath.Join(t.TempDir(), "auth.json"), "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	pageRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	page := httptest.NewRecorder()
	app.ServeHTTP(page, pageRequest)
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(body)), "<!doctype html>") || !strings.Contains(body, "/styles.css") || !strings.Contains(body, "/_dreego/plugin-auth.js") {
		t.Fatalf("page = %d %q", page.Code, page.Body.String())
	}
	for _, control := range []string{`id="logout"`, `id="totp-login-form"`, `id="recovery-login-form"`, `rel="icon"`, `method="post"`} {
		if !strings.Contains(body, control) {
			t.Fatalf("page is missing %s", control)
		}
	}

	assertAssetContains(t, app, "/styles.css", "--accent")
	assertAssetContains(t, app, "/_dreego/plugin-auth.js", "X-CSRF-Token")
	assertAssetContains(t, app, "/favicon.svg", "<svg")
	assertAssetExcludes(t, app, "/app.js", "event.currentTarget.reset()")

	payload, _ := json.Marshal(map[string]string{
		"identifier": "demo@example.com", "displayName": "Demo User", "password": "correct horse battery staple",
	})
	request := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range page.Result().Cookies() {
		request.AddCookie(cookie)
		if cookie.Name == "csrf_token" {
			request.Header.Set("X-CSRF-Token", cookie.Value)
		}
	}
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("registration = %d %q", response.Code, response.Body.String())
	}
}

func TestDemoServesHardwareKeyTestPage(t *testing.T) {
	app, err := newApp(bytes.Repeat([]byte{7}, 32), filepath.Join(t.TempDir(), "auth.json"), "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{
		"/hardware-keys":                 "Start hardware test",
		"/hardware-keys/register":        `id="register-form"`,
		"/hardware-keys/login":           `id="login-form"`,
		"/hardware-keys/connect-passkey": `id="platform-register"`,
		"/hardware-keys/logout-passkey":  `id="logout"`,
		"/hardware-keys/verify-passkey":  `id="webauthn-login"`,
		"/hardware-keys/connect-yubikey": `id="yubikey-register"`,
		"/hardware-keys/logout-yubikey":  `id="logout"`,
		"/hardware-keys/verify-yubikey":  `id="webauthn-login"`,
	}
	for path, expected := range pages {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("hardware page %s = %d, missing %q", path, response.Code, expected)
		}
	}
	assertAssetContains(t, app, "/hardware-flow.js", "cross-platform")
}

func assertAssetExcludes(t *testing.T, app http.Handler, path, unexpected string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), unexpected) {
		t.Fatalf("asset %s = %d %q", path, response.Code, response.Body.String())
	}
}

func assertAssetContains(t *testing.T, app http.Handler, path, expected string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), expected) {
		t.Fatalf("asset %s = %d %q", path, response.Code, response.Body.String())
	}
}
