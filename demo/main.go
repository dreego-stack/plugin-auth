package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	dreego "github.com/dreego-stack/dreego/core"
	"github.com/dreego-stack/dreego/core/ssr"
	auth "github.com/dreego-stack/plugin-auth"
	"github.com/dreego-stack/plugin-auth/demo/jsonstore"
	"github.com/dreego-stack/plugin-auth/demo/www"
)

func main() {
	secret, err := hex.DecodeString(os.Getenv("AUTH_SECRET"))
	if err != nil || len(secret) < 32 {
		log.Fatal("AUTH_SECRET must contain at least 32 random bytes encoded as hex")
	}
	app, err := newApp(secret, envOr("AUTH_DB", "data/auth.json"))
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(ssr.Listen(app, ":8080"))
}

func newApp(secret []byte, databasePath string) (*dreego.App, error) {
	store, err := jsonstore.Open(databasePath)
	if err != nil {
		return nil, err
	}
	app := dreego.New()
	sessions := dreego.NewCookieStore(secret)
	sessions.SetCookiePolicy(dreego.CookiePolicy{HttpOnly: true, Path: "/", Encrypt: true})
	if err := app.SetSessionStore(sessions); err != nil {
		return nil, err
	}
	plugin, err := auth.Register(app, auth.Options{
		Store: store, SessionStore: sessions, Secret: secret,
		Password: auth.PasswordOptions{Enabled: true},
		Passkeys: auth.PasskeyOptions{Enabled: true, RPName: "Dreego Auth Demo", RPID: "localhost", RPOrigins: []string{"http://localhost:8080"}},
		TOTP:     auth.TOTPOptions{Enabled: true, Issuer: "Dreego Auth Demo"},
		Codes:    auth.CodeOptions{Enabled: true}, Messenger: demoMessenger{},
		Policies: []auth.Policy{auth.PolicyFunc(demoPolicy)}, Observers: []auth.Observer{demoObserver{}},
	})
	if err != nil {
		return nil, err
	}
	currentUser := plugin.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, err := plugin.User(r)
		if err != nil {
			http.Error(w, "request failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": user})
	}))
	if err := app.Register(http.MethodGet, "/api/me", currentUser.ServeHTTP); err != nil {
		return nil, err
	}
	if err := www.Register(app); err != nil {
		return nil, err
	}
	return app, nil
}

func demoPolicy(_ context.Context, attempt auth.Attempt) error {
	if strings.Contains(attempt.UserAgent, "Dreego-Demo-Blocked") {
		return auth.ErrDisabled
	}
	return nil
}

type demoObserver struct{}

func (demoObserver) Record(_ context.Context, event auth.Event) {
	slog.Info("auth event", "type", event.Type, "user", event.UserID, "ip", event.RemoteAddr)
}

type demoMessenger struct{}

func (demoMessenger) Send(_ context.Context, message auth.Message) error {
	slog.Info("demo code", "purpose", message.Purpose, "recipient", message.Recipient, "code", message.Code)
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
