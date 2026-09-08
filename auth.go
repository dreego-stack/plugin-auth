package auth

import (
	"fmt"
	"net/http"
	"time"

	dreego "github.com/dreego-stack/dreego/core"
)

const ClientURL = "/_dreego/plugin-auth.js"

type Auth struct {
	options   Options
	dummyHash string
	now       func() time.Time
}

func Register(app *dreego.App, options Options) (*Auth, error) {
	normalized, err := normalizeOptions(app, options)
	if err != nil {
		return nil, err
	}
	auth := &Auth{options: normalized, now: time.Now}
	if normalized.Password.Enabled {
		auth.dummyHash, err = normalized.Password.Hasher.Hash("dreego-auth-dummy-password")
		if err != nil {
			return nil, fmt.Errorf("auth: prepare password verifier: %w", err)
		}
	}
	if err := auth.register(app); err != nil {
		return nil, err
	}
	return auth, nil
}

func (a *Auth) register(app *dreego.App) error {
	routes := []struct {
		enabled bool
		method  string
		path    string
		handler http.HandlerFunc
	}{
		{a.options.Password.Enabled, http.MethodPost, "/register", a.registerPassword},
		{a.options.Password.Enabled, http.MethodPost, "/login/password", a.loginPassword},
		{true, http.MethodPost, "/logout", a.logout},
	}
	for _, route := range routes {
		if !route.enabled {
			continue
		}
		if err := app.Register(route.method, a.options.BasePath+route.path, route.handler); err != nil {
			return fmt.Errorf("auth: register %s %s: %w", route.method, route.path, err)
		}
	}
	return nil
}

func (a *Auth) record(r *http.Request, kind, userID, identifier string) {
	if a.options.Observer == nil {
		return
	}
	a.options.Observer.Record(r.Context(), Event{Type: kind, UserID: userID, Identifier: identifier, RemoteAddr: requestIP(r), UserAgent: r.UserAgent(), At: a.now().UTC()})
}
