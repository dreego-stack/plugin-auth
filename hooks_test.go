package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
)

type recordingPolicy struct {
	mu      sync.Mutex
	actions []Action
	deny    Action
}

func (p *recordingPolicy) Authorize(_ context.Context, attempt Attempt) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.actions = append(p.actions, attempt.Action)
	if attempt.Action == p.deny {
		return errors.New("blocked by risk engine")
	}
	return nil
}

type recordingObserver struct {
	mu     sync.Mutex
	events []Event
}

func (o *recordingObserver) Record(_ context.Context, event Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, event)
}

func TestPolicyCanStopLoginBeforeSessionCreation(t *testing.T) {
	policy := &recordingPolicy{deny: ActionLoginPassword}
	observer := &recordingObserver{}
	auth, app, _ := testAuthOptions(t, func(options *Options) {
		options.Policies = []Policy{policy}
		options.Observers = []Observer{observer}
	})
	requestJSON(t, app, http.MethodPost, "/auth/register", map[string]string{
		"identifier": "hook@example.com", "displayName": "Hook User", "password": "correct horse battery staple",
	}, nil)
	login := requestJSON(t, app, http.MethodPost, "/auth/login/password", map[string]string{
		"identifier": "hook@example.com", "password": "correct horse battery staple",
	}, nil)
	if login.Code != http.StatusForbidden {
		t.Fatalf("login status = %d, body = %s", login.Code, login.Body.String())
	}
	if len(login.Result().Cookies()) != 0 {
		t.Fatal("denied login created a cookie")
	}
	if _, authenticated, err := auth.User(requestWithCookies(http.MethodGet, "/", login.Result().Cookies())); err != nil || authenticated {
		t.Fatalf("denied session = %v, %v", authenticated, err)
	}
	if len(observer.events) == 0 || observer.events[len(observer.events)-1].Type != "policy.denied" {
		t.Fatalf("events = %+v", observer.events)
	}
}

func TestPolicyFuncAndMultipleObserversReceiveTypedContext(t *testing.T) {
	var got Attempt
	policy := PolicyFunc(func(_ context.Context, attempt Attempt) error {
		got = attempt
		return nil
	})
	first := &recordingObserver{}
	second := &recordingObserver{}
	_, app, _ := testAuthOptions(t, func(options *Options) {
		options.Policies = []Policy{policy}
		options.Observers = []Observer{first, second}
	})
	response := requestJSON(t, app, http.MethodPost, "/auth/register", map[string]string{
		"identifier": "hooks@example.com", "displayName": "Hooks", "password": "correct horse battery staple",
	}, nil)
	if response.Code != http.StatusCreated {
		t.Fatalf("register status = %d", response.Code)
	}
	if got.Action != ActionRegister || got.Identifier != "hooks@example.com" || got.RemoteAddr == "" {
		t.Fatalf("attempt = %+v", got)
	}
	if len(first.events) == 0 || len(second.events) == 0 {
		t.Fatalf("observer events = %d, %d", len(first.events), len(second.events))
	}
}
