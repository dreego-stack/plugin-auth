package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireUserProvidesPrincipalAndUserToDownstreamPlugins(t *testing.T) {
	auth, app, _ := testAuth(t)
	cookies := registerAndLoginUser(t, app)
	called := false
	handler := auth.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.UserID == "" || principal.Level != LevelPassword {
			t.Fatalf("principal = %+v, %v", principal, ok)
		}
		user, ok := UserFromContext(r.Context())
		if !ok || user.ID != principal.UserID {
			t.Fatalf("user = %+v, %v", user, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := requestWithCookies(http.MethodGet, "/billing", cookies)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("called = %v, status = %d", called, response.Code)
	}
}
