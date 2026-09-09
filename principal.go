package auth

import (
	"context"
	"net/http"
	"time"
)

type Principal struct {
	UserID          string
	Level           AuthLevel
	AuthenticatedAt time.Time
}

type Resolver interface {
	User(*http.Request) (User, bool, error)
	Session(*http.Request) (Session, bool, error)
	RequireUser(http.Handler) http.Handler
}

type principalContextKey struct{}
type userContextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(userContextKey{}).(User)
	return user, ok
}

func withIdentity(r *http.Request, user User, session Session) *http.Request {
	principal := Principal{UserID: user.ID, Level: session.Level, AuthenticatedAt: session.AuthenticatedAt}
	ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
	ctx = context.WithValue(ctx, userContextKey{}, user)
	return r.WithContext(ctx)
}

var _ Resolver = (*Auth)(nil)
