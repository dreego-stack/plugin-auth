# plugin-auth

Authentication for [Dreego](https://github.com/dreego-stack/dreego) SSR applications.

The plugin provides password login, platform passkeys, external WebAuthn security keys, TOTP, single-use recovery codes, email or SMS one-time codes, account verification, password reset, and server-side sessions. Storage and message delivery remain application-owned interfaces.

See the [interactive demo](demo/README.md) for a Dreego application using embedded plain CSS and a JSON-backed demo store.

## Install

```sh
go get github.com/dreego-stack/plugin-auth
```

Configure the Dreego client modules in `dreego.json`:

```json
{
  "plugins": {
    "github.com/dreego-stack/plugin-auth": {
      "client": ["password", "passkeys", "totp", "codes"]
    }
  }
}
```

## Register

```go
package main

import (
    "encoding/base64"
    "log"
    "os"

    dreego "github.com/dreego-stack/dreego/core"
    auth "github.com/dreego-stack/plugin-auth"
)

func main() {
    app := dreego.New()
    secret, err := base64.RawURLEncoding.DecodeString(os.Getenv("AUTH_SECRET"))
    if err != nil {
        log.Fatal(err)
    }

    sessions := dreego.NewCookieStore(secret)
    if err := app.SetSessionStore(sessions); err != nil {
        log.Fatal(err)
    }

    _, err = auth.Register(app, auth.Options{
        Store:        auth.NewMemoryStore(),
        SessionStore: sessions,
        Secret:       secret,
        Password:     auth.PasswordOptions{Enabled: true},
        Passkeys: auth.PasskeyOptions{
            Enabled:   true,
            RPName:    "Example",
            RPID:      "example.com",
            RPOrigins: []string{"https://example.com"},
        },
        TOTP: auth.TOTPOptions{Enabled: true, Issuer: "Example"},
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(app.Listen(":8080"))
}
```

`NewMemoryStore` and `NewMemoryChallengeStore` are for tests and single-process development. Production applications must implement durable storage with the atomic semantics described by `Store` and `ChallengeStore`.

## Browser API

The generated client bundle exposes `globalThis.DreegoAuth`:

```js
DreegoAuth.configure({ basePath: "/auth" });
await DreegoAuth.loginWithPassword({ identifier, password });
await DreegoAuth.registerPasskey({ attachment: "platform" });
await DreegoAuth.registerPasskey({ attachment: "cross-platform" });
await DreegoAuth.loginWithPasskey();
await DreegoAuth.loginWithTOTP(code);
```

The browser modules are optional. The HTTP endpoints can also be called directly by HTMX or application JavaScript.

## Server API

- `Auth.User(request)` resolves the current user.
- `Auth.Session(request)` resolves the server-side session.
- `Auth.RequireUser(handler)` requires any authenticated session.
- `Auth.RequireLevel(level)(handler)` requires a specific authentication level or MFA.
- `Auth.RevokeAll(context, userID)` revokes every session for a user.
- `PrincipalFromContext(context)` exposes a minimal stable identity to downstream plugins protected by `RequireUser`.

## Hooks and Policies

Observers are informational and cannot change the flow. They are suitable for login emails, audit logs, metrics, and notifications:

```go
type LoginObserver struct{}

func (LoginObserver) Record(ctx context.Context, event auth.Event) {
    if event.Type == "login.password.succeeded" {
        // Queue a login notification without changing auth state.
    }
}
```

Policies run before security-sensitive state changes and fail closed when they return an error:

```go
riskPolicy := auth.PolicyFunc(func(ctx context.Context, attempt auth.Attempt) error {
    if riskEngine.Deny(attempt.User.ID, attempt.RemoteAddr, attempt.UserAgent) {
        return errors.New("risk policy denied attempt")
    }
    return nil
})
```

Configure multiple hooks with `Observers: []auth.Observer{...}` and `Policies: []auth.Policy{...}`. The original singular `Observer` option remains supported.

## Integration With Billing and Other Plugins

Authentication owns identity and credential verification. Billing, subscriptions, organizations, teams, roles, and product permissions remain application or dedicated-plugin concerns.

Use the minimal `Principal` boundary after `RequireUser`:

```go
protected := authentication.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    principal, ok := auth.PrincipalFromContext(r.Context())
    if !ok {
        http.Error(w, "authentication required", http.StatusUnauthorized)
        return
    }
    subscription, err := billing.SubscriptionForUser(r.Context(), principal.UserID)
    // Apply application-owned entitlement rules.
}))
```

A Stripe or Polar adapter only needs the opaque `UserID`; `plugin-auth` does not need to know which payment provider or subscription model the application uses.

API keys are intentionally not part of this package yet. They are machine credentials with application-specific scopes, ownership, rotation, and audit policy. A dedicated API-key plugin can reference `Principal.UserID` without expanding the interactive-login contract.

## Security Notes

- Passwords use Argon2id with configurable bounded parameters.
- TOTP secrets use AES-GCM encryption derived from the application secret.
- Recovery and one-time codes are stored as purpose-bound HMAC proofs.
- WebAuthn validates the relying-party ID and exact allowed origins.
- Registration can allow both authenticator types or require `platform` or `cross-platform`. The latter covers roaming security keys such as YubiKey; WebAuthn cannot securely filter by hardware vendor.
- Passkey challenges are short-lived and consumed once.
- Session IDs are random, rotated after authentication, stored server-side, and carried in encrypted HTTP-only cookies.
- Login errors do not distinguish unknown users from invalid credentials.

Applications still own authorization, TLS, durable storage, message delivery, key management, monitoring, and abuse policy. See [SECURITY.md](SECURITY.md).

## License

MPL-2.0.
