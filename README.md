# plugin-auth

Authentication for [Dreego](https://github.com/dreego-stack/dreego) SSR applications.

The plugin provides password login, passkeys, TOTP, single-use recovery codes, email or SMS one-time codes, account verification, password reset, and server-side sessions. Storage and message delivery remain application-owned interfaces.

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

## Security Notes

- Passwords use Argon2id with configurable bounded parameters.
- TOTP secrets use AES-GCM encryption derived from the application secret.
- Recovery and one-time codes are stored as purpose-bound HMAC proofs.
- WebAuthn validates the relying-party ID and exact allowed origins.
- Passkey challenges are short-lived and consumed once.
- Session IDs are random, rotated after authentication, stored server-side, and carried in encrypted HTTP-only cookies.
- Login errors do not distinguish unknown users from invalid credentials.

Applications still own authorization, TLS, durable storage, message delivery, key management, monitoring, and abuse policy. See [SECURITY.md](SECURITY.md).

## License

MPL-2.0.
