# Authentication Demo

This Dreego application demonstrates password authentication, platform passkeys, external security keys such as YubiKey, TOTP, recovery codes, policy hooks, event observers, and a protected route.

It uses Dreego's built-in static asset pipeline for `www/static/styles.css` and `www/static/app.js`. It does not use Tailwind, a CDN, or an external database. Authentication state is persisted to `data/auth.json` with restrictive file permissions and atomic file replacement.

## Run

Install the Dreego CLI, then run:

```sh
export AUTH_SECRET="$(openssl rand -hex 32)"
dreego generate
dreego run
```

Open <http://localhost:8080>.

If port 8080 is occupied, set both the listener and public WebAuthn origin:

```sh
export PORT=8081
export AUTH_ORIGIN=http://localhost:8081
dreego run
```

Keep `AUTH_SECRET` stable between restarts if you want existing sessions and encrypted TOTP credentials to remain usable. `AUTH_DB` can override the default `data/auth.json` path.

One-time codes are printed to the application log instead of being sent. This behavior and the JSON store are demo conveniences, not production infrastructure.

## Automated Browser Test

The CI runs `e2e/run.sh` with Bun 1.4.2 and its experimental `Bun.WebView` API. The test starts an isolated demo instance, exercises registration, password login, TOTP, recovery, logout, the MFA gate, and narrow-screen rendering in headless Chrome. It then verifies the JSON database and expected structured auth events.

On every run, diagnostics are written to `.tmp/e2e`: the server log, browser results, and a final screenshot. GitHub Actions uploads this directory even when the test fails.

## Hook Demonstration

`demoPolicy` rejects attempts whose user agent contains `Dreego-Demo-Blocked`:

```sh
curl -A Dreego-Demo-Blocked http://localhost:8080/auth/login/password
```

`demoObserver` records authentication events through structured logs. A real application can replace it with email notification, audit, metrics, or risk-system adapters.
