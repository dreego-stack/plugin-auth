## v0.0.7

- Breaking: require Go 1.27 or newer and Dreego v0.7.0.

## v0.0.6

- Feat: add an accessible multi-page demo flow for manual platform passkey and YubiKey verification.

## v0.0.5

- Fix: keep demo form references valid across asynchronous authentication requests.
- Fix: render the demo in standards mode and prevent narrow-screen overflow.
- Chore: add a local demo favicon and semantic form destinations.
- Test: exercise the demo, persisted JSON state, and auth event logs through Bun WebView in CI.

## v0.0.4

- Bug: expose logout, TOTP login, and recovery-code login controls in the interactive demo.

## v0.0.3

- Bug: allow the demo listener and WebAuthn origin to use a non-default port.

## v0.0.2

- Feat: add blocking authentication policies and multiple informational observers.
- Feat: support explicit platform-passkey and external security-key registration.
- Feat: provide a stable principal context for downstream plugins.
- Feat: add an accessible Dreego demo with plain embedded CSS and JSON persistence.
- Bug: forward Dreego CSRF tokens from browser client requests.

## v0.0.1

- Feat: add password, passkey, TOTP, recovery-code, and one-time-code authentication.
- Feat: add server-side sessions, secure credential storage primitives, and browser client modules.

# Changelog

All notable changes to this project are recorded here by the release workflow.
