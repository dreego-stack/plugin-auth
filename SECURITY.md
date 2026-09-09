# Security Policy

## Reporting a Vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting for this repository.

Include the affected version, configuration, reproduction steps, impact, and any proposed mitigation. Reports are acknowledged as soon as practical. Public disclosure is coordinated after a fix is available.

## Security Model

Applications provide persistent implementations of `Store`, Dreego's session `Store`, `ChallengeStore`, and optionally `Messenger`, `RateLimiter`, and `Observer`. The included memory stores are intended for tests and single-process development only.

The application secret must contain at least 32 random bytes and must be managed outside source control. Rotating it invalidates encrypted TOTP secrets, recovery-code proofs, one-time-code proofs, and encrypted session cookies.

TLS termination, secure deployment, account policy, authorization, backup, and audit retention remain application responsibilities.
