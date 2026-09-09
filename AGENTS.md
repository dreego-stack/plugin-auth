# Agent Instructions

- Keep all repository content in English.
- Run development commands through the shared `smd.toml` in the parent Dreego workspace.
- Run Git operations on the host.
- Keep handwritten files at or below 300 lines.
- Add integration tests before changing authentication behavior.
- Do not weaken generic authentication failures, atomic attempt limits, one-time challenge consumption, or passkey counter compare-and-swap behavior.
- Every pull request contains exactly one `.changes/*.md` file.
