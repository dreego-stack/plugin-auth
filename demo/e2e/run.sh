#!/bin/sh
set -eu

artifact_dir="${E2E_ARTIFACT_DIR:-.tmp/e2e}"
mkdir -p "$artifact_dir"

if ! bun run e2e/browser.ts; then
  test ! -f "$artifact_dir/server.log" || sed -n '1,240p' "$artifact_dir/server.log"
  test ! -f "$artifact_dir/results.json" || sed -n '1,240p' "$artifact_dir/results.json"
  exit 1
fi

grep -q 'user.registered' "$artifact_dir/server.log"
grep -q 'login.password.succeeded' "$artifact_dir/server.log"
grep -q 'totp.enabled' "$artifact_dir/server.log"
grep -q 'login.totp.succeeded' "$artifact_dir/server.log"
grep -q 'login.recovery.succeeded' "$artifact_dir/server.log"
