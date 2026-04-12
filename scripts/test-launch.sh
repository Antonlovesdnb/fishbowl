#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

TEST_CRED="$TMP_DIR/demo.key"
TEST_LOGS="$TMP_DIR/logs"
mkdir -p "$TEST_LOGS"
chmod 777 "$TEST_LOGS"
printf 'demo-secret\n' > "$TEST_CRED"

export FISHBOWL_TEST_TOKEN="fishbowl-smoke-test"

cd "$ROOT_DIR"

echo "[test-launch] building image"
cargo run -- build-image >/dev/null

echo "[test-launch] running launcher smoke test"
cargo run -- run \
  --project "$ROOT_DIR" \
  --mount "$TEST_CRED" \
  --mount FISHBOWL_TEST_TOKEN \
  --logs-dir "$TEST_LOGS" \
  --name fishbowl-smoke-test \
  -- \
  /bin/bash -lc '
    set -euo pipefail
    test -d /workspace
    test -f /fishbowl/creds/demo.key
    test "$(cat /fishbowl/creds/demo.key)" = "demo-secret"
    test "$(printenv FISHBOWL_TEST_TOKEN)" = "fishbowl-smoke-test"
    test -d /var/log/fishbowl
    touch /var/log/fishbowl/smoke.log
  '

echo "[test-launch] verifying host log export"
test -f "$TEST_LOGS/smoke.log"

echo "[test-launch] PASS"
