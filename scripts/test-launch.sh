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

export AGENTFENCE_TEST_TOKEN="agentfence-smoke-test"

cd "$ROOT_DIR"

echo "[test-launch] building image"
cargo run -- build-image >/dev/null

echo "[test-launch] running launcher smoke test"
cargo run -- run \
  --project "$ROOT_DIR" \
  --mount-cred "$TEST_CRED" \
  --mount-env AGENTFENCE_TEST_TOKEN \
  --logs-dir "$TEST_LOGS" \
  --name agentfence-smoke-test \
  -- \
  /bin/bash -lc '
    set -euo pipefail
    test -d /workspace
    test -f /agentfence/creds/demo.key
    test "$(cat /agentfence/creds/demo.key)" = "demo-secret"
    test "$(printenv AGENTFENCE_TEST_TOKEN)" = "agentfence-smoke-test"
    test -d /var/log/agentfence
    touch /var/log/agentfence/smoke.log
  '

echo "[test-launch] verifying host log export"
test -f "$TEST_LOGS/smoke.log"

echo "[test-launch] PASS"
