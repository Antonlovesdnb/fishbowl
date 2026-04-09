#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

LOG_DIR="$TMP_DIR/logs"
SECRET_FILE="$TMP_DIR/demo.key"
mkdir -p "$LOG_DIR"
chmod 777 "$LOG_DIR"
printf 'super-secret\n' > "$SECRET_FILE"

cd "$ROOT_DIR"

echo "[test-file-access] building image"
cargo run -- build-image >/dev/null

echo "[test-file-access] reading mounted credential"
cargo run -- run \
  --project "$ROOT_DIR" \
  --mount-cred "$SECRET_FILE" \
  --logs-dir "$LOG_DIR" \
  --name agentfence-file-access-test \
  -- \
  /bin/bash -lc \
  'sleep 1; python3 - <<'"'"'PY'"'"'
import time
with open("/agentfence/creds/demo.key", "r", encoding="utf-8") as handle:
    handle.read()
    time.sleep(1)
PY
sleep 1'

echo "[test-file-access] registry output"
cat "$LOG_DIR/registry.json"

echo "[test-file-access] audit output"
cat "$LOG_DIR/audit.jsonl"

grep -q '"path": "/agentfence/creds/demo.key"' "$LOG_DIR/registry.json"
grep -q '"access_count": 1' "$LOG_DIR/registry.json"
grep -q '"event":"credential_access"' "$LOG_DIR/audit.jsonl"
grep -q '"path":"/agentfence/creds/demo.key"' "$LOG_DIR/audit.jsonl"
grep -q '"process_name":"python3"' "$LOG_DIR/audit.jsonl"
grep -q 'python3(pid=' "$LOG_DIR/audit.jsonl"

echo "[test-file-access] PASS"
