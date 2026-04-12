#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(mktemp -d)"
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$PROJECT_DIR" "$LOG_DIR"' EXIT

chmod 777 "$LOG_DIR"
chmod 755 "$PROJECT_DIR"
printf 'OPENAI_API_KEY=demo-openai-key\n' > "$PROJECT_DIR/.env"
chmod 644 "$PROJECT_DIR/.env"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[test-workspace] building image"
cargo run -- build-image >/dev/null

echo "[test-workspace] triggering workspace discovery and access"
cargo run -- run \
  --project "$PROJECT_DIR" \
  --logs-dir "$LOG_DIR" \
  --name fishbowl-workspace-test \
  -- \
  /bin/bash -lc \
  'sleep 1; python3 - <<'"'"'PY'"'"'
import time
with open("/workspace/.env", "r", encoding="utf-8") as handle:
    handle.read()
    time.sleep(1)
PY
sleep 1'

echo "[test-workspace] registry output"
cat "$LOG_DIR/registry.json"

echo "[test-workspace] audit output"
cat "$LOG_DIR/audit.jsonl"

grep -q '"path": "/workspace/.env"' "$LOG_DIR/registry.json"
grep -q '"access_count": 1' "$LOG_DIR/registry.json"
grep -q '"event":"credential_discovered"' "$LOG_DIR/audit.jsonl"
grep -q '"event":"credential_access"' "$LOG_DIR/audit.jsonl"
grep -q '"path":"/workspace/.env"' "$LOG_DIR/audit.jsonl"
grep -q '"process_name":"python3"' "$LOG_DIR/audit.jsonl"
grep -q 'python3(pid=' "$LOG_DIR/audit.jsonl"

echo "[test-workspace] PASS"
