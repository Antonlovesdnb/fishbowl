#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

chmod 777 "$LOG_DIR"

cd "$ROOT_DIR"

echo "[test-audit] building image"
cargo run -- build-image >/dev/null

echo "[test-audit] triggering env mutation and enumeration"
cargo run -- run \
  --project "$ROOT_DIR" \
  --logs-dir "$LOG_DIR" \
  --name agentfence-audit-test \
  -- \
  /bin/bash -lc \
  'export PAGER=/tmp/payload.sh; printenv >/dev/null'

echo "[test-audit] audit log output"
cat "$LOG_DIR/audit.jsonl"

grep -q '"event":"dangerous_env_mutation"' "$LOG_DIR/audit.jsonl"
grep -q '"variable":"PAGER"' "$LOG_DIR/audit.jsonl"
grep -q '"event":"env_enumeration"' "$LOG_DIR/audit.jsonl"

echo "[test-audit] PASS"
