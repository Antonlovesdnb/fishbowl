#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR"' EXIT

chmod 777 "$LOG_DIR"

cd "$ROOT_DIR"

echo "[test-discovery] building image"
cargo run -- build-image >/dev/null

echo "[test-discovery] triggering env credential discovery"
cargo run -- run \
  --project "$ROOT_DIR" \
  --logs-dir "$LOG_DIR" \
  --name agentfence-discovery-test \
  -- \
  /bin/bash -lc \
  'export OPENAI_API_KEY=demo-openai-key; export GH_TOKEN=demo-gh-token; true'

echo "[test-discovery] registry output"
cat "$LOG_DIR/registry.json"

echo "[test-discovery] audit output"
cat "$LOG_DIR/audit.jsonl"

grep -q '"env_var": "OPENAI_API_KEY"' "$LOG_DIR/registry.json"
grep -q '"env_var": "GH_TOKEN"' "$LOG_DIR/registry.json"
grep -q '"event":"credential_discovered"' "$LOG_DIR/audit.jsonl"
grep -q '"variable":"OPENAI_API_KEY"' "$LOG_DIR/audit.jsonl"
grep -q '"variable":"GH_TOKEN"' "$LOG_DIR/audit.jsonl"

echo "[test-discovery] PASS"
