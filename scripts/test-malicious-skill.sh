#!/usr/bin/env bash
set -euo pipefail

MODE="run"
if [ "${1:-}" = "--install" ]; then
  MODE="install"
  shift
fi

PROJECT_DIR="${1:-/home/anton/Desktop/claudeforblueteam}"
AGENTFENCE_BIN="${AGENTFENCE_BIN:-agentfence}"
MONITOR="${AGENTFENCE_MONITOR:-strong}"
NETWORK="${AGENTFENCE_NETWORK:-host}"
CONTAINER_NAME="${AGENTFENCE_CONTAINER_NAME:-agentfence-malicious-skill-test}"
LOG_DIR="${AGENTFENCE_LOG_DIR:-$(mktemp -d)}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAYLOAD_SOURCE="$ROOT_DIR/scripts/fake-malicious-skill.py"
PAYLOAD_TARGET="$PROJECT_DIR/.agentfence/fake-malicious-skill.py"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

chmod 777 "$LOG_DIR"

install_payload() {
  mkdir -p "$PROJECT_DIR/.agentfence"
  cp "$PAYLOAD_SOURCE" "$PAYLOAD_TARGET"
  chmod 755 "$PAYLOAD_TARGET"
  echo "[test-malicious-skill] installed payload: $PAYLOAD_TARGET"
  echo "[test-malicious-skill] run inside AgentFence with:"
  echo "  python3 \"\${AGENTFENCE_WORKSPACE:-/workspace}/.agentfence/fake-malicious-skill.py\""
}

if [ "$MODE" = "install" ]; then
  install_payload
  exit 0
fi

install_payload

echo "[test-malicious-skill] project: $PROJECT_DIR"
echo "[test-malicious-skill] logs: $LOG_DIR"
echo "[test-malicious-skill] monitor: $MONITOR"
echo "[test-malicious-skill] network: $NETWORK"
echo "[test-malicious-skill] running controlled fake exfiltration"

"$AGENTFENCE_BIN" run "$PROJECT_DIR" \
  --monitor "$MONITOR" \
  --network "$NETWORK" \
  --logs-dir "$LOG_DIR" \
  --name "$CONTAINER_NAME" \
  -- \
  /bin/bash -lc '
set -euo pipefail
python3 "${AGENTFENCE_WORKSPACE:-/workspace}/.agentfence/fake-malicious-skill.py"
'

echo "[test-malicious-skill] relevant audit events"
grep -hE '"'"'credential_access|network_egress|network_connect'"'"' "$LOG_DIR"/*.jsonl 2>/dev/null || true

echo "[test-malicious-skill] relevant host eBPF file events"
grep -h 'credential_access' "$LOG_DIR"/ebpf_file.jsonl 2>/dev/null || true

echo "[test-malicious-skill] relevant host eBPF connect events"
grep -h 'network_connect' "$LOG_DIR"/ebpf_connect.jsonl 2>/dev/null || true

echo "[test-malicious-skill] correlation findings"
cat "$LOG_DIR"/findings.jsonl 2>/dev/null || true

echo "[test-malicious-skill] done"
