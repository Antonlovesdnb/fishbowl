#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────
# Fishbowl end-to-end demo
#
# Creates a demo project, runs Fishbowl with strong monitoring,
# exercises every collector, then shows the audit report.
#
# Usage:
#   ./scripts/demo.sh           # full automated demo
#   ./scripts/demo.sh --pause   # pause between steps for screenshots
# ─────────────────────────────────────────────────────────────────

PAUSE=false
[ "${1:-}" = "--pause" ] && PAUSE=true

DEMO_DIR="$HOME/fishbowl-demo"
CRED_FILE="$HOME/demo-api-key.txt"

banner() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if $PAUSE; then
    echo "  (press Enter to continue)"
    read -r
  fi
}

cleanup() {
  rm -rf "$DEMO_DIR" "$CRED_FILE"
}
trap cleanup EXIT

# ── Step 1: Create demo project ──────────────────────────────────
banner "Step 1: Setting up demo project"

mkdir -p "$DEMO_DIR"
cat > "$DEMO_DIR/.env" << 'EOF'
DATABASE_URL=postgres://admin:s3cret@db.internal:5432/myapp
STRIPE_SECRET_KEY=sk_live_demo1234567890abcdef
EOF

cat > "$DEMO_DIR/README.md" << 'EOF'
# Demo Project

This project uses `GH_TOKEN` and `AWS_SECRET_ACCESS_KEY` for CI.
EOF

# Initialize a git repo with a GitHub remote (triggers SSH key prompt)
cd "$DEMO_DIR"
git init -q
git remote add origin git@github.com:example/demo-project.git
cd - > /dev/null

# Create a credential file to mount explicitly
echo "sk-demo-api-key-1234567890abcdef" > "$CRED_FILE"

echo "[demo] Created project at $DEMO_DIR"
echo "[demo]   .env with DATABASE_URL and STRIPE_SECRET_KEY"
echo "[demo]   README.md referencing GH_TOKEN and AWS_SECRET_ACCESS_KEY"
echo "[demo]   Git remote: github.com (will trigger SSH key prompt)"
echo "[demo] Created credential file at $CRED_FILE"

# ── Step 2: Run Fishbowl ───────────────────────────────────────
banner "Step 2: Running Fishbowl with strong monitoring"

echo "[demo] Command:"
echo "  fishbowl run --mount $CRED_FILE $DEMO_DIR -- /bin/bash -lc '...'"
echo ""

fishbowl run --mount "$CRED_FILE" "$DEMO_DIR" -- /bin/bash -lc '
  echo ""
  echo "┌──────────────────────────────────────────────────────────┐"
  echo "│  Inside the Fishbowl container                        │"
  echo "└──────────────────────────────────────────────────────────┘"
  echo ""

  echo "[demo] === Trigger exec events ==="
  /bin/date
  /usr/bin/id
  echo ""

  echo "[demo] === Read workspace .env (triggers file collector) ==="
  cat /workspace/.env
  echo ""

  echo "[demo] === Read mounted credential (triggers file collector) ==="
  cat /fishbowl/creds/demo-api-key.txt
  echo ""

  echo "[demo] === Mutate a dangerous env var (triggers env audit) ==="
  export PAGER="evil-pager"
  echo "PAGER is now: $PAGER"
  echo ""

  echo "[demo] === Make an outbound connection (triggers connect collector) ==="
  curl -sS -o /dev/null -w "HTTP %{http_code} from %{remote_ip}\n" https://example.com/ || echo "(curl failed, ok)"
  echo ""

  echo "[demo] === DNS lookup (triggers connect collector) ==="
  getent hosts example.org || true
  echo ""

  # Give collectors time to flush
  sleep 1

  echo "[demo] === Container filesystem is read-only ==="
  touch /test-write 2>&1 || echo "Read-only filesystem confirmed"
  echo ""

  echo "[demo] === eBPF logs are tamper-proof (parent dir is RO) ==="
  touch /var/log/fishbowl/tamper-test 2>&1 || echo "eBPF logs protected"
  echo ""

  echo "[demo] Done! Exiting container."
'

# ── Step 3: Show audit report ────────────────────────────────────
banner "Step 3: Session audit report"

fishbowl audit

# ── Step 4: Show session files ───────────────────────────────────
banner "Step 4: Session log contents"

SESSION=$(ls -td ~/.fishbowl/logs/session-* 2>/dev/null | head -1)
if [ -z "$SESSION" ]; then
  echo "[demo] No session found"
  exit 1
fi

echo "[demo] Session: $SESSION"
echo ""

echo "── Event counts ──"
wc -l "$SESSION"/ebpf_*.jsonl 2>/dev/null || echo "(no eBPF events)"
echo ""

echo "── Registry (credential access tracking) ──"
python3 -c "
import json, sys
r = json.load(open('$SESSION/registry.json'))
for c in r.get('credentials', []):
    path = c['path']
    ac = c['access_count']
    cls = c['classification']
    print(f'  {path:50} access={ac}  {cls}')
" 2>/dev/null || cat "$SESSION/registry.json"
echo ""

echo "── File collector events (credential access via eBPF) ──"
python3 -c "
import json, sys
for line in open('$SESSION/ebpf_file.jsonl'):
    e = json.loads(line)
    op = e.get('operation','?')
    pn = e.get('process_name','?')
    rp = e.get('raw_path','?')
    cls = e.get('classification','?')
    print(f'  {op:8} {pn:8} -> {rp:50} [{cls}]')
" 2>/dev/null || echo "(no file events)"
echo ""

echo "── host_scan.json NOT in container mount ──"
if [ ! -f "$SESSION/host_scan.json" ]; then
  echo "  PASS: host_scan.json relocated to ~/.fishbowl/host-scans/"
else
  echo "  FAIL: host_scan.json still in session dir"
fi
echo ""

banner "Demo complete"
echo "Full session logs: $SESSION"
echo "Host scan report:  ~/.fishbowl/host-scans/"
echo ""
