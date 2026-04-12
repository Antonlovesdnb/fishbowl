#!/usr/bin/env sh
set -eu

export FISHBOWL_HOME="${FISHBOWL_HOME:-/fishbowl/home}"
export HOME="${HOME:-${FISHBOWL_HOME}}"
export PATH="${HOME}/.local/bin:${PATH}"

mkdir -p /fishbowl/ssh /fishbowl/creds /var/log/fishbowl/watcher
# Watchers write to the /watcher subdir (RW nested mount); the parent is RO.
touch /var/log/fishbowl/watcher/audit.jsonl
if [ ! -s /var/log/fishbowl/watcher/registry.json ]; then
  printf '{"credentials":[]}\n' > /var/log/fishbowl/watcher/registry.json
fi
export BASH_ENV=/fishbowl/bash_env.sh
/usr/local/bin/fishbowl-file-watcher </dev/null >/dev/null 2>&1 &
/usr/local/bin/fishbowl-workspace-watcher </dev/null >/dev/null 2>&1 &
if [ "${FISHBOWL_DISABLE_FILE_ACCESS_AUDIT:-0}" = "1" ]; then
  FILE_ACCESS_STATUS="disabled (host eBPF collector active)"
else
  FILE_ACCESS_STATUS="enabled for mounted credentials and workspace credential files"
fi
if [ "${FISHBOWL_DISABLE_NETWORK_WATCHER:-0}" != "1" ]; then
  /usr/local/bin/fishbowl-network-watcher </dev/null >/dev/null 2>&1 &
  NETWORK_WATCHER_STATUS="enabled"
else
  NETWORK_WATCHER_STATUS="disabled (host eBPF collector active)"
fi
if [ "${FISHBOWL_HOST_EXEC_ENV_AUDIT:-0}" = "1" ]; then
  ENV_AUDIT_STATUS="enabled for bash shells + host exec env snapshots"
else
  ENV_AUDIT_STATUS="enabled for bash shells only"
fi

cat <<EOF
[Fishbowl] Container started.
[Fishbowl] Agent mode: ${FISHBOWL_AGENT:-shell}
[Fishbowl] Workspace: ${FISHBOWL_WORKSPACE:-/workspace}
[Fishbowl] SSH mounts: /fishbowl/ssh
[Fishbowl] Credential mounts: /fishbowl/creds
[Fishbowl] Audit logs: /var/log/fishbowl
[Fishbowl] File access auditing: ${FILE_ACCESS_STATUS}
[Fishbowl] Workspace credential discovery: enabled
[Fishbowl] Outbound network watcher: ${NETWORK_WATCHER_STATUS}
[Fishbowl] Env audit: ${ENV_AUDIT_STATUS}
EOF

if [ "${FISHBOWL_MONITORING_STARTUP_GRACE_MS:-0}" -gt 0 ] 2>/dev/null; then
  sleep 1
fi

cd "${FISHBOWL_WORKSPACE:-/workspace}"

if [ "$#" -eq 0 ] || { [ "$#" -eq 1 ] && [ "$1" = "/bin/bash" ]; }; then
  exec /bin/bash --rcfile /fishbowl/bashrc -i
fi

exec "$@"
