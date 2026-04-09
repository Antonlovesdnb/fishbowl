#!/usr/bin/env sh
set -eu

export AGENTFENCE_HOME="${AGENTFENCE_HOME:-/agentfence/home}"
export HOME="${HOME:-${AGENTFENCE_HOME}}"
export PATH="${HOME}/.local/bin:${PATH}"

mkdir -p /agentfence/ssh /agentfence/creds /var/log/agentfence
touch /var/log/agentfence/audit.jsonl
if [ ! -s /var/log/agentfence/registry.json ]; then
  printf '{"credentials":[]}\n' > /var/log/agentfence/registry.json
fi
export BASH_ENV=/agentfence/bash_env.sh
/usr/local/bin/agentfence-file-watcher </dev/null >/dev/null 2>&1 &
/usr/local/bin/agentfence-workspace-watcher </dev/null >/dev/null 2>&1 &
if [ "${AGENTFENCE_DISABLE_FILE_ACCESS_AUDIT:-0}" = "1" ]; then
  FILE_ACCESS_STATUS="disabled (host eBPF collector active)"
else
  FILE_ACCESS_STATUS="enabled for mounted credentials and workspace credential files"
fi
if [ "${AGENTFENCE_DISABLE_NETWORK_WATCHER:-0}" != "1" ]; then
  /usr/local/bin/agentfence-network-watcher </dev/null >/dev/null 2>&1 &
  NETWORK_WATCHER_STATUS="enabled"
else
  NETWORK_WATCHER_STATUS="disabled (host eBPF collector active)"
fi
if [ "${AGENTFENCE_HOST_EXEC_ENV_AUDIT:-0}" = "1" ]; then
  ENV_AUDIT_STATUS="enabled for bash shells + host exec env snapshots"
else
  ENV_AUDIT_STATUS="enabled for bash shells only"
fi

cat <<EOF
[AgentFence] Container started.
[AgentFence] Agent mode: ${AGENTFENCE_AGENT:-shell}
[AgentFence] Workspace: ${AGENTFENCE_WORKSPACE:-/workspace}
[AgentFence] SSH mounts: /agentfence/ssh
[AgentFence] Credential mounts: /agentfence/creds
[AgentFence] Audit logs: /var/log/agentfence
[AgentFence] File access auditing: ${FILE_ACCESS_STATUS}
[AgentFence] Workspace credential discovery: enabled
[AgentFence] Outbound network watcher: ${NETWORK_WATCHER_STATUS}
[AgentFence] Env audit: ${ENV_AUDIT_STATUS}
EOF

if [ "${AGENTFENCE_MONITORING_STARTUP_GRACE_MS:-0}" -gt 0 ] 2>/dev/null; then
  sleep 1
fi

cd "${AGENTFENCE_WORKSPACE:-/workspace}"

if [ "$#" -eq 0 ] || { [ "$#" -eq 1 ] && [ "$1" = "/bin/bash" ]; }; then
  exec /bin/bash --rcfile /agentfence/bashrc -i
fi

exec "$@"
