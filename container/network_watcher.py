#!/usr/bin/env python3
"""Outbound network connection monitor for AgentFence containers.

Polls ss for TCP and UDP connections, correlates with the credential
registry, writes audit events directly to the JSONL log, and emits
real-time alerts for high-severity events.
"""
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


AUDIT_PATH = Path("/var/log/agentfence/watcher/audit.jsonl")
REGISTRY_PATH = Path("/var/log/agentfence/watcher/registry.json")
POLL_INTERVAL = 0.05  # 50ms
SEEN_MAX_AGE = 60  # prune entries older than 60s
ALERT_PATH = "/proc/1/fd/2"

# Registry cache -- only re-read when the file changes on disk.
_registry_cache: dict | None = None
_registry_mtime: float = 0


def load_registry() -> dict:
    global _registry_cache, _registry_mtime
    try:
        mtime = REGISTRY_PATH.stat().st_mtime
    except OSError:
        return {"credentials": []}
    if _registry_cache is not None and mtime == _registry_mtime:
        return _registry_cache
    try:
        _registry_cache = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        _registry_mtime = mtime
    except (json.JSONDecodeError, OSError):
        _registry_cache = {"credentials": []}
    return _registry_cache


def invalidate_registry_cache() -> None:
    global _registry_cache, _registry_mtime
    _registry_cache = None
    _registry_mtime = 0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_audit_event(record: dict) -> None:
    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError:
        pass


def emit_alert(severity: str, message: str) -> None:
    if severity not in {"medium", "high", "critical"}:
        return
    tag = severity.upper()
    line = f"[AgentFence] {tag}: {message}\n"
    try:
        with open(ALERT_PATH, "w") as fh:
            fh.write(line)
    except OSError:
        pass


def parse_ss_line(line: str) -> dict | None:
    parts = line.split()
    if len(parts) < 5:
        return None

    proto = parts[0].lower() if parts[0].lower() in {"tcp", "udp"} else ""
    local_addr = parts[3]
    remote_addr = parts[4]
    metadata = " ".join(parts[5:]) if len(parts) > 5 else ""

    if remote_addr.startswith(("127.", "[::1]", "0.0.0.0")):
        return None

    process_name = ""
    pid = ""
    cmdline = ""
    if 'users:(("' in metadata:
        try:
            proc_part = metadata.split('users:(("', 1)[1]
            process_name = proc_part.split('"', 1)[0]
            if "pid=" in proc_part:
                pid = proc_part.split("pid=", 1)[1].split(",", 1)[0]
            if pid and (Path("/proc") / pid / "cmdline").exists():
                cmdline = (Path("/proc") / pid / "cmdline").read_text(encoding="utf-8").replace("\x00", " ").strip()
        except Exception:
            pass

    if ":" not in remote_addr:
        return None
    destination, port = remote_addr.rsplit(":", 1)
    destination = destination.strip("[]")
    return {
        "destination": destination,
        "port": port,
        "protocol": proto or "tcp",
        "process_name": process_name,
        "pid": pid,
        "cmdline": cmdline,
        "local_addr": local_addr,
    }


def process_info(pid: str) -> dict | None:
    proc_dir = Path("/proc") / pid
    if not proc_dir.exists():
        return None
    try:
        comm = (proc_dir / "comm").read_text(encoding="utf-8").strip()
        cmdline = (proc_dir / "cmdline").read_text(encoding="utf-8").replace("\x00", " ").strip()
        stat_parts = (proc_dir / "stat").read_text(encoding="utf-8").split()
        ppid = stat_parts[3] if len(stat_parts) > 3 else ""
        return {"pid": pid, "ppid": ppid, "name": comm, "cmdline": cmdline}
    except Exception:
        return None


def build_process_chain(pid: str) -> list[dict]:
    chain = []
    current = pid
    seen_pids: set[str] = set()
    while current and current not in seen_pids and current != "0":
        seen_pids.add(current)
        info = process_info(current)
        if info is None:
            break
        chain.append(info)
        if info["ppid"] in {"", "0", current}:
            break
        current = info["ppid"]
    return chain


def format_process_chain(chain: list[dict]) -> str:
    return " <- ".join(f'{item["name"]}(pid={item["pid"]},ppid={item["ppid"]})' for item in chain)


def correlate_connection(connection: dict, registry: dict) -> tuple[list[str], bool, bool]:
    matched_ids: list[str] = []
    cmdline = connection.get("cmdline", "")
    pid = connection.get("pid", "")
    direct_reference = False
    inherited_env = False

    environ_text = ""
    if pid and (Path("/proc") / pid / "environ").exists():
        try:
            environ_text = (Path("/proc") / pid / "environ").read_text(encoding="utf-8", errors="ignore")
        except Exception:
            environ_text = ""

    for item in registry.get("credentials", []):
        registry_id = item.get("id")
        if not registry_id:
            continue
        if item.get("type") == "file":
            path = item.get("path", "")
            if path and path in cmdline:
                matched_ids.append(registry_id)
                direct_reference = True
        elif item.get("type") == "env_var":
            env_var = item.get("env_var", "")
            if env_var and (env_var in cmdline or f"{env_var}=" in environ_text):
                matched_ids.append(registry_id)
                inherited_env = True

    seen: set[str] = set()
    deduped = []
    for item in matched_ids:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped, direct_reference, inherited_env


def classify_severity(connection: dict, direct_reference: bool, inherited_env: bool) -> str:
    cmdline = connection.get("cmdline", "")
    process_name = connection.get("process_name", "")
    suspicious_transport = any(
        token in f"{process_name} {cmdline}".lower()
        for token in ["curl", "wget", "python", "nc", "ncat", "socat", "tunnel"]
    )

    if direct_reference and suspicious_transport:
        return "critical"
    if direct_reference or ("tunnel" in process_name.lower() or "tunnel" in cmdline.lower()):
        return "high"
    if inherited_env and suspicious_transport:
        return "medium"
    return "info"


def build_reason(connection: dict, direct_reference: bool, inherited_env: bool) -> str:
    reasons = [f"outbound {connection.get('protocol', 'tcp')} connection observed"]
    if direct_reference:
        reasons.append("process command line references a discovered credential file")
    if inherited_env:
        reasons.append("process environment includes discovered credential variables")
    if "tunnel" in connection.get("process_name", "").lower() or "tunnel" in connection.get("cmdline", "").lower():
        reasons.append("tunnel-like process name or command detected")
    return "; ".join(reasons)


def update_expected_destinations(registry: dict, matched_registry_ids: list[str], connection: dict) -> None:
    destination = f'{connection["destination"]}:{connection["port"]}'
    changed = False
    for item in registry.get("credentials", []):
        if item.get("id") not in matched_registry_ids:
            continue
        expected = item.setdefault("expected_destinations", [])
        if destination not in expected:
            expected.append(destination)
            changed = True
    if changed:
        try:
            REGISTRY_PATH.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
        except OSError:
            pass
        invalidate_registry_cache()


def emit_connection_event(connection: dict, active_credential_count: int) -> None:
    registry = load_registry()
    matched_registry_ids, direct_credential_reference, inherited_env_credentials = correlate_connection(connection, registry)
    severity = classify_severity(connection, direct_credential_reference, inherited_env_credentials)
    verdict = "alerted" if severity in {"high", "critical"} else "observed"
    process_chain = ""
    observed_ppid = ""
    if connection["pid"]:
        chain = build_process_chain(connection["pid"])
        if chain:
            process_chain = format_process_chain(chain)
            observed_ppid = chain[0]["ppid"]
    if matched_registry_ids:
        update_expected_destinations(registry, matched_registry_ids, connection)

    record = {
        "timestamp": utc_now(),
        "event": "network_egress",
        "severity": severity,
        "shell": "network-watcher",
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "cwd": os.getcwd(),
        "agent": os.getenv("AGENTFENCE_AGENT", "shell"),
        "command": None,
        "variable": None,
        "old_value": None,
        "new_value": None,
        "classification": None,
        "discovery_method": "network_watch",
        "registry_id": None,
        "path": None,
        "operation": "connect",
        "process_name": connection["process_name"],
        "process_cmdline": connection["cmdline"],
        "observed_pid": connection["pid"],
        "observed_ppid": observed_ppid,
        "process_chain": process_chain,
        "destination": connection["destination"],
        "destination_port": connection["port"],
        "protocol": connection.get("protocol", "tcp"),
        "active_credential_count": str(active_credential_count),
        "matched_registry_ids": ",".join(matched_registry_ids),
        "verdict": verdict,
        "reason": build_reason(connection, direct_credential_reference, inherited_env_credentials),
    }
    write_audit_event(record)

    if severity in {"medium", "high", "critical"}:
        dest = f'{connection["destination"]}:{connection["port"]}'
        proc = connection["process_name"] or "unknown"
        pid = connection["pid"] or "?"
        emit_alert(severity, f"network egress -- {proc} (pid {pid}) -> {dest}")


def main() -> int:
    seen: dict[tuple[str, str, str], float] = {}
    last_prune = time.monotonic()
    while True:
        result = subprocess.run(["ss", "-tupnH"], capture_output=True, text=True, check=False)
        active_credential_count = len(load_registry().get("credentials", []))
        now = time.monotonic()
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("LISTEN"):
                continue
            parsed = parse_ss_line(line)
            if parsed is None:
                continue
            key = (parsed["pid"], parsed["destination"], parsed["port"])
            if key in seen:
                continue
            seen[key] = now
            emit_connection_event(parsed, active_credential_count)

        if now - last_prune > SEEN_MAX_AGE:
            cutoff = now - SEEN_MAX_AGE
            seen = {k: v for k, v in seen.items() if v > cutoff}
            last_prune = now

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
