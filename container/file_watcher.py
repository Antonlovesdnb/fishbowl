#!/usr/bin/env python3
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


WATCH_DIRS = [Path("/agentfence/creds"), Path("/agentfence/ssh")]
REGISTRY_PATH = Path("/var/log/agentfence/watcher/registry.json")
AUDIT_PATH = Path("/var/log/agentfence/watcher/audit.jsonl")
AUDIT_BIN = "/usr/local/bin/agentfence-audit"
REGISTRY_BIN = "/usr/local/bin/agentfence-registry"
ALERT_PATH = "/proc/1/fd/2"
DISABLE_FILE_ACCESS_AUDIT = os.getenv("AGENTFENCE_DISABLE_FILE_ACCESS_AUDIT", "0") == "1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {"credentials": []}
    try:
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"credentials": []}


def save_registry(registry: dict) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")


def classify_file(path: Path) -> tuple[str, str]:
    if str(path).startswith("/agentfence/ssh/"):
        return "ssh_private_key", "SSH Private Key"

    suffix = path.suffix.lower()
    if suffix in {".pem", ".key"}:
        return "credential_file", "Private Key Material"
    if suffix in {".json"}:
        return "credential_file", "Credential JSON File"

    return "credential_file", "Mounted Credential File"


def register_existing_files() -> None:
    for directory in WATCH_DIRS:
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if path.is_file():
                kind, classification = classify_file(path)
                subprocess.run(
                    [
                        REGISTRY_BIN,
                        "--path",
                        str(path),
                        "--kind",
                        kind,
                        "--mount-mode",
                        "read-only",
                        "--classification",
                        classification,
                        "--discovery-method",
                        "explicit_mount",
                    ],
                    check=False,
                )


def watched_files() -> list[Path]:
    paths: list[Path] = []
    for directory in WATCH_DIRS:
        if not directory.exists():
            continue
        for path in directory.rglob("*"):
            if path.is_file():
                paths.append(path)
    return paths


def process_info(pid: str) -> dict | None:
    proc_dir = Path("/proc") / pid
    if not proc_dir.exists():
        return None
    try:
        comm = (proc_dir / "comm").read_text(encoding="utf-8").strip()
        cmdline = (proc_dir / "cmdline").read_text(encoding="utf-8").replace("\x00", " ").strip()
        stat_parts = (proc_dir / "stat").read_text(encoding="utf-8").split()
        ppid = stat_parts[3] if len(stat_parts) > 3 else ""
        return {
            "pid": pid,
            "ppid": ppid,
            "name": comm,
            "cmdline": cmdline,
        }
    except Exception:
        return None


def is_internal_watcher_process(info: dict) -> bool:
    name = info.get("name", "")
    cmdline = info.get("cmdline", "")
    if name == "inotifywait":
        return True
    return "agentfence-file-watcher" in cmdline


def resolve_process_by_cmdline(path: Path) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    target = str(path)
    candidates: list[tuple[int, tuple[str | None, str | None, str | None, str | None, str | None]]] = []
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        info = process_info(proc_dir.name)
        if info is None:
            continue
        if is_internal_watcher_process(info):
            continue
        cmdline = info.get("cmdline", "")
        if not cmdline or target not in cmdline:
            continue
        chain = build_process_chain(proc_dir.name)
        if not chain:
            continue
        current = chain[0]
        score = process_match_score(current["name"], current["cmdline"], current["pid"])
        candidates.append(
            (
                score,
                (
                    current["pid"],
                    current["ppid"],
                    current["name"],
                    current["cmdline"],
                    format_process_chain(chain),
                ),
            )
        )
    if not candidates:
        return None, None, None, None, None
    candidates.sort(key=lambda item: item[0], reverse=True)
    best = candidates[0][1]
    if best[2] in {"tini", "bash", "sh", "dash"}:
        return None, None, None, None, None
    return best


def process_match_score(name: str, cmdline: str, pid: str) -> int:
    wrappers = {"tini", "bash", "sh", "dash"}
    score = 0
    if name not in wrappers:
        score += 100
    if any(token in name.lower() for token in ["curl", "wget", "python", "ssh", "scp", "sftp", "git"]):
        score += 50
    try:
        score += int(pid)
    except ValueError:
        pass
    if name in wrappers:
        score -= 25
    return score


def build_process_chain(pid: str) -> list[dict]:
    chain = []
    current = pid
    seen = set()
    while current and current not in seen and current != "0":
        seen.add(current)
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


def resolve_process(path: Path) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    target = str(path.resolve())
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.name.isdigit():
                continue
            fd_dir = proc_dir / "fd"
            if not fd_dir.is_dir():
                continue
            try:
                proc_info = process_info(proc_dir.name)
                if proc_info is None or is_internal_watcher_process(proc_info):
                    continue
                for fd in fd_dir.iterdir():
                    try:
                        link = os.readlink(fd)
                    except OSError:
                        continue
                    link = link.replace(" (deleted)", "")
                    if os.path.realpath(link) != target:
                        continue
                    chain = build_process_chain(proc_dir.name)
                    if not chain:
                        continue
                    current = chain[0]
                    return (
                        current["pid"],
                        current["ppid"],
                        current["name"],
                        current["cmdline"],
                        format_process_chain(chain),
                    )
            except OSError:
                continue
        time.sleep(0.02)
    return resolve_process_by_cmdline(path)


def update_access_metadata(path: Path, should_count_access: bool) -> tuple[str | None, str | None]:
    registry = load_registry()
    credential_id = f"file::{path}"
    classification = None
    for item in registry.get("credentials", []):
        if item.get("id") == credential_id:
            if should_count_access:
                item["access_count"] = int(item.get("access_count", 0)) + 1
                item["last_accessed_at"] = utc_now()
            classification = item.get("classification")
            save_registry(registry)
            return credential_id, classification
    return None, classification


def write_audit_event(record: dict) -> None:
    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
    except OSError:
        pass


def emit_alert(severity: str, message: str) -> None:
    if severity not in {"medium", "high", "critical"}:
        return
    try:
        with open(ALERT_PATH, "w") as fh:
            fh.write(f"[AgentFence] {severity.upper()}: {message}\n")
    except OSError:
        pass


def emit_access_event(path: Path, event_name: str, process_cache: dict[str, tuple[str | None, str | None, str | None, str | None, str | None]]) -> None:
    if DISABLE_FILE_ACCESS_AUDIT:
        return
    should_count_access = "access" in event_name.lower()
    credential_id, classification = update_access_metadata(path, should_count_access)
    cache_key = str(path)
    observed_pid = observed_ppid = process_name = process_cmdline = process_chain = None

    if "close" in event_name and cache_key in process_cache:
        observed_pid, observed_ppid, process_name, process_cmdline, process_chain = process_cache[cache_key]
    else:
        observed_pid, observed_ppid, process_name, process_cmdline, process_chain = resolve_process(path)
        if observed_pid:
            process_cache[cache_key] = (
                observed_pid,
                observed_ppid,
                process_name,
                process_cmdline,
                process_chain,
            )

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "credential_access",
        "severity": "info",
        "shell": "file-watcher",
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "cwd": os.getcwd(),
        "agent": os.getenv("AGENTFENCE_AGENT", "shell"),
        "command": None,
        "variable": None,
        "old_value": None,
        "new_value": None,
        "classification": classification or "Mounted Credential File",
        "discovery_method": "file_watch",
        "registry_id": credential_id or f"file::{path}",
        "path": str(path),
        "operation": event_name,
        "process_name": process_name or "",
        "process_cmdline": process_cmdline or "",
        "observed_pid": observed_pid or "",
        "observed_ppid": observed_ppid or "",
        "process_chain": process_chain or "",
        "destination": None,
        "destination_port": None,
        "protocol": None,
        "active_credential_count": None,
        "matched_registry_ids": None,
        "verdict": "observed",
        "reason": "mounted credential file accessed",
    }
    write_audit_event(record)

    if process_name and process_name.lower() in {"curl", "wget", "nc", "ncat", "socat", "python3", "python", "node"}:
        emit_alert("high", f"credential file {path.name} accessed by {process_name} (pid {observed_pid or '?'})")

    if "close" in event_name:
        process_cache.pop(cache_key, None)


def main() -> int:
    register_existing_files()

    watch_paths = [str(path) for path in watched_files()]
    if not watch_paths:
        return 0

    process = subprocess.Popen(
        [
            "stdbuf",
            "-oL",
            "inotifywait",
            "-m",
            "-e",
            "access",
            "-e",
            "open",
            "-e",
            "close_nowrite",
            "--format",
            "%w|%f|%e",
            *watch_paths,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    assert process.stdout is not None
    process_cache: dict[str, tuple[str | None, str | None, str | None, str | None, str | None]] = {}
    for line in process.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            directory, file_name, event_name = line.split("|", 2)
        except ValueError:
            continue

        path = Path(directory) / file_name
        if not path.is_file():
            continue

        emit_access_event(path, event_name.lower(), process_cache)

    return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
