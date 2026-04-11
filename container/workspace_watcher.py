#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


WORKSPACE = Path(os.getenv("AGENTFENCE_WORKSPACE", "/workspace"))
REGISTRY_PATH = Path("/var/log/agentfence/watcher/registry.json")
AUDIT_PATH = Path("/var/log/agentfence/watcher/audit.jsonl")
AUDIT_BIN = "/usr/local/bin/agentfence-audit"
REGISTRY_BIN = "/usr/local/bin/agentfence-registry"
ALERT_PATH = "/proc/1/fd/2"
DISABLE_FILE_ACCESS_AUDIT = os.getenv("AGENTFENCE_DISABLE_FILE_ACCESS_AUDIT", "0") == "1"
IGNORED_PARTS = {".git", "node_modules", "target", ".venv", "dist", "build"}
MAX_SCAN_BYTES = 1024 * 1024
ALLOWED_SUFFIXES = {".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg", ".pem", ".key", ".tfvars"}
ALLOWED_FILENAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "credentials",
    "config",
    "config.json",
    "secret.json",
    "secrets.json",
    "ludus.conf",
    "kubeconfig",
    "terraform.tfvars",
    "terraform.tfvars.json",
}

KNOWN_CREDENTIAL_VARS = {
    "AWS_SECRET_ACCESS_KEY": "AWS Secret Access Key",
    "AWS_ACCESS_KEY_ID": "AWS Access Key ID",
    "GH_TOKEN": "GitHub Token",
    "GITHUB_TOKEN": "GitHub Token",
    "GITHUB_PAT": "GitHub Token",
    "OPENAI_API_KEY": "OpenAI API Key",
    "ANTHROPIC_API_KEY": "Anthropic API Key",
    "SPLUNK_HEC_TOKEN": "Splunk HEC Token",
    "SPLUNK_PASSWORD": "Splunk Password",
    "LUDUS_API_KEY": "Ludus API Key",
    "LUDUS_PASSWORD": "Ludus Password",
    "KUBECONFIG": "Kubernetes Config",
    "NPM_TOKEN": "NPM Token",
    "PYPI_TOKEN": "Python Package Index Token",
    "DOCKER_AUTH_CONFIG": "Docker Auth Config",
    "GOOGLE_APPLICATION_CREDENTIALS": "GCP Application Credentials",
    "GEMINI_API_KEY": "Gemini API Key",
    "XAI_API_KEY": "xAI API Key",
}

ASSIGNMENT_RE = re.compile(r'["\']?([A-Z][A-Z0-9_]{2,})["\']?\s*[:=]\s*["\']?([^\s,"\'}]+)')


def load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        return {"credentials": []}
    try:
        return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"credentials": []}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def should_ignore(path: Path) -> bool:
    return any(part in IGNORED_PARTS for part in path.parts)


def is_candidate_credential_file(path: Path) -> bool:
    name = path.name.lower()
    if name in ALLOWED_FILENAMES:
        return True
    if name.startswith(".env"):
        return True
    if "secret" in name or "credential" in name or "kubeconfig" in name:
        return True
    if name.endswith(".tfvars"):
        return True
    return path.suffix.lower() in ALLOWED_SUFFIXES


def is_credential_var(name: str) -> bool:
    if name in KNOWN_CREDENTIAL_VARS:
        return True
    return name.endswith(("_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_CREDENTIAL", "_API_KEY", "_PASS"))


def classify_fields(fields: list[str], path: Path) -> str:
    if "OPENAI_API_KEY" in fields and len(fields) == 1:
        return "Workspace File with OpenAI API Key"
    if (
        any(field in {"GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PAT"} for field in fields)
        and len(fields) == 1
    ):
        return "Workspace File with GitHub Token"

    has_passwords = any(field.endswith("_PASS") or field.endswith("_PASSWORD") for field in fields)
    has_tokens = any(field.endswith("_TOKEN") for field in fields)
    has_api_keys = any(field.endswith("_API_KEY") for field in fields)
    has_secrets = any(
        field.endswith("_SECRET") or field.endswith("_KEY") or field.endswith("_CREDENTIAL")
        for field in fields
        if not field.endswith("_API_KEY")
    )

    categories: list[str] = []
    if has_tokens:
        categories.append("Tokens")
    if has_api_keys:
        categories.append("API Keys")
    if has_passwords:
        categories.append("Passwords")
    if has_secrets:
        categories.append("Secrets")

    if len(categories) > 1:
        return "Workspace File with " + " and ".join(categories)
    if categories:
        return f"Workspace File with {categories[0]}"

    if path.suffix.lower() in {".pem", ".key"}:
        return "Workspace Private Key File"
    if path.name == ".env":
        return "Workspace .env Credential File"
    return "Workspace Credential File"


def scan_file_for_credentials(path: Path) -> tuple[bool, list[str], str | None]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_SCAN_BYTES or not is_candidate_credential_file(path):
            return False, [], None
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False, [], None

    fields: list[str] = []
    for name, _ in ASSIGNMENT_RE.findall(text):
        if is_credential_var(name) and name not in fields:
            fields.append(name)

    if "-----BEGIN" in text and "PRIVATE KEY-----" in text and "PEM_PRIVATE_KEY" not in fields:
        fields.append("PEM_PRIVATE_KEY")

    if not fields:
        return False, [], None

    classification = classify_fields(fields, path)
    signature = f"{classification}|{'/'.join(sorted(fields))}|{path.stat().st_size}|{int(path.stat().st_mtime)}"
    return True, fields, signature


def register_workspace_file(path: Path, classification: str, fields: list[str]) -> None:
    subprocess.run(
        [
            REGISTRY_BIN,
            "--path",
            str(path),
            "--kind",
            "workspace_credential_file",
            "--mount-mode",
            "workspace",
            "--classification",
            classification,
            "--discovery-method",
            "workspace_scan",
            "--command",
            ",".join(fields),
        ],
        check=False,
    )


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


def emit_discovery_event(path: Path, classification: str, fields: list[str]) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "credential_discovered",
        "severity": "info",
        "shell": "workspace-watcher",
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "cwd": os.getcwd(),
        "agent": os.getenv("AGENTFENCE_AGENT", "shell"),
        "command": None,
        "variable": None,
        "old_value": None,
        "new_value": None,
        "classification": classification,
        "discovery_method": "workspace_scan",
        "registry_id": f"file::{path}",
        "path": str(path),
        "operation": None,
        "process_name": None,
        "process_cmdline": None,
        "observed_pid": None,
        "observed_ppid": None,
        "process_chain": None,
        "destination": None,
        "destination_port": None,
        "protocol": None,
        "active_credential_count": None,
        "matched_registry_ids": None,
        "verdict": "observed",
        "reason": f"workspace file contains credential-like fields: {','.join(fields)}",
    }
    write_audit_event(record)


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
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        for proc_dir in Path("/proc").iterdir():
            if not proc_dir.name.isdigit():
                continue
            fd_dir = proc_dir / "fd"
            if not fd_dir.is_dir():
                continue
            try:
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
    return None, None, None, None, None


def update_access_metadata(path: Path, should_count_access: bool) -> tuple[str | None, str | None]:
    registry = load_registry()
    credential_id = f"file::{path}"
    classification = None
    changed = False
    for item in registry.get("credentials", []):
        if item.get("id") == credential_id:
            classification = item.get("classification")
            if should_count_access:
                item["access_count"] = int(item.get("access_count", 0)) + 1
                item["last_accessed_at"] = utc_now()
                changed = True
            break
    if changed:
        REGISTRY_PATH.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    return (credential_id, classification) if classification else (None, None)


def emit_access_event(path: Path, event_name: str, process_cache: dict[str, tuple[str | None, str | None, str | None, str | None, str | None]]) -> None:
    if DISABLE_FILE_ACCESS_AUDIT:
        return
    credential_id, classification = update_access_metadata(path, "access" in event_name.lower())
    if credential_id is None:
        return
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
        "shell": "workspace-watcher",
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "cwd": os.getcwd(),
        "agent": os.getenv("AGENTFENCE_AGENT", "shell"),
        "command": None,
        "variable": None,
        "old_value": None,
        "new_value": None,
        "classification": classification or "Workspace Credential File",
        "discovery_method": "workspace_scan",
        "registry_id": credential_id,
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
        "reason": "workspace credential file accessed",
    }
    write_audit_event(record)

    if process_name and process_name.lower() in {"curl", "wget", "nc", "ncat", "socat", "python3", "python", "node"}:
        emit_alert("high", f"workspace credential {path.name} accessed by {process_name} (pid {observed_pid or '?'})")

    if "close" in event_name:
        process_cache.pop(cache_key, None)


def current_workspace_file_registry() -> set[str]:
    registry = load_registry()
    result = set()
    for item in registry.get("credentials", []):
        item_path = str(item.get("path", ""))
        if item.get("type") == "file" and item_path.startswith(f"{WORKSPACE}/"):
            result.add(item["path"])
    return result


def scan_existing_workspace(signatures: dict[str, str]) -> None:
    for path in WORKSPACE.rglob("*"):
        if should_ignore(path) or not path.is_file():
            continue
        discovered, fields, signature = scan_file_for_credentials(path)
        if not discovered or signature is None:
            continue
        old = signatures.get(str(path))
        if old == signature:
            continue
        classification = classify_fields(fields, path)
        register_workspace_file(path, classification, fields)
        emit_discovery_event(path, classification, fields)
        signatures[str(path)] = signature


def main() -> int:
    if not WORKSPACE.exists():
        return 0

    signatures: dict[str, str] = {}
    scan_existing_workspace(signatures)

    process = subprocess.Popen(
        [
            "stdbuf",
            "-oL",
            "inotifywait",
            "-m",
            "-r",
            "-e",
            "create",
            "-e",
            "modify",
            "-e",
            "close_write",
            "-e",
            "open",
            "-e",
            "access",
            "-e",
            "close_nowrite",
            "--format",
            "%w|%f|%e",
            str(WORKSPACE),
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
        if should_ignore(path) or not path.exists() or not path.is_file():
            continue

        event_name = event_name.lower()
        if any(token in event_name for token in ("create", "modify", "close_write")):
            discovered, fields, signature = scan_file_for_credentials(path)
            if discovered and signature is not None and signatures.get(str(path)) != signature:
                classification = classify_fields(fields, path)
                register_workspace_file(path, classification, fields)
                emit_discovery_event(path, classification, fields)
                signatures[str(path)] = signature
        if any(token in event_name for token in ("open", "access", "close_nowrite")):
            if str(path) in current_workspace_file_registry():
                emit_access_event(path, event_name, process_cache)

    return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
