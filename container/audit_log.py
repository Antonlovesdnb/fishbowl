#!/usr/bin/env python3
import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write Fishbowl audit events")
    parser.add_argument("--event", required=True)
    parser.add_argument("--severity", required=True)
    parser.add_argument("--command")
    parser.add_argument("--variable")
    parser.add_argument("--old-value")
    parser.add_argument("--new-value")
    parser.add_argument("--reason")
    parser.add_argument("--classification")
    parser.add_argument("--discovery-method")
    parser.add_argument("--registry-id")
    parser.add_argument("--path")
    parser.add_argument("--operation")
    parser.add_argument("--process-name")
    parser.add_argument("--process-cmdline")
    parser.add_argument("--observed-pid")
    parser.add_argument("--observed-ppid")
    parser.add_argument("--process-chain")
    parser.add_argument("--destination")
    parser.add_argument("--destination-port")
    parser.add_argument("--protocol")
    parser.add_argument("--active-credential-count")
    parser.add_argument("--matched-registry-ids")
    parser.add_argument("--verdict")
    parser.add_argument("--shell", default="bash")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": args.event,
        "severity": args.severity,
        "shell": args.shell,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "cwd": os.getcwd(),
        "agent": os.getenv("FISHBOWL_AGENT", "shell"),
        "command": args.command,
        "variable": args.variable,
        "old_value": args.old_value,
        "new_value": args.new_value,
        "classification": args.classification,
        "discovery_method": args.discovery_method,
        "registry_id": args.registry_id,
        "path": args.path,
        "operation": args.operation,
        "process_name": args.process_name,
        "process_cmdline": args.process_cmdline,
        "observed_pid": args.observed_pid,
        "observed_ppid": args.observed_ppid,
        "process_chain": args.process_chain,
        "destination": args.destination,
        "destination_port": args.destination_port,
        "protocol": args.protocol,
        "active_credential_count": args.active_credential_count,
        "matched_registry_ids": args.matched_registry_ids,
        "verdict": args.verdict,
        "reason": args.reason,
    }

    audit_log = Path("/var/log/fishbowl/watcher/audit.jsonl")
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
