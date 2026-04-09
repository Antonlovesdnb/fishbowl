#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update AgentFence credential registry")
    parser.add_argument("--env-var")
    parser.add_argument("--value")
    parser.add_argument("--path")
    parser.add_argument("--kind")
    parser.add_argument("--mount-mode")
    parser.add_argument("--classification", required=True)
    parser.add_argument("--discovery-method", default="env_watch")
    parser.add_argument("--command")
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_registry(path: Path) -> dict:
    if not path.exists():
        return {"credentials": []}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"credentials": []}


def main() -> int:
    args = parse_args()
    if not args.env_var and not args.path:
        raise SystemExit("either --env-var or --path is required")

    registry_path = Path("/var/log/agentfence/registry.json")
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    registry = load_registry(registry_path)
    credentials = registry.setdefault("credentials", [])
    now = utc_now()

    if args.env_var:
        credential_id = f"env::{args.env_var}"
        preview_value = args.value or ""
    else:
        credential_id = f"file::{args.path}"
        preview_value = ""

    existing = None
    for item in credentials:
        if item.get("id") == credential_id:
            existing = item
            break

    if existing is None:
        item = {
            "id": credential_id,
            "classification": args.classification,
            "discovery_method": args.discovery_method,
            "discovered_at": now,
            "last_seen_at": now,
            "source_command": args.command,
        }
        if args.env_var:
            item.update(
                {
                    "type": "env_var",
                    "env_var": args.env_var,
                    "value_preview": preview_value[:4] + "..." if len(preview_value) > 4 else preview_value,
                    "expected_destinations": [],
                }
            )
        else:
            item.update(
                {
                    "type": "file",
                    "path": args.path,
                    "kind": args.kind,
                    "mount_mode": args.mount_mode or "read-only",
                    "access_count": 0,
                    "last_accessed_at": None,
                    "expected_destinations": [],
                }
            )
        credentials.append(item)
    else:
        existing["classification"] = args.classification
        existing["last_seen_at"] = now
        existing["source_command"] = args.command
        if args.env_var:
            existing["value_preview"] = preview_value[:4] + "..." if len(preview_value) > 4 else preview_value
        else:
            existing["path"] = args.path
            existing["kind"] = args.kind
            existing["mount_mode"] = args.mount_mode or existing.get("mount_mode", "read-only")

    registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
