from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_audit_log(path: str | Path) -> list[dict[str, Any]]:
    audit_path = Path(path)
    raw = json.loads(audit_path.read_text())

    if isinstance(raw, list):
        return raw

    if isinstance(raw, dict) and isinstance(raw.get("events"), list):
        return raw["events"]

    raise ValueError("Audit log must be a JSON list or an object with an 'events' list.")


def audit_events(manifest: dict[str, Any], events: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    findings: list[str] = []

    agent_id = manifest.get("agent", {}).get("id")
    tools = {tool.get("name"): tool for tool in manifest.get("tools", [])}

    for idx, event in enumerate(events):
        prefix = f"event[{idx}]"

        if agent_id and event.get("agent_id") != agent_id:
            findings.append(f"{prefix}: agent_id mismatch: {event.get('agent_id')} != {agent_id}")

        tool_name = event.get("tool")
        if tool_name not in tools:
            findings.append(f"{prefix}: undeclared tool used: {tool_name}")
            continue

        manifest_tool = tools[tool_name]
        expected_access = manifest_tool.get("access")
        actual_action = event.get("action")

        if expected_access != actual_action:
            findings.append(
                f"{prefix}: action mismatch for {tool_name}: actual={actual_action}, allowed={expected_access}"
            )

        approval = manifest_tool.get("approval", "none")
        if approval != "none" and not event.get("approved"):
            findings.append(f"{prefix}: {tool_name} requires approval but event is not approved")

    return not findings, findings
