from __future__ import annotations

import json
from pathlib import Path
from typing import Any


APPROVAL_REQUIRED = {"required", "human_confirm", "step_up", "manager"}


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
    allowed_flows = {
        (flow.get("from"), flow.get("to")): flow.get("allowed")
        for flow in manifest.get("data_flows", [])
    }

    for idx, event in enumerate(events):
        prefix = f"event[{idx}]"

        if agent_id and event.get("agent_id") != agent_id:
            findings.append(f"{prefix}: agent_id mismatch: {event.get('agent_id')} != {agent_id}")

        tool_name = event.get("tool")
        if tool_name not in tools:
            findings.append(f"{prefix}: undeclared tool used: {tool_name}")
            continue

        manifest_tool = tools[tool_name]
        if manifest_tool.get("access") != event.get("action"):
            findings.append(
                f"{prefix}: action mismatch for {tool_name}: actual={event.get('action')}, allowed={manifest_tool.get('access')}"
            )

        approval = manifest_tool.get("approval", "none")
        if approval in APPROVAL_REQUIRED and not event.get("approved"):
            findings.append(f"{prefix}: {tool_name} requires approval but event is not approved")
        if approval == "block":
            findings.append(f"{prefix}: {tool_name} is blocked by manifest policy")

        auth_mode = manifest_tool.get("auth_mode", "delegated")
        if auth_mode == "just_in_time":
            if not event.get("jit_grant_id"):
                findings.append(f"{prefix}: {tool_name} requires JIT authorization but no jit_grant_id is present")
            if event.get("jit_grant_valid") is False:
                findings.append(f"{prefix}: JIT grant is marked invalid")

        data_from = event.get("data_from")
        data_to = event.get("data_to")
        if data_from and data_to:
            allowed = allowed_flows.get((data_from, data_to))
            if allowed is False:
                findings.append(f"{prefix}: blocked data flow used: {data_from} -> {data_to}")
            elif allowed is None:
                findings.append(f"{prefix}: undeclared data flow: {data_from} -> {data_to}")

        called_agent = event.get("called_agent")
        if called_agent:
            chain = manifest.get("delegation_chain", {})
            allowed_agents = set(chain.get("allowed_agents", []))
            if not chain.get("may_call_agents"):
                findings.append(f"{prefix}: agent-to-agent delegation is not allowed")
            elif called_agent not in allowed_agents:
                findings.append(f"{prefix}: called agent is not in allowed_agents: {called_agent}")

    return not findings, findings
