from __future__ import annotations

from typing import Any


def generate_opa_policy(manifest: dict[str, Any]) -> str:
    """Generate a starter OPA/Rego policy from an AgentID manifest."""
    agent_id = manifest.get("agent", {}).get("id", "unknown-agent")
    tools = manifest.get("tools", [])

    allowed_rules: list[str] = []
    approval_rules: list[str] = []

    for tool in tools:
        name = tool.get("name")
        access = tool.get("access")
        approval = tool.get("approval", "none")

        if not name or not access:
            continue

        allowed_rules.append(f'allowed_tools["{name}"] := "{access}"')

        if approval != "none":
            approval_rules.append(f'requires_approval["{name}"]')

    allowed_block = "\n".join(allowed_rules) or "# No tools declared."
    approval_block = "\n".join(approval_rules) or "# No approval-required tools declared."

    return f"""package agentid

default allow := false

agent_id := "{agent_id}"

{allowed_block}

{approval_block}

allow if {{
    input.agent_id == agent_id
    allowed_tools[input.tool] == input.action
    not requires_approval[input.tool]
}}

allow if {{
    input.agent_id == agent_id
    allowed_tools[input.tool] == input.action
    requires_approval[input.tool]
    input.approved == true
}}
"""


def generate_policy(manifest: dict[str, Any], target: str) -> str:
    if target != "opa":
        raise ValueError("Only target='opa' is currently supported.")
    return generate_opa_policy(manifest)
