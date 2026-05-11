from __future__ import annotations

from typing import Any


APPROVAL_REQUIRED = {"required", "human_confirm", "step_up", "manager"}
BLOCKING_APPROVAL = {"block"}


def generate_opa_policy(manifest: dict[str, Any]) -> str:
    agent_id = manifest.get("agent", {}).get("id", "unknown-agent")
    tools = manifest.get("tools", [])
    flows = manifest.get("data_flows", [])

    allowed_rules: list[str] = []
    approval_rules: list[str] = []
    blocked_rules: list[str] = []
    jit_rules: list[str] = []
    flow_rules: list[str] = []

    for tool in tools:
        name = tool.get("name")
        access = tool.get("access")
        approval = tool.get("approval", "none")
        auth_mode = tool.get("auth_mode", "delegated")
        if not name or not access:
            continue
        allowed_rules.append(f'allowed_tools["{name}"] := "{access}"')
        if approval in APPROVAL_REQUIRED:
            approval_rules.append(f'requires_approval["{name}"]')
        if approval in BLOCKING_APPROVAL:
            blocked_rules.append(f'blocked_tools["{name}"]')
        if auth_mode == "just_in_time":
            jit_rules.append(f'requires_jit["{name}"]')

    for flow in flows:
        source = flow.get("from")
        dest = flow.get("to")
        if source and dest and flow.get("allowed") is True:
            flow_rules.append(f'allowed_flows["{source}::{dest}"]')

    allowed_block = "\n".join(allowed_rules) or "# No tools declared."
    approval_block = "\n".join(approval_rules) or "# No approval-required tools declared."
    blocked_block = "\n".join(blocked_rules) or "# No blocked tools declared."
    jit_block = "\n".join(jit_rules) or "# No JIT-required tools declared."
    flow_block = "\n".join(flow_rules) or "# No explicit allowed data flows declared."

    return f"""package agentid

default allow := false

agent_id := "{agent_id}"

{allowed_block}

{approval_block}

{blocked_block}

{jit_block}

{flow_block}

tool_allowed if {{
    input.agent_id == agent_id
    allowed_tools[input.tool] == input.action
    not blocked_tools[input.tool]
}}

flow_allowed if {{
    input.data_from == ""
    input.data_to == ""
}}

flow_allowed if {{
    allowed_flows[concat("::", [input.data_from, input.data_to])]
}}

jit_satisfied if {{
    not requires_jit[input.tool]
}}

jit_satisfied if {{
    requires_jit[input.tool]
    input.jit_grant_valid == true
    input.jit_grant_agent_id == input.agent_id
    input.jit_grant_tool == input.tool
    input.jit_grant_action == input.action
}}

approval_satisfied if {{
    not requires_approval[input.tool]
}}

approval_satisfied if {{
    requires_approval[input.tool]
    input.approved == true
}}

allow if {{
    tool_allowed
    flow_allowed
    jit_satisfied
    approval_satisfied
}}
"""


def generate_policy(manifest: dict[str, Any], target: str) -> str:
    if target != "opa":
        raise ValueError("Only target='opa' is currently supported.")
    return generate_opa_policy(manifest)
