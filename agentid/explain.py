from __future__ import annotations

from typing import Any


def explain_manifest(manifest: dict[str, Any]) -> str:
    agent = manifest.get("agent", {})
    delegation = manifest.get("delegation", {})
    tools = manifest.get("tools", [])
    audit = manifest.get("audit", {})
    kill_switch = manifest.get("kill_switch", {})

    lines: list[str] = []

    lines.append(f"Agent: {agent.get('name', 'Unnamed agent')} ({agent.get('id', 'missing-id')})")
    lines.append(f"Owner: {agent.get('owner', 'missing-owner')}")
    lines.append(f"Environment: {agent.get('environment', 'unspecified')}")
    lines.append(f"Purpose: {agent.get('purpose', 'unspecified')}")
    if agent.get("expires_at"):
        lines.append(f"Authority expires: {agent['expires_at']}")

    acts_for = delegation.get("acts_for", {})
    if acts_for:
        required = "required" if acts_for.get("required") else "optional"
        lines.append(f"Delegation: acts for {acts_for.get('type', 'unknown')} ({required})")

    if delegation.get("allowed_subjects"):
        lines.append("Allowed subjects: " + ", ".join(delegation["allowed_subjects"]))

    lines.append("")
    lines.append("Tools:")

    if not tools:
        lines.append("- No tools declared.")
    else:
        for tool in tools:
            approval = tool.get("approval", "none")
            line = f"- {tool.get('name', 'unnamed-tool')}: {tool.get('access', 'unknown')} access"
            if approval != "none":
                line += f", approval={approval}"
            else:
                line += ", no approval required"

            constraints = tool.get("constraints")
            if constraints:
                line += f", constrained by {', '.join(constraints.keys())}"

            lines.append(line)

    lines.append("")
    lines.append("Audit:")
    lines.append(f"- Log prompt summaries: {bool(audit.get('log_prompt_summary'))}")
    lines.append(f"- Log tool calls: {bool(audit.get('log_tool_calls'))}")
    lines.append(f"- Log decisions: {bool(audit.get('log_decisions'))}")
    if audit.get("retain_days"):
        lines.append(f"- Retention: {audit['retain_days']} days")

    lines.append("")
    lines.append("Kill switch:")
    lines.append(f"- Enabled: {bool(kill_switch.get('enabled'))}")
    lines.append(f"- Revoke on policy violation: {bool(kill_switch.get('revoke_on_policy_violation'))}")

    return "\n".join(lines)
