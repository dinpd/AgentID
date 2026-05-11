from __future__ import annotations

from typing import Any


def risk_score(manifest: dict[str, Any]) -> tuple[int, list[str]]:
    """Return a rough 0-100 risk score and explanation."""
    score = 0
    reasons: list[str] = []

    environment = manifest.get("agent", {}).get("environment")
    if environment == "production":
        score += 15
        reasons.append("production environment")

    tools = manifest.get("tools", [])
    if len(tools) > 5:
        score += 10
        reasons.append("large number of tools")

    for tool in tools:
        access = tool.get("access")
        approval = tool.get("approval", "none")
        constraints = tool.get("constraints", {})

        if access == "read":
            score += 3
        elif access == "write":
            score += 12
            reasons.append(f"{tool.get('name')} has write access")
        elif access == "execute":
            score += 18
            reasons.append(f"{tool.get('name')} has execute access")
        elif access == "admin":
            score += 30
            reasons.append(f"{tool.get('name')} has admin access")

        if approval in {"required", "step_up", "manager"}:
            score -= 5
        elif access in {"write", "execute", "admin"}:
            score += 10
            reasons.append(f"{tool.get('name')} does not require approval")

        if constraints:
            score -= 4
        elif access in {"write", "execute", "admin"}:
            score += 8
            reasons.append(f"{tool.get('name')} lacks constraints")

    audit = manifest.get("audit", {})
    if audit.get("log_tool_calls"):
        score -= 5
    else:
        score += 8
        reasons.append("tool-call logging not enabled")

    if audit.get("log_decisions"):
        score -= 5
    else:
        score += 8
        reasons.append("decision logging not enabled")

    kill_switch = manifest.get("kill_switch", {})
    if kill_switch.get("enabled"):
        score -= 8
    else:
        score += 12
        reasons.append("kill switch not enabled")

    score = max(0, min(100, score))
    return score, sorted(set(reasons))


def risk_label(score: int) -> str:
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"
