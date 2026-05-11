from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml


class ManifestError(Exception):
    """Raised when a manifest cannot be loaded or parsed."""


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str]
    warnings: list[str]


REQUIRED_AGENT_FIELDS = ["id", "name", "owner", "environment", "purpose"]


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load an AgentID YAML manifest."""
    manifest_path = Path(path)

    if not manifest_path.exists():
        raise ManifestError(f"Manifest not found: {manifest_path}")

    try:
        data = yaml.safe_load(manifest_path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ManifestError(f"Invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ManifestError("Manifest root must be a mapping/object.")

    return data


def validate_manifest(manifest: dict[str, Any]) -> ValidationResult:
    """Validate required AgentID fields and common safety expectations."""
    errors: list[str] = []
    warnings: list[str] = []

    agent = manifest.get("agent")
    if not isinstance(agent, dict):
        errors.append("Missing required section: agent")
        agent = {}

    for field in REQUIRED_AGENT_FIELDS:
        if not agent.get(field):
            errors.append(f"Missing required field: agent.{field}")

    if not manifest.get("tools"):
        warnings.append("No tools declared. Agent authority may be incomplete or intentionally empty.")

    tools = manifest.get("tools", [])
    if tools and not isinstance(tools, list):
        errors.append("tools must be a list.")

    for idx, tool in enumerate(tools if isinstance(tools, list) else []):
        prefix = f"tools[{idx}]"
        if not isinstance(tool, dict):
            errors.append(f"{prefix} must be an object.")
            continue

        if not tool.get("name"):
            errors.append(f"{prefix}.name is required.")

        access = tool.get("access")
        if access not in {"read", "write", "admin", "execute"}:
            errors.append(f"{prefix}.access must be one of: read, write, execute, admin.")

        approval = tool.get("approval", "none")
        if approval not in {"none", "required", "step_up", "manager"}:
            errors.append(f"{prefix}.approval must be one of: none, required, step_up, manager.")

        if access in {"write", "admin", "execute"} and approval == "none":
            warnings.append(f"{prefix} has {access} access without approval.")

        if access == "admin":
            warnings.append(f"{prefix} uses admin access. Prefer narrower tool permissions.")

    audit = manifest.get("audit", {})
    if not isinstance(audit, dict):
        errors.append("audit must be an object if provided.")
    else:
        if not audit.get("log_tool_calls"):
            warnings.append("audit.log_tool_calls is not enabled.")
        if not audit.get("log_decisions"):
            warnings.append("audit.log_decisions is not enabled.")

    kill_switch = manifest.get("kill_switch", {})
    if not isinstance(kill_switch, dict):
        errors.append("kill_switch must be an object if provided.")
    elif not kill_switch.get("enabled"):
        warnings.append("kill_switch.enabled is not true.")

    expires_at = agent.get("expires_at")
    if expires_at:
        _validate_expiry(expires_at, warnings, errors)
    else:
        warnings.append("agent.expires_at is not set. Consider expiring production agent authority.")

    return ValidationResult(ok=not errors, errors=errors, warnings=warnings)


def _validate_expiry(value: Any, warnings: list[str], errors: list[str]) -> None:
    try:
        if isinstance(value, date):
            expiry = value
        else:
            expiry = datetime.strptime(str(value), "%Y-%m-%d").date()
    except ValueError:
        errors.append("agent.expires_at must be YYYY-MM-DD.")
        return

    if expiry < date.today():
        warnings.append("agent.expires_at is in the past.")
