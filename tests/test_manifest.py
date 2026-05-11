from agentid.manifest import validate_manifest


def test_valid_manifest_minimum():
    manifest = {
        "agent": {
            "id": "a1",
            "name": "Test Agent",
            "owner": "team",
            "environment": "dev",
            "purpose": "test",
        },
        "jit_authorization": {
            "enabled": True,
            "default_ttl_seconds": 300,
            "bind_token_to": ["agent_id", "user_id", "tool", "action", "resource", "approval_id"],
            "revoke_after_use": True,
        },
        "delegation_chain": {"may_call_agents": False, "allowed_agents": []},
        "intent": {"confirmation_required_for": ["external_email"]},
        "tools": [
            {
                "name": "docs.search",
                "access": "read",
                "auth_mode": "delegated",
                "approval": "none",
            }
        ],
        "data_flows": [{"from": "docs", "to": "agent", "allowed": True}],
        "runtime": {
            "enforce_manifest": True,
            "detect_tool_drift": True,
            "detect_new_destinations": True,
        },
        "audit": {"log_tool_calls": True, "log_decisions": True, "log_jit_grants": True},
    }

    result = validate_manifest(manifest)

    assert result.ok
