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
        "tools": [
            {
                "name": "docs.search",
                "access": "read",
                "approval": "none",
            }
        ],
    }

    result = validate_manifest(manifest)

    assert result.ok
