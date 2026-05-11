# AgentID

**AgentID** is a lightweight open-source toolkit for declaring, validating, reviewing, and auditing AI agent authority.

The core idea is simple:

> Every production agent should have a manifest that says who it is, who owns it, what it can do, and when it must ask for help.

AgentID does **not** replace IAM, OAuth, MCP gateways, OPA, Cedar, or enterprise security tools. It sits one layer above them as a portable declaration format for agent identity, delegation, tool access, approval boundaries, audit expectations, and kill-switch behavior.

---

## Why this exists

Most agent projects define tools and credentials in ad hoc config files.

What is often missing is a clear answer to:

- What is this agent?
- Who owns it?
- What systems can it touch?
- What actions can it take?
- Which actions require approval?
- When does its authority expire?
- What should be logged?
- How can it be stopped?

AgentID turns those questions into a small manifest that can be reviewed by developers, security teams, platform teams, and product owners.

---

## Example

```yaml
agent:
  id: customer-support-refund-agent
  name: Customer Support Refund Agent
  owner: support-platform-team
  environment: production
  purpose: Handles refund triage and drafts refund decisions
  expires_at: 2026-12-31

delegation:
  acts_for:
    type: user
    required: true
  allowed_subjects:
    - support_rep
    - support_manager

tools:
  - name: zendesk.search_tickets
    access: read
    approval: none

  - name: stripe.create_refund
    access: write
    approval: required
    constraints:
      max_amount_usd: 100
      allowed_reasons:
        - duplicate_charge
        - service_failure

audit:
  log_prompt_summary: true
  log_tool_calls: true
  log_decisions: true
  retain_days: 365

kill_switch:
  enabled: true
  revoke_on_policy_violation: true
```

---

## Install locally

```bash
git clone <your-repo-url>
cd agentid
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## CLI

```bash
agentid validate examples/customer-support-refund-agent.yaml
agentid explain examples/customer-support-refund-agent.yaml
agentid risk-score examples/customer-support-refund-agent.yaml
agentid generate-policy examples/customer-support-refund-agent.yaml --target opa
agentid audit examples/sample-tool-log.json --manifest examples/customer-support-refund-agent.yaml
```

---

## Manifest concepts

| Concept | Meaning |
|---|---|
| `agent` | Unique identity, owner, purpose, environment, and expiry |
| `delegation` | Who or what the agent is allowed to act on behalf of |
| `tools` | External capabilities the agent may use |
| `approval` | Whether an action requires explicit approval |
| `constraints` | Limits such as max amount, allowed reasons, domains, or resource patterns |
| `audit` | What must be logged and retained |
| `kill_switch` | Whether policy violations should revoke or suspend authority |

---

## Design principles

1. **Agents are first-class identities.**
2. **Authority should be explicit.**
3. **Delegation matters.**
4. **Approval should be action-level.**
5. **Auditability is part of identity.**
6. **Revocation must be practical.**

---

## Roadmap

- JSON Schema for the manifest
- GitHub Action for PR validation
- Stronger policy generation for OPA and Cedar
- MCP tool metadata import/export
- OAuth scope recommendation
- Web-based manifest viewer
- Risk policy profiles by environment
- Audit log normalization
- CI/CD gates for unsafe agent configs

---

## License

MIT
