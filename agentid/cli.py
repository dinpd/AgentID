from __future__ import annotations

import argparse
import sys

from agentid.audit import audit_events, load_audit_log
from agentid.explain import explain_manifest
from agentid.manifest import ManifestError, load_manifest, validate_manifest
from agentid.policy import generate_policy
from agentid.risk import risk_label, risk_score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentid",
        description="Validate, explain, score, generate policy for, and audit AI agent identity manifests.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate an AgentID manifest.")
    validate_parser.add_argument("manifest")

    explain_parser = subparsers.add_parser("explain", help="Explain an AgentID manifest in plain English.")
    explain_parser.add_argument("manifest")

    risk_parser = subparsers.add_parser("risk-score", help="Generate a rough risk score for an AgentID manifest.")
    risk_parser.add_argument("manifest")

    policy_parser = subparsers.add_parser("generate-policy", help="Generate starter policy from an AgentID manifest.")
    policy_parser.add_argument("manifest")
    policy_parser.add_argument("--target", choices=["opa"], default="opa")

    audit_parser = subparsers.add_parser("audit", help="Audit a tool-call log against an AgentID manifest.")
    audit_parser.add_argument("audit_log")
    audit_parser.add_argument("--manifest", required=True)

    args = parser.parse_args(argv)

    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate":
        result = validate_manifest(manifest)
        _print_validation(result)
        return 0 if result.ok else 1

    if args.command == "explain":
        result = validate_manifest(manifest)
        _print_validation(result, include_success=False)
        print(explain_manifest(manifest))
        return 0 if result.ok else 1

    if args.command == "risk-score":
        result = validate_manifest(manifest)
        _print_validation(result, include_success=False)
        score, reasons = risk_score(manifest)
        print(f"Risk score: {score}/100 ({risk_label(score)})")
        if reasons:
            print("Reasons:")
            for reason in reasons:
                print(f"- {reason}")
        return 0 if result.ok else 1

    if args.command == "generate-policy":
        result = validate_manifest(manifest)
        if not result.ok:
            _print_validation(result)
            return 1
        print(generate_policy(manifest, args.target))
        return 0

    if args.command == "audit":
        result = validate_manifest(manifest)
        if not result.ok:
            _print_validation(result)
            return 1

        try:
            events = load_audit_log(args.audit_log)
        except Exception as exc:
            print(f"ERROR: failed to load audit log: {exc}", file=sys.stderr)
            return 2

        ok, findings = audit_events(manifest, events)

        if ok:
            print("Audit passed. No policy violations found.")
            return 0

        print("Audit findings:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    return 0


def _print_validation(result, include_success: bool = True) -> None:
    if include_success and result.ok:
        print("Manifest is valid.")

    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"- {error}")

    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"- {warning}")


if __name__ == "__main__":
    raise SystemExit(main())
