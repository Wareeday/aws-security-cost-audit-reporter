"""IAM Identity & Access Governance Checks: Root MFA/Keys, Password Policy, User MFA, Keys, Policies."""

from __future__ import annotations

from typing import Any

from aws_audit.checks.base import build_finding
from aws_audit.config import ADMIN_POLICY_NAMES, AuditConfig
from aws_audit.models import Finding


def _check_iam_account_summary(snapshot: dict[str, Any], cfg: AuditConfig) -> list[Finding]:
    if "iam_summary" not in snapshot:
        return []

    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))
    summary = snapshot.get("iam_summary", {})

    # SEC-IAM-001: Root MFA
    if summary.get("root_mfa_enabled") is False:
        findings.append(
            build_finding(
                "SEC-IAM-001",
                resource_id=f"arn:aws:iam::{account_id}:root",
                resource_type="AWS::IAM::RootAccount",
                resource_name="AWS Account Root User",
                region="global",
                account_id=account_id,
                issue="Root account MFA is disabled",
                remediation="Enable a hardware FIDO2/U2F security key or virtual MFA device on the AWS root user.",
                remediation_cli="aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
            )
        )

    # SEC-IAM-002: Root Access Keys
    if summary.get("root_access_keys_present") is True:
        findings.append(
            build_finding(
                "SEC-IAM-002",
                resource_id=f"arn:aws:iam::{account_id}:root",
                resource_type="AWS::IAM::RootAccount",
                resource_name="AWS Account Root User",
                region="global",
                account_id=account_id,
                issue="Active root account access keys exist",
                remediation="Delete root access keys immediately and use short-lived IAM Identity Center / STS role credentials.",
                remediation_cli="aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'",
            )
        )

    # SEC-IAM-006: Account Password Policy
    policy = summary.get("password_policy")
    if isinstance(policy, dict):
        gaps: list[str] = []
        if not policy.get("exists", True):
            gaps.append("no custom IAM password policy configured")
        else:
            min_len = int(policy.get("minimum_password_length", 0))
            if min_len < cfg.min_password_length:
                gaps.append(f"min length {min_len} < {cfg.min_password_length}")
            for flag, label in (
                ("require_symbols", "symbols"),
                ("require_numbers", "numbers"),
                ("require_uppercase", "uppercase"),
                ("require_lowercase", "lowercase"),
            ):
                if not policy.get(flag, False):
                    gaps.append(f"missing {label} requirement")
            max_age = policy.get("max_password_age")
            if max_age is None or int(max_age) > cfg.max_password_age_days:
                gaps.append(f"max age > {cfg.max_password_age_days}d")
            reuse = int(policy.get("password_reuse_prevention", 0) or 0)
            if reuse < 24:
                gaps.append(f"reuse prevention {reuse} < 24")

        if gaps:
            findings.append(
                build_finding(
                    "SEC-IAM-006",
                    resource_id=f"arn:aws:iam::{account_id}:account-password-policy",
                    resource_type="AWS::IAM::PasswordPolicy",
                    resource_name="IAM Account Password Policy",
                    region="global",
                    account_id=account_id,
                    issue=f"Password policy non-compliant: {'; '.join(gaps)}",
                    remediation=(
                        f"Enforce minimum length >= {cfg.min_password_length}, character complexity, "
                        f"<= {cfg.max_password_age_days}-day expiration, and 24-password history."
                    ),
                    remediation_cli=(
                        f"aws iam update-account-password-policy --minimum-password-length {cfg.min_password_length} "
                        f"--require-symbols --require-numbers --require-uppercase-characters "
                        f"--require-lowercase-characters --max-password-age {cfg.max_password_age_days} "
                        f"--password-reuse-prevention 24"
                    ),
                    evidence={"gaps": gaps},
                )
            )

    return findings


def _check_iam_users(snapshot: dict[str, Any], cfg: AuditConfig) -> list[Finding]:
    findings: list[Finding] = []
    account_id = str(snapshot.get("account_id", "unknown"))

    for user in snapshot.get("iam_users", []):
        uname = str(user.get("username", "unknown"))

        # SEC-IAM-003: Console user without MFA (if has_console_access omitted, preserve legacy behavior)
        has_console = user.get("has_console_access", True)
        if has_console and not user.get("has_mfa", False):
            findings.append(
                build_finding(
                    "SEC-IAM-003",
                    resource_id=f"iam-user:{uname}",
                    resource_type="AWS::IAM::User",
                    resource_name=f"IAM User: {uname}",
                    region="global",
                    account_id=account_id,
                    issue="Console-enabled IAM user has no MFA device enrolled",
                    remediation="Enroll a virtual or hardware MFA device and enforce MFA via IAM condition policies.",
                    remediation_cli=f"aws iam list-mfa-devices --user-name {uname}",
                )
            )

        # SEC-IAM-007: Over-privileged direct user policies / inline policies
        attached = [str(p) for p in user.get("attached_policies", [])]
        inline = [str(p) for p in user.get("inline_policies", [])]
        admin_hits = [p for p in attached if p in ADMIN_POLICY_NAMES]
        if admin_hits or inline:
            details = []
            if admin_hits:
                details.append(f"broad managed policies ({', '.join(admin_hits)})")
            if inline:
                details.append(f"inline policies ({', '.join(inline)})")
            findings.append(
                build_finding(
                    "SEC-IAM-007",
                    resource_id=f"iam-user:{uname}",
                    resource_type="AWS::IAM::User",
                    resource_name=f"IAM User: {uname}",
                    region="global",
                    account_id=account_id,
                    issue=f"IAM user has direct privileged permissions: {' and '.join(details)}",
                    remediation="Attach least-privilege managed policies through IAM groups or migrate human users to IAM Identity Center roles.",
                    remediation_cli=f"aws iam list-attached-user-policies --user-name {uname}",
                    evidence={"attached_admin_policies": admin_hits, "inline_policies": inline},
                )
            )

        # Access keys: rotation age & dormancy
        for key in user.get("access_keys", []):
            key_id = str(key.get("access_key_id", ""))
            status = str(key.get("status", "Inactive"))
            if status != "Active":
                continue

            age = int(key.get("age_days", 0))
            if age > cfg.max_access_key_age_days:
                sev = "HIGH" if age >= cfg.critical_access_key_age_days else "MEDIUM"
                findings.append(
                    build_finding(
                        "SEC-IAM-004",
                        severity=sev,
                        resource_id=key_id or f"{uname}-key",
                        resource_type="AWS::IAM::AccessKey",
                        resource_name=f"IAM Key: {uname} ({key_id})",
                        region="global",
                        account_id=account_id,
                        issue=f"Active access key is {age} days old (limit: {cfg.max_access_key_age_days} days)",
                        remediation="Create a replacement access key, update applications or migrate to IAM Roles, then deactivate and delete the stale key.",
                        remediation_cli=(
                            f"aws iam update-access-key --user-name {uname} "
                            f"--access-key-id {key_id} --status Inactive"
                        ),
                        evidence={"age_days": age},
                    )
                )

            if "last_used_days" in key:
                last_used = key.get("last_used_days")
                if last_used is None and age > 30:
                    findings.append(
                        build_finding(
                            "SEC-IAM-005",
                            resource_id=key_id or f"{uname}-key",
                            resource_type="AWS::IAM::AccessKey",
                            resource_name=f"IAM Key: {uname} ({key_id})",
                            region="global",
                            account_id=account_id,
                            issue=f"Active access key ({age} days old) has never been used",
                            remediation="Deactivate and delete unused programmatic access keys to shrink credential exposure.",
                            remediation_cli=(
                                f"aws iam delete-access-key --user-name {uname} --access-key-id {key_id}"
                            ),
                            evidence={"age_days": age, "last_used_days": None},
                        )
                    )
                elif last_used is not None and int(last_used) > cfg.unused_access_key_days:
                    findings.append(
                        build_finding(
                            "SEC-IAM-005",
                            resource_id=key_id or f"{uname}-key",
                            resource_type="AWS::IAM::AccessKey",
                            resource_name=f"IAM Key: {uname} ({key_id})",
                            region="global",
                            account_id=account_id,
                            issue=(
                                f"Active access key unused for {last_used} days "
                                f"(limit: {cfg.unused_access_key_days} days)"
                            ),
                            remediation="Deactivate dormant access key and verify no automation depends on it before deletion.",
                            remediation_cli=(
                                f"aws iam update-access-key --user-name {uname} "
                                f"--access-key-id {key_id} --status Inactive"
                            ),
                            evidence={"age_days": age, "last_used_days": int(last_used)},
                        )
                    )

    return findings


def run_iam_checks(snapshot: dict[str, Any], cfg: AuditConfig) -> list[Finding]:
    """Evaluate account-level and user-level IAM security controls."""
    findings: list[Finding] = []
    findings.extend(_check_iam_account_summary(snapshot, cfg))
    findings.extend(_check_iam_users(snapshot, cfg))
    return findings
