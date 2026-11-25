# IAM Permissions & Cross-Account Setup

## Least-Privilege Policy

Attach [iam/readonly-audit-policy.json](../iam/readonly-audit-policy.json) to a dedicated IAM Role or audit identity. Every action is strictly read-only (`Describe*`, `List*`, `Get*`). Zero mutation permissions are required or used.

## Cross-Account AssumeRole Workflow

For multi-account environments, deploy an IAM Role (for example, `SecurityCostAuditReadOnly`) in target member accounts trusting your central security tooling account with an `ExternalId`:

```bash
aws-audit \
  --mode aws \
  --role-arn arn:aws:iam::210987654321:role/SecurityCostAuditReadOnly \
  --external-id audit-readonly-2026 \
  --all-regions \
  --formats all
```

## Partial-Permission Behavior

If the attached IAM policy omits an optional service (for example, `cloudwatch:GetMetricStatistics` or `rds:DescribeDBInstances`), `LiveAWSCollector` logs a `CollectionWarning` entry surfaced in the generated Markdown, HTML, and JSON reports and completes all remaining checks normally.
