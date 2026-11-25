# Architecture & Design

## Overview

`aws-security-cost-audit-reporter` separates **read-only cloud telemetry collection** from **deterministic rule evaluation**, **risk governance (waivers & scoring)**, and **multi-format reporting**.

```
+-----------------------+     +----------------------------+     +-----------------------+
|  Data Sources         |     |  Evaluation Engine         |     |  Outputs & CI Gates   |
+-----------------------+     +----------------------------+     +-----------------------+
| LiveAWSCollector      |     | Security Rules (SEC-*)     |     | Markdown Executive    |
|  - STS AssumeRole     | --> | FinOps Rules   (FIN-*)     | --> | Interactive HTML      |
|  - Global (IAM, S3)   |     | Waiver / Expiry Filter     |     | Safe CSV Tracker      |
|  - Regional Workers   |     | Posture Score & Grading    |     | JSON (SIEM/SOAR)      |
| Offline Snapshot JSON |     |                            |     | SARIF v2.1.0 (GHAS)   |
+-----------------------+     +----------------------------+     +-----------------------+
```

## Key Engineering Principles

1. **Snapshot-First Decoupling (`v2.0` Schema)**
   - Both `LiveAWSCollector.collect()` and `load_snapshot()` produce an identical normalized dictionary structure.
   - Organizations can capture production metadata once (`--save-snapshot`), inspect or archive the JSON artifact, and run policy/waiver evaluations repeatedly offline (`--mode snapshot`).
   - Backward compatibility (`normalize_snapshot`) ensures `v1` snapshot files load without schema errors.

2. **Resilient Live Collection (`LiveAWSCollector`)**
   - Uses `botocore.config.Config(retries={"max_attempts": 5, "mode": "adaptive"})` for rate-limit resilience.
   - Uses boto3 paginators across `ec2`, `iam`, `rds`, `elbv2`, and `logs` so large accounts never silently truncate results.
   - Separates global services (`STS`, `IAM`, `S3`) from regional services (`EC2`, `VPC`, `EBS`, `ELBv2`, `RDS`, `CloudTrail`, `CloudWatch Logs`) and executes regional scans concurrently via `ThreadPoolExecutor`.
   - Isolates per-API errors: `AccessDenied` or transient failures emit structured `CollectionWarning` items rather than aborting the entire account audit, while explicit "missing resource" codes (such as `NoSuchPublicAccessBlockConfiguration` or `NoSuchEntity` for IAM login profiles / password policies) are evaluated deterministically.

3. **FinOps Double-Counting Prevention**
   - `FIN-EBS-001` only prices unattached (`available`) EBS volumes.
   - `FIN-EC2-001` prices storage attached to long-stopped (`>30d`) EC2 instances.
   - `FIN-EBS-002` recommends online `gp2 -> gp3` upgrades exclusively for active `in-use` `gp2` volumes that are not already attached to long-stopped zombie instances slated for termination.

4. **Output Safety**
   - HTML reporting applies strict `html.escape(..., quote=True)` across every dynamic attribute and text node to neutralize stored XSS from untrusted AWS tags, bucket names, or descriptions.
   - CSV reporting neutralizes spreadsheet formula injection (`=`, `+`, `-`, `@`, `\t`, `\r`).
