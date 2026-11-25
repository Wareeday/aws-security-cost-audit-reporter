# AWS Security & Cost Audit Reporter

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=githubactions&logoColor=white)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-16a34a)](pyproject.toml)
[![Output](https://img.shields.io/badge/Reports-HTML%20%7C%20MD%20%7C%20CSV%20%7C%20JSON%20%7C%20SARIF-0f172a)](#reporting-outputs)

A production-grade, **strictly read-only** AWS DevSecOps and FinOps auditing engine that evaluates cloud posture across **29 security, compliance, and cost-optimization rules**, scores overall security posture (`0–100`, Grade `A–F`), supports **time-bound risk waivers**, and generates **Markdown, interactive HTML, Excel-safe CSV, JSON, and SARIF v2.1.0** reports.

Designed around a **snapshot-first architecture**, the engine runs completely offline for CI validation and reproducible audits, or queries live multi-region AWS accounts via paginated `boto3` collectors and cross-account `STS AssumeRole`.

---

## Key Capabilities

- **21 Security & Compliance Controls (`SEC-*`)** mapped to **CIS AWS Foundations Benchmark v3.0** and **AWS Foundational Security Best Practices (FSBP)**:
  - **Network & Compute:** Unrestricted `0.0.0.0/0` / `::/0` Security Group ingress, sensitive ports (`SSH`, `RDP`, `MySQL`, `PostgreSQL`, `MSSQL`, `Redis`, `MongoDB`, `Elasticsearch`, `Docker`, `VNC`, `Memcached`), non-empty default VPC Security Groups, VPC Flow Logs coverage, EC2 IMDSv2 enforcement, and public RDS exposure.
  - **IAM Governance:** Root account MFA & access keys, IAM account password policy compliance, console-user MFA detection (without false positives on programmatic service accounts), stale active key rotation (`>90d` / `>=180d`), dormant/unused keys, and direct inline or administrative user policies.
  - **Storage, Encryption & Audit Logging:** S3 Block Public Access, default S3 encryption, S3 versioning, EBS & RDS encryption at rest, multi-region CloudTrail logging & SHA-256 log file integrity validation, and CloudWatch Log Group retention governance.
- **8 FinOps Cost Optimization Rules (`FIN-*`)** using direct metadata pricing (avoiding `$0.01/request` Cost Explorer API overhead and eliminating double-counting between stopped-instance storage and `gp2 -> gp3` recommendations):
  - Unattached (`available`) EBS volumes (`gp3`, `gp2`, `io1/io2`, `st1`, `sc1`)
  - Online `gp2 -> gp3` migration opportunities (`~20%` storage savings)
  - Aged unreferenced EBS snapshots (`>90d`, excluding active AMI-backed snapshots)
  - Unassociated public IPv4 Elastic IPs (`$3.65/mo`)
  - Zero-traffic NAT Gateways (`$32.85/mo` via 7-day CloudWatch transfer metrics)
  - Idle Application / Network / Classic Load Balancers with zero targets (`$16.43–$18.25/mo`)
  - Long-stopped EC2 instances (`>30d`) retaining billed EBS storage
  - Unbounded CloudWatch Log Groups storing significant historical bytes
- **Enterprise Resilience & Governance:**
  - **Multi-Region & Cross-Account:** Concurrent regional scanning (`--regions`, `--all-regions`) and `STS AssumeRole` (`--role-arn`, `--external-id`) with adaptive `botocore` retries and full pagination.
  - **Fault Isolation:** `AccessDenied` on any optional service records a structured `CollectionWarning` in the output reports instead of aborting the audit.
  - **Time-Bound Risk Waivers:** Suppress approved exceptions via YAML or JSON regex rules with automatic re-opening after `expires_at`.
  - **CI/CD Policy Gates & SARIF:** Configurable `--fail-on` exit code (`2`) for pipeline enforcement and native **SARIF v2.1.0** export for GitHub Code Scanning / SIEM ingestion.
  - **Hardened Output Generation:** Strict `html.escape()` across all HTML report fields (preventing stored XSS via AWS tags/names) and spreadsheet formula neutralization in CSV exports.

---

## Architecture

```
+----------------------------+       +-------------------------------+       +-----------------------------+
| Telemetry Collection       |       | Policy & Evaluation Engine    |       | Multi-Format Outputs        |
+----------------------------+       +-------------------------------+       +-----------------------------+
| LiveAWSCollector (boto3)   |       | Security Rules  (SEC-*)       |       | Interactive HTML Dashboard  |
|  - STS AssumeRole / SSO    |       | FinOps Rules    (FIN-*)       |       | Executive Markdown Report   |
|  - Global (IAM, S3, STS)   | ----> | Policy Threshold Overrides    | ----> | Formula-Safe CSV Tracker    |
|  - Regional ThreadPool     |       | Expiring Waiver Filter        |       | Structured JSON (v2.0)      |
| Offline Snapshot JSON      |       | Posture Score (0-100, A-F)    |       | SARIF v2.1.0 (CI / GHAS)    |
+----------------------------+       +-------------------------------+       +-----------------------------+
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for collector isolation details, scoring math, and snapshot schema compatibility.

---

## Project Structure

```text
aws-security-cost-audit-reporter/
├── main.py                              # Zero-install CLI wrapper entrypoint
├── pyproject.toml                       # PEP 621 packaging, `aws-audit` console script, tool config
├── requirements.txt                     # Optional runtime deps (`boto3`, `PyYAML`)
├── requirements-dev.txt                 # Development & test dependencies
├── Dockerfile                           # Non-root production container image
├── iam/
│   └── readonly-audit-policy.json       # Least-privilege read-only AWS IAM policy
├── examples/
│   ├── audit-policy.yaml                # Custom thresholds, sensitive ports, and disabled rules
│   └── waivers.yaml                     # Time-bound risk-acceptance suppression policy
├── sample_data/
│   └── mock_aws_snapshot.json           # Multi-region v2.0 anonymized demonstration snapshot
├── docs/
│   ├── ARCHITECTURE.md                  # System architecture & scoring design
│   ├── IAM_PERMISSIONS.md               # IAM setup & cross-account AssumeRole guide
│   └── RULES_CATALOG.md                 # Full 29-rule security & FinOps catalog
├── src/aws_audit/
│   ├── cli.py                           # CLI parser, logging, and CI exit codes
│   ├── collector.py                     # Snapshot loader + paginated multi-region LiveAWSCollector
│   ├── config.py                        # Policy loader & expiring regex waiver engine
│   ├── models.py                        # Typed domain dataclasses (`Finding`, `AuditResult`, etc.)
│   ├── scoring.py                       # Posture scoring, compliance summary, and evaluation pipeline
│   ├── checks/                          # Modular rule suites (`security_*` and `cost_checks`)
│   └── reporters/                       # `html`, `markdown`, `csv`, `json`, and `sarif` writers
└── tests/                               # Unit & end-to-end test suite
```

---

## Quickstart

### 1. Run Offline Demo Audit (Zero AWS Account or Dependencies Required)

Offline `--mode demo` and `--mode snapshot` execute on pure Python 3.10+ standard library:

```bash
python3 main.py --mode demo --formats all --output-dir output
```

Expected console summary on the built-in multi-region demo snapshot:

```text
[AWS Audit] Account=123456789012 Regions=us-east-1,eu-central-1 Score=19/100 (F)
            Open=28 (CRIT=2, HIGH=8, MED=11, LOW=7) | Suppressed=0 | Warnings=0
            Estimated Savings=$117.93/mo ($1,415.16/yr)
            Markdown -> output/aws_audit_report.md
            HTML     -> output/aws_audit_report.html
            CSV      -> output/findings.csv
            JSON     -> output/aws_audit_report.json
            SARIF    -> output/findings.sarif
```

### 2. Install as a Package & Run Live Read-Only AWS Audit

```bash
pip install -e ".[all]"

# Scan specific regions using an AWS CLI profile
aws-audit --mode aws --profile readonly-auditor --regions us-east-1,eu-central-1

# Scan all enabled regions across an account via STS AssumeRole and archive snapshot
aws-audit \
  --mode aws \
  --role-arn arn:aws:iam::123456789012:role/SecurityCostAuditReadOnly \
  --external-id audit-readonly-2026 \
  --all-regions \
  --save-snapshot output/prod-snapshot.json \
  --formats all
```

### 3. Reproducible Offline Policy & CI Gate Evaluation

Capture once, then evaluate custom policies or waivers offline without additional AWS API calls:

```bash
aws-audit \
  --mode snapshot \
  --input-snapshot output/prod-snapshot.json \
  --config examples/audit-policy.yaml \
  --waivers examples/waivers.yaml \
  --fail-on HIGH \
  --formats md,html,sarif
```

### 4. Container Execution (Docker)

```bash
docker build -t aws-audit-reporter .
docker run --rm -v "$(pwd)/output:/app/output" aws-audit-reporter --mode demo --output-dir /app/output
```

---

## CLI Reference

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--mode {demo,aws,snapshot}` | Execution mode (`demo`, live `aws`, or offline `snapshot` JSON) | `demo` |
| `--input-snapshot PATH` | Input snapshot JSON path (`--mode snapshot` or custom demo) | `sample_data/mock_aws_snapshot.json` |
| `--save-snapshot PATH` | Save normalized collected snapshot JSON to disk | Disabled |
| `--region REGION` | Single AWS region in live mode | `us-east-1` |
| `--regions R1,R2` | Comma-separated AWS regions scanned concurrently | — |
| `--all-regions` | Auto-discover and scan all enabled AWS regions | `false` |
| `--profile NAME` | AWS CLI named profile | Default credential chain |
| `--role-arn ARN` | IAM Role ARN assumed via `sts:AssumeRole` | — |
| `--external-id ID` | Optional STS `ExternalId` for cross-account trust policies | — |
| `--config PATH` | Custom YAML/JSON thresholds, ports, pricing, and disabled rules | Built-in defaults |
| `--waivers PATH` | YAML/JSON risk-acceptance suppressions with optional `expires_at` | None |
| `--only {all,security,cost}` | Run security checks only, FinOps checks only, or both | `all` |
| `--min-severity {LOW,MEDIUM,HIGH,CRITICAL}` | Filter reported findings to a minimum severity | `LOW` |
| `--fail-on {NONE,LOW,MEDIUM,HIGH,CRITICAL}` | Exit with code `2` when open findings meet/exceed threshold | `NONE` |
| `--formats LIST` | Output formats: `md,html,csv,json,sarif,all` | `all` |
| `--output-dir DIR` | Destination directory for generated reports | `output` |
| `--json-logs` | Emit structured JSON logs to `stderr` | `false` |

---

## Reporting Outputs

| Artifact | Audience / Consumer | Highlights |
| :--- | :--- | :--- |
| `aws_audit_report.html` | Engineering & Leadership | Self-contained, print-ready (`@media print`) dashboard with live severity/category/region/text filtering and AWS CLI remediation commands. |
| `aws_audit_report.md` | PR Reviews & Runbooks | Executive posture score, compliance summary table, prioritized findings, and copyable remediation CLI quick reference. |
| `findings.csv` | FinOps & Tracking | Spreadsheet-safe CSV (`=,+,-,@` formula-escaped) with monthly/annualized savings and waiver status. |
| `aws_audit_report.json` | SIEM / SOAR / Automation | Schema-versioned (`2.0`) summary KPIs, findings, suppressed items, and `collection_warnings`. |
| `findings.sarif` | GitHub Code Scanning / DevSecOps | SARIF v2.1.0 payload with rule catalog metadata, `security-severity` scores, and logical AWS ARNs/IDs. |

---

## Least-Privilege IAM Setup & Rule Catalog

- **Least-Privilege Policy:** [iam/readonly-audit-policy.json](iam/readonly-audit-policy.json) grants strictly read-only permissions (`Describe*`, `List*`, `Get*`).
- **IAM & Cross-Account Guide:** [docs/IAM_PERMISSIONS.md](docs/IAM_PERMISSIONS.md)
- **Full 29-Rule Catalog & Pricing Basis:** [docs/RULES_CATALOG.md](docs/RULES_CATALOG.md)

---

## Testing & Verification

Run the automated test suite via either `pytest` or standard-library `unittest`:

```bash
pytest
# or without extra test dependencies:
python3 -m unittest discover -s tests -v
```

Automated CI validation is configured in [.github/workflows/ci.yml](.github/workflows/ci.yml) across Python `3.10`, `3.11`, and `3.12`.
# aws-security-cost-audit-reporter
