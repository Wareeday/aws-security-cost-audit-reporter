# Audit Rules Catalog

## Security & Compliance Rules (`SEC-*`)

| Rule ID | Default Severity | Resource Type | Compliance Mapping | Description |
| :--- | :---: | :--- | :--- | :--- |
| `SEC-NET-001` | CRITICAL | `AWS::EC2::SecurityGroup` | CIS 5.2, 5.3; FSBP EC2.19 | Security Group allows all protocols (`-1`) or all ports (`0-65535`) from `0.0.0.0/0` or `::/0`. |
| `SEC-NET-002` | CRITICAL / HIGH | `AWS::EC2::SecurityGroup` | CIS 5.2, 5.3; FSBP EC2.19 | Security Group exposes sensitive management or database ports to the internet. |
| `SEC-NET-003` | MEDIUM | `AWS::EC2::SecurityGroup` | CIS 5.4; FSBP EC2.2 | Default VPC Security Group retains active ingress or egress rules. |
| `SEC-NET-004` | HIGH | `AWS::EC2::VPC` | CIS 3.9; FSBP EC2.6 | VPC Flow Logs are disabled on a VPC. |
| `SEC-NET-005` | HIGH / MEDIUM | `AWS::EC2::Instance` | FSBP EC2.8 | Running/stopped EC2 instance does not enforce IMDSv2 (`HttpTokens=required`). |
| `SEC-NET-006` | CRITICAL | `AWS::RDS::DBInstance` | CIS 2.3.3; FSBP RDS.2 | RDS database instance has `PubliclyAccessible=true`. |
| `SEC-IAM-001` | CRITICAL | `AWS::IAM::RootAccount` | CIS 1.5; FSBP IAM.9 | Root account MFA is not enabled. |
| `SEC-IAM-002` | CRITICAL | `AWS::IAM::RootAccount` | CIS 1.4; FSBP IAM.4 | Active API access keys exist on the root user. |
| `SEC-IAM-003` | HIGH | `AWS::IAM::User` | CIS 1.10; FSBP IAM.5 | Console-enabled IAM user does not have MFA enrolled. |
| `SEC-IAM-004` | MEDIUM / HIGH | `AWS::IAM::AccessKey` | CIS 1.14; FSBP IAM.3 | Active IAM access key exceeds age threshold (`>90d` MEDIUM, `>=180d` HIGH). |
| `SEC-IAM-005` | MEDIUM | `AWS::IAM::AccessKey` | CIS 1.12; FSBP IAM.22 | Active IAM access key has never been used (`>30d` old) or is dormant (`>90d` idle). |
| `SEC-IAM-006` | MEDIUM | `AWS::IAM::PasswordPolicy` | CIS 1.8, 1.9; FSBP IAM.7 | Account password policy is missing or fails length, complexity, age, or reuse checks. |
| `SEC-IAM-007` | HIGH | `AWS::IAM::User` | CIS 1.15, 1.16; FSBP IAM.1 | IAM user has direct inline policies or broad admin managed policies (`AdministratorAccess`, etc.). |
| `SEC-STG-001` | HIGH | `AWS::S3::Bucket` | CIS 2.1.4; FSBP S3.8 | S3 Block Public Access is incomplete or disabled. |
| `SEC-STG-002` | MEDIUM | `AWS::S3::Bucket` | CIS 2.1.1; FSBP S3.4 | Explicit S3 bucket server-side encryption rule is missing. |
| `SEC-STG-003` | LOW | `AWS::S3::Bucket` | FSBP S3.14 | S3 bucket versioning is disabled or suspended. |
| `SEC-STG-004` | HIGH | `AWS::EC2::Volume` | CIS 2.2.1; FSBP EC2.7 | EBS volume is not encrypted at rest. |
| `SEC-STG-005` | HIGH | `AWS::RDS::DBInstance` | CIS 2.3.1; FSBP RDS.3 | RDS database storage encryption is disabled. |
| `SEC-LOG-001` | CRITICAL | `AWS::CloudTrail::Trail` | CIS 3.1; FSBP CloudTrail.1 | No active multi-region CloudTrail trail is logging events. |
| `SEC-LOG-002` | MEDIUM | `AWS::CloudTrail::Trail` | CIS 3.2; FSBP CloudTrail.4 | CloudTrail log file integrity validation is disabled. |
| `SEC-LOG-003` | LOW | `AWS::Logs::LogGroup` | Well-Architected SUS04 | CloudWatch Log Group has no retention expiration configured. |

## FinOps Cost Optimization Rules (`FIN-*`)

| Rule ID | Default Pricing Basis (`us-east-1`) | Resource Type | Description |
| :--- | :--- | :--- | :--- |
| `FIN-EBS-001` | `gp3` \$0.08, `gp2` \$0.10, `io1/io2` \$0.125/GB-mo | `AWS::EC2::Volume` | Unattached (`available`) EBS volume incurring idle storage fees. |
| `FIN-EBS-002` | `gp2` -> `gp3` delta (\$0.02/GB-mo) | `AWS::EC2::Volume` | Active `in-use` `gp2` volume eligible for online `gp3` migration (~20% savings). |
| `FIN-EBS-003` | \$0.05/GB-mo (nominal volume size) | `AWS::EC2::Snapshot` | Aged (`>90d`) EBS snapshot not referenced by any registered AMI. |
| `FIN-NET-001` | \$3.65/mo (`$0.005/hr * 730h`) | `AWS::EC2::EIP` | Unassociated public IPv4 Elastic IP. |
| `FIN-NET-002` | \$32.85/mo (`$0.045/hr * 730h`) | `AWS::EC2::NatGateway` | Available NAT Gateway with zero traffic over 7 days. |
| `FIN-NET-003` | \$16.43/mo ALB / \$18.25/mo CLB | `AWS::ElasticLoadBalancingV2::LoadBalancer` | Provisioned load balancer with zero registered targets. |
| `FIN-EC2-001` | Sum of attached EBS volume rates | `AWS::EC2::Instance` | EC2 instance stopped `>30d` while attached EBS volumes remain billed. |
| `FIN-LOG-001` | \$0.03/GB-mo stored logs | `AWS::Logs::LogGroup` | CloudWatch Log Group with infinite retention and material stored log bytes. |
