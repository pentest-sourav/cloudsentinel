<!-- # CloudSentinel

**Multi-Cloud Security Posture & Compliance Auditor**

CloudSentinel is an open-source security auditing platform designed to discover cloud resources, evaluate security configurations, generate security findings, calculate contextual risk, and map findings to compliance controls.

> **Project status:** Active development  
> CloudSentinel is currently a production-oriented foundation, not a production-complete enterprise CSPM platform.

---

## Overview

Cloud environments contain many resources, identities, network configurations, storage services, and workloads.

A single security misconfiguration can create unnecessary exposure.

CloudSentinel aims to automate cloud security assessment through a structured pipeline:

```text
Cloud Account / IaC
        ↓
Asset Discovery
        ↓
Configuration Collection
        ↓
Security Rules
        ↓
Findings Engine
        ↓
Risk Assessment
        ↓
Compliance Mapping
        ↓
Reports / Dashboard
```
Risk scores are capped at `10` and converted into risk levels.
---

## Example Security Rules

| Rule ID | Check |
|---|---|
| `CS-AWS-EC2-001` | Public management access through Security Groups |
| `CS-AWS-EC2-002` | Public EC2 exposure |
| `CS-AWS-EC2-003` | IMDSv1 enabled |
| `CS-AWS-EC2-004` | Unencrypted EBS volume |
| `CS-AWS-EC2-005` | Public EBS snapshot |

The rule engine is registry-driven so that security rules can be added without tightly coupling them to the scanner implementation.

---

## Architecture

```text
                    CloudSentinel
                         │
             ┌───────────┴───────────┐
             │                       │
            AWS                    Azure
             │                       │
             └───────────┬───────────┘
                         ↓
                  Asset Discovery
                         ↓
                Data Normalization
                         ↓
                  Rule Registry
                         ↓
                  Rule Executor
                         ↓
                 Findings Engine
                         ↓
                 Risk Assessment
                         ↓
              Compliance Mapping
                         ↓
              Database / Reporting
                         ↓
                  API / Dashboard
```
---

## API

The backend exposes a REST API.

Current API areas include:

```text
/api/v1/scans
/api/v1/findings
```

---

## Roadmap

### Cloud Providers

- [x] AWS foundation
- [ ] Expanded AWS service coverage
- [ ] Azure security scanning
- [ ] Multi-account AWS scanning
- [ ] Multi-subscription Azure scanning

### Security Rules

- [x] EC2 security group exposure
- [x] Public EC2 detection
- [x] IMDSv1 detection
- [x] EBS encryption detection
- [x] Public EBS snapshot detection
- [x] S3 security checks
- [x] IAM security checks
- [ ] RDS security rules
- [ ] Lambda security rules
- [ ] KMS security rules
- [ ] CloudTrail security rules
- [ ] VPC security rules
- [ ] Azure equivalent rules

### Risk & Compliance

- [x] Contextual risk scoring
- [x] Risk levels
- [x] Evidence collection
- [x] CIS mapping foundation
- [ ] Expanded CIS coverage
- [ ] NIST mapping
- [ ] PCI DSS mapping
- [ ] Custom compliance frameworks

### Platform

- [x] FastAPI backend
- [x] PostgreSQL persistence
- [x] Scan history
- [x] Finding API
- [ ] Next.js dashboard
- [ ] HTML reports
- [ ] PDF reports
- [ ] Scheduled scans
- [ ] Historical configuration comparison
- [ ] Finding deduplication
- [ ] Notification integrations

### Infrastructure

- [x] Docker foundation
- [x] Automated tests
- [ ] CI/CD security gates
- [ ] Container security scanning
- [ ] IaC policy enforcement

---

## Design Goals

CloudSentinel is being built around several principles.

### 1. Read-only by default

Cloud auditing should not unexpectedly modify customer infrastructure.

### 2. Evidence-driven findings

Every finding should explain why it was generated and provide machine-readable evidence.

### 3. Context-aware risk

A finding's severity alone does not always represent its actual risk.

CloudSentinel therefore considers additional context such as:

- Internet exposure
- Asset criticality
- Sensitive data indicators
- Exploitability

### 4. Extensible rule engine

Security checks should be independently testable and easy to extend.

### 5. Provider normalization

Different cloud providers expose different APIs.

CloudSentinel aims to normalize provider-specific data before security rules evaluate it.

---

## Project Status

CloudSentinel is an active development project.

The current implementation provides a working foundation for:

- AWS resource discovery
- Security configuration analysis
- Rule-driven scanning
- Finding persistence
- Risk assessment
- Scan history
- Automated testing

The platform is **not yet intended to replace a mature commercial CSPM product**.

---

## Contributing

Contributions, ideas, security improvements, and new detection rules are welcome.

Before submitting a pull request:

```bash
pytest -q
git diff --check
```

Please read `CONTRIBUTING.md` for contribution guidelines.

---

## Security

If you discover a security vulnerability in CloudSentinel, please follow the responsible disclosure process described in `SECURITY.md`.

---

## License

See `LICENSE` for the project's licensing terms. -->














# CloudSentinel

> **Multi-Cloud Security Posture & Compliance Auditor**

CloudSentinel is a production-oriented cloud security posture and compliance auditing platform designed to discover cloud resources, evaluate security configurations, detect misconfigurations, generate evidence-driven security findings, assess contextual risk, and map security findings to compliance controls.

The project is being developed with an extensible architecture for AWS, Azure, and Infrastructure-as-Code security assessment.

---

## Project Status

**Status:** Active Development
**Current Primary Provider:** AWS
**Current AWS Security Rules:** **88**
**Current AWS Security Domains:** **8**

CloudSentinel has progressed beyond a basic proof-of-concept or simple collection of security scripts.

The current implementation focuses on building a reliable security-engineering foundation with:

- [x] AWS provider architecture
- [x] AWS resource discovery
- [x] Multi-service AWS security scanning
- [x] Registry-driven security rules
- [x] Service and collector separation
- [x] Normalized security data
- [x] Evidence-driven findings
- [x] Severity classification
- [x] Contextual risk assessment
- [x] CIS compliance mapping foundation
- [x] Finding persistence
- [x] Scan history
- [x] REST APIs
- [x] Worker-based scan execution
- [x] Automated regression testing

The project is intentionally focused on **quality of detection and architecture**, rather than increasing the rule count without meaningful security value.

---

# Overview

Cloud environments contain large numbers of resources, identities, permissions, network configurations, storage systems, databases, serverless workloads, encryption keys, and logging configurations.

A single insecure configuration can expose sensitive resources, increase attack surface, create privilege escalation opportunities, or reduce visibility during a security incident.

CloudSentinel aims to automate the security assessment of these environments.

The core workflow is:

```text
Cloud Account / IaC
        |
        v
Asset Discovery
        |
        v
Configuration Collection
        |
        v
Data Normalization
        |
        v
Security Rule Registry
        |
        v
Rule Execution
        |
        v
Security Findings
        |
        v
Risk Assessment
        |
        v
Compliance Mapping
        |
        v
Persistence
        |
        +-------------------+
        |                   |
        v                   v
       API              Reporting
```

The core philosophy is:

> **Discover → Normalize → Evaluate → Explain → Persist**

---

# Key Objectives

CloudSentinel is designed to provide:

- Cloud asset discovery
- Security posture assessment
- Misconfiguration detection
- Identity and access security analysis
- Network security analysis
- Storage security analysis
- Database security analysis
- Serverless security analysis
- Encryption security analysis
- Audit logging assessment
- Risk prioritization
- Compliance mapping
- Evidence-backed findings
- API-based security results
- Scan history
- Extensible provider architecture
- Future multi-cloud security assessment
- Future Infrastructure-as-Code security assessment

---

# Current AWS Security Coverage

CloudSentinel currently contains **88 AWS security rules** across eight major AWS security domains.

| AWS Service | Rules | Status |
|---|---:|:---:|
| EC2 | 10 | [x] |
| IAM | 38 | [x] |
| S3 | 8 | [x] |
| RDS | 8 | [x] |
| Lambda | 6 | [x] |
| KMS | 3 | [x] |
| VPC | 5 | [x] |
| CloudTrail | 10 | [x] |
| **Total** | **88** | **[x]** |

---

# AWS Security Coverage Overview

```text
AWS Security
|
+-- EC2
|     |
|     +-- Compute security
|     +-- Instance hardening
|     +-- Metadata service security
|     +-- EBS security
|     +-- Snapshot exposure
|     +-- Network exposure
|     +-- Resource hygiene
|
+-- IAM
|     |
|     +-- Identity security
|     +-- Credential security
|     +-- Password policy
|     +-- Policy security
|     +-- Privilege management
|     +-- Role trust
|     +-- Access Analyzer
|
+-- S3
|     |
|     +-- Public access
|     +-- Access control
|     +-- Bucket policies
|     +-- Encryption
|     +-- Versioning
|     +-- Logging
|     +-- Object protection
|
+-- RDS
|     |
|     +-- Public exposure
|     +-- Encryption
|     +-- Backups
|     +-- Availability
|     +-- Deletion protection
|     +-- Authentication
|     +-- Monitoring
|
+-- Lambda
|     |
|     +-- Function exposure
|     +-- Resource policies
|     +-- Runtime security
|     +-- VPC configuration
|     +-- Network architecture
|     +-- Tracing
|
+-- KMS
|     |
|     +-- Key rotation
|     +-- Key lifecycle
|     +-- Key policies
|
+-- VPC
|     |
|     +-- VPC architecture
|     +-- Internet gateways
|     +-- Security groups
|     +-- Flow logs
|     +-- Network ACLs
|
+-- CloudTrail
      |
      +-- Audit visibility
      +-- Logging configuration
      +-- Encryption
      +-- CloudTrail Lake
      +-- Event data store security
```

---

# Architecture

CloudSentinel follows a layered architecture designed to keep cloud-provider communication separate from security detection logic.

```text
+------------------------------------------------------+
|                 API / Frontend Layer                 |
+------------------------------------------------------+
                         |
                         v
+------------------------------------------------------+
|              Application / Service Layer             |
+------------------------------------------------------+
                         |
                         v
+------------------------------------------------------+
|                 Scan / Worker Layer                  |
+------------------------------------------------------+
                         |
                         v
+------------------------------------------------------+
|                 Security Rule Engine                 |
+------------------------------------------------------+
                         |
                         v
+------------------------------------------------------+
|              Collectors / Normalization              |
+------------------------------------------------------+
                         |
                         v
+------------------------------------------------------+
|              Cloud Provider Services                 |
+------------------------------------------------------+
                         |
                         v
+------------------------------------------------------+
|                  Cloud Provider API                  |
+------------------------------------------------------+
```

The architecture follows the principle:

> **Provider-specific implementation should remain isolated from generic security evaluation whenever possible.**

---

# End-to-End Scan Flow

A complete security scan follows this general flow:

```text
                    Scan Request
                         |
                         v
                Provider Initialization
                         |
                         v
                   Asset Discovery
                         |
                         v
               Service API Collection
                         |
                         v
                  Data Normalization
                         |
                         v
                   Rule Registry
                         |
                         v
                   Rule Execution
                         |
                         v
                 Security Findings
                         |
              +----------+----------+
              |                     |
              v                     v
        Risk Assessment      Compliance Mapping
              |                     |
              +----------+----------+
                         |
                         v
                   Persistence
                         |
              +----------+----------+
              |                     |
              v                     v
             API                Reporting
```

---

# Provider Architecture

The provider layer is responsible for cloud-provider communication.

For AWS, this includes:

- AWS session initialization
- Credential handling
- Regional configuration
- AWS client access
- Account context
- Provider-level configuration

The provider layer should not contain security detection logic.

Its purpose is to provide a reliable interface to the cloud environment.

---

# AWS Service Layer

AWS service modules encapsulate provider API operations.

Examples include:

```text
scanner/aws/services/

    ec2.py
    iam.py
    s3.py
    rds.py
    lambda_service.py
    kms.py
    vpc.py
    cloudtrail.py
```

The service layer is responsible for:

- Listing resources
- Fetching resource configuration
- Retrieving security-relevant metadata
- Encapsulating AWS SDK calls
- Handling provider-specific API behavior
- Providing reusable service operations to collectors

Security rules should avoid directly depending on raw AWS SDK calls.

---

# Collector Layer

Collectors sit between service APIs and security rules.

Their responsibility is to gather the data required by security checks and normalize it into predictable structures.

```text
AWS API
   |
   v
AWS Service
   |
   v
Collector
   |
   v
Normalized Security Data
   |
   +------> Rule A
   |
   +------> Rule B
   |
   +------> Rule C
```

Collectors can also reuse common data across multiple rules to reduce unnecessary API requests.

---

# Data Normalization

Cloud provider APIs frequently expose complex provider-specific structures.

CloudSentinel therefore separates provider response handling from rule logic.

```text
Provider API Response
        |
        v
Provider-specific structure
        |
        v
Collector normalization
        |
        v
Security-oriented data
        |
        v
Rule evaluation
```

This approach makes security rules easier to understand, test, and maintain.

It also provides a foundation for future multi-cloud support.

---

# Security Rule Engine

CloudSentinel uses a registry-driven rule architecture.

Security rules are not simply embedded inside scanner code.

Instead, rules are represented through structured definitions and registered with the relevant service.

Conceptually:

```text
                  Rule Registry
                        |
                        v
                 Rule Definition
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
      Data Source   Check Logic   Finding Builder
          |             |             |
          +-------------+-------------+
                        |
                        v
                  Rule Executor
                        |
                        v
                     Finding
```

A security rule can contain:

- Rule ID
- Rule name
- Security description
- Severity
- Data source
- Collection requirements
- Detection logic
- Evidence
- Remediation guidance
- Compliance references

---

# Rule Design Philosophy

A security rule should answer:

```text
What configuration is insecure?
            |
            v
Why is it insecure?
            |
            v
Which resource is affected?
            |
            v
What evidence proves the condition?
            |
            v
How should it be remediated?
```

A rule should not simply return:

```text
True
```

or:

```text
False
```

The objective is to produce an actionable finding.

---

# Finding Model

CloudSentinel follows an evidence-driven finding model.

A finding can contain:

- Rule ID
- Finding title
- Severity
- Provider
- Account context
- Resource type
- Resource ID
- Resource name
- Description
- Security impact
- Evidence
- Remediation guidance
- Compliance references
- Risk information

Conceptually:

```text
                       Finding
                          |
        +-----------------+-----------------+
        |                 |                 |
        v                 v                 v
    Identity           Evidence         Severity
        |
        +-- Rule ID
        +-- Provider
        +-- Account
        +-- Resource
        |
        v
   Security Impact
        |
        v
    Remediation
        |
        v
    Compliance
```

---

# Evidence-Driven Findings

A finding should explain exactly why the resource was detected.

For example:

```text
Finding
|
+-- Rule: CS-AWS-VPC-005
|
+-- Resource: Network ACL
|
+-- Resource ID: acl-xxxxxxxx
|
+-- Direction: INBOUND
|
+-- Protocol: ALL
|
+-- Source: 0.0.0.0/0
|
+-- Action: ALLOW
|
+-- Severity: MEDIUM
|
+-- Remediation:
      Restrict the rule to only required traffic sources
```

This provides significantly more useful information than:

```text
Network ACL is insecure.
```

---

# Risk Assessment

CloudSentinel separates **security detection** from **risk prioritization**.

A rule identifies a security condition.

The risk engine provides additional context.

```text
Security Rule
      |
      v
Detected Issue
      |
      v
Risk Assessment
      |
      +-- Exposure
      +-- Asset Context
      +-- Security Impact
      +-- Other Context
      |
      v
Risk Score / Risk Level
```

This separation allows detection and prioritization to evolve independently.

---

# Severity vs Risk

CloudSentinel treats severity and risk as related but distinct concepts.

```text
Severity
    |
    +-- How serious is the security condition?
    |
    v
Security Finding


Risk
    |
    +-- How important is this issue in its current context?
    |
    v
Risk Prioritization
```

This distinction becomes increasingly important in large environments containing many findings.

---

# Compliance Architecture

Compliance mapping is implemented as a separate layer from security detection.

```text
Security Rule
      |
      v
Security Finding
      |
      +-----------------------+
      |                       |
      v                       v
CIS Mapping           Future Frameworks
                              |
                              +-- NIST
                              +-- PCI DSS
                              +-- Custom Frameworks
```

This allows one security rule to map to multiple frameworks without duplicating the underlying detection logic.

---

# Current Compliance Status

### Implemented

- [x] CIS mapping foundation
- [x] Finding-level compliance references
- [x] Compliance metadata architecture

### Planned

- [ ] Expanded CIS coverage
- [ ] NIST mapping
- [ ] PCI DSS mapping
- [ ] Custom compliance frameworks
- [ ] Compliance coverage reports
- [ ] Compliance dashboards
- [ ] Framework-specific scoring

---

# EC2 Security Coverage

CloudSentinel currently contains **10 EC2 security rules**.

The EC2 domain focuses on compute security, instance hardening, storage protection, exposure detection, and resource hygiene.

## EC2 Coverage Areas

```text
EC2
|
+-- Compute Security
|
+-- Instance Hardening
|
+-- Metadata Service Security
|
+-- EBS Security
|
+-- Snapshot Security
|
+-- Network Exposure
|
+-- Network Interface Hygiene
|
+-- Elastic IP Hygiene
|
+-- Instance Lifecycle
```

## EC2 Rule Status

- [x] `CS-AWS-EC2-001`
- [x] `CS-AWS-EC2-002`
- [x] `CS-AWS-EC2-003`
- [x] `CS-AWS-EC2-004`
- [x] `CS-AWS-EC2-005`
- [x] `CS-AWS-EC2-006`
- [x] `CS-AWS-EC2-007`
- [x] `CS-AWS-EC2-008`
- [x] `CS-AWS-EC2-009`
- [x] `CS-AWS-EC2-010`

---

# IAM Security Coverage

IAM is currently the largest security domain in CloudSentinel.

Current coverage:

> **38 IAM security rules**

IAM security is divided into:

```text
IAM
|
+-- Authentication
|
+-- Credentials
|
+-- Password Policy
|
+-- Permission Security
|
+-- Privilege Management
|
+-- Role Trust
|
+-- Cross-Account Security
|
+-- Access Analyzer
```

---

## IAM Authentication & Credential Security

- [x] `CS-AWS-IAM-001` - Root MFA
- [x] `CS-AWS-IAM-002` - User MFA
- [x] `CS-AWS-IAM-003` - Access key age
- [x] `CS-AWS-IAM-004` - Inactive access key
- [x] `CS-AWS-IAM-011` - Unused console password
- [x] `CS-AWS-IAM-017` - Multiple active access keys
- [x] `CS-AWS-IAM-018` - Multiple authentication methods
- [x] `CS-AWS-IAM-019` - Access key never used
- [x] `CS-AWS-IAM-020` - No active authentication credential
- [x] `CS-AWS-IAM-021` - Root access key
- [x] `CS-AWS-IAM-023` - Stale IAM user

---

## IAM Password Policy Security

- [x] `CS-AWS-IAM-005` - Minimum password length
- [x] `CS-AWS-IAM-006` - Password symbols
- [x] `CS-AWS-IAM-007` - Password numbers
- [x] `CS-AWS-IAM-008` - Password uppercase
- [x] `CS-AWS-IAM-009` - Password lowercase
- [x] `CS-AWS-IAM-010` - Password reuse

---

## IAM Policy Security

- [x] `CS-AWS-IAM-012` - Broad user policy
- [x] `CS-AWS-IAM-013` - Broad group policy
- [x] `CS-AWS-IAM-014` - Broad user inline policy
- [x] `CS-AWS-IAM-015` - Broad group inline policy
- [x] `CS-AWS-IAM-016` - Broad action with restricted resource
- [x] `CS-AWS-IAM-022` - User-attached policy
- [x] `CS-AWS-IAM-024` - Sensitive credential action
- [x] `CS-AWS-IAM-025` - Administrative user policy
- [x] `CS-AWS-IAM-026` - Administrative group policy
- [x] `CS-AWS-IAM-027` - Privilege management action
- [x] `CS-AWS-IAM-028` - PassRole wildcard resource
- [x] `CS-AWS-IAM-029` - Service wildcard action
- [x] `CS-AWS-IAM-030` - NotAction wildcard resource
- [x] `CS-AWS-IAM-031` - NotResource broad action

---

## IAM Privilege & Trust Security

- [x] `CS-AWS-IAM-032` - Privileged user without permissions boundary
- [x] `CS-AWS-IAM-033` - Wildcard role trust principal
- [x] `CS-AWS-IAM-034` - Self-modifiable IAM policy
- [x] `CS-AWS-IAM-035` - Cross-account trust without condition
- [x] `CS-AWS-IAM-036` - IAM Access Analyzer security warning
- [x] `CS-AWS-IAM-037` - Cross-account role trust
- [x] `CS-AWS-IAM-038` - Privileged role without permissions boundary

---

# IAM Security Architecture

```text
                         IAM
                          |
          +---------------+---------------+
          |               |               |
          v               v               v
      Identity         Policies          Roles
          |               |               |
          v               v               v
     Credentials      Permissions        Trust
          |               |               |
          +---------------+---------------+
                          |
                          v
                   Security Findings
```

IAM receives significant coverage because identity and authorization misconfigurations can have broad impact across cloud environments.

---

# S3 Security Coverage

CloudSentinel currently contains **8 S3 security rules**.

The S3 security domain focuses on:

```text
S3
|
+-- Public Exposure
|
+-- Access Control
|
+-- Bucket Policies
|
+-- ACL Configuration
|
+-- Encryption
|
+-- Versioning
|
+-- Logging
|
+-- Object Protection
```

## S3 Status

- [x] S3 service integration
- [x] S3 resource collection
- [x] S3 security rule registry
- [x] S3 security checks
- [x] S3 tests
- [x] S3 scanner integration

---

# RDS Security Coverage

CloudSentinel currently contains **8 RDS security rules**.

The RDS domain focuses on:

```text
RDS
|
+-- Public Exposure
|
+-- Storage Encryption
|
+-- Backup Configuration
|
+-- Availability
|
+-- Deletion Protection
|
+-- Maintenance
|
+-- Authentication
|
+-- Monitoring
```

## RDS Status

- [x] RDS service integration
- [x] RDS resource collection
- [x] RDS security rule registry
- [x] RDS security checks
- [x] RDS tests
- [x] RDS scanner integration

---

# Lambda Security Coverage

CloudSentinel currently contains **6 Lambda security rules**.

The Lambda domain focuses on:

```text
Lambda
|
+-- Function Exposure
|
+-- Resource Policies
|
+-- Runtime Security
|
+-- VPC Configuration
|
+-- Network Architecture
|
+-- Tracing
```

## Lambda Status

- [x] Lambda service integration
- [x] Lambda resource collection
- [x] Lambda security rule registry
- [x] Lambda security checks
- [x] Lambda tests
- [x] Lambda scanner integration

---

# KMS Security Coverage

CloudSentinel currently contains **3 KMS security rules**.

The KMS domain focuses on:

```text
KMS
|
+-- Key Rotation
|
+-- Key Lifecycle
|
+-- Key Policy Security
```

## KMS Status

- [x] KMS service integration
- [x] KMS resource collection
- [x] KMS security rule registry
- [x] KMS security checks
- [x] KMS tests

---

# VPC Security Coverage

CloudSentinel currently contains **5 VPC security rules**.

The VPC security domain focuses on:

```text
VPC
|
+-- VPC Architecture
|
+-- Internet Gateways
|
+-- Security Groups
|
+-- Flow Logs
|
+-- Network ACLs
```

## VPC Status

- [x] VPC service integration
- [x] VPC resource collection
- [x] VPC security rule registry
- [x] VPC security checks
- [x] VPC tests
- [x] VPC scanner integration

---

# Network ACL Security

CloudSentinel includes a security rule for detecting unrestricted Network ACL exposure.

The detection focuses on non-default Network ACL entries that allow:

```text
ALLOW
  +
ALL PROTOCOLS
  +
0.0.0.0/0
        OR
::/0
```

The rule evaluates:

- [x] Inbound rules
- [x] Outbound rules
- [x] IPv4 unrestricted access
- [x] IPv6 unrestricted access
- [x] All-protocol rules
- [x] Non-default Network ACLs

Default Network ACLs are intentionally excluded from this specific detection to reduce unnecessary noise.

Finding evidence can include:

- Network ACL ID
- VPC ID
- Rule number
- Direction
- Protocol
- IPv4 CIDR
- IPv6 CIDR
- Rule action

---

# CloudTrail Security Coverage

CloudSentinel currently contains **10 CloudTrail security rules**.

CloudTrail security focuses on audit visibility and protection of cloud activity logging.

Major areas include:

```text
CloudTrail
|
+-- Logging
|
+-- Trail Configuration
|
+-- Audit Visibility
|
+-- Encryption
|
+-- CloudTrail Lake
|
+-- Event Data Store Security
```

## CloudTrail Status

- [x] CloudTrail service integration
- [x] CloudTrail resource collection
- [x] CloudTrail security rule registry
- [x] CloudTrail security checks
- [x] CloudTrail tests
- [x] CloudTrail Lake coverage
- [x] Event data store encryption coverage

---

# AWS Rule Count Summary

```text
EC2         10
IAM         38
S3           8
RDS          8
Lambda       6
KMS          3
VPC          5
CloudTrail  10
----------------
TOTAL       88
```

The number of rules is treated as a coverage metric, not as the primary measure of project quality.

---

# Backend Architecture

CloudSentinel contains a backend responsible for exposing scanning and finding functionality through APIs and coordinating scan execution.

The backend follows a service-oriented architecture.

```text
API Routes
    |
    v
Application Services
    |
    v
Scan / Worker
    |
    v
Security Engine
    |
    v
Findings
    |
    v
Persistence
```

---

# Backend Components

The backend contains:

```text
backend/
|
+-- app/
|   |
|   +-- api/
|   +-- core/
|   +-- models/
|   +-- schemas/
|   +-- services/
|
+-- worker.py
```

Responsibilities include:

- API request handling
- Application service logic
- Scan coordination
- Finding persistence
- Scan persistence
- Worker execution
- API response schemas

---

# API

Current API areas include:

```text
/api/v1/scans
/api/v1/findings
```

The API architecture follows:

```text
HTTP Request
     |
     v
API Route
     |
     v
Service Layer
     |
     +----------------+
     |                |
     v                v
Scanner           Database
     |
     v
Findings
```

The API layer is intended to remain thin.

Business logic belongs in application services instead of being duplicated across route handlers.

---

# Scan Lifecycle

A scan follows this general lifecycle:

```text
Scan Request
     |
     v
Create Scan
     |
     v
Initialize Provider
     |
     v
Discover Resources
     |
     v
Collect Configuration
     |
     v
Execute Rules
     |
     v
Generate Findings
     |
     v
Calculate Risk
     |
     v
Map Compliance
     |
     v
Persist Results
     |
     v
Complete Scan
```

---

# Worker Architecture

Long-running cloud scans should not block API requests.

CloudSentinel therefore includes worker-oriented scan execution.

```text
API
 |
 | Start Scan
 v
Scan Record
 |
 v
Worker
 |
 v
Provider Scan
 |
 v
Security Engine
 |
 v
Findings
 |
 v
Persistence
```

This provides a foundation for future:

- Scheduled scanning
- Queue-based execution
- Distributed workers
- Retry handling
- Large-account scanning
- Continuous monitoring

---

# Persistence

CloudSentinel maintains persistence for security assessment data.

Current platform capabilities include:

- [x] Finding persistence
- [x] Scan persistence
- [x] Scan history
- [x] Finding API access
- [x] Scan API access

Future persistence improvements include:

- [ ] Finding state tracking
- [ ] Finding deduplication
- [ ] Historical comparison
- [ ] Remediation tracking
- [ ] Configuration drift tracking

---

# Scan History

Scan history provides the foundation for tracking security posture over time.

```text
Scan 001
   |
   v
Scan 002
   |
   v
Scan 003
   |
   v
Security Posture Trend
```

Future scan-history capabilities can include:

- New findings
- Resolved findings
- Persistent findings
- Risk trends
- Compliance trends
- Configuration changes
- Drift detection

---

# Testing Strategy

Testing is a core part of CloudSentinel.

The test architecture covers multiple layers:

```text
                    Test Suite
                        |
        +---------------+---------------+
        |               |               |
        v               v               v
      Rules         Collectors       Services
        |               |               |
        +---------------+---------------+
                        |
                        v
                    Scanner
                        |
                        v
                     Backend
                        |
                        v
                 Full Regression
```

---

# Rule Testing

Security rules should test:

### Positive Cases

The rule detects an insecure configuration.

```text
Insecure Configuration
        |
        v
      Rule
        |
        v
Finding Generated
```

### Negative Cases

The rule does not report compliant configurations.

```text
Secure Configuration
        |
        v
      Rule
        |
        v
No Finding
```

### Edge Cases

Rules should consider cases such as:

- Empty collections
- Missing data
- Multiple resources
- Multiple policies
- Multiple statements
- Multiple principals
- Unexpected provider responses
- Resource-specific conditions

---

# Regression Testing

The complete test suite is used to ensure that security rule changes do not unexpectedly break existing services or backend functionality.

Current verified project state:

```text
1102 tests passed
1 warning
```

Run the complete test suite:

```bash
pytest -q
```

Before committing:

```bash
pytest -q
git diff --check
```

---

# Engineering Quality Gates

A new rule should not be considered complete simply because its main test passes.

Expected workflow:

```text
Implementation
      |
      v
Unit Tests
      |
      v
Integration Tests
      |
      v
Full Regression
      |
      v
Diff Review
      |
      v
Commit
```

---

# False Positive Reduction

CloudSentinel prioritizes detection quality.

A rule should not flag a resource merely because a configuration is unusual.

Detection should be based on an explicit security requirement.

For example:

```text
Weak Detection:

"Network ACL exists"


Better Detection:

"Non-default Network ACL allows all protocols
from the entire public IPv4 or IPv6 address space"
```

The second approach provides a clear security condition and reduces unnecessary findings.

---

# Evidence Quality

A useful finding should answer:

```text
What happened?
     |
     v
Which resource is affected?
     |
     v
Which configuration caused the issue?
     |
     v
Why is it a security concern?
     |
     v
What evidence supports the finding?
     |
     v
How should it be remediated?
```

---

# Remediation

Security findings should provide actionable remediation guidance.

The intended structure is:

```text
Detection
    |
    v
Evidence
    |
    v
Security Impact
    |
    v
Remediation
```

The remediation should be connected to the actual configuration that triggered the finding.

---

# Production-Oriented Engineering Principles

## 1. Separation of Concerns

Provider communication, data collection, security detection, risk calculation, compliance mapping, and persistence should remain separate.

```text
Provider
   !=
Collector
   !=
Rule
   !=
Risk Engine
   !=
Persistence
```

---

## 2. Provider Isolation

AWS-specific implementation should not unnecessarily leak into generic security logic.

Future providers should be able to implement their own:

```text
Provider
   |
   +-- Service Layer
   |
   +-- Collectors
   |
   +-- Registry
   |
   +-- Rules
```

while sharing common security concepts.

---

## 3. Evidence First

A security finding without evidence is difficult to investigate.

Therefore:

```text
Detection
    +
Evidence
    =
Useful Finding
```

---

## 4. Test Before Commit

Security rules should be backed by appropriate tests.

Expected:

```text
Rule
+
Positive Test
+
Negative Test
+
Edge Cases
+
Regression
```

---

## 5. Avoid Unnecessary Rule Expansion

CloudSentinel does not treat the raw number of rules as the primary measure of maturity.

The objective is:

```text
Meaningful Security Coverage
+
Reliable Detection
+
Strong Evidence
+
Low Noise
+
Maintainable Architecture
```

---

# Security Rule Development Workflow

The standard workflow for adding a new security rule is:

```text
1. Security Requirement
          |
          v
2. Identify Required Cloud Data
          |
          v
3. Check Existing Service APIs
          |
          v
4. Extend Service if Required
          |
          v
5. Extend Collector
          |
          v
6. Normalize Data
          |
          v
7. Implement Rule
          |
          v
8. Register Rule
          |
          v
9. Add Positive Tests
          |
          v
10. Add Negative Tests
          |
          v
11. Add Edge-Case Tests
          |
          v
12. Run Service Tests
          |
          v
13. Run Rule Tests
          |
          v
14. Run Full Regression
          |
          v
15. Review Git Diff
          |
          v
16. Commit
```

---

# Project Structure

```text
cloudsentinel/
|
+-- .github/
|   +-- workflows/
|
+-- backend/
|   +-- app/
|   |   +-- api/
|   |   +-- core/
|   |   +-- models/
|   |   +-- schemas/
|   |   +-- services/
|   |
|   +-- tests/
|   |
|   +-- worker.py
|
+-- database/
|
+-- demo-lab/
|
+-- docker/
|
+-- docs/
|
+-- engine/
|   +-- compliance/
|   +-- findings/
|   +-- risk/
|   +-- rules/
|
+-- frontend/
|
+-- reporting/
|   +-- generated/
|   +-- templates/
|
+-- scanner/
|   +-- aws/
|   |   +-- collectors/
|   |   +-- services/
|   |   +-- provider.py
|   |
|   +-- azure/
|   +-- common/
|   +-- terraform/
|
+-- tests/
|
+-- README.md
```

---

# Multi-Cloud Architecture

CloudSentinel is designed to support multiple cloud providers.

Current implementation maturity:

```text
AWS
 |
 +-- Provider        [x]
 +-- Services        [x]
 +-- Collectors      [x]
 +-- Rules           [x]
 +-- Findings        [x]
 +-- Risk            [x]
 +-- Compliance      [x]


Azure
 |
 +-- Provider        [ ]
 +-- Services        [ ]
 +-- Collectors      [ ]
 +-- Rules           [ ]
 +-- Findings        [ ]
 +-- Risk            [ ]
 +-- Compliance      [ ]
```

AWS is currently the primary implemented provider.

Azure is part of the planned multi-cloud architecture.

---

# Azure Roadmap

Planned Azure capabilities:

- [ ] Azure authentication/session layer
- [ ] Azure subscription discovery
- [ ] Azure resource discovery
- [ ] Azure service layer
- [ ] Azure collectors
- [ ] Azure normalized data
- [ ] Azure security rule registry
- [ ] Azure security rules
- [ ] Azure compliance mappings
- [ ] Multi-subscription scanning

The objective is to reuse the common security engine wherever practical rather than building a completely separate security platform.

---

# Infrastructure-as-Code Security

CloudSentinel includes a planned Infrastructure-as-Code security direction.

Target architecture:

```text
Terraform
    |
    v
IaC Parser
    |
    v
Normalized Configuration
    |
    v
Security Rules
    |
    v
Findings
```

Planned capabilities:

- [ ] Terraform scanning
- [ ] IaC resource discovery
- [ ] IaC misconfiguration detection
- [ ] Security policy checks
- [ ] CIS mapping
- [ ] IaC compliance mapping
- [ ] CI/CD integration

---

# DevSecOps Roadmap

Planned DevSecOps capabilities include:

- [x] Automated regression tests
- [ ] CI/CD security gates
- [ ] Terraform scanning
- [ ] Container scanning
- [ ] Dependency security checks
- [ ] Secret detection
- [ ] Security policy enforcement
- [ ] Pull request security checks
- [ ] Automated compliance validation

---

# Container Security Roadmap

Planned container security capabilities include:

- [ ] Container image analysis
- [ ] Vulnerability integration
- [ ] Container misconfiguration detection
- [ ] Docker security checks
- [ ] Kubernetes security checks
- [ ] Container runtime security checks

---

# Dashboard Roadmap

A future web dashboard will provide centralized security posture visibility.

Planned dashboard sections:

```text
Dashboard
|
+-- Security Posture
|
+-- Risk Overview
|
+-- Findings
|
+-- Critical Resources
|
+-- Cloud Accounts
|
+-- Services
|
+-- Compliance
|
+-- Scan History
|
+-- Trends
|
+-- Remediation
```

Current status:

- [ ] Next.js dashboard
- [ ] Security posture overview
- [ ] Risk dashboard
- [ ] Findings dashboard
- [ ] Compliance dashboard
- [ ] Scan history visualization
- [ ] Trend visualization

---

# Reporting Roadmap

Planned report types include:

## Executive Report

```text
Security Posture
Critical Findings
High-Risk Resources
Risk Trends
Compliance Summary
```

## Technical Report

```text
Rule
Resource
Evidence
Severity
Risk
Remediation
Compliance
```

## Compliance Report

```text
Framework
Control
Status
Findings
Coverage
Gaps
```

Current status:

- [ ] HTML reports
- [ ] PDF reports
- [ ] Executive reports
- [ ] Technical reports
- [ ] Compliance reports

---

# Continuous Monitoring Roadmap

The long-term architecture can evolve from one-time scanning toward continuous security posture monitoring.

```text
Cloud
 |
 v
Scheduled Scan
 |
 v
Current State
 |
 +----------------------+
 |                      |
 v                      v
Previous State       Current State
 |                      |
 +----------+-----------+
            |
            v
        Difference
            |
            v
    Configuration Drift
            |
            v
      Security Finding
```

Planned capabilities:

- [ ] Scheduled scans
- [ ] Periodic posture assessment
- [ ] Configuration drift detection
- [ ] Finding state tracking
- [ ] Finding resolution tracking
- [ ] Notifications
- [ ] Continuous compliance monitoring

---

# Finding Lifecycle

The intended finding lifecycle is:

```text
Detected
   |
   v
Open
   |
   v
Investigating
   |
   +------> Accepted Risk
   |
   +------> False Positive
   |
   v
Remediated
   |
   v
Resolved
```

This provides a foundation for evolving CloudSentinel from a scanner into a security operations platform.

---

# Future Finding Management

Planned capabilities:

- [ ] Finding status
- [ ] Finding ownership
- [ ] Finding assignment
- [ ] Analyst comments
- [ ] Accepted risk
- [ ] False-positive handling
- [ ] Remediation tracking
- [ ] SLA tracking
- [ ] Finding deduplication
- [ ] Finding suppression
- [ ] Historical finding state

---

# Authentication & Authorization Roadmap

Future enterprise access control is planned around:

- [ ] User authentication
- [ ] Role-based access control
- [ ] Organization support
- [ ] Project/workspace isolation
- [ ] API authentication
- [ ] API tokens
- [ ] Audit logs
- [ ] Permission management

---

# Enterprise Roadmap

Long-term enterprise capabilities include:

- [ ] Multi-tenant architecture
- [ ] Organization management
- [ ] RBAC
- [ ] SSO
- [ ] Audit logging
- [ ] API tokens
- [ ] Scheduled scans
- [ ] Notifications
- [ ] Security integrations
- [ ] Centralized compliance
- [ ] Multi-account management
- [ ] Multi-subscription management

---

# Development Roadmap

## Phase 1 — AWS Security Foundation

- [x] AWS provider architecture
- [x] AWS service architecture
- [x] EC2 security coverage
- [x] IAM security coverage
- [x] S3 security coverage
- [x] RDS security coverage
- [x] Lambda security coverage
- [x] KMS security coverage
- [x] VPC security coverage
- [x] CloudTrail security coverage

---

## Phase 2 — Detection Quality

- [x] Evidence-driven findings
- [x] Rule-level testing
- [x] Collector testing
- [x] Provider service testing
- [x] Scanner integration testing
- [x] Backend testing
- [x] Full regression suite
- [ ] Finding deduplication
- [ ] Historical configuration comparison
- [ ] Detection confidence improvements
- [ ] Further false-positive reduction
- [ ] Expanded edge-case coverage

---

## Phase 3 — Compliance

- [x] CIS mapping foundation
- [ ] Expanded CIS coverage
- [ ] NIST mapping
- [ ] PCI DSS mapping
- [ ] Custom compliance frameworks
- [ ] Compliance reporting
- [ ] Compliance dashboard

---

## Phase 4 — Infrastructure Security

- [ ] Terraform / IaC scanning
- [ ] IaC policy enforcement
- [ ] Container security scanning
- [ ] CI/CD security gates
- [ ] Dependency security
- [ ] Secret detection
- [ ] Configuration drift detection

---

## Phase 5 — Multi-Cloud

- [ ] Azure provider
- [ ] Azure authentication
- [ ] Azure resource discovery
- [ ] Azure collectors
- [ ] Azure security rules
- [ ] Azure compliance mapping
- [ ] Multi-account AWS scanning
- [ ] Multi-subscription Azure scanning

---

## Phase 6 — Security Platform

- [x] FastAPI backend
- [x] Finding persistence
- [x] Scan history
- [x] Findings API
- [x] Scan APIs
- [x] Worker architecture
- [ ] Next.js dashboard
- [ ] HTML reports
- [ ] PDF reports
- [ ] Scheduled scans
- [ ] Notifications
- [ ] Enterprise RBAC
- [ ] Advanced reporting
- [ ] Continuous monitoring

---

# Current Completed Work

## AWS

- [x] AWS provider foundation
- [x] EC2 security coverage
- [x] IAM security coverage
- [x] S3 security coverage
- [x] RDS security coverage
- [x] Lambda security coverage
- [x] KMS security coverage
- [x] VPC security coverage
- [x] CloudTrail security coverage

## Detection Architecture

- [x] Provider service layer
- [x] Collector layer
- [x] Data normalization
- [x] Rule registry
- [x] Rule handlers
- [x] Finding generation
- [x] Evidence collection
- [x] Remediation guidance
- [x] Compliance references
- [x] Risk assessment

## Platform

- [x] FastAPI backend
- [x] Finding persistence
- [x] Scan persistence
- [x] Scan history
- [x] Findings API
- [x] Scan API
- [x] Worker architecture

## Quality

- [x] Unit testing
- [x] Rule testing
- [x] Service testing
- [x] Collector testing
- [x] Registry testing
- [x] Scanner testing
- [x] Backend testing
- [x] Full regression testing

---

# Remaining Work

## Cloud Coverage

- [ ] Azure implementation
- [ ] Multi-account AWS scanning
- [ ] Multi-subscription Azure scanning
- [ ] Additional meaningful AWS services where required

## Security Engineering

- [ ] Finding deduplication
- [ ] Historical configuration comparison
- [ ] Configuration drift detection
- [ ] Detection confidence improvements
- [ ] Further false-positive reduction
- [ ] Finding lifecycle management

## Compliance

- [ ] Expanded CIS coverage
- [ ] NIST mapping
- [ ] PCI DSS mapping
- [ ] Custom frameworks
- [ ] Compliance reporting
- [ ] Compliance dashboard

## Infrastructure Security

- [ ] Terraform / IaC scanning
- [ ] IaC policy enforcement
- [ ] Container security scanning
- [ ] Kubernetes security checks
- [ ] CI/CD security gates
- [ ] Dependency security
- [ ] Secret detection

## Platform

- [ ] Next.js dashboard
- [ ] HTML reports
- [ ] PDF reports
- [ ] Scheduled scans
- [ ] Notifications
- [ ] Enterprise RBAC
- [ ] SSO
- [ ] Multi-tenancy
- [ ] Advanced reporting
- [ ] Continuous monitoring

---

# Security Coverage Summary

```text
AWS Security Coverage
=====================

IAM        ###################################### 38
EC2        ##########                           10
S3           ########                              8
RDS          ########                              8
CloudTrail ##########                            10
Lambda       ######                               6
VPC          #####                                5
KMS          ###                                  3
---------------------------------------------------
TOTAL                                             88
```

The project intentionally avoids treating rule count as the primary measure of maturity.

The goal is:

```text
Meaningful Coverage
        +
Reliable Detection
        +
Strong Evidence
        +
Low Noise
        +
Strong Testing
        +
Maintainable Architecture
```

---

# Production-Oriented Goals

CloudSentinel is being developed toward a production-grade cloud security platform.

Long-term goals include:

- [x] Strong AWS security foundation
- [x] Extensible rule architecture
- [x] Evidence-driven findings
- [x] Risk assessment
- [x] Compliance foundation
- [x] Automated testing
- [x] API-based access
- [x] Scan persistence
- [ ] Multi-cloud security coverage
- [ ] IaC security
- [ ] Container security
- [ ] Continuous monitoring
- [ ] Security dashboard
- [ ] Compliance reporting
- [ ] Enterprise access control
- [ ] Notification integrations

---

# Project Philosophy

CloudSentinel is not being developed around the question:

> "How many rules can we add?"

The focus is:

> "How much meaningful security coverage can we provide with reliable detection, strong evidence, low noise, maintainable architecture, and production-quality testing?"

The project therefore prioritizes:

```text
Coverage
   +
Accuracy
   +
Evidence
   +
Testability
   +
Maintainability
   +
Extensibility
```

over raw rule count.

---

# Security Rule Quality Standard

A production-oriented security rule should ideally satisfy:

```text
+--------------------------------------+
| Security Requirement Clearly Defined |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Required Data Identified             |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Provider Data Collected              |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Data Normalized                      |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Detection Logic Implemented          |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Rule Registered                      |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Positive Tests                       |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Negative Tests                       |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Edge-Case Tests                      |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Integration Testing                  |
+--------------------------------------+
                  |
                  v
+--------------------------------------+
| Full Regression                      |
+--------------------------------------+
```

---

# Testing Before Release

Before a security-related change is considered complete:

```bash
pytest -q
```

Then verify:

```bash
git diff --check
```

Review the staged diff before committing.

Avoid staging unrelated local changes.

For example:

```bash
git status --short
git diff
git diff --cached
```

Only the intended project changes should be included in a commit.

---

# Contributing

Contributions, security improvements, ideas, and new detection rules are welcome.

For new security rules:

1. Clearly define the security requirement.
2. Identify the required cloud data.
3. Reuse existing service methods where possible.
4. Extend collectors when necessary.
5. Normalize provider-specific data.
6. Implement the rule.
7. Register the rule.
8. Add positive tests.
9. Add negative tests.
10. Add edge-case tests.
11. Run relevant service tests.
12. Run relevant rule tests.
13. Run the complete regression suite.
14. Review the Git diff.
15. Ensure unrelated changes are not staged.

---

# Security

If a security vulnerability is discovered in CloudSentinel, responsible disclosure should be followed.

Do not publicly disclose sensitive vulnerability details before maintainers have had an opportunity to investigate and respond.

See `SECURITY.md` for the project's security policy when available.

---

# License

See `LICENSE` for the project's licensing terms.

---

# Current State

CloudSentinel currently represents a substantial AWS-focused cloud security auditing foundation.

```text
                    CloudSentinel
                          |
                          v
                  AWS Provider
                          |
                          v
                8 Security Domains
                          |
                          v
                    88 Rules
                          |
                          v
               Evidence-Driven Findings
                          |
                          v
                  Risk Assessment
                          |
                          v
                Compliance Foundation
                          |
                          v
                    Persistence
                          |
                          v
                       REST API
                          |
                          v
                 Worker Architecture
                          |
                          v
              Automated Regression Tests
```

The current project is production-oriented but remains under active development.

The next major milestones are focused on platform completeness rather than simply adding more security rules:

```text
Platform Completeness
        +
Detection Quality
        +
Compliance Depth
        +
Infrastructure-as-Code Security
        +
Multi-Cloud Support
        +
Operational Capabilities
```

---

# Roadmap at a Glance

```text
                         CURRENT
                            |
                            v
                 +---------------------+
                 | AWS Security Engine |
                 +---------------------+
                            |
                            v
                 +---------------------+
                 | Detection Quality   |
                 +---------------------+
                            |
                            v
                 +---------------------+
                 | Compliance Depth    |
                 +---------------------+
                            |
                            v
                 +---------------------+
                 | IaC / DevSecOps     |
                 +---------------------+
                            |
                            v
                 +---------------------+
                 | Azure / Multi-Cloud |
                 +---------------------+
                            |
                            v
                 +---------------------+
                 | Security Platform   |
                 +---------------------+
                            |
                            v
                 +---------------------+
                 | Continuous CSPM     |
                 +---------------------+
```

---

# CloudSentinel

> **Discover. Evaluate. Explain. Secure.**
