# CloudSentinel

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

See `LICENSE` for the project's licensing terms.
