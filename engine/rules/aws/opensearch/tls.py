from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


LATEST_TLS_POLICY = "Policy-Min-TLS-1-2-PFS-2023-10"


@dataclass(frozen=True)
class OpenSearchTLSResult:
    domain_arn: str
    domain_name: str
    https_enforced: bool
    tls_security_policy: str | None
    endpoint_options: dict[str, Any]


def check_opensearch_tls(
    domain_arn: str,
    domain_name: str,
    domain_endpoint_options: dict[str, Any],
) -> OpenSearchTLSResult:
    if not isinstance(domain_endpoint_options, dict):
        domain_endpoint_options = {}

    https_enforced = (
        domain_endpoint_options.get("EnforceHTTPS") is True
    )

    policy = domain_endpoint_options.get(
        "TLSSecurityPolicy"
    )

    if not isinstance(policy, str):
        policy = None

    return OpenSearchTLSResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        https_enforced=https_enforced,
        tls_security_policy=policy,
        endpoint_options=domain_endpoint_options,
    )


def build_opensearch_tls_finding(
    result: OpenSearchTLSResult,
) -> Finding | None:
    if (
        result.https_enforced
        and result.tls_security_policy == LATEST_TLS_POLICY
    ):
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-008",
        title="OpenSearch Domain Does Not Use The Latest TLS Security Policy",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "The OpenSearch domain does not enforce HTTPS with "
            "the latest supported TLS security policy."
        ),
        evidence={
            "domain_name": result.domain_name,
            "https_enforced": result.https_enforced,
            "tls_security_policy": result.tls_security_policy,
            "required_tls_security_policy": LATEST_TLS_POLICY,
        },
        remediation=(
            "Enable HTTPS enforcement and configure the OpenSearch "
            f"domain to use {LATEST_TLS_POLICY}."
        ),
        compliance=[
            "AWS Security Hub Opensearch.8",
        ],
    )
