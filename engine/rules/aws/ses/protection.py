from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SESTaggingResult:
    resource_id: str
    resource_type: str


def check_ses_tagging(
    resource_id: str,
    resource_type: str,
    tags: list[dict[str, str]],
) -> SESTaggingResult | None:
    if not resource_id:
        return None

    if tags:
        return None

    return SESTaggingResult(
        resource_id=resource_id,
        resource_type=resource_type,
    )


def build_ses_contact_list_tagging_finding(
    result: SESTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SES-001",
        title="SES contact lists should be tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The SES contact list "
            f"{result.resource_id} does not have "
            "any non-system tags."
        ),
        evidence={
            "resource_id": result.resource_id,
            "resource_type": result.resource_type,
            "tagged": False,
        },
        remediation=(
            "Add one or more meaningful non-system tags "
            "to the SES contact list. If your "
            "organization uses required tag keys, "
            "configure the corresponding Security Hub "
            "control parameter."
        ),
        compliance=[
            "AWS Security Hub SES.1",
        ],
    )


def build_ses_configuration_set_tagging_finding(
    result: SESTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SES-002",
        title="SES configuration sets should be tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            f"The SES configuration set "
            f"{result.resource_id} does not have "
            "any non-system tags."
        ),
        evidence={
            "resource_id": result.resource_id,
            "resource_type": result.resource_type,
            "tagged": False,
        },
        remediation=(
            "Add one or more meaningful non-system tags "
            "to the SES configuration set. If your "
            "organization uses required tag keys, "
            "configure the corresponding Security Hub "
            "control parameter."
        ),
        compliance=[
            "AWS Security Hub SES.2",
        ],
    )


@dataclass(frozen=True)
class SESTLSResult:
    resource_id: str
    tls_policy: str | None


def check_ses_tls_policy(
    resource_id: str,
    tls_policy: str | None,
) -> SESTLSResult | None:
    if not resource_id:
        return None

    if tls_policy == "REQUIRE":
        return None

    return SESTLSResult(
        resource_id=resource_id,
        tls_policy=tls_policy,
    )


def build_ses_tls_finding(
    result: SESTLSResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SES-003",
        title=(
            "SES configuration sets should require TLS "
            "for sending emails"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ses_configuration_set",
        resource_id=result.resource_id,
        description=(
            f"The SES configuration set "
            f"{result.resource_id} does not require "
            "TLS for sending email."
        ),
        evidence={
            "configuration_set_name": result.resource_id,
            "tls_policy": result.tls_policy,
            "tls_required": False,
        },
        remediation=(
            "Configure the SES configuration set "
            "DeliveryOptions TlsPolicy to REQUIRE so "
            "messages are only delivered when a TLS "
            "connection can be established."
        ),
        compliance=[
            "AWS Security Hub SES.3",
        ],
    )
