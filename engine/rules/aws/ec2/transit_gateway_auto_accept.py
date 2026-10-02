from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class TransitGatewayAutoAcceptResult:
    transit_gateway_id: str
    auto_accept_shared_attachments: str

    @property
    def is_non_compliant(self) -> bool:
        return (
            self.auto_accept_shared_attachments.lower()
            == "enable"
        )


def check_transit_gateway_auto_accept(
    transit_gateway_id: str,
    auto_accept_shared_attachments: str | None,
) -> TransitGatewayAutoAcceptResult | None:
    if not auto_accept_shared_attachments:
        return None

    result = TransitGatewayAutoAcceptResult(
        transit_gateway_id=transit_gateway_id,
        auto_accept_shared_attachments=auto_accept_shared_attachments,
    )

    if not result.is_non_compliant:
        return None

    return result


def build_transit_gateway_auto_accept_finding(
    result: TransitGatewayAutoAcceptResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-023",
        title="Transit Gateway Should Not Automatically Accept VPC Attachments",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ec2_transit_gateway",
        resource_id=result.transit_gateway_id,
        description=(
            "The transit gateway is configured to automatically "
            "accept shared VPC attachment requests."
        ),
        evidence={
            "transit_gateway_id": result.transit_gateway_id,
            "auto_accept_shared_attachments": (
                result.auto_accept_shared_attachments
            ),
        },
        remediation=(
            "Set AutoAcceptSharedAttachments to disable unless "
            "automatic acceptance is explicitly required."
        ),
        compliance=["AWS Security Hub EC2.23"],
    )
