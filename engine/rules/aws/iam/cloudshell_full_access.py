from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudShellFullAccessResult:
    identity_type: str
    identity_name: str
    identity_arn: str | None
    policy_arn: str


def check_cloudshell_full_access(
    identity_type: str,
    identity_name: str,
    identity_arn: str | None,
    policy_arn: str,
) -> CloudShellFullAccessResult:
    return CloudShellFullAccessResult(
        identity_type=identity_type,
        identity_name=identity_name,
        identity_arn=identity_arn,
        policy_arn=policy_arn,
    )


def build_cloudshell_full_access_finding(
    result: CloudShellFullAccessResult,
) -> Finding:
    resource_type = (
        f"iam_{result.identity_type}"
    )

    return Finding(
        rule_id="CS-AWS-IAM-044",
        title=(
            "AWSCloudShellFullAccess Attached to IAM Identity"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type=resource_type,
        resource_id=(
            result.identity_arn
            or result.identity_name
        ),
        description=(
            f"The IAM {result.identity_type} "
            f"'{result.identity_name}' has the AWS-managed "
            "AWSCloudShellFullAccess policy attached."
        ),
        evidence={
            "identity_type": result.identity_type,
            "identity_name": result.identity_name,
            "identity_arn": result.identity_arn,
            "policy_arn": result.policy_arn,
        },
        remediation=(
            "Detach AWSCloudShellFullAccess unless the identity "
            "has a documented requirement for full CloudShell access. "
            "Prefer narrower CloudShell permissions where possible."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
