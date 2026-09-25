from engine.findings.model import Finding, Severity

from engine.rules.aws.inspector.common import (
    InspectorControlResult,
    check_scanning_enabled,
)


def check_ec2_scanning(
    resource_id: str,
    ec2_status: str | None,
) -> InspectorControlResult | None:
    return check_scanning_enabled(
        resource_id,
        ec2_status,
        control_name=(
            "Amazon Inspector EC2 scanning"
        ),
        status_field="ec2_status",
    )


def check_ecr_scanning(
    resource_id: str,
    ecr_status: str | None,
) -> InspectorControlResult | None:
    return check_scanning_enabled(
        resource_id,
        ecr_status,
        control_name=(
            "Amazon Inspector ECR scanning"
        ),
        status_field="ecr_status",
    )


def check_lambda_code_scanning(
    resource_id: str,
    lambda_code_status: str | None,
) -> InspectorControlResult | None:
    return check_scanning_enabled(
        resource_id,
        lambda_code_status,
        control_name=(
            "Amazon Inspector Lambda code scanning"
        ),
        status_field="lambda_code_status",
    )


def check_lambda_scanning(
    resource_id: str,
    lambda_status: str | None,
) -> InspectorControlResult | None:
    return check_scanning_enabled(
        resource_id,
        lambda_status,
        control_name=(
            "Amazon Inspector Lambda standard scanning"
        ),
        status_field="lambda_status",
    )


def build_finding(
    result: InspectorControlResult,
    *,
    rule_id: str,
    title: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity.HIGH,
        provider="aws",
        resource_type="inspector_account",
        resource_id=result.resource_id,
        description=(
            f"{result.control_name} is not enabled "
            "as required."
        ),
        evidence={
            "account_id": result.resource_id,
            "status_field": result.status_field,
            "expected_status": result.expected_status,
            "actual_status": result.actual_status,
        },
        remediation=(
            "Enable the required Amazon Inspector "
            "scanning feature for the AWS account."
        ),
        compliance=[
            f"AWS Security Hub "
            f"{rule_id.replace('CS-AWS-INSPECTOR-', 'Inspector.')}"
        ],
    )


def build_inspector_001(
    result: InspectorControlResult,
) -> Finding:
    return build_finding(
        result,
        rule_id="CS-AWS-INSPECTOR-001",
        title=(
            "Amazon Inspector EC2 scanning "
            "should be enabled"
        ),
    )


def build_inspector_002(
    result: InspectorControlResult,
) -> Finding:
    return build_finding(
        result,
        rule_id="CS-AWS-INSPECTOR-002",
        title=(
            "Amazon Inspector ECR scanning "
            "should be enabled"
        ),
    )


def build_inspector_003(
    result: InspectorControlResult,
) -> Finding:
    return build_finding(
        result,
        rule_id="CS-AWS-INSPECTOR-003",
        title=(
            "Amazon Inspector Lambda code scanning "
            "should be enabled"
        ),
    )


def build_inspector_004(
    result: InspectorControlResult,
) -> Finding:
    return build_finding(
        result,
        rule_id="CS-AWS-INSPECTOR-004",
        title=(
            "Amazon Inspector Lambda standard scanning "
            "should be enabled"
        ),
    )
