from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.launch_template_ebs_encryption import (
    LaunchTemplateEBSEncryptionResult,
    build_launch_template_ebs_encryption_finding,
    check_launch_template_ebs_encryption,
)


def test_unencrypted_launch_template_ebs_volume_creates_finding():
    result = check_launch_template_ebs_encryption(
        launch_template_id="lt-001",
        launch_template_name="production-template",
        version_number=7,
        device_name="/dev/xvda",
        encrypted=False,
    )

    assert result is not None
    assert isinstance(
        result,
        LaunchTemplateEBSEncryptionResult,
    )
    assert result.launch_template_id == "lt-001"
    assert result.launch_template_name == "production-template"
    assert result.version_number == 7
    assert result.device_name == "/dev/xvda"
    assert result.encrypted is False


def test_encrypted_launch_template_ebs_volume_is_compliant():
    result = check_launch_template_ebs_encryption(
        launch_template_id="lt-001",
        launch_template_name="production-template",
        version_number=7,
        device_name="/dev/xvda",
        encrypted=True,
    )

    assert result is None


def test_launch_template_result_is_immutable():
    result = LaunchTemplateEBSEncryptionResult(
        launch_template_id="lt-001",
        launch_template_name="production-template",
        version_number=7,
        device_name="/dev/xvda",
        encrypted=False,
    )

    try:
        result.encrypted = True
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "LaunchTemplateEBSEncryptionResult must be immutable"
        )


def test_launch_template_ebs_finding_metadata():
    result = check_launch_template_ebs_encryption(
        launch_template_id="lt-002",
        launch_template_name="database-template",
        version_number=3,
        device_name="/dev/sdb",
        encrypted=False,
    )

    assert result is not None

    finding = build_launch_template_ebs_encryption_finding(
        result
    )

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-181"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_launch_template"
    assert finding.resource_id == "lt-002"
    assert finding.evidence["launch_template_id"] == "lt-002"
    assert finding.evidence["launch_template_name"] == (
        "database-template"
    )
    assert finding.evidence["version_number"] == 3
    assert finding.evidence["device_name"] == "/dev/sdb"
    assert finding.evidence["encrypted"] is False
    assert finding.compliance == [
        "AWS Security Hub EC2.181",
    ]
    assert finding.remediation
