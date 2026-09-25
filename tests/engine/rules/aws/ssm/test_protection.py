from engine.rules.aws.ssm.protection import (
    check_association_compliance,
    check_automation_logging,
    check_document_not_public,
    check_ec2_managed_by_ssm,
    check_patch_compliance,
    check_public_sharing_block,
)


def test_ec2_managed_by_ssm_passes():
    assert (
        check_ec2_managed_by_ssm(
            "i-001",
            "running",
            True,
        )
        is None
    )


def test_ec2_managed_by_ssm_fails():
    result = check_ec2_managed_by_ssm(
        "i-001",
        "stopped",
        False,
    )

    assert result is not None
    assert result.resource_id == "i-001"
    assert result.instance_state == "stopped"


def test_patch_compliance_ignores_association():
    assert (
        check_patch_compliance(
            "i-001",
            "Association",
            "NON_COMPLIANT",
            "HIGH",
            None,
        )
        is None
    )


def test_patch_compliance_passes():
    assert (
        check_patch_compliance(
            "i-001",
            "Patch",
            "COMPLIANT",
            None,
            None,
        )
        is None
    )


def test_patch_compliance_fails():
    result = check_patch_compliance(
        "i-001",
        "Patch",
        "NON_COMPLIANT",
        "HIGH",
        {"ExecutionTime": "2026-09-25"},
    )

    assert result is not None
    assert result.status == "NON_COMPLIANT"


def test_association_compliance_passes():
    assert (
        check_association_compliance(
            "i-001",
            "Association",
            "COMPLIANT",
            None,
            None,
        )
        is None
    )


def test_association_compliance_fails():
    result = check_association_compliance(
        "i-001",
        "Association",
        "NON_COMPLIANT",
        "HIGH",
        None,
    )

    assert result is not None
    assert result.status == "NON_COMPLIANT"


def test_document_public_passes_when_not_public():
    assert (
        check_document_not_public(
            "doc-001",
            "MyDocument",
            "123456789012",
            ["123456789012"],
            False,
        )
        is None
    )


def test_document_public_fails():
    result = check_document_not_public(
        "doc-001",
        "MyDocument",
        "123456789012",
        ["All"],
        True,
    )

    assert result is not None
    assert result.public is True


def test_automation_logging_accepts_cloudwatch():
    assert (
        check_automation_logging(
            "setting",
            "setting",
            "CloudWatch",
            "Customized",
        )
        is None
    )


def test_automation_logging_fails_for_other_value():
    result = check_automation_logging(
        "setting",
        "setting",
        "None",
        "Default",
    )

    assert result is not None
    assert result.setting_value == "None"


def test_public_sharing_block_accepts_disable():
    assert (
        check_public_sharing_block(
            "setting",
            "setting",
            "Disable",
            "Customized",
        )
        is None
    )


def test_public_sharing_block_fails_for_enable():
    result = check_public_sharing_block(
        "setting",
        "setting",
        "Enable",
        "Default",
    )

    assert result is not None
    assert result.setting_value == "Enable"


def test_public_sharing_block_fails_when_missing():
    result = check_public_sharing_block(
        "setting",
        "setting",
        None,
        None,
    )

    assert result is not None
    assert result.setting_value is None
