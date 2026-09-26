from engine.findings.model import Severity
from engine.rules.aws.autoscaling.controls import (
    build_autoscaling_elb_health_checks_finding,
    build_autoscaling_imdsv2_finding,
    build_autoscaling_launch_template_finding,
    build_autoscaling_multiple_az_finding,
    build_autoscaling_multiple_instance_types_finding,
    build_autoscaling_public_ip_finding,
    build_autoscaling_tags_finding,
    check_autoscaling_elb_health_checks,
    check_autoscaling_imdsv2,
    check_autoscaling_launch_template,
    check_autoscaling_multiple_az,
    check_autoscaling_multiple_instance_types,
    check_autoscaling_public_ip,
    check_autoscaling_tags,
)


def test_elb_health_check_passes():
    assert check_autoscaling_elb_health_checks(
        "web",
        "arn",
        True,
        "ELB",
    ) is None


def test_elb_health_check_fails_for_load_balancer_without_elb_health_check():
    result = check_autoscaling_elb_health_checks(
        "web",
        "arn",
        True,
        "EC2",
    )

    assert result is not None
    finding = build_autoscaling_elb_health_checks_finding(result)
    assert finding.rule_id == "CS-AWS-AUTOSCALING-001"
    assert finding.severity == Severity.LOW


def test_elb_health_check_skips_group_without_load_balancer():
    assert check_autoscaling_elb_health_checks(
        "web",
        "arn",
        False,
        "EC2",
    ) is None


def test_multiple_az_passes():
    assert check_autoscaling_multiple_az(
        "web",
        "arn",
        2,
    ) is None


def test_multiple_az_fails_for_single_az():
    result = check_autoscaling_multiple_az(
        "web",
        "arn",
        1,
    )

    assert result is not None
    finding = build_autoscaling_multiple_az_finding(result)
    assert finding.rule_id == "CS-AWS-AUTOSCALING-002"
    assert finding.severity == Severity.MEDIUM


def test_imdsv2_passes():
    assert check_autoscaling_imdsv2(
        "web",
        "arn",
        "legacy",
        True,
        "required",
    ) is None


def test_imdsv2_fails_when_optional():
    result = check_autoscaling_imdsv2(
        "web",
        "arn",
        "legacy",
        True,
        "optional",
    )

    assert result is not None
    finding = build_autoscaling_imdsv2_finding(result)
    assert finding.rule_id == "CS-AWS-AUTOSCALING-003"
    assert finding.severity == Severity.HIGH


def test_imdsv2_skips_launch_template_group():
    assert check_autoscaling_imdsv2(
        "web",
        "arn",
        None,
        False,
        None,
    ) is None


def test_public_ip_passes_when_disabled():
    assert check_autoscaling_public_ip(
        "web",
        "arn",
        "legacy",
        True,
        False,
    ) is None


def test_public_ip_fails_when_enabled():
    result = check_autoscaling_public_ip(
        "web",
        "arn",
        "legacy",
        True,
        True,
    )

    assert result is not None
    finding = build_autoscaling_public_ip_finding(result)
    assert finding.rule_id == "CS-AWS-AUTOSCALING-005"
    assert finding.severity == Severity.HIGH


def test_multiple_instance_types_pass():
    assert check_autoscaling_multiple_instance_types(
        "web",
        "arn",
        ["m6i.large", "m6a.large"],
        2,
        True,
        False,
    ) is None


def test_multiple_instance_types_fail_for_single_type():
    result = check_autoscaling_multiple_instance_types(
        "web",
        "arn",
        ["m6i.large"],
        1,
        True,
        False,
    )

    assert result is not None
    finding = build_autoscaling_multiple_instance_types_finding(
        result
    )
    assert finding.rule_id == "CS-AWS-AUTOSCALING-006"
    assert finding.severity == Severity.MEDIUM


def test_multiple_instance_types_skips_attribute_based_selection():
    assert check_autoscaling_multiple_instance_types(
        "web",
        "arn",
        [],
        0,
        False,
        True,
    ) is None


def test_launch_template_passes():
    assert check_autoscaling_launch_template(
        "web",
        "arn",
        True,
    ) is None


def test_launch_template_fails():
    result = check_autoscaling_launch_template(
        "web",
        "arn",
        False,
    )

    assert result is not None
    finding = build_autoscaling_launch_template_finding(result)
    assert finding.rule_id == "CS-AWS-AUTOSCALING-009"
    assert finding.severity == Severity.MEDIUM


def test_tags_pass_with_non_system_tag():
    assert check_autoscaling_tags(
        "web",
        "arn",
        True,
    ) is None


def test_tags_fail_without_non_system_tag():
    result = check_autoscaling_tags(
        "web",
        "arn",
        False,
    )

    assert result is not None
    finding = build_autoscaling_tags_finding(result)
    assert finding.rule_id == "CS-AWS-AUTOSCALING-010"
    assert finding.severity == Severity.LOW
