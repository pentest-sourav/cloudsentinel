from engine.findings.model import Severity

from engine.rules.aws.ses.protection import (
    build_ses_configuration_set_tagging_finding,
    build_ses_contact_list_tagging_finding,
    build_ses_tls_finding,
    check_ses_tagging,
    check_ses_tls_policy,
)


def test_tagging_passes_with_non_system_tag():
    assert (
        check_ses_tagging(
            resource_id="resource-1",
            resource_type="ses_contact_list",
            tags=[
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        )
        is None
    )


def test_tagging_fails_without_tags():
    result = check_ses_tagging(
        resource_id="resource-1",
        resource_type="ses_contact_list",
        tags=[],
    )

    assert result is not None
    assert result.resource_id == "resource-1"


def test_tls_passes_when_require():
    assert (
        check_ses_tls_policy(
            resource_id="config-1",
            tls_policy="REQUIRE",
        )
        is None
    )


def test_tls_fails_when_opportunistic():
    result = check_ses_tls_policy(
        resource_id="config-1",
        tls_policy="OPPORTUNISTIC",
    )

    assert result is not None
    assert result.resource_id == "config-1"
    assert result.tls_policy == "OPPORTUNISTIC"


def test_tls_fails_when_missing():
    result = check_ses_tls_policy(
        resource_id="config-1",
        tls_policy=None,
    )

    assert result is not None


def test_contact_list_finding():
    result = check_ses_tagging(
        resource_id="marketing",
        resource_type="ses_contact_list",
        tags=[],
    )

    finding = (
        build_ses_contact_list_tagging_finding(result)
    )

    assert finding.rule_id == "CS-AWS-SES-001"
    assert finding.severity == Severity.LOW
    assert finding.compliance == [
        "AWS Security Hub SES.1",
    ]


def test_configuration_set_tagging_finding():
    result = check_ses_tagging(
        resource_id="prod",
        resource_type="ses_configuration_set",
        tags=[],
    )

    finding = (
        build_ses_configuration_set_tagging_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-SES-002"
    assert finding.severity == Severity.LOW
    assert finding.compliance == [
        "AWS Security Hub SES.2",
    ]


def test_tls_finding():
    result = check_ses_tls_policy(
        resource_id="prod",
        tls_policy="OPPORTUNISTIC",
    )

    finding = build_ses_tls_finding(result)

    assert finding.rule_id == "CS-AWS-SES-003"
    assert finding.severity == Severity.MEDIUM
    assert finding.compliance == [
        "AWS Security Hub SES.3",
    ]
